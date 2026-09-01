#!/usr/bin/env node
/**
 * Second-pass deep audit for LEADS only (not the whole inventory).
 * All checks are passive lookups of public information: the business's own
 * homepage, its TLS certificate, and public DNS records. Nothing is probed.
 *
 * Reads  out/leads.json
 * Writes out/audits.json  (keyed by hostname)
 *
 * Per site: SEO basics (title/description/h1), page weight signals, HSTS,
 * TLS certificate expiry/issuer, SPF + DMARC + MX records.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import tls from 'node:tls';
import dns from 'node:dns/promises';
import { hostnameOf, SOCIAL_RE } from './lib.mjs';

const dir = path.dirname(fileURLToPath(import.meta.url));
const out = path.join(dir, 'out');
const UA = 'IgniteCyber-LeadScanner/1.0 (local business research; ignitecyber.io)';
const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);

// Builder-hosted subdomains: TLS/DNS belong to the platform, not the business.
const PLATFORM_RE = /(wixsite|godaddysites|weebly|squarespace|wordpress|blogspot|business\.site|webs)\.(com|site)$|business\.site$/i;

const leads = JSON.parse(fs.readFileSync(path.join(out, 'leads.json'), 'utf8'));
const hosts = [...new Set(
  leads.filter((l) => l.website && !SOCIAL_RE.test(l.website))
    .map((l) => hostnameOf(l.website)).filter(Boolean)
)];
// slow-moving signals (RDAP expiry, Wayback, sitemap, contact crawl) are cached
// per host for ~7 days so daily light runs stay cheap
let existing = {};
try { existing = JSON.parse(fs.readFileSync(path.join(out, 'audits.json'), 'utf8')); } catch { /* first run */ }
const D2_TTL = 6.5 * 86400000;
log(`Deep-auditing ${hosts.length} lead domains (passive checks only)...`);

async function rdapExpiry(apex) {
  const tld = apex.split('.').pop();
  const url = (tld === 'com' || tld === 'net')
    ? `https://rdap.verisign.com/${tld}/v1/domain/${apex}`
    : `https://rdap.org/domain/${apex}`;
  try {
    const res = await fetch(url, { headers: { Accept: 'application/rdap+json' }, redirect: 'follow', signal: AbortSignal.timeout(15000) });
    if (!res.ok) return null;
    const d = await res.json();
    const ev = (d.events || []).find((e) => e.eventAction === 'expiration');
    return ev && ev.eventDate ? ev.eventDate.slice(0, 10) : null;
  } catch { return null; }
}

async function waybackStale(host) {
  try {
    const res = await fetch(`https://web.archive.org/cdx/search/cdx?url=${host}&output=json&fl=timestamp,digest&filter=statuscode:200&limit=-6`,
      { signal: AbortSignal.timeout(20000), headers: { 'User-Agent': UA } });
    if (!res.ok) return null;
    const rows = await res.json();
    if (!Array.isArray(rows) || rows.length < 3) return null;
    const snaps = rows.slice(1);
    const digests = new Set(snaps.map((r) => r[1]));
    const oldestY = +snaps[0][0].slice(0, 4);
    const newestY = +snaps[snaps.length - 1][0].slice(0, 4);
    if (digests.size === 1 && newestY - oldestY >= 2) return { since: String(oldestY) };
    if (new Date().getFullYear() - newestY >= 3) return { lastSnap: String(newestY) };
    return null;
  } catch { return null; }
}

function classifyMx(mxHost) {
  const h = (mxHost || '').toLowerCase();
  if (!h) return '';
  if (/google|gmail/.test(h)) return 'Google Workspace';
  if (/outlook|protection\.|microsoft/.test(h)) return 'Microsoft 365';
  if (/secureserver/.test(h)) return 'GoDaddy email';
  if (/zoho/.test(h)) return 'Zoho Mail';
  if (/emailsrvr|rackspace/.test(h)) return 'Rackspace email';
  if (/yahoodns/.test(h)) return 'Yahoo Small Business';
  if (/mimecast|pphosted|barracuda|mailanyone|fusemail/.test(h)) return 'filtered enterprise mail';
  return 'self/other-hosted mail';
}

function getCert(host) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve(v); } };
    try {
      const s = tls.connect({ host, port: 443, servername: host, rejectUnauthorized: false, timeout: 8000 }, () => {
        try {
          const c = s.getPeerCertificate();
          finish(c && c.valid_to ? { validTo: c.valid_to, issuer: (c.issuer && (c.issuer.O || c.issuer.CN)) || '' } : null);
        } catch { finish(null); }
        s.destroy();
      });
      s.on('error', () => finish(null));
      s.on('timeout', () => { s.destroy(); finish(null); });
    } catch { finish(null); }
  });
}

async function txtLookup(name) {
  try {
    const rows = await dns.resolveTxt(name);
    return { ok: true, txt: rows.map((r) => r.join('')) };
  } catch (e) {
    if (e.code === 'ENODATA' || e.code === 'ENOTFOUND') return { ok: true, txt: [] };
    return { ok: false, txt: [] }; // lookup failure — make no claims
  }
}

function apexOf(host) {
  const parts = host.split('.');
  return parts.length <= 2 ? host : parts.slice(-2).join('.');
}

async function auditHost(host) {
  const a = { host, platform: PLATFORM_RE.test(host) };

  // Homepage: try www/apex on both schemes — a site only counts as unreachable
  // if every variant fails (many sites answer on exactly one hostname).
  let text = null, res = null;
  for (const cand of [`https://www.${host}/`, `https://${host}/`, `http://www.${host}/`, `http://${host}/`]) {
    try {
      res = await fetch(cand, {
        headers: { 'User-Agent': UA, Accept: 'text/html,*/*' },
        redirect: 'follow',
        signal: AbortSignal.timeout(12000),
      });
      if (res.ok) { text = (await res.text()).slice(0, 300000); break; }
    } catch { /* try next variant */ }
  }
  if (text) {
    a.ok = true;
    const title = text.match(/<title[^>]*>([\s\S]{0,300}?)<\/title>/i);
    a.title = title ? title[1].replace(/\s+/g, ' ').trim() : '';
    a.desc = /<meta[^>]+name=["']description["'][^>]+content=["'][^"']{10,}/i.test(text)
      || /<meta[^>]+content=["'][^"']{10,}["'][^>]+name=["']description["']/i.test(text);
    a.h1 = /<h1[\s>]/i.test(text);
    a.viewport = /<meta[^>]+name=["']?viewport/i.test(text);
    a.imgs = (text.match(/<img/gi) || []).length;
    a.scripts = (text.match(/<script[^>]+src=/gi) || []).length;
    a.htmlKB = Math.round(text.length / 1024);
    a.hsts = !!(res.headers.get('strict-transport-security'));
    a.finalHttps = (res.url || '').startsWith('https://');
    a.ld = /<script[^>]+ld\+json/i.test(text);
    a.localSchema = a.ld && /LocalBusiness|Dentist|Restaurant|Attorney|AutoRepair|MedicalBusiness|Plumber|Electrician|HomeAndConstructionBusiness|ProfessionalService|Store\b/i.test(text);

    // Tech-stack + analytics fingerprint (from homepage HTML — cheap, every run)
    const tech = [];
    if (/wp-content|wp-includes|wp-json/i.test(text)) tech.push('WordPress');
    if (/wixstatic|_wix|wix\.com/i.test(text)) tech.push('Wix');
    if (/squarespace|sqsp\.net/i.test(text)) tech.push('Squarespace');
    if (/cdn\.shopify|shopify/i.test(text)) tech.push('Shopify');
    if (/wsimg\.com|godaddy.*(website ?builder)?/i.test(text)) tech.push('GoDaddy Builder');
    if (/weebly/i.test(text)) tech.push('Weebly');
    if (/dudamobile|dudaone|\.duda\b/i.test(text)) tech.push('Duda');
    if (/joomla/i.test(text)) tech.push('Joomla');
    if (/drupal/i.test(text)) tech.push('Drupal');
    if (/webflow/i.test(text)) tech.push('Webflow');
    a.tech = tech;
    a.analytics = /gtag\(|google-analytics\.com|googletagmanager\.com|\bga\.js|analytics\.js|fbevents\.js|fbq\(|clarity\.ms|hotjar/i.test(text);
  } else {
    a.ok = false;
  }

  // Slow-moving checks, cached ~7 days (see D2_TTL): RDAP expiry, Wayback
  // staleness, sitemap presence, one contact-page crawl.
  const prev = existing[host];
  if (prev && prev.d2at && Date.now() - prev.d2at < D2_TTL) {
    for (const f of ['exp', 'wbSince', 'wbLast', 'smOk', 'cFound', 'cForm', 'cMailto', 'cEmails', 'd2at']) {
      if (prev[f] !== undefined) a[f] = prev[f];
    }
  } else if (!a.platform) {
    a.d2at = Date.now();
    const apex = apexOf(host);
    const [exp, wb] = await Promise.all([rdapExpiry(apex), waybackStale(host)]);
    if (exp) a.exp = exp;
    if (wb?.since) a.wbSince = wb.since;
    if (wb?.lastSnap) a.wbLast = wb.lastSnap;
    if (a.ok) {
      const scheme = (res?.url || '').startsWith('http:') ? 'http' : 'https';
      try {
        const sm = await fetch(`${scheme}://${host}/sitemap.xml`, { headers: { 'User-Agent': UA }, signal: AbortSignal.timeout(10000) });
        a.smOk = sm.ok;
      } catch { a.smOk = false; }
      const cm = text.match(/href=["']([^"']*contact[^"']{0,60})["']/i);
      if (cm) {
        a.cFound = true;
        try {
          const curl = new URL(cm[1], res.url || `https://${host}/`).href;
          const cres = await fetch(curl, { headers: { 'User-Agent': UA, Accept: 'text/html,*/*' }, redirect: 'follow', signal: AbortSignal.timeout(12000) });
          const ctext = cres.ok ? (await cres.text()).slice(0, 200000) : '';
          a.cForm = /<form[\s>]/i.test(ctext);
          a.cMailto = /mailto:/i.test(ctext);
          const emails = [...new Set((ctext.match(/\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b/gi) || [])
            .map((e) => e.toLowerCase()).filter((e) => !/\.(png|jpg|gif|webp|svg)$/.test(e)))];
          if (emails.length) a.cEmails = emails.slice(0, 3);
        } catch { /* contact page unreachable */ }
      } else {
        a.cFound = false;
      }
    }
  }

  if (!a.platform) {
    // Check the certificate on the hostname that actually serves the site
    // (a www-only site legitimately has no cert on the bare apex).
    let certHost = host;
    if (a.ok && a.finalHttps === undefined) a.finalHttps = (res?.url || '').startsWith('https://');
    try { if (a.ok && res?.url) certHost = new URL(res.url).hostname; } catch { /* keep host */ }
    const cert = await getCert(certHost);
    if (cert) {
      a.certIssuer = cert.issuer;
      const t = Date.parse(cert.validTo);
      if (!Number.isNaN(t)) {
        a.certValidTo = new Date(t).toISOString().slice(0, 10);
        a.certDaysLeft = Math.round((t - Date.now()) / 86400000);
      }
    }
    const apex = apexOf(host);
    const [spfQ, dmarcQ] = await Promise.all([txtLookup(apex), txtLookup('_dmarc.' + apex)]);
    if (spfQ.ok) a.spf = spfQ.txt.some((t) => /^v=spf1/i.test(t));
    if (dmarcQ.ok) a.dmarc = dmarcQ.txt.some((t) => /^v=dmarc1/i.test(t));
    try {
      const mx = await dns.resolveMx(apex);
      a.mx = mx.length > 0;
      a.mxh = mx.sort((x, y) => x.priority - y.priority)[0]?.exchange || '';
      a.mxp = classifyMx(a.mxh);
    } catch { /* unknown */ }
  }
  return a;
}

const results = {};
let i = 0, done = 0;
async function worker() {
  while (i < hosts.length) {
    const host = hosts[i++];
    try { results[host] = await auditHost(host); }
    catch { results[host] = { host, ok: false }; }
    done++;
    if (done % 40 === 0) log(`  ${done}/${hosts.length} domains...`);
  }
}
await Promise.all(Array.from({ length: 12 }, worker));

fs.writeFileSync(path.join(out, 'audits.json'), JSON.stringify(results, null, 1));
const withDns = Object.values(results).filter((a) => a.spf !== undefined);
log(`Done → out/audits.json (${Object.keys(results).length} domains; ` +
  `${withDns.filter((a) => !a.spf).length} missing SPF, ` +
  `${Object.values(results).filter((a) => a.dmarc === false).length} missing DMARC, ` +
  `${Object.values(results).filter((a) => a.certDaysLeft != null && a.certDaysLeft < 0).length} expired certs)`);
