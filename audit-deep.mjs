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
log(`Deep-auditing ${hosts.length} lead domains (passive checks only)...`);

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
  } else {
    a.ok = false;
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
    try { a.mx = (await dns.resolveMx(apex)).length > 0; } catch { /* unknown */ }
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
await Promise.all(Array.from({ length: 8 }, worker));

fs.writeFileSync(path.join(out, 'audits.json'), JSON.stringify(results, null, 1));
const withDns = Object.values(results).filter((a) => a.spf !== undefined);
log(`Done → out/audits.json (${Object.keys(results).length} domains; ` +
  `${withDns.filter((a) => !a.spf).length} missing SPF, ` +
  `${Object.values(results).filter((a) => a.dmarc === false).length} missing DMARC, ` +
  `${Object.values(results).filter((a) => a.certDaysLeft != null && a.certDaysLeft < 0).length} expired certs)`);
