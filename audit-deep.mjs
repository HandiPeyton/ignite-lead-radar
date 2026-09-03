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
 * TLS certificate expiry/issuer, SPF + DMARC + MX records, email-hardening
 * depth (DMARC policy, SPF qualifier/lookup count, common DKIM selectors,
 * MTA-STS, self-hosted mail), RDAP registration status (hold / lapsed / grace),
 * exposed-service hostnames (DNS existence only), broken same-host links.
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
const PLATFORM_RE = /(wixsite|godaddysites|weebly|squarespace|wordpress|blogspot|business\.site|webs)\.(com|site)$|business\.site$|\.square\.site$|\.blogspot\.[a-z.]+$|\.zmenu\.com$|\.sites\.erarealestate\.com$/i;

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
const D2V = 3; // bump to discard cached slow-check verdicts produced by older logic
const BLOCKED_STATUS = new Set([401, 403, 405, 406, 409, 429, 503]);
const CHALLENGE_2XX_RE = /\.well-known\/sgcaptcha|_Incapsula_Resource|cf-browser-verification|cf_chl_|\/cgi-sys\/defaultwebpage\.cgi|window\.location\.href\s*=\s*["']\/lander/i;
const visibleText = (t) => t.replace(/<script[\s\S]*?<\/script>|<style[\s\S]*?<\/style>|<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
log(`Deep-auditing ${hosts.length} lead domains (passive checks only)...`);

// RDAP: registry expiration date + EPP status list. Returns null when the lookup
// fails (no claims); `status` is normalized to lowercase with no spaces/_/- so
// 'client transfer prohibited', 'clientTransferProhibited' and
// 'client_transfer_prohibited' all become 'clienttransferprohibited'.
async function rdapInfo(apex) {
  const tld = apex.split('.').pop();
  const url = (tld === 'com' || tld === 'net')
    ? `https://rdap.verisign.com/${tld}/v1/domain/${apex}`
    : `https://rdap.org/domain/${apex}`;
  try {
    // rdap.org (the non-.com/.net bootstrap redirector) answers 403 to UA-less requests
    const res = await fetch(url, { headers: { Accept: 'application/rdap+json', 'User-Agent': UA }, redirect: 'follow', signal: AbortSignal.timeout(15000) });
    if (!res.ok) return null;
    const d = await res.json();
    const ev = (d.events || []).find((e) => e.eventAction === 'expiration');
    const status = [...new Set((Array.isArray(d.status) ? d.status : [])
      .filter((s) => typeof s === 'string')
      .map((s) => s.toLowerCase().replace(/[\s_-]+/g, ''))
      .filter(Boolean))];
    return { exp: ev && ev.eventDate ? ev.eventDate.slice(0, 10) : null, status };
  } catch { return null; }
}

// Map normalized RDAP statuses onto the contract fields; every field stays
// undefined unless the status list proves it.
function domainStatusFlags(status) {
  const s = new Set(status || []);
  const f = {};
  if (s.has('pendingdelete')) f.domLapsed = 'pendingdelete';
  else if (s.has('redemptionperiod')) f.domLapsed = 'redemptionperiod';
  if (s.has('clienthold') || s.has('serverhold')) f.domHold = true;
  if (s.has('autorenewperiod')) f.domGrace = true;
  return f;
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

// Public suffixes that take a third label (co.uk, va.gov, com.au, ...): the
// registrable apex sits one label deeper, otherwise every apex-level check
// would describe the suffix operator instead of the business.
const PUBLIC_2LD_RE = /^(co|org|me|ac|gov|ltd|plc|net|sch)\.uk$|^(com|net|org|id|edu|gov)\.au$|^(co|net|org|govt)\.nz$|^[a-z]+\.gov$|^[a-z]{2}\.us$|^(com|net|org)\.(br|mx|tr|ar|co|pe|ph|sg|my|hk|tw|cn|jp|in)$/i;
function apexOf(host) {
  const parts = host.split('.');
  if (parts.length <= 2) return host;
  const two = parts.slice(-2).join('.');
  return PUBLIC_2LD_RE.test(two) ? parts.slice(-3).join('.') : two;
}

// Run `fn` over `items` with at most `n` in flight; results keep input order.
async function pool(items, n, fn) {
  const outArr = new Array(items.length);
  let idx = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (idx < items.length) { const k = idx++; try { outArr[k] = await fn(items[k], k); } catch { outArr[k] = undefined; } }
  }));
  return outArr;
}

// ---- Email hardening depth (DNS only, every run) ----

// DMARC policy + pct from the _dmarc TXT record(s). Returns {} when there is no
// DMARC record (caller leaves dmarcPolicy undefined — never false).
function parseDmarc(txt) {
  const rec = (txt || []).find((t) => /^\s*v\s*=\s*dmarc1\s*;/i.test(t));
  if (!rec) return {};
  const tags = {};
  for (const part of rec.split(';')) {
    const m = part.match(/^\s*([a-z]+)\s*=\s*(.*?)\s*$/i);
    if (m) tags[m[1].toLowerCase()] = m[2];
  }
  const p = (tags.p || '').toLowerCase();
  if (!['none', 'quarantine', 'reject'].includes(p)) return {};
  const r = { dmarcPolicy: p, dmarcPct: 100 };
  if (tags.pct !== undefined) {
    const n = Number(tags.pct);
    if (Number.isInteger(n) && n >= 0 && n <= 100) r.dmarcPct = n;
  }
  return r;
}

const SPF_LOOKUP_RE = /^[-~?+]?(a|mx|ptr|exists|include)(?::|\/|$)/i;

// Terminal `all` qualifier and the DNS-querying-mechanism count of the apex SPF
// record, resolving include:/redirect= recursively (depth <= 10). `spfLookups`
// is left undefined on any DNS failure during recursion; `spfAll` comes from
// the apex record, or from the redirect= target when the apex has no `all`.
async function spfAnalyze(apex, apexTxt) {
  const r = {};
  const recs = (apexTxt || []).filter((t) => /^v=spf1(\s|$)/i.test(t));
  if (recs.length !== 1) return r; // no SPF, or multiple records (permerror) — inconclusive
  const terms = (rec) => rec.trim().split(/\s+/).slice(1);
  const allOf = (rec) => { const m = terms(rec).map((t) => t.match(/^([-~?+]?)all$/i)).find(Boolean); return m ? ((m[1] || '+') + 'all') : null; };
  const redirectOf = (rec) => { const m = terms(rec).map((t) => t.match(/^redirect=(.+)$/i)).find(Boolean); return m ? m[1].toLowerCase() : null; };

  const apexAll = allOf(recs[0]);
  if (apexAll) r.spfAll = apexAll;

  let failed = false;
  const visited = new Set([apex.toLowerCase()]);
  async function count(rec, depth) {
    let n = 0;
    for (const t of terms(rec)) {
      const inc = t.match(/^[-~?+]?include:(.+)$/i);
      const red = t.match(/^redirect=(.+)$/i);
      if (inc || red) {
        n++;
        const target = (inc ? inc[1] : red[1]).toLowerCase().replace(/\.$/, '');
        if (/%\{/.test(target) || depth >= 10 || visited.has(target)) continue; // macro / depth cap / loop
        visited.add(target);
        const q = await txtLookup(target);
        if (!q.ok) { failed = true; return n; }
        const sub = q.txt.filter((x) => /^v=spf1(\s|$)/i.test(x));
        if (sub.length !== 1) continue; // target has no (single) SPF record: the lookup still counted
        n += await count(sub[0], depth + 1);
        if (failed) return n;
      } else if (SPF_LOOKUP_RE.test(t)) {
        n++;
      }
    }
    return n;
  }
  const n = await count(recs[0], 0);
  if (!failed) r.spfLookups = n;

  if (!r.spfAll) {
    const red = redirectOf(recs[0]);
    if (red && !/%\{/.test(red)) {
      const q = await txtLookup(red);
      if (q.ok) {
        const sub = q.txt.filter((x) => /^v=spf1(\s|$)/i.test(x));
        if (sub.length === 1) { const a = allOf(sub[0]); if (a) r.spfAll = a; }
      }
    }
  }
  return r;
}

const DKIM_SELECTORS = ['selector1', 'selector2', 'google', 'k1', 'k2', 'k3', 'default', 'dkim', 's1', 's2', 'mail', 'smtp',
  'everlytickey1', 'everlytickey2', 'mandrill', 'mailo', 'zoho', 'protonmail', 'pm', 'sig1', 'mxvault', 'hs1', 'hs2',
  'sendgrid', 'em', 'amazonses', 'cm', 'ctct1', 'ctct2', 'mailjet', 'fm1', 'fm2', 'fm3'];
const DKIM_REC_RE = /(^|;)\s*v\s*=\s*DKIM1\s*(;|$)/i;
const DKIM_KEY_RE = /(^|;)\s*p\s*=/i;

const isDkimRecord = (t) => DKIM_REC_RE.test(t) || (DKIM_KEY_RE.test(t) && /(^|;)\s*k\s*=/i.test(t));

// Selectors (from the fixed list) whose <sel>._domainkey.<apex> holds a DKIM
// record (resolveTxt follows the CNAMEs that M365/Mailchimp-style selectors
// use). An empty array means "none of the common selectors", not "no DKIM".
// A wildcard *._domainkey record (example.com publishes "v=DKIM1; p=") would
// make every selector "exist", so that case yields [] plus dkimWildcard: true.
async function dkimScan(apex) {
  const rnd = Array.from({ length: 12 }, () => 'abcdefghijklmnopqrstuvwxyz0123456789'[Math.floor(Math.random() * 36)]).join('');
  const wc = await txtLookup(`${rnd}._domainkey.${apex}`);
  if (!wc.ok) return {}; // resolver trouble: unknown, not "none found"
  if (wc.txt.some(isDkimRecord)) return { dkim: [], dkimWildcard: true };
  let failed = false;
  const hits = await pool(DKIM_SELECTORS, 8, async (sel) => {
    const q = await txtLookup(`${sel}._domainkey.${apex}`);
    if (!q.ok) failed = true;
    return q.ok && q.txt.some(isDkimRecord) ? sel : null;
  });
  const found = hits.filter(Boolean);
  if (!found.length && failed) return {}; // a lookup failed and nothing was found: unknown
  return { dkim: found };
}

// MTA-STS: true = TXT present and the policy file is served; false = TXT
// provably absent; undefined = anything inconclusive.
async function mtaStsCheck(apex) {
  const q = await txtLookup(`_mta-sts.${apex}`);
  if (!q.ok) return undefined;
  if (!q.txt.length) return false;
  if (!q.txt.some((t) => /^\s*v\s*=\s*STSv1\s*;/i.test(t))) return undefined;
  try {
    const res = await fetch(`https://mta-sts.${apex}/.well-known/mta-sts.txt`, { headers: { 'User-Agent': UA }, redirect: 'follow', signal: AbortSignal.timeout(10000) });
    if (!res.ok) return undefined;
    const body = (await res.text()).slice(0, 4000);
    return /(^|\n)\s*version\s*:\s*STSv1/i.test(body) ? true : undefined;
  } catch { return undefined; }
}

// ---- Exposed-service hostnames (DNS existence only; nothing is connected to) ----

const DNS_HOST_NAMES = ['mail', 'webmail', 'owa', 'autodiscover', 'remote', 'rdp', 'vpn', 'exchange', 'ftp', 'sftp', 'cpanel',
  'portal', 'intranet', 'citrix', 'smtp', 'imap', 'pop', 'mail2', 'vpn2', 'gateway'];

// 'yes' when the name has an A, AAAA or CNAME record; 'no' when DNS says it
// does not (ENOTFOUND/ENODATA on every type); 'err' when a lookup failed.
async function nameResolves(name) {
  let err = false;
  for (const fn of ['resolve4', 'resolve6', 'resolveCname']) {
    try { if ((await dns[fn](name)).length) return 'yes'; }
    catch (e) { if (e.code !== 'ENODATA' && e.code !== 'ENOTFOUND') err = true; }
  }
  return err ? 'err' : 'no';
}

// Returns { dnsHosts, wildcardDns } — dnsHosts is left undefined when the
// wildcard probe itself was inconclusive (a wildcard zone would make every
// name "exist", so presence claims need that probe to be conclusive).
async function dnsHostsScan(apex) {
  const rnd = Array.from({ length: 12 }, () => 'abcdefghijklmnopqrstuvwxyz0123456789'[Math.floor(Math.random() * 36)]).join('');
  const wc = await nameResolves(`${rnd}.${apex}`);
  if (wc === 'yes') return { dnsHosts: [], wildcardDns: true };
  if (wc === 'err') return {};
  const found = await pool(DNS_HOST_NAMES, 6, async (n) => (await nameResolves(`${n}.${apex}`)) === 'yes' ? n : null);
  return { dnsHosts: found.filter(Boolean) };
}

// ---- Broken internal links (same-host links from the homepage, cap 12) ----

const stripWww = (h) => (h || '').toLowerCase().replace(/^www\./, '');

// broken = HTTP 404/410 only. 403/405/429/5xx/timeouts/network errors are
// inconclusive and excluded from `checked` altogether.
async function brokenLinksCheck(host, html, baseUrl) {
  let base;
  try { base = new URL(baseUrl || `https://${host}/`); } catch { return undefined; }
  const self = stripWww(host);
  const baseSelf = stripWww(base.hostname);
  const urls = [];
  const seen = new Set();
  // Only markup a visitor can click: drop comments, scripts (incl. text/x-*
  // templates), <template> and <noscript>; skip unrendered template placeholders.
  const clickable = html.replace(/<!--[\s\S]*?-->|<script\b[\s\S]*?<\/script>|<template\b[\s\S]*?<\/template>|<noscript\b[\s\S]*?<\/noscript>/gi, ' ');
  for (const m of clickable.matchAll(/<a\b[^>]*?\shref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi)) {
    const raw = (m[1] ?? m[2] ?? m[3] ?? '').trim().replace(/&amp;/g, '&');
    if (!raw || /^(#|mailto:|tel:|sms:|javascript:|data:)/i.test(raw) || /\{\{|\{%|<%|\$\{|<\?/.test(raw)) continue;
    let u;
    try { u = new URL(raw, base); } catch { continue; }
    if (!/^https?:$/.test(u.protocol)) continue;
    const h = stripWww(u.hostname);
    if (h !== self && h !== baseSelf) continue;
    u.hash = '';
    const key = u.href;
    if (seen.has(key) || key === base.href || key === base.href.replace(/\/$/, '')) continue;
    seen.add(key);
    urls.push(key);
    if (urls.length >= 12) break;
  }
  if (!urls.length) return { checked: 0, broken: 0, sample: [] };
  const statuses = await pool(urls, 4, async (u) => {
    try {
      const r = await fetch(u, { headers: { 'User-Agent': UA, Accept: 'text/html,*/*' }, redirect: 'follow', signal: AbortSignal.timeout(12000) });
      try { await r.body?.cancel(); } catch { /* ignore */ }
      return r.status;
    } catch { return null; }
  });
  let checked = 0;
  const sample = [];
  urls.forEach((u, k) => {
    const s = statuses[k];
    if (s == null || s === 403 || s === 405 || s === 429 || s >= 500) return; // inconclusive
    checked++;
    if (s === 404 || s === 410) sample.push(u);
  });
  return { checked, broken: sample.length, sample: sample.slice(0, 5) };
}

async function auditHost(host) {
  const a = { host, platform: PLATFORM_RE.test(host) };

  // Homepage: try www/apex on both schemes — a site only counts as unreachable
  // if every variant fails (many sites answer on exactly one hostname).
  let text = null, res = null, blocked = false;
  for (const cand of [`https://www.${host}/`, `https://${host}/`, `http://www.${host}/`, `http://${host}/`]) {
    try {
      res = await fetch(cand, {
        headers: { 'User-Agent': UA, Accept: 'text/html,*/*' },
        redirect: 'follow',
        signal: AbortSignal.timeout(12000),
      });
      if (res.status !== 200) { if (res.status < 400 || BLOCKED_STATUS.has(res.status)) blocked = true; continue; }
      const body = (await res.text()).slice(0, 300000);
      // a bot challenge / empty shell is not the homepage — grading it would invent SEO and mobile findings
      if (CHALLENGE_2XX_RE.test(body.slice(0, 20000)) || visibleText(body).length < 40) { blocked = true; continue; }
      text = body; break;
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
    if (blocked) a.blocked = true;
  }

  // Slow-moving checks, cached ~7 days (see D2_TTL): RDAP expiry + status,
  // broken internal links, Wayback staleness, sitemap presence, one contact-page crawl.
  const prev = existing[host];
  if (prev && prev.d2at && prev.d2v === D2V && Date.now() - prev.d2at < D2_TTL) {
    for (const f of ['exp', 'rdapStatus', 'domLapsed', 'domHold', 'domGrace', 'brokenLinks',
      'wbSince', 'wbLast', 'smOk', 'cFound', 'cForm', 'cMailto', 'cEmails', 'cStatus', 'd2at', 'd2v']) {
      if (prev[f] !== undefined) a[f] = prev[f];
    }
  } else if (!a.platform) {
    a.d2at = Date.now();
    a.d2v = D2V;
    const apex = apexOf(host);
    const [rdap, wb, links] = await Promise.all([
      rdapInfo(apex), waybackStale(host),
      a.ok ? brokenLinksCheck(host, text, res?.url) : Promise.resolve(undefined),
    ]);
    if (rdap?.exp) a.exp = rdap.exp; // kept even when already in the past
    if (rdap) { a.rdapStatus = rdap.status; Object.assign(a, domainStatusFlags(rdap.status)); }
    if (links) a.brokenLinks = links;
    if (wb?.since) a.wbSince = wb.since;
    if (wb?.lastSnap) a.wbLast = wb.lastSnap;
    if (a.ok) {
      const scheme = (res?.url || '').startsWith('http:') ? 'http' : 'https';
      try {
        const sm = await fetch(`${scheme}://${host}/sitemap.xml`, { headers: { 'User-Agent': UA }, signal: AbortSignal.timeout(10000) });
        a.smOk = sm.ok;
      } catch { a.smOk = false; }
      const cm = [...text.matchAll(/<a[^>]+href=["']([^"'#]*contact[^"']{0,60})["']/gi)]
        .map((m) => m[1]).find((h) => !/\.(css|js|json|png|jpe?g|gif|svg|webp|pdf|xml)(\?|$)/i.test(h) && !/^(mailto|tel|javascript):/i.test(h));
      if (cm) {
        a.cFound = true;
        try {
          const curl = new URL(cm, res.url || `https://${host}/`).href;
          const cres = await fetch(curl, { headers: { 'User-Agent': UA, Accept: 'text/html,*/*' }, redirect: 'follow', signal: AbortSignal.timeout(12000) });
          if (!cres.ok) { a.cStatus = cres.status; /* cForm/cMailto stay undefined = unknown */ }
          else {
          const ctext = (await cres.text()).slice(0, 400000);
          a.cForm = /<form[\s>]/i.test(ctext)
            || (ctext.match(/<(?:input|textarea)\b/gi) || []).length >= 2
            || /wpcf7-form|wpforms-form|gform_wrapper|nf-form-cont|elementor-form|sqs-block-form|hbspt\.forms|formstack|cognitoforms|123formbuilder|jotform|typeform|docs\.google\.com\/forms/i.test(ctext);
          a.cMailto = /mailto:/i.test(ctext);
          const emails = [...new Set((ctext.match(/\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b/gi) || [])
            .map((e) => e.toLowerCase()).filter((e) => !/\.(png|jpg|gif|webp|svg)$/.test(e)))];
          if (emails.length) a.cEmails = emails.slice(0, 3);
          }
        } catch { /* contact page unreachable — leave cForm/cMailto unknown */ }
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
    // Email hardening depth: DMARC policy/pct, SPF terminal qualifier + lookup
    // count, common DKIM selectors, MTA-STS. Each stays undefined when unknown.
    if (dmarcQ.ok) Object.assign(a, parseDmarc(dmarcQ.txt));
    if (spfQ.ok) { try { Object.assign(a, await spfAnalyze(apex, spfQ.txt)); } catch { /* unknown */ } }
    try { Object.assign(a, await dkimScan(apex)); } catch { /* unknown */ }
    try { const sts = await mtaStsCheck(apex); if (sts !== undefined) a.mtaSts = sts; } catch { /* unknown */ }
    try {
      const mx = await dns.resolveMx(apex);
      a.mx = mx.length > 0;
      a.mxh = mx.sort((x, y) => x.priority - y.priority)[0]?.exchange || '';
      a.mxp = classifyMx(a.mxh);
      // selfHostedMail: every exchange is the apex or under it (a null-MX "." is not mail)
      const exch = mx.map((m) => (m.exchange || '').toLowerCase().replace(/\.$/, '')).filter((e) => e && e !== '.');
      if (exch.length) a.selfHostedMail = exch.every((e) => e === apex || e.endsWith('.' + apex));
    } catch (e) { if (e && (e.code === 'ENODATA' || e.code === 'ENOTFOUND')) a.mx = false; /* other errors: a.mx stays undefined = inconclusive */ }
    // Hostnames that exist under the apex (DNS existence only — never connected to)
    try { Object.assign(a, await dnsHostsScan(apex)); } catch { /* unknown */ }
    // A domain with no mail servers and no address records isn't running email at all —
    // 'missing SPF/DMARC' would be a claim about email that doesn't exist.
    if (!a.mx) {
      const absent = (e) => e && (e.code === 'ENODATA' || e.code === 'ENOTFOUND');
      let resolves = false, dnsErr = a.mx === undefined; // MX lookup itself failed → inconclusive
      try { resolves = (await dns.resolve4(apex)).length > 0; } catch (e) { if (!absent(e)) dnsErr = true; }
      if (!resolves) { try { resolves = (await dns.resolve6(apex)).length > 0; } catch (e) { if (!absent(e)) dnsErr = true; } }
      if (!resolves) {
        // no records at all: email claims would be about email that doesn't exist; but a resolver
        // failure is not proof of absence — then say nothing either way
        for (const f of ['spf', 'dmarc', 'dmarcPolicy', 'dmarcPct', 'spfAll', 'spfLookups', 'dkim', 'mtaSts']) delete a[f];
        if (!dnsErr) a.noDns = true;
      }
    }
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
await Promise.all(Array.from({ length: 20 }, worker));

fs.writeFileSync(path.join(out, 'audits.json'), JSON.stringify(results, null, 1));
const withDns = Object.values(results).filter((a) => a.spf !== undefined);
log(`Done → out/audits.json (${Object.keys(results).length} domains; ` +
  `${withDns.filter((a) => !a.spf).length} missing SPF, ` +
  `${Object.values(results).filter((a) => a.dmarc === false).length} missing DMARC, ` +
  `${Object.values(results).filter((a) => a.certDaysLeft != null && a.certDaysLeft < 0).length} expired certs)`);
