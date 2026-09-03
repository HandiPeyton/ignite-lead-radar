#!/usr/bin/env node
// Injects out/leads.json + out/summary.json into board-template.html → out/board.html
// (the file Claude publishes as the shareable lead-board artifact).
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { REGIONS } from './regions.mjs';
import { slugOf, hostnameOf, keyOf, DIRECTORY_RE } from './lib.mjs';

const dir = path.dirname(fileURLToPath(import.meta.url));
const out = path.join(dir, 'out');

const leads = JSON.parse(fs.readFileSync(path.join(out, 'leads.json'), 'utf8'));
const summary = JSON.parse(fs.readFileSync(path.join(out, 'summary.json'), 'utf8'));
const readOpt = (f) => { try { return JSON.parse(fs.readFileSync(path.join(out, f), 'utf8')); } catch { return null; } };
const audits = readOpt('audits.json') || {};
const auditSlugs = readOpt('audit-slugs.json') || {};
const inventory = readOpt('inventory.json') || [];
const ratings = readOpt('ratings.json') || {};
const deepscan = readOpt('deepscan.json') || {};
const prevLeads = readOpt('prev-leads.json');
const prevMap = prevLeads ? new Map(prevLeads.map((l) => [keyOf(l), l.wScore + l.itScore])) : null;
const prevLeadMap = prevLeads ? new Map(prevLeads.map((l) => [keyOf(l), l])) : null;
const prevInv = readOpt('prev-inventory.json');
const prevInvKeys = prevInv ? new Set(prevInv.map(keyOf)) : null;

// A lapsed or registrar-held domain is the most time-critical hook there is (the
// name is about to drop, or the site and email are already dark). Stable-sort those
// leads to the top so the board's priority order, "Next lead", and the schedule all
// see them first; everything else keeps scan.mjs's need → score order.
const domainDark = (l) => {
  const h = l.website ? hostnameOf(l.website) : null;
  const d = h ? audits[h] : null;
  return d && !d.platform && !d.ok && (d.domLapsed || d.domHold) ? 0 : 1;
};
leads.sort((a, b) => domainDark(a) - domainDark(b));

// Break-timing: what changed for this business since the last scan.
// Calling the week a site breaks is the warmest cold call there is.
const BAD = new Set(['down', 'parked', 'ssl-error']);
function breakOf(l) {
  if (!prevLeadMap) return '';
  const k = keyOf(l);
  const st = l.audit && l.audit.status;
  const p = prevLeadMap.get(k);
  if (p) {
    const pst = p.audit && p.audit.status;
    // only a site the previous scan actually audited as reachable can "break"
    if (BAD.has(st) && pst && !BAD.has(pst)) {
      return st === 'ssl-error' ? 'Security certificate broke since last scan' : 'Website went down since last scan';
    }
    return '';
  }
  if (prevInvKeys && !prevInvKeys.has(k)) return 'Newly listed business';
  return ''; // no previous audit of this site — nothing to compare against
}
const retired = prevLeads
  ? prevLeads.filter((p) => !leads.some((l) => keyOf(l) === keyOf(p))).length
  : 0;

// Competitor-gap cohorts: same town+vertical (fallback: region+vertical).
const coAll = {}, coWeb = {}, coFlagWeb = {};
const ck1 = (b) => b.region + '|' + b.town + '|' + b.vertical;
const ck2 = (b) => b.region + '|' + b.vertical;
for (const b of inventory) {
  for (const ck of [ck1(b), ck2(b)]) {
    coAll[ck] = (coAll[ck] || 0) + 1;
    if (b.website) coWeb[ck] = (coWeb[ck] || 0) + 1;
  }
}
for (const l of leads) {
  if (!l.website) continue;
  for (const ck of [ck1(l), ck2(l)]) coFlagWeb[ck] = (coFlagWeb[ck] || 0) + 1;
}
function competitorGap(l) {
  if (l.vertical === 'other' || l.vertical === 'professional') return '';
  // town-level only: with states as regions, a state-wide cohort says nothing useful
  const ck = ck1(l), place = l.town;
  const total = coAll[ck] || 0;
  if (total < 3) return '';
  const solid = Math.max(0, (coWeb[ck] || 0) - (coFlagWeb[ck] || 0));
  if (solid === 0) return `None of the ${total} ${l.vertical} businesses in ${place} has a solid website — the first one to fix that owns the market.`;
  return `${solid} of the ${total} ${l.vertical} businesses in ${place} have solid websites — this one is falling behind.`;
}

// Multi-location detection: same normalized name in 2+ towns across the full
// inventory → probably a regional operation, ask for the owner/head office.
const nameCounts = {};
for (const b of inventory) {
  const n = b.name.toLowerCase().replace(/[^a-z0-9]/g, '');
  if (!nameCounts[n]) nameCounts[n] = new Set();
  nameCounts[n].add(b.town + '|' + b.st);
}

// slim rows to what the board renders; Google-verified CLOSED_PERMANENTLY
// businesses are removed entirely (the still-in-business verification).
const rows = [];
const keptLeads = [];
let closedRemoved = 0;
for (const l of leads) {
  const row = ((l) => {
  const host = l.website ? hostnameOf(l.website) : null;
  const deep = host ? audits[host] : null;
  const extra = [];
  if (deep && !deep.platform) {
    if (deep.spf === false && deep.dmarc === false) extra.push('Email domain spoofable (no SPF/DMARC)');
    else if (deep.dmarc === false) extra.push('Email domain missing DMARC');
    else if (deep.spf === false) extra.push('Email domain missing SPF');
    if (deep.certDaysLeft != null && deep.certDaysLeft < 0) extra.push(`SSL certificate expired ${deep.certValidTo}`);
    else if (deep.certDaysLeft != null && deep.certDaysLeft < 30) extra.push(`SSL certificate expires in ${deep.certDaysLeft} days`);
  }
  if (deep?.ok) {
    if (!deep.title || (deep.title || '').length < 8) extra.push('Homepage missing a real title (invisible to Google)');
    if (deep.desc === false) extra.push('No search description');
    if (deep.localSchema === false) extra.push('No local-business schema (weak Google Maps signal)');
    if (deep.cFound && deep.cForm === false && deep.cMailto === false) extra.push('Contact page has no working form or email link');
  }
  let expDays = null;
  if (deep?.exp) {
    expDays = Math.round((Date.parse(deep.exp) - Date.now()) / 86400000);
    if (expDays >= 0 && expDays < 60) extra.push(`Domain registration expires ${deep.exp} (${expDays} days)`);
  }
  if (deep && !deep.platform) {
    if (deep.domLapsed && !deep.ok) extra.push(`Domain registration lapsed — registry status "${deep.domLapsed === 'pendingdelete' ? 'pending delete' : 'redemption period'}"`);
    else if (deep.domHold && !deep.ok) extra.push('Domain suspended by the registrar (hold status) — site and email dark');
    else if (deep.domGrace) extra.push('Domain registration in the registry’s auto-renew grace window (status autoRenewPeriod) — renewal not confirmed');
    if (deep.spfAll === '+all' || deep.spfAll === '?all') extra.push(`SPF record ends in ${deep.spfAll} — it doesn’t restrict who can send as the domain`);
    if (typeof deep.spfLookups === 'number' && deep.spfLookups > 10) extra.push(`SPF record needs ${deep.spfLookups} DNS lookups (limit 10) — legitimate mail can bounce`);
  }
  if (deep?.brokenLinks && typeof deep.brokenLinks.broken === 'number' && deep.brokenLinks.broken >= 2) {
    extra.push(`${deep.brokenLinks.broken} homepage links go to missing pages (404)`);
  }
  if (deep?.wbSince) extra.push(`Homepage unchanged since ${deep.wbSince} (archive.org)`);
  else if (deep?.wbLast) extra.push(`Not even archived since ${deep.wbLast} (archive.org)`);
  if (deep?.tech && deep.tech.length) { /* surfaced in prep, not as a flag */ }
  if (deep?.analytics === false) extra.push('No analytics installed — they can’t see who visits');

  // Rendered performance (Sunday deep scan)
  const ds = host ? deepscan[host] : null;
  if (ds) {
    if (ds.loadMs >= 6000) extra.push(`Slow site: takes ${(ds.loadMs / 1000).toFixed(1)}s to load`);
    else if (ds.loadMs >= 4000) extra.push(`Sluggish load (${(ds.loadMs / 1000).toFixed(1)}s)`);
    if (ds.weightKB >= 6000) extra.push(`Heavy page: ${(ds.weightKB / 1024).toFixed(1)} MB to load`);
    if (ds.imgKB >= 3500) extra.push(`Unoptimized images (${(ds.imgKB / 1024).toFixed(1)} MB of images)`);
    if (ds.mobileOverflow) extra.push(`Broken on phones: content runs ${ds.overflowPx}px off-screen (real render)`);
    if (ds.tinyTaps >= 8) extra.push(`${ds.tinyTaps} buttons/links too small to tap on a phone`);
  }
  const slug = slugOf(l);
  const locs = nameCounts[l.name.toLowerCase().replace(/[^a-z0-9]/g, '')];
  const k = keyOf(l);
  let chg = '';
  if (prevMap) {
    if (!prevMap.has(k)) chg = 'new';
    else if (l.wScore + l.itScore > prevMap.get(k)) chg = 'up';
  }
  const rat = ratings[k];
  return {
    name: l.name, town: l.town, st: l.st, region: l.region, vertical: l.vertical,
    need: l.need, confidence: l.confidence, wScore: l.wScore, itScore: l.itScore,
    evidence: l.evidence, phone: l.phone, website: l.website,
    mi: l.mi == null ? null : l.mi,                                  // miles from Bristol
    hours: l.hours || '',
    x: extra.join('; '),
    slug: auditSlugs[slug] ? slug : '',
    multi: locs && locs.size > 1 ? locs.size : 0,
    chg,
    brk: breakOf(l),
    nw: (() => {                                                     // recently opened (FSQ record age)
      const dc = rat && rat.matched && rat.dc;
      if (!dc) return '';
      const days = (Date.now() - Date.parse(dc)) / 86400000;
      return days >= 0 && days <= 120 ? dc : '';
    })(),
    em: l.email || (l.audit && l.audit.freeEmail) || (rat && rat.e) || (deep && deep.cEmails && deep.cEmails[0]) || '',
    mx: deep?.mxp || '',
    tech: (deep?.tech || []).join(', '),
    perf: ds ? { load: +(ds.loadMs / 1000).toFixed(1), mb: +(ds.weightKB / 1024).toFixed(1), mob: ds.mobileOverflow ? 1 : 0 } : null,
    cg: competitorGap(l),
    xd: expDays !== null && expDays >= 0 && expDays < 60 ? expDays : null,
    r: rat && rat.matched ? rat.r : 0,
    rc: rat && rat.matched ? rat.rc : 0,
    g: rat && rat.matched && (!rat.bs || rat.bs === 'OPERATIONAL') ? 1 : 0, // places-verified as open
    gl: rat && rat.matched && rat.bs === 'LISTED' ? 1 : 0,          // listed, open/closed status not stated
    dv: rat && rat.matched ? (rat.dr || '') : '',                   // record refresh / release date
    fw: rat && rat.matched && rat.w && !l.website && !DIRECTORY_RE.test(rat.w) ? rat.w : '', // places-data website
    pm: (() => {                                                     // phone mismatch: FSQ's number
      if (!(rat && rat.matched && rat.t && l.phone)) return '';
      const a = l.phone.replace(/\D/g, '').slice(-10);
      const b = rat.t.replace(/\D/g, '').slice(-10);
      return a && b && a !== b ? rat.t : '';
    })(),
    ct: rat && rat.bs === 'CLOSED_TEMPORARILY' ? 1 : 0,             // temp closed
    gone: rat && rat.bs === 'CLOSED_PERMANENTLY' ? 1 : 0,
    // deep-audit contract fields (absent → neutral defaults; never asserts absence)
    dl: deep && !deep.platform && !deep.ok && (deep.domLapsed || deep.domHold) ? 1 : 0, // registration lapsed / registrar hold (and the site is down)
    dp: (deep && !deep.platform && deep.dmarcPolicy) || '',           // DMARC policy tag
    sa: (deep && !deep.platform && deep.spfAll) || '',                // SPF terminal qualifier
    sl: deep && !deep.platform && typeof deep.spfLookups === 'number' ? deep.spfLookups : null,
    dk: deep && Array.isArray(deep.dkim) ? deep.dkim.length : 0,     // common-selector DKIM hits (0 ≠ "no DKIM")
    dkn: deep && Array.isArray(deep.dkim) ? deep.dkim.join(',') : '', // the selector names
    sh: deep && deep.selfHostedMail === true ? 1 : 0,
    dh: deep && Array.isArray(deep.dnsHosts) ? deep.dnsHosts.join(',') : '',
    bl: deep?.brokenLinks && typeof deep.brokenLinks.broken === 'number' ? deep.brokenLinks.broken : 0,
    lcp: ds && typeof ds.lcpMs === 'number' ? +(ds.lcpMs / 1000).toFixed(1) : null,
    cls: ds && typeof ds.cls === 'number' ? ds.cls : null,
    ina: ds && typeof ds.imgNoAlt === 'number' ? ds.imgNoAlt : 0,
    inl: ds && typeof ds.inputsNoLabel === 'number' ? ds.inputsNoLabel : 0,
  };
  })(l);
  if (row.gone) { closedRemoved++; continue; }
  rows.push(row);
  keptLeads.push(l);
}
const regionLabels = Object.fromEntries(Object.entries(REGIONS).map(([k, v]) => [k, v.label]));

const esc = (o) => JSON.stringify(o).replace(/</g, '\\u003c');

const base = fs.readFileSync(path.join(dir, 'board-template.html'), 'utf8')
  .split('/*__DATA__*/[]').join(esc(rows))
  .split('/*__META__*/{}').join(esc({ ranAt: summary.ranAt, byNeed: summary.byNeed, mode: summary.mode, retired, closedRemoved }))
  .split('/*__REGIONS__*/{}').join(esc(regionLabels));

// Artifact copy: static, no tracking (claude.ai sandbox can't reach the API).
fs.writeFileSync(path.join(out, 'board.html'), base);

// Netlify copy: tracking on (talks to /api/state), CSV download link in footer.
const sitePublic = path.join(dir, 'site', 'public');
fs.mkdirSync(sitePublic, { recursive: true });
const siteHtml = base
  .split('/*__TRACKING__*/false').join('true')
  .replace('<!--CSV_LINK-->',
    ' <a href="leads.csv" download>Download the raw scan CSV</a> for Google Sheets/Excel.');
fs.writeFileSync(path.join(sitePublic, 'index.html'), siteHtml);

// Site CSV regenerated from the FINAL lead set (closed businesses excluded,
// Google verification columns included).
const csvEsc = (v) => { const s = String(v ?? ''); return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
const header = ['Region', 'Town', 'State', 'Business', 'Vertical', 'Need', 'Confidence',
  'Web score', 'IT score', 'Evidence', 'Phone', 'Website', 'Address',
  'Rating', 'Reviews', 'Listing status', 'Maps'];
const csvRows = keptLeads.map((l, i) => {
  const row = rows[i];
  return [(REGIONS[l.region] && REGIONS[l.region].label) || l.region, l.town, l.st, l.name, l.vertical, l.need, l.confidence,
    l.wScore, l.itScore, row.x ? l.evidence + '; ' + row.x : l.evidence, l.phone, l.website, l.address || '',
    row.r || '', row.rc || '', row.g ? (row.ct ? 'Possibly/temporarily closed' : 'Operational') : 'Not found',
    'https://www.google.com/maps/search/?api=1&query=' + encodeURIComponent(`${l.name} ${l.town} ${l.st}`)];
});
fs.writeFileSync(path.join(sitePublic, 'leads.csv'),
  '﻿' + [header, ...csvRows].map((r) => r.map(csvEsc).join(',')).join('\r\n'));

console.log(`board built: ${rows.length} leads (${closedRemoved} permanently-closed removed) → out/board.html + site/public/`);
