#!/usr/bin/env node
// Injects out/leads.json + out/summary.json into board-template.html → out/board.html
// (the file Claude publishes as the shareable lead-board artifact).
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { REGIONS } from './regions.mjs';
import { slugOf, hostnameOf, keyOf } from './lib.mjs';

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
  let ck = ck1(l), place = l.town;
  if ((coAll[ck] || 0) < 3) { ck = ck2(l); place = 'the ' + (REGIONS[l.region]?.label || l.region) + ' region'; }
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
    hours: l.hours || '',
    x: extra.join('; '),
    slug: auditSlugs[slug] ? slug : '',
    multi: locs && locs.size > 1 ? locs.size : 0,
    chg,
    em: l.email || (l.audit && l.audit.freeEmail) || (rat && rat.e) || (deep && deep.cEmails && deep.cEmails[0]) || '',
    mx: deep?.mxp || '',
    tech: (deep?.tech || []).join(', '),
    perf: ds ? { load: +(ds.loadMs / 1000).toFixed(1), mb: +(ds.weightKB / 1024).toFixed(1), mob: ds.mobileOverflow ? 1 : 0 } : null,
    cg: competitorGap(l),
    xd: expDays !== null && expDays >= 0 && expDays < 60 ? expDays : null,
    r: rat && rat.matched ? rat.r : 0,
    rc: rat && rat.matched ? rat.rc : 0,
    g: rat && rat.matched ? 1 : 0,                                  // places-verified
    dv: rat && rat.matched ? (rat.dr || '') : '',                   // record refresh date
    fw: rat && rat.matched && rat.w && !l.website ? rat.w : '',     // FSQ-only website
    pm: (() => {                                                     // phone mismatch: FSQ's number
      if (!(rat && rat.matched && rat.t && l.phone)) return '';
      const a = l.phone.replace(/\D/g, '').slice(-10);
      const b = rat.t.replace(/\D/g, '').slice(-10);
      return a && b && a !== b ? rat.t : '';
    })(),
    ct: rat && rat.bs === 'CLOSED_TEMPORARILY' ? 1 : 0,             // temp closed
    gone: rat && rat.bs === 'CLOSED_PERMANENTLY' ? 1 : 0,
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
  return [REGIONS[l.region].label, l.town, l.st, l.name, l.vertical, l.need, l.confidence,
    l.wScore, l.itScore, row.x ? l.evidence + '; ' + row.x : l.evidence, l.phone, l.website, l.address || '',
    row.r || '', row.rc || '', row.g ? (row.ct ? 'Possibly/temporarily closed' : 'Operational') : 'Not found',
    'https://www.google.com/maps/search/?api=1&query=' + encodeURIComponent(`${l.name} ${l.town} ${l.st}`)];
});
fs.writeFileSync(path.join(sitePublic, 'leads.csv'),
  '﻿' + [header, ...csvRows].map((r) => r.map(csvEsc).join(',')).join('\r\n'));

console.log(`board built: ${rows.length} leads (${closedRemoved} permanently-closed removed) → out/board.html + site/public/`);
