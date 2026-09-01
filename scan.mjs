#!/usr/bin/env node
/**
 * Ignite Cyber lead scanner
 * -------------------------
 * Sweeps public business listings across NE TN, SW VA, S WV, W NC, W KY, N SC,
 * audits each business's web presence, and flags whether it likely needs a new
 * WEBSITE (Ridge Web Designs pitch), an IT COMPANY (Ignite Cyber pitch), or BOTH.
 *
 * Data sources:
 *   - OpenStreetMap Overpass API (default, no key needed). Caveat: OSM often
 *     lacks website tags even when a site exists, so "no website" rows from OSM
 *     are marked Confidence=Verify.
 *   - Google Places API (New) when GOOGLE_PLACES_API_KEY is set and --google is
 *     passed. Stronger "no website" signal (billing/ToS are your responsibility).
 *
 * Usage:
 *   node tools/lead-scanner/scan.mjs                     # all six regions
 *   node tools/lead-scanner/scan.mjs --region netn,swva  # subset
 *   node tools/lead-scanner/scan.mjs --max-audit 200     # cap site audits per region
 *   node tools/lead-scanner/scan.mjs --limit 50          # cap businesses per region (smoke test)
 *   node tools/lead-scanner/scan.mjs --webhook <url>     # also POST rows to Google Sheets webhook
 *                                                        # (or set SHEET_WEBHOOK env var)
 * Outputs (tools/lead-scanner/out/):
 *   leads.csv, leads.json, summary.json, inventory.json
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { REGIONS, SELECTORS, CHAIN_RE, IT_HEAVY, VERTICAL_PRIORITY, classifyVertical } from './regions.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT_DIR = path.join(__dirname, 'out');
const UA = 'IgniteCyber-LeadScanner/1.0 (local business research; ignitecyber.io)';
const CUR_YEAR = new Date().getFullYear();

const OVERPASS_ENDPOINTS = [
  'https://maps.mail.ru/osm/tools/overpass/api/interpreter',
  'https://overpass-api.de/api/interpreter',
  'https://overpass.private.coffee/api/interpreter',
  'https://overpass.kumi.systems/api/interpreter',
];

// ---------- CLI ----------
const args = process.argv.slice(2);
function flagVal(name, dflt) {
  const i = args.indexOf(name);
  return i >= 0 && args[i + 1] ? args[i + 1] : dflt;
}
const REGION_KEYS = (flagVal('--region', flagVal('--regions', Object.keys(REGIONS).join(','))))
  .split(',').map((s) => s.trim()).filter((k) => REGIONS[k]);
const MAX_AUDIT = parseInt(flagVal('--max-audit', '500'), 10);
const LIMIT = parseInt(flagVal('--limit', '0'), 10);
const MAX_NOSITE = parseInt(flagVal('--max-nosite', '150'), 10);
const WEBHOOK = flagVal('--webhook', process.env.SHEET_WEBHOOK || '');
const USE_GOOGLE = args.includes('--google') && !!process.env.GOOGLE_PLACES_API_KEY;
const AUDIT_CONCURRENCY = parseInt(flagVal('--concurrency', '10'), 10);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);

// ---------- geo helpers ----------
function haversineKm(lat1, lon1, lat2, lon2) {
  const R = 6371, d2r = Math.PI / 180;
  const dLat = (lat2 - lat1) * d2r, dLon = (lon2 - lon1) * d2r;
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(lat1 * d2r) * Math.cos(lat2 * d2r) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(a));
}
const ALL_TOWNS = REGION_KEYS.flatMap((rk) => REGIONS[rk].towns.map((t) => ({ ...t, region: rk })));
function nearestTown(lat, lng) {
  let best = null, bd = Infinity;
  for (const t of ALL_TOWNS) {
    const d = haversineKm(lat, lng, t.lat, t.lng);
    if (d < bd) { bd = d; best = t; }
  }
  return best;
}

// ---------- Overpass ----------
// One query per town using a bounding box (cheaper for the server than
// around-circles); region-sized unions draw 504s, town-sized ones are quick.
function bboxOf(t) {
  const dLat = t.r / 111320;
  const dLng = t.r / (111320 * Math.cos((t.lat * Math.PI) / 180));
  return `${(t.lat - dLat).toFixed(4)},${(t.lng - dLng).toFixed(4)},${(t.lat + dLat).toFixed(4)},${(t.lng + dLng).toFixed(4)}`;
}
function buildTownQuery(t) {
  const bb = bboxOf(t);
  const lines = SELECTORS.map((sel) => `nwr${sel}(${bb});`);
  return `[out:json][timeout:90];(${lines.join('')});out center;`;
}

const epCooldown = new Map(); // endpoint -> timestamp when usable again
async function overpass(query) {
  let lastErr;
  for (let attempt = 0; attempt < 10; attempt++) {
    // pick the first endpoint not cooling down; if all are, wait for the soonest
    let ep = OVERPASS_ENDPOINTS.find((e) => (epCooldown.get(e) || 0) <= Date.now());
    if (!ep) {
      const soonest = Math.min(...OVERPASS_ENDPOINTS.map((e) => epCooldown.get(e) || 0));
      await sleep(Math.max(1000, soonest - Date.now()));
      ep = OVERPASS_ENDPOINTS.find((e) => (epCooldown.get(e) || 0) <= Date.now()) || OVERPASS_ENDPOINTS[0];
    }
    try {
      const res = await fetch(ep, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'User-Agent': UA,
          Accept: 'application/json',
        },
        body: 'data=' + encodeURIComponent(query),
        signal: AbortSignal.timeout(120000),
      });
      if (res.status === 429) {
        epCooldown.set(ep, Date.now() + 90000);
        throw new Error(`HTTP 429 from ${ep} (cooling that endpoint 90s)`);
      }
      if (!res.ok) {
        epCooldown.set(ep, Date.now() + 30000);
        throw new Error(`HTTP ${res.status} from ${ep}`);
      }
      const data = await res.json();
      if (data.remark) {
        log(`  overpass remark: ${data.remark}`);
        if (/timed out/i.test(data.remark)) {
          epCooldown.set(ep, Date.now() + 45000);
          throw new Error(`server-side timeout from ${ep}`);
        }
      }
      return data;
    } catch (e) {
      lastErr = e;
      log(`  overpass attempt ${attempt + 1} failed (${e.message}); backing off...`);
      await sleep(6000);
    }
  }
  throw lastErr;
}

function parseElements(elements) {
  const out = [];
  for (const el of elements) {
    const tags = el.tags || {};
    const name = (tags.name || '').trim();
    if (!name) continue;
    if (tags.brand || CHAIN_RE.test(name)) continue;
    const lat = el.lat ?? el.center?.lat;
    const lng = el.lon ?? el.center?.lon;
    if (lat == null || lng == null) continue;
    const vertical = classifyVertical(tags);
    if (vertical === 'itcompany' || vertical === 'bank') continue;
    let website = (tags.website || tags['contact:website'] || tags.url || '').split(';')[0].trim();
    if (website && !/^https?:\/\//i.test(website)) website = 'https://' + website;
    const town = nearestTown(lat, lng);
    if (!town) continue;
    out.push({
      name,
      vertical,
      website,
      phone: (tags.phone || tags['contact:phone'] || '').split(';')[0].trim(),
      email: (tags.email || tags['contact:email'] || '').split(';')[0].trim(),
      hours: (tags.opening_hours || '').trim(),
      address: [tags['addr:housenumber'], tags['addr:street']].filter(Boolean).join(' '),
      town: town.name, st: town.st, region: town.region,
      lat: +lat.toFixed(5), lng: +lng.toFixed(5),
      source: 'OSM',
    });
  }
  return out;
}

// ---------- Google Places (optional upgrade) ----------
const GOOGLE_QUERIES = [
  'dentist', 'doctors office', 'law firm', 'accountant', 'insurance agency',
  'manufacturer', 'machine shop', 'veterinarian', 'real estate agency', 'hvac contractor',
  'plumber', 'electrician', 'auto repair', 'restaurant', 'hotel', 'cabin rentals',
];
async function googlePlaces(regionKey, region) {
  const key = process.env.GOOGLE_PLACES_API_KEY;
  const out = [];
  for (const t of region.towns) {
    for (const q of GOOGLE_QUERIES) {
      try {
        const res = await fetch('https://places.googleapis.com/v1/places:searchText', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Goog-Api-Key': key,
            'X-Goog-FieldMask':
              'places.displayName,places.formattedAddress,places.websiteUri,places.nationalPhoneNumber,places.location,places.primaryType,places.businessStatus',
          },
          body: JSON.stringify({ textQuery: `${q} in ${t.name}, ${t.st}`, pageSize: 20 }),
          signal: AbortSignal.timeout(30000),
        });
        if (!res.ok) { log(`  google ${t.name}/${q}: HTTP ${res.status}`); continue; }
        const data = await res.json();
        for (const p of data.places || []) {
          const name = p.displayName?.text || '';
          if (!name || CHAIN_RE.test(name)) continue;
          if (p.businessStatus && p.businessStatus !== 'OPERATIONAL') continue;
          out.push({
            name,
            vertical: 'other',
            website: p.websiteUri || '',
            phone: p.nationalPhoneNumber || '',
            email: '',
            address: p.formattedAddress || '',
            town: t.name, st: t.st, region: regionKey,
            lat: +(p.location?.latitude || t.lat).toFixed(5),
            lng: +(p.location?.longitude || t.lng).toFixed(5),
            source: 'Google',
          });
        }
        await sleep(150);
      } catch (e) { log(`  google ${t.name}/${q}: ${e.message}`); }
    }
  }
  return out;
}

// ---------- Website audit ----------
const auditCache = new Map(); // hostname -> audit result

function hostnameOf(url) {
  try { return new URL(url).hostname.replace(/^www\./, ''); } catch { return null; }
}

const SOCIAL_RE = /facebook\.com|fb\.com|instagram\.com|linktr\.ee|m\.me\//i;
const FREE_EMAIL_RE = /\b[a-z0-9._%+-]+@(?:gmail|yahoo|aol|hotmail|outlook|icloud|comcast|bellsouth|charter|att|frontier|windstream|earthlink)\.(?:com|net)\b/gi;
const PARKED_RE = /domain (?:is )?(?:parked|for sale)|buy this domain|sedoparking|parked free|this webpage was generated by the domain owner|hugedomains|godaddy\.com\/forsale/i;

async function tryFetch(url) {
  const res = await fetch(url, {
    headers: { 'User-Agent': UA, Accept: 'text/html,*/*' },
    redirect: 'follow',
    signal: AbortSignal.timeout(12000),
  });
  const text = (await res.text()).slice(0, 300000);
  return { res, text };
}

function causeCode(e) {
  return e?.cause?.code || e?.code || (e?.name === 'TimeoutError' ? 'ETIMEDOUT' : '') || '';
}
const CERT_CODES = /CERT|UNABLE_TO_VERIFY|SELF_SIGNED|ALTNAME|SSL|TLS/i;

async function auditSite(rawUrl) {
  // Double-check design: a site only counts as down/broken if EVERY reasonable
  // variant fails — the URL exactly as listed, then www/apex × https/http.
  // Many small-business sites answer on only one of these.
  let u;
  try { u = new URL(rawUrl); } catch { return { status: 'down', notes: ['Bad URL'] }; }
  const bare = u.hostname.replace(/^www\./, '');
  if (auditCache.has(bare)) return auditCache.get(bare);

  const candidates = [];
  const push = (c) => { if (!candidates.includes(c)) candidates.push(c); };
  push(u.href);
  push(`https://www.${bare}/`);
  push(`https://${bare}/`);
  push(`http://www.${bare}/`);
  push(`http://${bare}/`);

  const result = {
    status: 'ok', viewport: false, year: null, flags: [], freeEmail: '',
    oldServer: '', finalUrl: '', https: true,
  };
  let page = null, sawCert = false, lastNote = '';
  for (const cand of candidates) {
    try {
      const p = await tryFetch(cand);
      if (p.res.status >= 400) { lastNote = `HTTP ${p.res.status}`; continue; }
      page = p;
      break;
    } catch (e) {
      const code = causeCode(e);
      if (CERT_CODES.test(code) || CERT_CODES.test(String(e?.cause?.message || ''))) sawCert = true;
      lastNote = code || 'unreachable';
    }
  }
  if (!page) {
    const r = { status: sawCert ? 'ssl-error' : 'down', notes: [lastNote] };
    auditCache.set(bare, r);
    return r;
  }

  const { res, text } = page;
  result.finalUrl = res.url || '';
  if (!result.finalUrl.startsWith('https://')) {
    result.https = false;
    result.status = sawCert ? 'ssl-error' : 'http-only';
  }
  if (PARKED_RE.test(text)) {
    result.status = 'parked';
    auditCache.set(bare, result);
    return result;
  }

  result.viewport = /<meta[^>]+name=["']?viewport/i.test(text);

  const yearMatches = [...text.matchAll(/(?:©|&#169;|&copy;|copyright)\s*(?:\d{4}\s*[-–—]\s*)?((?:19|20)\d{2})/gi)]
    .map((m) => parseInt(m[1], 10)).filter((y) => y <= CUR_YEAR + 1);
  if (yearMatches.length) result.year = Math.max(...yearMatches);

  if (/microsoft frontpage/i.test(text)) result.flags.push('Built with FrontPage (1990s-era)');
  if (/<frameset/i.test(text)) result.flags.push('Uses HTML framesets (1990s-era)');
  if (/\.swf["']/i.test(text)) result.flags.push('Uses Flash (dead tech)');
  if (/wsimg\.com|godaddy.*website ?builder/i.test(text)) result.flags.push('GoDaddy site builder');
  if (/wixstatic\.com|wix\.com/i.test(text)) result.flags.push('Wix builder');
  if (/weebly\.com/i.test(text)) result.flags.push('Weebly builder');

  // "Genuinely outdated / dated-looking" signals — sites that load fine but
  // scream 2005: legacy markup, ancient frameworks, authoring-tool exports.
  if (/<font[\s>]|<center[\s>]|<marquee|<body[^>]+bgcolor=/i.test(text)) result.flags.push('2000s-era HTML (font/center/marquee markup)');
  if (/<!DOCTYPE html PUBLIC[^>]*(XHTML 1\.0|HTML 4\.0)/i.test(text.slice(0, 400))) result.flags.push('Pre-2010 page framework (XHTML/HTML4 doctype)');
  if (/jquery[\/.-]1\.\d/i.test(text)) result.flags.push('Ancient jQuery library (1.x)');
  const genMeta = text.match(/<meta[^>]+generator[^>]*>/i)?.[0] || '';
  if (/(dreamweaver|adobe golive|microsoft (word|publisher)|netobjects)/i.test(genMeta)) result.flags.push('Exported from a 2000s authoring tool');
  const tableCount = (text.match(/<table/gi) || []).length;
  if (tableCount >= 6 && !/display:\s*(flex|grid)/i.test(text) && !result.viewport) result.flags.push('Table-based page layout (dated design)');

  const wpGen = text.match(/content=["']WordPress (\d+)\.(\d+)/i);
  const wpVer = text.match(/wp-(?:content|includes)[^"']{0,120}?[?&]ver=(\d+)\.(\d+)/i);
  const wp = wpGen || wpVer;
  if (wp && parseInt(wp[1], 10) < 6) result.flags.push(`WordPress ${wp[1]}.${wp[2]} (outdated)`);

  const freeMail = text.match(FREE_EMAIL_RE);
  if (freeMail) result.freeEmail = freeMail[0].toLowerCase();

  const server = `${res.headers.get('server') || ''} ${res.headers.get('x-powered-by') || ''}`;
  if (/apache\/2\.[0-2]\b|iis\/[4-7]\.|php\/[45]\./i.test(server)) result.oldServer = server.trim();

  auditCache.set(bare, result);
  return result;
}

async function auditPool(items) {
  let i = 0, done = 0;
  const worker = async () => {
    while (i < items.length) {
      const item = items[i++];
      // watchdog race: no single site may stall a worker (a silent exit-0
      // mid-audit was observed once in CI when the pool never completed)
      let timer;
      const guard = new Promise((res) => { timer = setTimeout(() => res({ status: 'down', notes: ['watchdog timeout'] }), 60000); });
      try { item.audit = await Promise.race([auditSite(item.website), guard]); }
      catch { item.audit = { status: 'down', notes: ['audit error'] }; }
      finally { clearTimeout(timer); }
      done++;
      if (done % 50 === 0) log(`  audited ${done}/${items.length} sites...`);
    }
  };
  await Promise.all(Array.from({ length: AUDIT_CONCURRENCY }, worker));
}

// ---------- Scoring ----------
function scoreRow(b) {
  const ev = [];
  let w = 0, it = 0;
  const heavy = IT_HEAVY.has(b.vertical);
  if (heavy) it += 2;
  let confidence = 'High';

  const emailIsFree = b.email && FREE_EMAIL_RE.test(b.email);
  FREE_EMAIL_RE.lastIndex = 0;

  if (!b.website) {
    w += 3;
    confidence = b.source === 'Google' ? 'High' : 'Verify';
    ev.push(b.source === 'Google'
      ? 'No website on Google listing'
      : 'No website listed (OSM) — verify with a quick Google/call');
    if (heavy) { it += 2; ev.push(`${b.vertical} business with no web presence — likely no IT partner either`); }
  } else if (SOCIAL_RE.test(b.website)) {
    w += 4;
    ev.push('Facebook/Instagram page instead of a real website');
    if (heavy) it += 1;
  } else if (b.audit) {
    const a = b.audit;
    if (a.status === 'down') {
      w += 5; it += 2; confidence = 'Verify';
      ev.push('Listed website unreachable on every variant we tried' + (a.notes?.length ? ` (${a.notes.join(',')})` : '') +
        ' — verify before pitching: the listing may point to an old domain');
    }
    else if (a.status === 'parked') { w += 5; ev.push('Domain parked — site is gone'); }
    else if (a.status === 'ssl-error') { w += 3; it += 2; ev.push('SSL certificate broken/expired'); }
    else if (a.status === 'http-only') { w += 2; it += 2; ev.push('No HTTPS (insecure site)'); }
    if (a.status === 'ok' || a.status === 'http-only' || a.status === 'ssl-error') {
      if (!a.viewport && a.status === 'ok') { w += 2; ev.push('Not mobile-friendly (no viewport meta)'); }
      if (a.year && a.year <= CUR_YEAR - 3) { w += 2; ev.push(`Copyright stuck at ${a.year}`); }
      for (const f of a.flags || []) {
        w += /FrontPage|frameset|Flash/.test(f) ? 3
          : /2000s-era|Pre-2010|authoring tool/.test(f) ? 2 : 1;
        ev.push(f);
      }
      if (a.freeEmail) { w += 1; it += 1; ev.push(`Uses free email for business (${a.freeEmail})`); }
      if (a.oldServer) { it += 1; ev.push(`Outdated server stack: ${a.oldServer}`); }
      if (/WordPress/.test((a.flags || []).join(' '))) it += 1;
    }
  } else if (b.website) {
    ev.push('Site not audited this run (audit cap)');
    confidence = 'Verify';
  }

  if (emailIsFree) { it += 1; w += 1; ev.push(`Business email is ${b.email}`); }
  if (b.corrected) ev.push('Using the corrected domain from the board');
  if (b.fsqSite) ev.push('Website found via Foursquare (OSM listed none)');

  let need = '';
  if (w >= 4 && it >= 4) need = 'Both';
  else if (w >= 4) need = 'Website';
  else if (it >= 4) need = 'IT';
  else if (w >= 3) need = 'Website';

  return { ...b, wScore: w, itScore: it, need, confidence, evidence: ev.join('; ') };
}

// ---------- Output ----------
const CSV_HEADER = [
  'Region', 'Town', 'State', 'Business', 'Vertical', 'Need', 'Confidence',
  'Website score', 'IT score', 'Evidence', 'Phone', 'Website', 'Address',
  'Google Maps', 'Source', 'Status/Notes',
];
function csvEscape(v) {
  const s = String(v ?? '');
  return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}
function toRow(b, regionLabel) {
  const maps = `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(`${b.name} ${b.town} ${b.st}`)}`;
  return [
    regionLabel, b.town, b.st, b.name, b.vertical, b.need, b.confidence,
    b.wScore, b.itScore, b.evidence, b.phone, b.website, b.address, maps, b.source, '',
  ];
}

async function postWebhook(rows) {
  try {
    const res = await fetch(WEBHOOK, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ header: CSV_HEADER, rows }),
      signal: AbortSignal.timeout(60000),
    });
    log(`webhook: HTTP ${res.status} — ${(await res.text()).slice(0, 200)}`);
  } catch (e) {
    log(`webhook failed: ${e.message}`);
  }
}

// ---------- Main ----------
async function main() {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  log(`Scanning regions: ${REGION_KEYS.join(', ')}${USE_GOOGLE ? ' (Google Places mode)' : ' (OSM mode)'}`);

  const seen = new Set();
  const all = [];

  for (const rk of REGION_KEYS) {
    const region = REGIONS[rk];
    log(`[${region.label}] querying ${USE_GOOGLE ? 'Google Places' : 'Overpass'} (${region.towns.length} towns)...`);
    let biz = [];
    try {
      if (USE_GOOGLE) {
        biz = await googlePlaces(rk, region);
      } else {
        for (const t of region.towns) {
          const data = await overpass(buildTownQuery(t));
          const parsed = parseElements(data.elements || []);
          biz.push(...parsed);
          log(`  ${t.name}, ${t.st}: ${data.elements?.length ?? 0} elements → ${parsed.length} local businesses`);
          await sleep(parseInt(flagVal('--pace', '7000'), 10));
        }
      }
    } catch (e) {
      log(`[${region.label}] FAILED: ${e.message}`);
      continue;
    }
    // dedupe (same biz mapped as node+building, overlapping town radii)
    let kept = 0;
    for (const b of biz) {
      const key = b.name.toLowerCase().replace(/[^a-z0-9]/g, '') + '|' + b.lat.toFixed(3) + '|' + b.lng.toFixed(3);
      if (seen.has(key)) continue;
      seen.add(key);
      all.push(b);
      kept++;
      if (LIMIT && kept >= LIMIT) break;
    }
    log(`[${region.label}] ${kept} unique local businesses`);
    if (!USE_GOOGLE) await sleep(3000); // be polite to Overpass
  }

  // Owner-corrected domains from the board ("Real website" field): rescan.cmd
  // saves the live tracking doc to out/state-live.json before scanning.
  try {
    const live = JSON.parse(fs.readFileSync(path.join(OUT_DIR, 'state-live.json'), 'utf8'));
    let applied = 0;
    for (const b of all) {
      const k = (b.name + '|' + b.town + '|' + b.st).toLowerCase();
      const w = live[k] && live[k].w;
      if (w) { b.website = w; b.corrected = true; applied++; }
    }
    if (applied) log(`Applied ${applied} owner-corrected website domains from the board.`);
  } catch { /* no state snapshot — fine */ }

  // Foursquare-discovered websites (free backfill): adopt for businesses OSM
  // had no site for, so they get audited like everyone else this run.
  try {
    const fsq = JSON.parse(fs.readFileSync(path.join(OUT_DIR, 'ratings.json'), 'utf8'));
    let adopted = 0;
    for (const b of all) {
      if (b.website) continue;
      const e = fsq[(b.name + '|' + b.town + '|' + b.st).toLowerCase()];
      if (e && e.matched && e.w && !SOCIAL_RE.test(e.w)) { b.website = e.w; b.fsqSite = true; adopted++; }
    }
    if (adopted) log(`Adopted ${adopted} Foursquare-listed websites for no-site businesses.`);
  } catch { /* no ratings yet — fine */ }

  fs.writeFileSync(path.join(OUT_DIR, 'inventory.json'), JSON.stringify(all, null, 1));

  // Pick audit set per region: businesses with real (non-social) websites,
  // prioritized by vertical, capped at MAX_AUDIT per region.
  const prio = (v) => { const i = VERTICAL_PRIORITY.indexOf(v); return i < 0 ? 99 : i; };
  const auditSet = [];
  for (const rk of REGION_KEYS) {
    const withSite = all
      .filter((b) => b.region === rk && b.website && !SOCIAL_RE.test(b.website))
      .sort((a, b) => prio(a.vertical) - prio(b.vertical));
    auditSet.push(...withSite.slice(0, MAX_AUDIT));
  }
  log(`Auditing ${auditSet.length} websites (${auditCache.size ? 'warm' : 'cold'} cache, concurrency ${AUDIT_CONCURRENCY})...`);
  await auditPool(auditSet);
  log('Audits complete.');

  // Score everything; keep actionable leads. Hard requirement: a phone number
  // to call — no phone, no lead (still counted in stats + inventory.json).
  const noSiteCount = {};
  const leads = [];
  const stats = {};
  for (const b of all) {
    const scored = scoreRow(b);
    const rk = b.region;
    stats[rk] = stats[rk] || { total: 0, website: 0, it: 0, both: 0, healthy: 0, noSiteListed: 0, noPhone: 0 };
    stats[rk].total++;
    if (!b.website) stats[rk].noSiteListed++;

    if (!scored.need) { stats[rk].healthy++; continue; }
    if (!b.phone) { stats[rk].noPhone++; continue; }

    // Throttle unverified "no website listed" OSM rows: keep the high-value verticals only.
    if (!b.website && b.source === 'OSM') {
      if (prio(b.vertical) > VERTICAL_PRIORITY.indexOf('construction')) continue;
      noSiteCount[rk] = (noSiteCount[rk] || 0) + 1;
      if (noSiteCount[rk] > MAX_NOSITE) continue;
    }

    if (scored.need === 'Both') stats[rk].both++;
    else if (scored.need === 'Website') stats[rk].website++;
    else if (scored.need === 'IT') stats[rk].it++;
    leads.push(scored);
  }

  const needRank = { Both: 0, Website: 1, IT: 2 };
  leads.sort((a, b) =>
    (needRank[a.need] - needRank[b.need]) ||
    ((b.wScore + b.itScore) - (a.wScore + a.itScore)) ||
    a.region.localeCompare(b.region));

  // Keep the previous scan for new/hotter diffing on the board.
  const leadsPath = path.join(OUT_DIR, 'leads.json');
  if (fs.existsSync(leadsPath)) fs.copyFileSync(leadsPath, path.join(OUT_DIR, 'prev-leads.json'));

  // CSV (UTF-8 BOM so Excel opens it cleanly)
  const rows = leads.map((b) => toRow(b, REGIONS[b.region].label));
  const BOM = '\ufeff';
  const csv = BOM + [CSV_HEADER, ...rows].map((r) => r.map(csvEscape).join(',')).join('\r\n');
  fs.writeFileSync(path.join(OUT_DIR, 'leads.csv'), csv);
  fs.writeFileSync(path.join(OUT_DIR, 'leads.json'), JSON.stringify(leads, null, 1));

  const summary = {
    ranAt: new Date().toISOString(),
    mode: USE_GOOGLE ? 'google' : 'osm',
    regions: Object.fromEntries(REGION_KEYS.map((rk) => [REGIONS[rk].label, stats[rk] || {}])),
    totalLeads: leads.length,
    byNeed: {
      Both: leads.filter((l) => l.need === 'Both').length,
      Website: leads.filter((l) => l.need === 'Website').length,
      IT: leads.filter((l) => l.need === 'IT').length,
    },
  };
  fs.writeFileSync(path.join(OUT_DIR, 'summary.json'), JSON.stringify(summary, null, 2));

  log(`Done. ${leads.length} leads → out/leads.csv`);
  console.log(JSON.stringify(summary, null, 2));

  if (WEBHOOK) {
    log('Posting to Google Sheets webhook in batches...');
    for (let i = 0; i < rows.length; i += 200) await postWebhook(rows.slice(i, i + 200));
  }
}

// keepalive interval: a drained event loop must never end the process
// before main() finishes — better to hang visibly than deploy stale data.
const keepalive = setInterval(() => {}, 30000);
main()
  .then(() => clearInterval(keepalive))
  .catch((e) => { console.error(e); process.exit(1); });
