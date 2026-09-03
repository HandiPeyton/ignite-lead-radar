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
import { REGIONS, SELECTORS, CHAIN_RE, IT_HEAVY, VERTICAL_PRIORITY, classifyVertical, CENTER, RADIUS_KM, TILE_LAT, TILE_LNG } from './regions.mjs';
import { DIRECTORY_RE } from './lib.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT_DIR = path.join(__dirname, 'out');
const UA = 'IgniteCyber-LeadScanner/1.0 (local business research; ignitecyber.io)';
const CUR_YEAR = new Date().getFullYear();

// Only mirrors that actually answer: private.coffee and kumi.systems were
// returning HTTP 500 (2026-09-01); a worker bound to a dead mirror just burns
// attempts. Re-add them here if they come back.
// overpass-api.de's bare hostname is a load balancer that 504s under load;
// its two named backends answer fine and each publishes 2 slots per IP.
// openstreetmap.fr only accepts GET. mail.ru has nightly slow windows (auto-benched).
const OVERPASS_ENDPOINTS = [
  'https://z.overpass-api.de/api/interpreter',
  'https://lz4.overpass-api.de/api/interpreter',
  // overpass.openstreetmap.fr refuses our user agent by policy ("only available to white-listed usages") — not used.
  'https://maps.mail.ru/osm/tools/overpass/api/interpreter',
];
// Per-mirror concurrency = what each server itself publishes. Workers never
// exceed a mirror's capacity, so this stays inside every server's own policy.
// z + lz4 are two front doors of ONE service with a shared 2-slot-per-IP
// limit — 1 each keeps the whole cluster inside its policy (4 concurrent
// requests got the runner's connections dropped: "fetch failed" storms).
const EP_CAPACITY = {
  'https://z.overpass-api.de/api/interpreter': 1,
  'https://lz4.overpass-api.de/api/interpreter': 1,
};
const EP_GET = new Set(); // mirrors that only accept GET (none currently)
const capOf = (e) => EP_CAPACITY[e] || 1;

// ---------- CLI ----------
const args = process.argv.slice(2);
function flagVal(name, dflt) {
  const i = args.indexOf(name);
  return i >= 0 && args[i + 1] ? args[i + 1] : dflt;
}
const REGION_KEYS = (flagVal('--region', flagVal('--regions', Object.keys(REGIONS).join(','))))
  .split(',').map((s) => s.trim()).filter((k) => REGIONS[k]);
const MAX_AUDIT = parseInt(flagVal('--max-audit', '1500'), 10);   // per state
const LIMIT = parseInt(flagVal('--limit', '0'), 10);
const MAX_NOSITE = parseInt(flagVal('--max-nosite', '400'), 10);  // per state
const TILES_CAP = parseInt(flagVal('--tiles', '0'), 10);          // smoke tests: stop after N tiles
const WEBHOOK = flagVal('--webhook', process.env.SHEET_WEBHOOK || '');
const USE_GOOGLE = args.includes('--google') && !!process.env.GOOGLE_PLACES_API_KEY;
const AUDIT_CONCURRENCY = parseInt(flagVal('--concurrency', '24'), 10); // distinct hosts — IO-bound, CI runner handles it
const SKIP_ENUM = args.includes('--skip-enum'); // light mode: reuse last enumeration, re-audit only

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);

// ---------- geo helpers ----------
function haversineKm(lat1, lon1, lat2, lon2) {
  const R = 6371, d2r = Math.PI / 180;
  const dLat = (lat2 - lat1) * d2r, dLon = (lon2 - lon1) * d2r;
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(lat1 * d2r) * Math.cos(lat2 * d2r) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(a));
}
// ---------- Places (every city/town/village inside the circle) ----------
// Pulled per state from OSM so each place carries its state; cached ~30 days.
let PLACES = [];
const placeBuckets = new Map();
const CELL = 0.25; // degrees; ~27 km buckets for fast nearest-place lookup
const cellKey = (lat, lng) => Math.floor(lat / CELL) + ':' + Math.floor(lng / CELL);

async function loadPlaces() {
  const cachePath = path.join(OUT_DIR, 'places.json');
  try {
    const c = JSON.parse(fs.readFileSync(cachePath, 'utf8'));
    if (Date.now() - c.at < 30 * 86400000 && c.places.length > 100) {
      log(`Places: ${c.places.length} cities/towns/villages (cached)`);
      return c.places;
    }
  } catch { /* fetch fresh */ }
  const places = [];
  for (const rk of Object.keys(REGIONS)) {
    const q = `[out:json][timeout:180];` +
      `area["boundary"="administrative"]["admin_level"="4"]["name"="${REGIONS[rk].osm}"]->.s;` +
      `node(area.s)["place"~"^(city|town|village)$"](around:${Math.round(RADIUS_KM * 1000)},${CENTER.lat},${CENTER.lng});out;`;
    try {
      const data = await overpass(q);
      let n = 0;
      for (const el of data.elements || []) {
        if (!el.tags || !el.tags.name || el.lat == null) continue;
        places.push({
          name: el.tags.name, lat: el.lat, lng: el.lon, type: el.tags.place,
          pop: parseInt(el.tags.population || '0', 10) || 0, region: rk, st: rk.toUpperCase(),
        });
        n++;
      }
      log(`  ${REGIONS[rk].label}: ${n} places`);
    } catch (e) {
      log(`  ${REGIONS[rk].label}: places query FAILED (${e.message})`);
    }
    await sleep(2500);
  }
  fs.writeFileSync(cachePath, JSON.stringify({ at: Date.now(), places }));
  log(`Places: ${places.length} cities/towns/villages within ${RADIUS_KM.toFixed(0)} km of ${CENTER.name}`);
  return places;
}

function indexPlaces(places) {
  PLACES = places;
  placeBuckets.clear();
  for (const p of places) {
    const k = cellKey(p.lat, p.lng);
    if (!placeBuckets.has(k)) placeBuckets.set(k, []);
    placeBuckets.get(k).push(p);
  }
}

function nearestPlace(lat, lng) {
  let best = null, bd = Infinity;
  const ci = Math.floor(lat / CELL), cj = Math.floor(lng / CELL);
  for (let ring = 1; ring <= 6; ring++) {
    for (let i = ci - ring; i <= ci + ring; i++) {
      for (let j = cj - ring; j <= cj + ring; j++) {
        const arr = placeBuckets.get(i + ':' + j);
        if (!arr) continue;
        for (const p of arr) {
          const d = haversineKm(lat, lng, p.lat, p.lng);
          if (d < bd) { bd = d; best = p; }
        }
      }
    }
    // everything within `ring` cells has been checked; a closer place can't be further out
    if (best && bd <= ring * CELL * 100) return best;
  }
  if (best) return best;
  for (const p of PLACES) { const d = haversineKm(lat, lng, p.lat, p.lng); if (d < bd) { bd = d; best = p; } }
  return best;
}

// ---------- Overpass ----------
// The circle is tiled into ~24 km bounding boxes; each tile is one query.
// Tiles that time out (dense metro cores) are split in four and retried.
function makeTiles() {
  const tiles = [];
  const latSpan = RADIUS_KM / 111.32;
  const lngSpan = RADIUS_KM / (111.32 * Math.cos((CENTER.lat * Math.PI) / 180));
  const lat0 = CENTER.lat - latSpan, lng0 = CENTER.lng - lngSpan;
  // Every tile inside the circle is queried — no "wilderness" skipping, so a
  // lodge on a forest road counts just as much as a dentist downtown.
  for (let lat = lat0; lat < CENTER.lat + latSpan; lat += TILE_LAT) {
    for (let lng = lng0; lng < CENTER.lng + lngSpan; lng += TILE_LNG) {
      const cLat = lat + TILE_LAT / 2, cLng = lng + TILE_LNG / 2;
      if (haversineKm(CENTER.lat, CENTER.lng, cLat, cLng) > RADIUS_KM + 18) continue;
      tiles.push({ s: lat, w: lng, n: lat + TILE_LAT, e: lng + TILE_LNG });
    }
  }
  // Pre-split tiles that hold a city or a cluster of towns: those always time
  // out at full size on a busy mirror, so start them at quarter size instead
  // of paying a timeout first.
  const dense = (t) => {
    let n = 0;
    for (const p of PLACES) {
      if (p.lat >= t.s && p.lat < t.n && p.lng >= t.w && p.lng < t.e) {
        if (p.type === 'city') return true;
        if (++n >= 6) return true;
      }
    }
    return false;
  };
  const out = [];
  let pre = 0;
  for (const t of tiles) {
    if (PLACES.length && dense(t)) {
      const mLat = (t.s + t.n) / 2, mLng = (t.w + t.e) / 2;
      out.push({ s: t.s, w: t.w, n: mLat, e: mLng }, { s: t.s, w: mLng, n: mLat, e: t.e },
        { s: mLat, w: t.w, n: t.n, e: mLng }, { s: mLat, w: mLng, n: t.n, e: t.e });
      pre++;
    } else out.push(t);
  }
  if (pre) log(`Pre-split ${pre} dense tiles (cities / town clusters) into quarters.`);
  return out;
}
const bboxStr = (t) => `${t.s.toFixed(4)},${t.w.toFixed(4)},${t.n.toFixed(4)},${t.e.toFixed(4)}`;
function buildBboxQuery(t) {
  const lines = SELECTORS.map((sel) => `nwr${sel}(${bboxStr(t)});`);
  return `[out:json][timeout:75];(${lines.join('')});out center;`; // fail fast into the split path
}

const epCooldown = new Map(); // endpoint -> timestamp when usable again
// Parallel tile workers share the mirrors politely: at most ONE in-flight
// request per endpoint, so 3 workers = 3 mirrors each seeing a serial stream.
const epInFlight = new Map();
// Adaptive mirror health: a mirror whose last few answers averaged > 30 s
// (mail.ru's nightly window hit 23 s for a 3 km probe) is benched for 10 min
// and retried later — no point feeding tiles to a server that will time out.
const epRecent = new Map(); // endpoint -> last durations (ms)
let netFailStreak = 0; // consecutive connection-level failures (any mirror); reset on success
// Overpass tells you when your next slot opens: "Slot available after: ..., in N seconds."
async function slotWait(ep) {
  try {
    const r = await fetch(ep.replace('/api/interpreter', '/api/status'), { signal: AbortSignal.timeout(8000) });
    const txt = await r.text();
    const secs = [...txt.matchAll(/in ([0-9]+) seconds/g)].map(m => +m[1]);
    if (/slots? available now/i.test(txt) && !secs.length) return 1;
    return secs.length ? Math.min(...secs) : 0;
  } catch { return 0; }
}
function noteLatency(ep, ms) {
  const arr = epRecent.get(ep) || [];
  arr.push(ms); if (arr.length > 3) arr.shift();
  epRecent.set(ep, arr);
  if (arr.length === 3 && arr.reduce((a, b) => a + b, 0) / 3 > 30000) {
    epCooldown.set(ep, Date.now() + 600000);
    epRecent.set(ep, []);
    log(`  mirror ${ep.split('/')[2]} averaging ${Math.round(arr.reduce((a, b) => a + b, 0) / 3000)} s/query — benching it for 10 min`);
  }
}
async function overpass(query) {
  let lastErr;
  for (let attempt = 0; attempt < 10; attempt++) {
    // pick a free endpoint (not cooling down, nothing in flight); wait if none
    let ep = null;
    for (let w = 0; w < 720 && !ep; w++) {
      ep = OVERPASS_ENDPOINTS.find((e) => (epCooldown.get(e) || 0) <= Date.now() && (epInFlight.get(e) || 0) < capOf(e));
      if (!ep) await sleep(500);
    }
    if (!ep) ep = OVERPASS_ENDPOINTS[0];
    epInFlight.set(ep, (epInFlight.get(ep) || 0) + 1);
    const t0 = Date.now();
    try {
      // mail.ru's gateway cuts queries at ~35 s: declare 30 s there so a heavy tile comes back as
      // Overpass's own 'timed out' (a real heaviness signal) instead of a gateway 504.
      const q = ep.includes('mail.ru') ? query.replace('[timeout:75]', '[timeout:30]') : query;
      const res = EP_GET.has(ep)
        ? await fetch(ep + '?data=' + encodeURIComponent(q), {
            headers: { 'User-Agent': UA, Accept: 'application/json' },
            signal: AbortSignal.timeout(90000),
          })
        : await fetch(ep, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded',
              'User-Agent': UA,
              Accept: 'application/json',
            },
            body: 'data=' + encodeURIComponent(q),
            signal: AbortSignal.timeout(90000),
          });
      if (res.status === 403) { // policy block (osm.fr) — bench 5 min instead of burning retries
        epCooldown.set(ep, Date.now() + 300000);
        throw new Error(`HTTP 403 from ${ep} (policy block — benched 5 min)`);
      }
      if (res.status === 429) {
        const wait = await slotWait(ep); // seconds until this IP's next slot, per the mirror itself
        if (wait) { epCooldown.set(ep, Date.now() + (wait + 2) * 1000); throw new Error(`HTTP 429 from ${ep} (slot frees in ${wait}s)`); }
        epCooldown.set(ep, Date.now() + 90000);
        throw new Error(`HTTP 429 from ${ep} (cooling that endpoint 90s)`);
      }
      if (!res.ok) {
        epCooldown.set(ep, Date.now() + 30000);
        throw new Error(`HTTP ${res.status} from ${ep}`);
      }
      const data = await res.json();
      netFailStreak = 0;
      noteLatency(ep, Date.now() - t0);
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
      const netFail = /fetch failed|ECONN|ENOTFOUND|EAI_AGAIN|socket|TLS/i.test(e.message) || e.name === 'TypeError';
      if (netFail) {
        netFailStreak++;
        epCooldown.set(ep, Date.now() + 20000); // let a dropped-connection mirror breathe
        if (netFailStreak >= 12) {
          log(`  ${netFailStreak} consecutive connection failures across mirrors — pausing 120 s (likely rate-blocked)`);
          await sleep(120000);
          netFailStreak = 0;
        }
      }
      log(`  overpass attempt ${attempt + 1} failed (${e.message} @ ${ep.split('/')[2]}); backing off...`);
      await sleep(4000);
    } finally {
      epInFlight.set(ep, Math.max(0, (epInFlight.get(ep) || 0) - 1));
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
    const distKm = haversineKm(CENTER.lat, CENTER.lng, lat, lng);
    if (distKm > RADIUS_KM) continue; // tile corners poke outside the circle
    const town = nearestPlace(lat, lng);
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
      mi: Math.round(distKm / 1.609344),
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
async function googlePlaces(regionKey) {
  const key = process.env.GOOGLE_PLACES_API_KEY;
  const out = [];
  const towns = PLACES.filter((p) => p.region === regionKey && p.type !== 'village');
  for (const t of towns) {
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
    signal: AbortSignal.timeout(12000), // generous on purpose: slow hosts are leads, not noise
  });
  const text = (await res.text()).slice(0, 300000);
  return { res, text };
}

function causeCode(e) {
  return e?.cause?.code || e?.code || (e?.name === 'TimeoutError' ? 'ETIMEDOUT' : '') || '';
}
// Only genuine certificate problems count as "your certificate is broken": expired, wrong
// name, self-signed, unverifiable chain. Handshake/protocol failures and resets are "unreachable".
const CERT_CODE_RE = /^(CERT_|ERR_TLS_CERT_|DEPTH_ZERO_SELF_SIGNED_CERT|SELF_SIGNED_CERT_IN_CHAIN|UNABLE_TO_VERIFY_LEAF_SIGNATURE|UNABLE_TO_GET_ISSUER_CERT)/i;
const CERT_MSG_RE = /certificate (?:has expired|is not yet valid)|self[- ]signed certificate|does not match certificate|unable to verify the first certificate|unable to get local issuer certificate|altnames/i;
// Hosting platforms whose sites live on a subdomain: adding www./apex variants to those only
// manufactures certificate errors against the platform's wildcard cert.
const PLATFORM_HOST_RE = /(wixsite|godaddysites|weebly|squarespace|wordpress|blogspot|webs|business\.site|toast\.site|square\.site|carrd\.co|my\.canva\.site|sites\.google)\.?/i;
// Bot protection answers (the host is up; it just won't serve a scanner) — never a lead signal.
const BLOCKED_STATUS = new Set([401, 403, 405, 406, 409, 429, 503]);
const CHALLENGE_RE = /just a moment|attention required|checking your browser|enable javascript and cookies|verify you are human|are you a human|access denied|cloudflare|incapsula|imperva|ddos-guard|sucuri website firewall|bot verification|request blocked/i;
const TRANSIENT_RE = /^(UND_ERR_CONNECT_TIMEOUT|ETIMEDOUT|UND_ERR_SOCKET|ECONNRESET|EAI_AGAIN)$/;

async function auditSite(rawUrl) {
  // Double-check design: a site only counts as down/broken if EVERY reasonable
  // variant fails — the URL exactly as listed, then www/apex × https/http.
  // Many small-business sites answer on only one of these.
  let u;
  // places-data backfills often arrive as bare domains ("www.example.com") — that's a site, not a bad URL
  const withScheme = String(rawUrl || '').trim().includes('://') ? String(rawUrl).trim() : 'https://' + String(rawUrl || '').trim();
  try { u = new URL(withScheme); } catch { return { status: 'down', notes: ['Bad URL'] }; }
  const bare = u.hostname.replace(/^www\./, '');
  if (auditCache.has(bare)) return auditCache.get(bare);

  const candidates = [];
  const push = (c) => { if (!candidates.includes(c)) candidates.push(c); };
  // https is tried before http even when the listing says http://, so a site that got a free
  // certificate isn't reported as "no HTTPS" just because the old listing answers on port 80.
  const bareDomain = bare.split('.').length === 2 && !PLATFORM_HOST_RE.test(bare);
  push(u.href.replace(/^http:/i, 'https:'));
  if (bareDomain) { push(`https://www.${bare}/`); push(`https://${bare}/`); }
  push(u.href);
  if (bareDomain) { push(`http://www.${bare}/`); push(`http://${bare}/`); }

  const result = {
    status: 'ok', viewport: false, year: null, flags: [], freeEmail: '',
    oldServer: '', finalUrl: '', https: true,
  };
  let page = null, sawCert = false, blocked = false, lastNote = '';
  for (const cand of candidates) {
    for (let attempt = 0; attempt < 2 && !page; attempt++) {
      try {
        const p = await tryFetch(cand);
        const st = p.res.status;
        if (st < 400) { page = p; break; }
        // an HTTP answer means the host is up: bot protection is not "down"
        if (BLOCKED_STATUS.has(st) || CHALLENGE_RE.test(p.text.slice(0, 20000))) { blocked = true; lastNote = `HTTP ${st} (bot protection)`; }
        else lastNote = `HTTP ${st}`;
        break;
      } catch (e) {
        const code = causeCode(e);
        const msg = String(e?.cause?.message || e?.message || '');
        if (CERT_CODE_RE.test(code) || CERT_MSG_RE.test(msg)) sawCert = true;
        lastNote = code || 'unreachable';
        // one retry for transient network failures — a single connect timeout from a busy
        // runner must not become "your website is unreachable" on a prospect's checkup page
        if (attempt === 0 && TRANSIENT_RE.test(code)) { await sleep(3000); continue; }
        break;
      }
    }
    if (page) break;
  }
  if (!page) {
    const r = blocked
      ? { status: 'blocked', notes: [lastNote] }
      : { status: sawCert ? 'ssl-error' : 'down', notes: [lastNote] };
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
  if (/<(?:object|embed|param)[^>]+\.swf["'\s>]|application\/x-shockwave-flash|clsid:D27CDB6E-AE6D-11cf-96B8-444553540000|swfobject\.embedSWF\s*\(/i.test(text)) result.flags.push('Uses Flash (dead tech)');
  if (/wsimg\.com|godaddy.*website ?builder/i.test(text)) result.flags.push('GoDaddy site builder');
  if (/wixstatic\.com|wix\.com/i.test(text)) result.flags.push('Wix builder');
  if (/weebly\.com/i.test(text)) result.flags.push('Weebly builder');

  // "Genuinely outdated / dated-looking" signals — sites that load fine but
  // scream 2005: legacy markup, ancient frameworks, authoring-tool exports.
  const legacyTags = (text.match(/<font[\s>]|<center[\s>]/gi) || []).length;
  if (/<marquee[\s>]|<body[^>]+bgcolor=/i.test(text) || (legacyTags >= 4 && !result.viewport)) result.flags.push('2000s-era HTML (font/center/marquee markup)');
  if (/<!DOCTYPE html PUBLIC[^>]*(XHTML 1\.0|HTML 4\.0)/i.test(text.slice(0, 400))) result.flags.push('Pre-2010 page framework (XHTML/HTML4 doctype)');
  if (/jquery[\/.-]1\.\d/i.test(text)) result.flags.push('Ancient jQuery library (1.x)');
  const genMeta = text.match(/<meta[^>]+generator[^>]*>/i)?.[0] || '';
  if (/(dreamweaver|adobe golive|microsoft (word|publisher)|netobjects)/i.test(genMeta)) result.flags.push('Exported from a 2000s authoring tool');
  const tableCount = (text.match(/<table/gi) || []).length;
  if (tableCount >= 6 && !/display:\s*(flex|grid)/i.test(text) && !result.viewport) result.flags.push('Table-based page layout (dated design)');

  const wpGen = text.match(/content=["']WordPress (\d+)\.(\d+)/i);
  const wpVer = text.match(/wp-includes(?:\\?\/)(?:js(?:\\?\/)(?:wp-emoji-release|wp-emoji|wp-embed)|css(?:\\?\/)dist(?:\\?\/)block-library)[^"'\s]{0,200}?[?&]ver=(\d+)\.(\d+)/i);
  const wp = wpGen || wpVer;
  if (wp && parseInt(wp[1], 10) < 6) result.flags.push(`WordPress ${wp[1]}.${wp[2]} (outdated)`);

  const visible = text.replace(/<style[\s\S]*?<\/style>/gi, ' ').replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/<input[^>]+type=["']hidden[^>]*>/gi, ' ');
  const mailtos = [...visible.matchAll(/mailto:([^"'?\s>]+)/gi)].map((m) => m[1]);
  const freeMail = mailtos.map((m) => m.match(FREE_EMAIL_RE)).find(Boolean) || visible.match(FREE_EMAIL_RE);
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

  const invPath = path.join(OUT_DIR, 'inventory.json');
  let reused = false;
  if (SKIP_ENUM && fs.existsSync(invPath)) {
    const inv = JSON.parse(fs.readFileSync(invPath, 'utf8'));
    const regionsPresent = new Set(inv.map((b) => b.region));
    if (inv.length >= 3000 && REGION_KEYS.every((rk) => regionsPresent.has(rk))) {
      all.push(...inv);
      reused = true;
      log(`Light mode: reusing ${all.length} businesses from the last enumeration (no Overpass queries).`);
    } else {
      log(`Light mode requested but inventory looks partial (${inv.length} businesses, ${regionsPresent.size} regions) — running FULL enumeration instead.`);
    }
  }
  if (!reused) {
    indexPlaces(await loadPlaces());
    const pace = parseInt(flagVal('--pace', '2000'), 10); // per worker; each mirror still sees ≥ ~7 s between queries
    const addAll = (biz) => {
      let kept = 0;
      for (const b of biz) {
        // dedupe (same biz mapped as node+building, tile overlaps)
        const key = b.name.toLowerCase().replace(/[^a-z0-9]/g, '') + '|' + b.lat.toFixed(3) + '|' + b.lng.toFixed(3);
        if (seen.has(key)) continue;
        seen.add(key);
        all.push(b);
        kept++;
      }
      return kept;
    };

    if (USE_GOOGLE) {
      for (const rk of REGION_KEYS) {
        log(`[${REGIONS[rk].label}] querying Google Places...`);
        try { addAll(await googlePlaces(rk)); } catch (e) { log(`[${REGIONS[rk].label}] FAILED: ${e.message}`); }
      }
    } else {
      const queue = makeTiles();
      const ENUM_WORKERS = Math.min(OVERPASS_ENDPOINTS.reduce((n, e) => n + capOf(e), 0), parseInt(flagVal('--enum-workers', '5'), 10));
      let total = queue.length, tileNo = 0, splits = 0, stop = false, doneCount = 0;
      // Resumable enumeration: progress is checkpointed every 25 tiles so a job
      // timeout (or a slow-mirror night) never throws away hours of work. The
      // Actions cache carries out/ between runs; a checkpoint < 36 h old resumes.
      const progPath = path.join(OUT_DIR, 'enum-progress.json');
      const doneKeys = new Set();
      const failedTiles = []; // exhausted retries this run → retried at the end, then carried to the next run
      try {
        const prog = JSON.parse(fs.readFileSync(progPath, 'utf8'));
        if (Date.now() - prog.at < 36 * 3600000 && (prog.keys || []).length < queue.length /* a checkpoint covering every tile is a finished scan, not a crash: start fresh */ && Array.isArray(prog.all) && prog.all.length) {
          for (const b of prog.all) {
            const key = b.name.toLowerCase().replace(/[^a-z0-9]/g, '') + '|' + b.lat.toFixed(3) + '|' + b.lng.toFixed(3);
            if (!seen.has(key)) { seen.add(key); all.push(b); }
          }
          for (const k of prog.keys || []) doneKeys.add(k);
          for (const t of prog.failed || []) queue.unshift(t); // previous run's dropped tiles go first
          log(`Resuming enumeration: ${doneKeys.size} tiles already done, ${all.length} businesses carried over, ${(prog.failed || []).length} previously-failed tiles requeued.`);
        }
      } catch { /* no checkpoint — start fresh */ }
      const saveProgress = () => {
        try { fs.writeFileSync(progPath, JSON.stringify({ at: Date.now(), keys: [...doneKeys], all, failed: failedTiles })); } catch { /* ignore */ }
      };
      log(`Enumerating ${total} grid tiles covering ${RADIUS_KM.toFixed(0)} km around ${CENTER.name} (${ENUM_WORKERS} workers, one in flight per mirror, pace ${pace} ms)...`);
      const tileWorker = async () => {
        while (queue.length && !stop) {
          const t = queue.shift();
          if (doneKeys.has(bboxStr(t))) continue; // finished in an earlier attempt
          const n = ++tileNo;
          if (TILES_CAP && n > TILES_CAP) { stop = true; log(`  --tiles cap reached (${TILES_CAP}); stopping enumeration early`); break; }
          if (LIMIT && all.length >= LIMIT) { stop = true; break; }
          let data;
          try {
            data = await overpass(buildBboxQuery(t));
          } catch (e) {
            const heavy = /timed out|timeout|HTTP 504|HTTP 429/i.test(e.message);
            if (heavy && t.n - t.s > TILE_LAT / 3) {
              const mLat = (t.s + t.n) / 2, mLng = (t.w + t.e) / 2;
              queue.push({ s: t.s, w: t.w, n: mLat, e: mLng }, { s: t.s, w: mLng, n: mLat, e: t.e },
                { s: mLat, w: t.w, n: t.n, e: mLng }, { s: mLat, w: mLng, n: t.n, e: t.e });
              total += 4; splits++;
              log(`  tile ${n} too heavy (${e.message}) — split into 4`);
            } else if (!t.retried) {
              t.retried = true; queue.push(t); total++;
              log(`  tile ${n} exhausted retries (${e.message}) — parked for a second pass at the end`);
            } else {
              failedTiles.push({ s: t.s, w: t.w, n: t.n, e: t.e });
              log(`  tile ${n} FAILED twice — recorded; the next run retries it first`);
            }
            continue;
          }
          const parsed = parseElements(data.elements || []);
          const kept = addAll(parsed);
          doneKeys.add(bboxStr(t));
          if (++doneCount % 25 === 0) saveProgress();
          if (kept) log(`  tile ${n}/${total}: ${data.elements.length} elements → ${kept} new businesses (running total ${all.length})`);
          await sleep(pace);
        }
      };
      await Promise.all(Array.from({ length: ENUM_WORKERS }, tileWorker));
      saveProgress();
      log(`Enumeration done: ${all.length} businesses across ${tileNo} tiles (${splits} splits, ${doneKeys.size} completed).`);
    }
    if (REGION_KEYS.length < Object.keys(REGIONS).length) {
      const keep = new Set(REGION_KEYS);
      const before = all.length;
      for (let i = all.length - 1; i >= 0; i--) if (!keep.has(all[i].region)) all.splice(i, 1);
      log(`Region filter kept ${all.length} of ${before}.`);
    }
    for (const rk of REGION_KEYS) log(`[${REGIONS[rk].label}] ${all.filter((b) => b.region === rk).length} local businesses`);
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

  // Places-data websites (Overture / Foursquare / Google backfill in ratings.json): adopt for
  // businesses OSM had no site for, so they get audited like everyone else this run.
  try {
    const fsq = JSON.parse(fs.readFileSync(path.join(OUT_DIR, 'ratings.json'), 'utf8'));
    let adopted = 0;
    for (const b of all) {
      if (b.website) continue;
      const e = fsq[(b.name + '|' + b.town + '|' + b.st).toLowerCase()];
      // never adopt a directory / ordering / review page, and never adopt from a record whose
      // phone disagrees with OSM's — that record is probably a neighbouring business
      const d10 = (p) => String(p || '').replace(/\D/g, '').slice(-10);
      const phoneClash = e && e.t && b.phone && d10(e.t).length === 10 && d10(b.phone).length === 10 && d10(e.t) !== d10(b.phone);
      if (e && e.matched && e.w && !SOCIAL_RE.test(e.w) && !DIRECTORY_RE.test(e.w) && !phoneClash) { b.website = e.w.includes('://') ? e.w : 'https://' + e.w; b.fsqSite = true; adopted++; }
    }
    if (adopted) log(`Adopted ${adopted} places-listed websites (Overture / Foursquare / Google) for no-site businesses.`);
  } catch { /* no ratings yet — fine */ }

  // Keep the previous inventory so the board can tell "newly listed" apart
  // from "was healthy last run and just broke".
  if (fs.existsSync(invPath)) fs.copyFileSync(invPath, path.join(OUT_DIR, 'prev-inventory.json'));
  fs.writeFileSync(invPath, JSON.stringify(all, null, 1));

  // Pick audit set per region: businesses with real (non-social) websites,
  // prioritized by vertical, capped at MAX_AUDIT per region.
  const prio = (v) => { const i = VERTICAL_PRIORITY.indexOf(v); return i < 0 ? 99 : i; };
  const auditSet = [];
  for (const rk of REGION_KEYS) {
    const withSite = all
      .filter((b) => b.region === rk && b.website && !SOCIAL_RE.test(b.website))
      .sort((a, b) => (prio(a.vertical) - prio(b.vertical)) || ((a.mi ?? 999) - (b.mi ?? 999)));
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
