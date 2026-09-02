#!/usr/bin/env node
/**
 * Overture Maps verification — free, keyless, unlimited.
 *
 * Overture's Places theme (Meta + Microsoft + Foursquare + PinMeTo, monthly
 * releases, open data) carries an operating_status per place — open /
 * temporarily_closed / permanently_closed — plus a confidence score and
 * websites / phones / emails. This pass cross-checks every lead against it:
 *
 *   • permanently_closed  → bs CLOSED_PERMANENTLY (lead leaves the board)
 *   • temporarily_closed  → bs CLOSED_TEMPORARILY
 *   • open / listed       → matched, "Listed as operational (places data …)"
 *   • websites / phones   → backfilled where OSM had none (feeds the next audit)
 *
 * Data access: DuckDB reads the release's parquet parts straight from the
 * public S3 bucket over HTTPS with bounding-box pruning, and a 0.01° cell join
 * keeps only places near our leads — no key, no quota, ~1–5 min for the whole
 * 200-mile circle. Needs `npm install --no-save duckdb`; exits cleanly without it.
 *
 * Precedence in ratings.json: a live Google / Foursquare match refreshed in the
 * last 45 days keeps its status; otherwise Overture's status applies. Overture
 * never overwrites another source's website/phone, only fills gaps.
 *
 * Flags: --release=YYYY-MM-DD.0 (pin), --force (re-check every lead),
 *        --bbox-pad=0.02 (degrees around the lead extent).
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { keyOf } from './lib.mjs';

const dir = path.dirname(fileURLToPath(import.meta.url));
const out = path.join(dir, 'out');
const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);
const argOf = (name, dflt) => { const a = process.argv.find((x) => x.startsWith(name + '=')); return a ? a.slice(name.length + 1) : dflt; };
const FORCE = process.argv.includes('--force');

const BUCKET = 'https://overturemaps-us-west-2.s3.amazonaws.com/';
const MATCH_KM = 1.2;     // OSM and Meta pins for the same storefront can sit a few hundred metres apart
const CELL = 0.01;        // ~1.1 km grid for the candidate join (3×3 neighbourhood per lead)
const MIN_CONF = 0.4;     // Overture already drops ≤0.2; below this we don't call it "listed"
const LIVE_FRESH_MS = 45 * 86400000;

const require = createRequire(import.meta.url);
let duckdb;
try {
  duckdb = require('duckdb');
} catch {
  console.log('overture: duckdb not installed — skipping (npm install --no-save duckdb to enable).');
  process.exit(0);
}

const leads = JSON.parse(fs.readFileSync(path.join(out, 'leads.json'), 'utf8'));
const ratingsPath = path.join(out, 'ratings.json');
let ratings = {};
try { ratings = JSON.parse(fs.readFileSync(ratingsPath, 'utf8')); } catch { /* first run */ }
const metaPath = path.join(out, 'overture-meta.json');

async function listS3(prefix, delimiter) {
  const u = BUCKET + '?list-type=2&max-keys=1000&prefix=' + encodeURIComponent(prefix) + (delimiter ? '&delimiter=%2F' : '');
  const res = await fetch(u, { signal: AbortSignal.timeout(30000) });
  if (!res.ok) throw new Error('S3 list HTTP ' + res.status);
  return await res.text();
}

let release = argOf('--release', '');
try {
  if (!release) {
    const xml = await listS3('release/', true);
    const rels = [...xml.matchAll(/<Prefix>release\/([^<\/]+)\//g)].map((m) => m[1]).sort();
    release = rels[rels.length - 1] || '';
  }
} catch (e) {
  log(`overture: could not list releases (${e.message}) — skipping.`);
  process.exit(0);
}
if (!release) { log('overture: no release found — skipping.'); process.exit(0); }
const releaseDate = release.slice(0, 10);

// Only leads with coordinates that haven't been checked against this release.
const todo = leads.filter((l) =>
  typeof l.lat === 'number' && typeof l.lng === 'number' &&
  (FORCE || !(ratings[keyOf(l)] && ratings[keyOf(l)].ov === release)));
log(`Overture ${release}: ${todo.length} of ${leads.length} leads to check (${leads.length - todo.length} already checked against this release).`);
if (!todo.length) {
  let prev = {};
  try { prev = JSON.parse(fs.readFileSync(metaPath, 'utf8')); } catch { /* none */ }
  fs.writeFileSync(metaPath, JSON.stringify({ ...prev, release, at: Date.now(), checked: 0 }));
  process.exit(0);
}

let parts = [];
try {
  const xml = await listS3(`release/${release}/theme=places/type=place/`, false);
  parts = [...xml.matchAll(/<Key>([^<]+\.parquet)<\/Key>/g)].map((m) => BUCKET + m[1]);
} catch (e) {
  log(`overture: could not list parquet parts (${e.message}) — skipping.`);
  process.exit(0);
}
if (!parts.length) { log('overture: no parquet parts listed — skipping.'); process.exit(0); }

// ---- pull candidates near our leads -------------------------------------------------
const slim = todo.map((l) => ({ k: keyOf(l), name: l.name, lat: l.lat, lng: l.lng }));
const slimPath = path.join(out, 'overture-leads.json');
fs.writeFileSync(slimPath, JSON.stringify(slim));
const pad = parseFloat(argOf('--bbox-pad', '0.02'));
const lats = slim.map((l) => l.lat), lngs = slim.map((l) => l.lng);
const minLat = Math.min(...lats) - pad, maxLat = Math.max(...lats) + pad;
const minLng = Math.min(...lngs) - pad, maxLng = Math.max(...lngs) + pad;

const db = new duckdb.Database(':memory:');
const con = db.connect();
const q = (sql) => new Promise((res, rej) => con.all(sql, (e, r) => (e ? rej(e) : res(r))));

let rows = [];
const t0 = Date.now();
try {
  await q('INSTALL httpfs; LOAD httpfs; SET http_retries=4; SET http_timeout=180000;');
  await q(`CREATE TABLE leads AS SELECT * FROM read_json_auto('${slimPath.replace(/\\/g, '/')}')`);
  await q(`CREATE TABLE cells AS
    SELECT DISTINCT CAST(floor(lat / ${CELL}) AS BIGINT) + dy AS cy, CAST(floor(lng / ${CELL}) AS BIGINT) + dx AS cx
    FROM leads, (VALUES (-1), (0), (1)) d1(dy), (VALUES (-1), (0), (1)) d2(dx)`);
  const list = parts.map((u) => "'" + u + "'").join(',');
  log(`Reading ${parts.length} parquet parts over HTTPS (bbox ${minLat.toFixed(2)},${minLng.toFixed(2)} → ${maxLat.toFixed(2)},${maxLng.toFixed(2)})...`);
  rows = await q(`
    SELECT DISTINCT ON (p.id) p.id, p.names.primary AS name, p.bbox.xmin AS lng, p.bbox.ymin AS lat,
           p.operating_status AS status, p.confidence AS conf,
           p.websites[1] AS web, p.phones[1] AS tel, p.emails[1] AS email, p.categories.primary AS cat
    FROM read_parquet([${list}]) p
    JOIN cells c ON CAST(floor(p.bbox.ymin / ${CELL}) AS BIGINT) = c.cy AND CAST(floor(p.bbox.xmin / ${CELL}) AS BIGINT) = c.cx
    WHERE p.bbox.xmin BETWEEN ${minLng} AND ${maxLng} AND p.bbox.ymin BETWEEN ${minLat} AND ${maxLat}
      AND p.names.primary IS NOT NULL
  `);
} catch (e) {
  log(`overture: query failed (${e.message}) — leaving ratings untouched.`);
  try { fs.unlinkSync(slimPath); } catch { /* ignore */ }
  process.exit(0);
}
try { fs.unlinkSync(slimPath); } catch { /* ignore */ }
log(`${rows.length} candidate places near ${todo.length} leads in ${((Date.now() - t0) / 1000).toFixed(0)} s.`);

// ---- match ----------------------------------------------------------------------------
const norm = (s) => String(s || '').toLowerCase().replace(/[^a-z0-9 ]+/g, ' ').replace(/\s+/g, ' ').trim();
const STOP = new Set(['the', 'of', 'and', 'llc', 'inc', 'co', 'company', 'corp', 'ltd', 'pllc', 'pc', 'pa', 'dds', 'md', 'dvm', 'od']);
const toks = (s) => new Set(norm(s).split(' ').filter((t) => t && !STOP.has(t)));
function nameScore(a, b) {
  const A = norm(a), B = norm(b);
  if (!A || !B) return 0;
  if (A === B) return 1;
  if (A.startsWith(B) || B.startsWith(A)) return 0.9;
  const ta = toks(a), tb = toks(b);
  if (!ta.size || !tb.size) return 0;
  let shared = 0;
  for (const t of ta) if (tb.has(t)) shared++;
  return shared / Math.min(ta.size, tb.size);
}
function haversineKm(lat1, lng1, lat2, lng2) {
  const R = 6371, dLat = (lat2 - lat1) * Math.PI / 180, dLng = (lng2 - lng1) * Math.PI / 180;
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) * Math.sin(dLng / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(a));
}
const cellOf = (lat, lng) => Math.floor(lat / CELL) + ':' + Math.floor(lng / CELL);
const byCell = new Map();
for (const r of rows) {
  const k = cellOf(r.lat, r.lng);
  if (!byCell.has(k)) byCell.set(k, []);
  byCell.get(k).push(r);
}
function bestMatch(l) {
  const cy = Math.floor(l.lat / CELL), cx = Math.floor(l.lng / CELL);
  const scored = [];
  for (let dy = -1; dy <= 1; dy++) for (let dx = -1; dx <= 1; dx++) {
    for (const c of byCell.get((cy + dy) + ':' + (cx + dx)) || []) {
      const d = haversineKm(l.lat, l.lng, c.lat, c.lng);
      if (d > MATCH_KM) continue;
      const s = nameScore(l.name, c.name);
      if (s < 0.5) continue;
      scored.push({ c, d, s });
    }
  }
  if (!scored.length) return null;
  // best name first, then nearest; a closed record only wins if nothing open matches at least as well
  scored.sort((a, b) => (b.s - a.s) || (a.d - b.d));
  const top = scored[0];
  if (top.c.status === 'permanently_closed') {
    const alive = scored.find((x) => x.c.status !== 'permanently_closed' && x.s >= top.s && x.d <= 0.3);
    if (alive) return alive;
  }
  return top;
}
const STATUS = { open: 'OPERATIONAL', permanently_closed: 'CLOSED_PERMANENTLY', temporarily_closed: 'CLOSED_TEMPORARILY' };

// ---- merge ----------------------------------------------------------------------------
let matched = 0, closed = 0, tempClosed = 0, webFill = 0, telFill = 0, kept = 0, unmatched = 0;
for (const l of todo) {
  const k = keyOf(l);
  const ex = ratings[k];
  const m = bestMatch(l);
  if (!m) {
    unmatched++;
    if (ex) ex.ov = release; else ratings[k] = { matched: false, ov: release };
    continue;
  }
  const c = m.c;
  const bs = STATUS[c.status] || 'LISTED'; // null status = record exists, status unknown
  const conf = Number(c.conf) || 0;
  const isClosed = bs === 'CLOSED_PERMANENTLY';
  if (!isClosed && conf < MIN_CONF) { // too weak to call it listed
    unmatched++;
    if (ex) ex.ov = release; else ratings[k] = { matched: false, ov: release };
    continue;
  }
  const liveFresh = ex && ex.matched && ex.src !== 'overture' && ex.dr && (Date.now() - Date.parse(ex.dr)) < LIVE_FRESH_MS;
  const entry = {
    matched: true, src: 'overture', r: 0, rc: 0, bs,
    dr: releaseDate, dc: '', w: c.web || '', t: c.tel || '', e: c.email || '',
    conf: Math.round(conf * 100) / 100, oid: c.id, ocat: c.cat || '', ov: release,
  };
  if (ex && ex.matched && ex.src !== 'overture') {
    // a live source already matched: keep it, add Overture's status/contacts as gap-fill
    kept++;
    ex.ov = release; ex.conf = entry.conf; ex.oid = c.id; ex.ocat = entry.ocat; ex.ovs = bs;
    if (!ex.w && entry.w) { ex.w = entry.w; webFill++; }
    if (!ex.t && entry.t) { ex.t = entry.t; telFill++; }
    if (!ex.e && entry.e) ex.e = entry.e;
    if (isClosed && !liveFresh && ex.bs !== 'CLOSED_PERMANENTLY') { ex.bs = 'CLOSED_PERMANENTLY'; ex.dr = releaseDate; closed++; }
    continue;
  }
  ratings[k] = entry;
  matched++;
  if (isClosed) closed++;
  else if (bs === 'CLOSED_TEMPORARILY') tempClosed++;
  if (entry.w && !l.website) webFill++;
  if (entry.t && !l.phone) telFill++;
}

fs.writeFileSync(ratingsPath, JSON.stringify(ratings));
fs.writeFileSync(metaPath, JSON.stringify({ release, at: Date.now(), checked: todo.length, matched, kept, closed, tempClosed, unmatched, webFill, telFill }));
log(`Done → out/ratings.json: ${matched} matched on Overture (${kept} already verified live, gap-filled), ` +
    `${closed} permanently closed, ${tempClosed} temporarily closed, ${unmatched} not found near their pin; ` +
    `${webFill} websites and ${telFill} phones backfilled. Release ${release}.`);
