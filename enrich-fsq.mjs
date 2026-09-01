#!/usr/bin/env node
/**
 * Foursquare fallback enrichment — fills the same out/ratings.json store the
 * board consumes, for leads Google hasn't matched (or when Google is off).
 * Signals: closed_bucket / date_closed → operational verification;
 * FSQ rating (0-10, converted to 5-star scale; sparse outside cities).
 *
 * Match quality: name similarity AND proximity (search is anchored to the
 * lead's own lat/lng with a 1.6 km radius).
 *
 * Needs FOURSQUARE_API_KEY. Without it, exits cleanly (pipeline-safe).
 * Tries the classic v3 endpoint first, then the new places-api host.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { keyOf } from './lib.mjs';

const dir = path.dirname(fileURLToPath(import.meta.url));
const out = path.join(dir, 'out');
const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);

const KEY = process.env.FOURSQUARE_API_KEY;
if (!KEY) {
  console.log('enrich-fsq: FOURSQUARE_API_KEY not set — skipping.');
  process.exit(0);
}

const leads = JSON.parse(fs.readFileSync(path.join(out, 'leads.json'), 'utf8'));
const ratingsPath = path.join(out, 'ratings.json');
let ratings = {};
try { ratings = JSON.parse(fs.readFileSync(ratingsPath, 'utf8')); } catch { /* first run */ }

const norm = (s) => s.toLowerCase().replace(/[^a-z0-9 ]+/g, ' ').replace(/\s+/g, ' ').trim();
function nameMatch(a, b) {
  const A = norm(a), B = norm(b);
  if (!A || !B) return false;
  if (A.startsWith(B) || B.startsWith(A)) return true;
  const ta = new Set(A.split(' ')), tb = new Set(B.split(' '));
  let shared = 0;
  for (const t of ta) if (tb.has(t)) shared++;
  return shared / Math.min(ta.size, tb.size) >= 0.5;
}

// Free-tier fields only (rating/closed_bucket are premium or gone on the new API):
// date_closed present = permanently closed; date_refreshed = when FSQ last verified.
// website/tel/email ride along free — used for backfill and phone cross-checks.
const FIELDS = 'name,date_closed,date_refreshed,website,tel,email';
let mode = 'new'; // new places-api host first (service keys 401 on classic v3)
async function fsqSearch(l) {
  const q = encodeURIComponent(l.name);
  const ll = `${l.lat},${l.lng}`;
  const attempts = mode === 'v3' ? ['v3', 'new'] : ['new', 'v3'];
  for (const m of attempts) {
    const url = m === 'v3'
      ? `https://api.foursquare.com/v3/places/search?query=${q}&ll=${ll}&radius=1600&limit=5&fields=${FIELDS}`
      : `https://places-api.foursquare.com/places/search?query=${q}&ll=${ll}&radius=1600&limit=5&fields=${FIELDS}`;
    const headers = m === 'v3'
      ? { Authorization: KEY, Accept: 'application/json' }
      : { Authorization: `Bearer ${KEY}`, Accept: 'application/json', 'X-Places-Api-Version': '2025-06-17' };
    const res = await fetch(url, { headers, signal: AbortSignal.timeout(20000) });
    if (res.status === 401 || res.status === 403) { continue; } // wrong auth style for this key — try the other host
    if (res.status === 429) return { rateLimited: true };
    if (!res.ok) return { err: res.status };
    mode = m;
    const data = await res.json();
    return { places: data.results || [] };
  }
  return { err: 'auth' };
}

// work on leads Google hasn't positively matched; skip ones FSQ already tried
const todo = leads.filter((l) => {
  const e = ratings[keyOf(l)];
  // last clause: refresh pre-backfill-schema fsq entries (no w field captured yet)
  return !e || (!e.matched && !e.f) || e.err || (e.matched && e.src === 'fsq' && e.w === undefined);
});
log(`Foursquare check for ${todo.length} leads (${leads.length - todo.length} already covered)...`);

let done = 0, matched = 0, closed = 0;
for (const l of todo) {
  const k = keyOf(l);
  try {
    const r = await fsqSearch(l);
    if (r.rateLimited) { log('Rate limited — stopping; re-run to resume.'); break; }
    if (r.err) { ratings[k] = { matched: false, f: 1, err: r.err }; if (r.err === 'auth') { log('Key rejected by both Foursquare endpoints — check the key.'); break; } continue; }
    const p = (r.places || []).find((c) => nameMatch(l.name, c.name || ''));
    if (p) {
      const bs = p.date_closed ? 'CLOSED_PERMANENTLY' : 'OPERATIONAL';
      if (bs !== 'OPERATIONAL') closed++;
      ratings[k] = {
        matched: true,
        src: 'fsq',
        r: 0, rc: 0, // ratings are premium-tier on FSQ — none on the free plan
        bs,
        dr: p.date_refreshed || '',
        w: p.website || '',
        t: p.tel || '',
        e: p.email || '',
      };
      matched++;
    } else {
      ratings[k] = { matched: false, f: 1 };
    }
  } catch {
    ratings[k] = { matched: false, f: 1, err: 'fetch' };
  }
  done++;
  if (done % 50 === 0) {
    fs.writeFileSync(ratingsPath, JSON.stringify(ratings));
    log(`  ${done}/${todo.length} (${matched} matched, ${closed} closed flags)...`);
  }
  await new Promise((res) => setTimeout(res, 150));
}
fs.writeFileSync(ratingsPath, JSON.stringify(ratings));
const vals = Object.values(ratings);
log(`Done → out/ratings.json: ${vals.filter((x) => x.matched).length} verified total, ` +
  `${vals.filter((x) => x.bs === 'CLOSED_PERMANENTLY').length} permanently closed, ` +
  `${vals.filter((x) => x.bs === 'CLOSED_TEMPORARILY').length} possibly/temporarily closed.`);
