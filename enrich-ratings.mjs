#!/usr/bin/env node
/**
 * Google enrichment for leads: star rating, review count, and — the
 * still-in-business verification — businessStatus (OPERATIONAL /
 * CLOSED_TEMPORARILY / CLOSED_PERMANENTLY).
 * Uses Places API (New) Text Search with a Pro-SKU field mask (no
 * website/phone fields), so ~700 lookups stay well inside the
 * 5,000/month Pro free tier.
 *
 * Needs GOOGLE_PLACES_API_KEY. Without it, exits cleanly (pipeline-safe).
 * Resumable: leads already checked under the current schema are skipped.
 *
 * Reads out/leads.json → writes out/ratings.json (keyed by lead key).
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { keyOf } from './lib.mjs';

const dir = path.dirname(fileURLToPath(import.meta.url));
const out = path.join(dir, 'out');
const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);

const KEY = process.env.GOOGLE_PLACES_API_KEY;
if (!KEY) {
  console.log('enrich-ratings: GOOGLE_PLACES_API_KEY not set — skipping (board works fine without ratings).');
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

// redo entries from the pre-businessStatus schema (matched but no bs field)
const todo = leads.filter((l) => {
  const e = ratings[keyOf(l)];
  return !e || (e.matched && !e.bs);
});
log(`Google check (rating + operational status) for ${todo.length} leads (${leads.length - todo.length} already done)...`);

let done = 0, matched = 0;
for (const l of todo) {
  const k = keyOf(l);
  try {
    const res = await fetch('https://places.googleapis.com/v1/places:searchText', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Goog-Api-Key': KEY,
        'X-Goog-FieldMask': 'places.displayName,places.rating,places.userRatingCount,places.businessStatus',
      },
      body: JSON.stringify({ textQuery: `${l.name}, ${l.town}, ${l.st}`, pageSize: 1 }),
      signal: AbortSignal.timeout(20000),
    });
    if (res.status === 429) { log('Rate limited — stopping here; re-run to resume.'); break; }
    if (!res.ok) { ratings[k] = { matched: false, err: res.status }; continue; }
    const data = await res.json();
    const p = (data.places || [])[0];
    if (p && nameMatch(l.name, p.displayName?.text || '')) {
      ratings[k] = {
        matched: true,
        r: p.rating || 0,
        rc: p.userRatingCount || 0,
        bs: p.businessStatus || 'OPERATIONAL',
      };
      matched++;
    } else {
      ratings[k] = { matched: false };
    }
  } catch {
    ratings[k] = { matched: false, err: 'fetch' };
  }
  done++;
  if (done % 50 === 0) {
    fs.writeFileSync(ratingsPath, JSON.stringify(ratings));
    log(`  ${done}/${todo.length} (${matched} matched)...`);
  }
  await new Promise((r) => setTimeout(r, 120));
}
fs.writeFileSync(ratingsPath, JSON.stringify(ratings));
const vals = Object.values(ratings);
log(`Done → out/ratings.json: ${vals.filter((x) => x.matched).length} verified on Google, ` +
  `${vals.filter((x) => x.bs === 'CLOSED_PERMANENTLY').length} permanently closed, ` +
  `${vals.filter((x) => x.bs === 'CLOSED_TEMPORARILY').length} temporarily closed, ` +
  `${vals.filter((x) => !x.matched).length} not found on Google.`);
