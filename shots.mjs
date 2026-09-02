#!/usr/bin/env node
/**
 * Weekly homepage screenshots for the checkup pages ("your website today").
 * Runs only in the Sunday FULL workflow step. Captures each reachable lead
 * site with headless Chrome and stores JPEGs in Netlify Blobs (store "shots"),
 * served by site/functions/shot.mjs at /shot/<slug>.jpg — so daily deploys
 * never touch them and the repo carries no image weight.
 *
 * Needs: puppeteer + @netlify/blobs installed (the workflow step installs
 * them --no-save), NETLIFY_AUTH_TOKEN in env. Exits cleanly if missing.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { slugOf, SOCIAL_RE } from './lib.mjs';

const dir = path.dirname(fileURLToPath(import.meta.url));
const out = path.join(dir, 'out');
const SITE_ID = '565e77e6-a859-4b59-aa14-c268aa57071c';
const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);

const require = createRequire(import.meta.url);
let puppeteer, getStore;
try {
  puppeteer = require('puppeteer');
  ({ getStore } = await import('@netlify/blobs'));
} catch {
  console.log('shots: puppeteer/@netlify/blobs not installed — skipping (screenshots are weekly-CI only).');
  process.exit(0);
}
if (!process.env.NETLIFY_AUTH_TOKEN) {
  console.log('shots: NETLIFY_AUTH_TOKEN not set — skipping.');
  process.exit(0);
}

const leads = JSON.parse(fs.readFileSync(path.join(out, 'leads.json'), 'utf8'));
const allTargets = [];
const seen = new Set();
for (const l of leads) {
  if (!l.website || SOCIAL_RE.test(l.website)) continue;
  if (l.audit && ['down', 'parked'].includes(l.audit.status)) continue;
  const slug = slugOf(l);
  if (seen.has(slug)) continue;
  seen.add(slug);
  allTargets.push({ slug, url: l.audit?.finalUrl || l.website, hi: l.confidence === 'High' ? 1 : 0, mi: typeof l.mi === 'number' ? l.mi : 999 });
}

const store = getStore({ name: 'shots', siteID: SITE_ID, token: process.env.NETLIFY_AUTH_TOKEN });
const browser = await puppeteer.launch({
  // ignore-certificate-errors: broken-SSL sites are our best leads — their
  // screenshot is the whole point
  args: ['--no-sandbox', '--disable-dev-shm-usage', '--ignore-certificate-errors'],
});

// Deep per-site metrics captured on the SAME page load as the screenshot:
// real load time, total page weight, image weight, request count, mobile
// horizontal overflow, tiny tap targets. Written to out/deepscan.json (host-keyed).
const deep = {};
let existingDeep = {};
try { existingDeep = JSON.parse(fs.readFileSync(path.join(out, 'deepscan.json'), 'utf8')); } catch { /* first run */ }
const hostOf = (u) => { try { return new URL(u).hostname.replace(/^www\./, ''); } catch { return null; } };
// Bounded workload at 200-mile scale: High-confidence + closest sites first, skip sites
// measured within the last week (their screenshot is still in Blobs) so weekly runs rotate
// through the rest, hard cap on count, and a wall-clock budget so the job can never time out here.
const argOf = (name, dflt) => { const a = process.argv.find((x) => x.startsWith(name + '=')); return a ? a.slice(name.length + 1) : dflt; };
const MAX_SHOTS = parseInt(argOf('--max-shots', '1500'), 10);
const SHOT_MINUTES = parseInt(argOf('--shots-minutes', '75'), 10);
const FRESH_MS = 6.5 * 86400000;
let skippedFresh = 0;
let targets = allTargets.filter((t) => { const d = existingDeep[hostOf(t.url)]; if (d && d.at && Date.now() - d.at < FRESH_MS) { skippedFresh++; return false; } return true; });
targets.sort((a, b) => (b.hi - a.hi) || (a.mi - b.mi));
if (targets.length > MAX_SHOTS) targets = targets.slice(0, MAX_SHOTS);
const deadline = Date.now() + SHOT_MINUTES * 60000;
log(`Screenshotting ${targets.length} of ${allTargets.length} lead sites (High-confidence + closest first; ${skippedFresh} still fresh from a prior week; cap ${MAX_SHOTS}; budget ${SHOT_MINUTES} min)...`);

let i = 0, done = 0, ok = 0, metriced = 0;
async function worker() {
  const page = await browser.newPage();
  await page.setViewport({ width: 1160, height: 870, deviceScaleFactor: 0.75 });
  page.setDefaultNavigationTimeout(24000); // a 20-second site is a lead — measure it, don't skip it
  while (i < targets.length && Date.now() < deadline) {
    const t = targets[i++];
    const host = hostOf(t.url);
    let bytes = 0, imgBytes = 0, imgCount = 0, reqCount = 0;
    const onResp = (res) => {
      reqCount++;
      try {
        const h = res.headers();
        const len = parseInt(h['content-length'] || '0', 10) || 0;
        bytes += len;
        if (/^image\//.test(h['content-type'] || '')) { imgBytes += len; imgCount++; }
      } catch { /* ignore */ }
    };
    page.on('response', onResp);
    try {
      const t0 = Date.now();
      await page.goto(t.url, { waitUntil: 'load' });
      const loadMs = Date.now() - t0;
      await new Promise((r) => setTimeout(r, 1200)); // let lazy images/fonts paint before the mirror shot
      const buf = await page.screenshot({ type: 'jpeg', quality: 52 });
      await store.set(t.slug, buf);
      ok++;
      // mobile-breakage pass: real 390px render, not just a meta tag
      try {
        await page.setViewport({ width: 390, height: 844, isMobile: true, hasTouch: true });
        await page.reload({ waitUntil: 'domcontentloaded' });
        const m = await page.evaluate(() => {
          const de = document.documentElement;
          const overflow = de.scrollWidth - window.innerWidth;
          const taps = [...document.querySelectorAll('a,button,input,select')].filter((e) => {
            const r = e.getBoundingClientRect();
            return r.width > 0 && r.height > 0 && (r.width < 30 || r.height < 30);
          }).length;
          return { overflowPx: Math.max(0, overflow), tinyTaps: taps };
        });
        if (host) {
          deep[host] = {
            loadMs, weightKB: Math.round(bytes / 1024), imgKB: Math.round(imgBytes / 1024),
            imgCount, reqCount, mobileOverflow: m.overflowPx > 12, overflowPx: m.overflowPx,
            tinyTaps: m.tinyTaps, at: Date.now(),
          };
          metriced++;
        }
      } catch { /* mobile pass failed — keep the screenshot anyway */ }
    } catch { /* site refused to render */ }
    page.off('response', onResp);
    await page.setViewport({ width: 1160, height: 870, deviceScaleFactor: 0.75 });
    done++;
    if (done % 50 === 0) log(`  ${done}/${targets.length} (${ok} shots, ${metriced} metrics)...`);
  }
  await page.close();
}
// 4 tabs, not more: measured load times are quoted to prospects, and CPU
// contention from too many parallel renders would inflate them.
await Promise.all(Array.from({ length: 4 }, worker));
await browser.close();

// merge over any prior deepscan (sites that failed this run keep last-known metrics)
fs.writeFileSync(path.join(out, 'deepscan.json'), JSON.stringify({ ...existingDeep, ...deep }, null, 0));
log(`Done: ${ok}/${done} screenshots, ${metriced} deep-metric captures` + (done < targets.length ? ` (time budget reached with ${targets.length - done} left; next weekly run picks them up)` : '') + '.');
