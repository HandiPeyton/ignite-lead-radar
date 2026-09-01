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
const targets = [];
const seen = new Set();
for (const l of leads) {
  if (!l.website || SOCIAL_RE.test(l.website)) continue;
  if (l.audit && ['down', 'parked'].includes(l.audit.status)) continue;
  const slug = slugOf(l);
  if (seen.has(slug)) continue;
  seen.add(slug);
  targets.push({ slug, url: l.audit?.finalUrl || l.website });
}
log(`Screenshotting ${targets.length} lead sites...`);

const store = getStore({ name: 'shots', siteID: SITE_ID, token: process.env.NETLIFY_AUTH_TOKEN });
const browser = await puppeteer.launch({ args: ['--no-sandbox', '--disable-dev-shm-usage'] });

let i = 0, done = 0, ok = 0;
async function worker() {
  const page = await browser.newPage();
  await page.setViewport({ width: 1160, height: 870, deviceScaleFactor: 0.75 });
  page.setDefaultNavigationTimeout(18000);
  while (i < targets.length) {
    const t = targets[i++];
    try {
      await page.goto(t.url, { waitUntil: 'domcontentloaded' });
      await new Promise((r) => setTimeout(r, 1500));
      const buf = await page.screenshot({ type: 'jpeg', quality: 52 });
      await store.set(t.slug, buf);
      ok++;
    } catch { /* site refused to render — checkup page hides the figure */ }
    done++;
    if (done % 50 === 0) log(`  ${done}/${targets.length} (${ok} captured)...`);
  }
  await page.close();
}
await Promise.all(Array.from({ length: 4 }, worker));
await browser.close();
log(`Done: ${ok}/${targets.length} screenshots stored.`);
