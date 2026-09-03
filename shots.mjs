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

// a stray rejection must never take down the stage — log it and keep shooting
process.on('unhandledRejection', (e) => log('unhandled: ' + (e && e.message ? e.message : e)));

const store = getStore({ name: 'shots', siteID: SITE_ID, token: process.env.NETLIFY_AUTH_TOKEN });
const browser = await puppeteer.launch({
  // ignore-certificate-errors: broken-SSL sites are our best leads — their
  // screenshot is the whole point
  args: ['--no-sandbox', '--disable-dev-shm-usage', '--ignore-certificate-errors'],
});

// Deep per-site metrics captured on the SAME page load as the screenshot:
// real load time, total page weight, image weight, request count, mobile
// horizontal overflow, tiny tap targets, LCP/CLS, and image-alt / form-label
// counts. Written to out/deepscan.json (host-keyed).
const deep = {};

// Installed before every navigation (survives the mobile reload too): buffered
// PerformanceObservers accumulate LCP + layout-shift entries into window.__radar.
// Every statement is guarded — a page that lacks the API or throws simply leaves
// __radar empty and the render metrics are recorded as unknown.
const PROBE = `(() => {
  try {
    const r = { lcp: [], cls: [] };
    Object.defineProperty(window, '__radar', { value: r, writable: false, configurable: false });
    if (typeof PerformanceObserver !== 'function') return;
    try {
      new PerformanceObserver((list) => { for (const e of list.getEntries()) r.lcp.push(e.startTime); })
        .observe({ type: 'largest-contentful-paint', buffered: true });
    } catch (e) {}
    try {
      new PerformanceObserver((list) => { for (const e of list.getEntries()) { if (!e.hadRecentInput) r.cls.push(e.value); } })
        .observe({ type: 'layout-shift', buffered: true });
      r.clsOk = true;
    } catch (e) {}
  } catch (e) {}
})();`;

// Runs in the desktop pass after the settle wait. Returns partial results: any
// section that throws is left out rather than failing the whole read.
function readRender() {
  const o = {};
  try {
    const r = window.__radar;
    if (r && Array.isArray(r.lcp) && r.lcp.length) o.lcp = r.lcp[r.lcp.length - 1];
    if (r && r.clsOk === true && Array.isArray(r.cls)) o.cls = r.cls.reduce((s, v) => s + (typeof v === 'number' && isFinite(v) ? v : 0), 0);
  } catch (e) { /* metrics unknown */ }
  try {
    // Chrome wraps a bare image/PDF/text response in a synthetic document — nothing to audit there
    const ct = String(document.contentType || '').toLowerCase();
    if (ct && ct !== 'text/html' && ct !== 'application/xhtml+xml') return o;
  } catch (e) { /* treat as html */ }
  try {
    const imgs = document.querySelectorAll('img');
    o.imgTotal = imgs.length;
    o.imgNoAlt = [...imgs].filter((im) => {
      if (im.hasAttribute('alt')) return false; // alt="" is valid (decorative)
      const role = (im.getAttribute('role') || '').trim().toLowerCase();
      if (role === 'presentation' || role === 'none' || im.closest('[aria-hidden="true"]')) return false; // decorative per ARIA
      if (typeof im.checkVisibility === 'function' && !im.checkVisibility({ checkVisibilityCSS: true })) return false; // tracking pixels
      return true;
    }).length;
  } catch (e) { /* counts unknown */ }
  try {
    const TEXTY = new Set(['', 'text', 'email', 'tel', 'url', 'search', 'password', 'number', 'date', 'datetime-local', 'month', 'week', 'time']);
    const fields = [...document.querySelectorAll('input,textarea,select')].filter((el) => {
      if (el.tagName === 'INPUT' && !TEXTY.has((el.getAttribute('type') || '').trim().toLowerCase())) return false;
      if (el.closest('[aria-hidden="true"]') || el.getAttribute('tabindex') === '-1') return false; // honeypots, select2 originals
      if (typeof el.checkVisibility === 'function' && !el.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true })) return false;
      const rc = el.getBoundingClientRect();
      if (!(rc.width > 0 && rc.height > 0)) return false;
      // fully off-canvas (left:-5000px honeypots, clip:rect(0 0 0 0) 1px boxes)
      const dw = Math.max(document.documentElement.scrollWidth, window.innerWidth);
      if (rc.right <= 0 || rc.bottom <= 0 || rc.left >= dw || rc.width < 2 || rc.height < 2) return false;
      return true;
    });
    const labeled = (el) => {
      try { if (el.labels && el.labels.length) return true; } catch (e) { /* fall through */ }
      if (el.closest('label')) return true;
      if (el.id) { try { if (document.querySelector('label[for="' + CSS.escape(el.id) + '"]')) return true; } catch (e) { /* bad id */ } }
      for (const a of ['aria-label', 'aria-labelledby', 'title', 'placeholder']) {
        if ((el.getAttribute(a) || '').trim()) return true;
      }
      return false;
    };
    o.inputsTotal = fields.length;
    o.inputsNoLabel = fields.filter((el) => !labeled(el)).length;
  } catch (e) { /* counts unknown */ }
  return o;
}

// Sanity bounds: an LCP outside (0, loadMs+5000] or a CLS outside [0, 5] is a
// measurement artifact, not a finding — record unknown instead.
function renderFields(raw, loadMs) {
  const f = {};
  if (!raw || typeof raw !== 'object') return f;
  const n = (v) => (typeof v === 'number' && isFinite(v) ? v : undefined);
  const lcp = n(raw.lcp);
  if (lcp !== undefined && lcp > 0 && lcp <= loadMs + 5000) f.lcpMs = Math.round(lcp);
  const cls = n(raw.cls);
  if (cls !== undefined && cls >= 0 && cls <= 5) f.cls = Math.round(cls * 1000) / 1000;
  const c = (v) => (Number.isInteger(v) && v >= 0 ? v : undefined);
  if (c(raw.imgTotal) !== undefined && c(raw.imgNoAlt) !== undefined) { f.imgTotal = raw.imgTotal; f.imgNoAlt = raw.imgNoAlt; }
  if (c(raw.inputsTotal) !== undefined && c(raw.inputsNoLabel) !== undefined) { f.inputsTotal = raw.inputsTotal; f.inputsNoLabel = raw.inputsNoLabel; }
  return f;
}

async function newTab() {
  const page = await browser.newPage();
  await page.setViewport({ width: 1160, height: 870, deviceScaleFactor: 0.75 });
  page.setDefaultNavigationTimeout(24000); // a 20-second site is a lead — measure it, don't skip it
  try { await page.evaluateOnNewDocument(PROBE); } catch { /* no probe: LCP/CLS stay unknown */ }
  return page;
}
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
  let page = await newTab();
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
      // LCP/CLS + alt/label counts from this same desktop load; unknown if the page blocks it
      let render = {};
      try { render = renderFields(await page.evaluate(readRender), loadMs); } catch { /* unknown */ }
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
            tinyTaps: m.tinyTaps, ...render, at: Date.now(),
          };
          metriced++;
        }
      } catch { /* mobile pass failed — keep the screenshot anyway */ }
    } catch { /* site refused to render */ }
    page.off('response', onResp);
    // setViewport reloads the page when emulation changes; a site that hangs on that reload
    // used to throw out of the worker and kill the whole stage. Replace the wedged tab instead.
    try { await page.setViewport({ width: 1160, height: 870, deviceScaleFactor: 0.75 }); }
    catch {
      try { await page.close(); } catch { /* already gone */ }
      page = await newTab();
    }
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
