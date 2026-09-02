# Ignite Cyber lead scanner

Finds local businesses across **NE TN, SW VA, Southern WV, Western NC, SE Kentucky, and
Upstate/N SC** that look like they need a **new website** (Ridge Web Designs pitch), an
**IT company** (Ignite Cyber pitch), or **both** — and says which one, with evidence.

No dependencies. Needs Node 18+.

## Run it

```
node tools/lead-scanner/scan.mjs                      # all six regions (~10-15 min)
node tools/lead-scanner/scan.mjs --region netn,swva   # just some regions
node tools/lead-scanner/scan.mjs --max-audit 200      # fewer site audits = faster
node tools/lead-scanner/scan.mjs --webhook "<url>"    # also push rows to Google Sheets
```

**Coverage = everything within 200 miles of Bristol TN/VA.** Towns are not hand-listed:
the scanner pulls every city/town/village OSM knows inside the circle (per state, so
each carries its state), tiles the circle into ~24 km grid boxes, and queries every
tile — so businesses between towns are covered too. Tiles that time out on dense metro
cores split in four automatically. Region keys are states: `tn`, `va`, `wv`, `nc`,
`ky`, `sc`, `ga` (`--region tn,va` to limit). Every lead carries `mi` = miles from
Bristol; the board has distance-band chips (≤50 / 50–100 / 100–150 / 150–200) for
day-trip planning. Center/radius/tile size live in [regions.mjs](regions.mjs).

Scan data (inventory, leads, audits, ratings, deep metrics, places) is **not committed**
— in CI it lives in the GitHub Actions cache (rolling `radar-data-*` key), which keeps
the public repo code-only and the lead database private. Locally it's just `out/`.

## What it does

1. **Enumerate** local businesses per town from OpenStreetMap (Overpass API — free, no
   key). Chains/franchises are filtered out (`brand` tag + a big name blocklist).
2. **Audit** each business website: down/parked domains, broken SSL, HTTP-only, not
   mobile-friendly, ancient copyright years, FrontPage/framesets/Flash, GoDaddy/Wix/Weebly
   builders, outdated WordPress, free Gmail/AOL business email, old server stacks, and
   **dated-design signals** (2000s-era font/center markup, pre-2010 doctypes, jQuery 1.x,
   Dreamweaver-era authoring tools, table-based layouts).
   **Double-check**: every site is tried as listed plus www/non-www × https/http — it only
   counts as down/broken if *all* variants fail; still-unreachable leads are marked
   `Verify` ("may have moved domains"). If a domain is simply wrong, paste the right one
   into the row's **Real website** field on the board — it overrides the scanned domain
   and gets re-audited every rescan.
3. **Filter**: every lead must have a **phone number** — businesses without one are
   dropped from the sheet (they still appear in `out/inventory.json` if you want them).
4. **Score** two ways — website need and IT need. IT-heavy verticals (healthcare, legal,
   accounting, finance, engineering, manufacturing, veterinary, real estate) get IT weight;
   broken/insecure/neglected tech adds more. The **Need** column says `Website`, `IT`, or
   `Both`; **Evidence** lists exactly why; **Confidence** is `High` or `Verify`.
4. **Output** to `out/leads.csv` (Excel/Sheets-ready), `out/leads.json`,
   `out/summary.json`, plus a full raw `out/inventory.json`.

## The live board + call tracking

**https://ignite-lead-radar.netlify.app** — its own Netlify project (`ignite-lead-radar`,
site id `565e77e6-a859-4b59-aa14-c268aa57071c`; completely separate from
ignitecybersolutions.com). The lead table is viewable by anyone with the link;
**tracking, schedule, and call prep are PIN-gated** (numeric PIN, entered once per
device). The PIN lives only in the `LEAD_BOARD_KEY` Netlify env var — recover it with
`npx netlify-cli env:get LEAD_BOARD_KEY --site 565e77e6-…`, rotate it with `env:set`
plus a redeploy.

- Click any row → the call-prep brief, a progress label (To call / No answer / Call back /
  Interested / Quoted / Won / Not interested / Bad number), call notes, and a
  **follow-up date** (with a "+1 week" shortcut); saves automatically. The **Due** chip
  filters to follow-ups dated today or earlier (overdue shows red on the row).
- **Finding leads at 200-mile scale**: region (state) chips, need chips, miles-from-Bristol
  bands, a **vertical dropdown**, a **town typeahead**, **sort modes** (priority / closest /
  hottest / newest since last scan), and 15/30/50 per page. Every filter combination is
  written to the URL hash, so a view like "Kingsport dentists ≤ 50 mi, Both" is a
  bookmark you can reopen or send. The schedule builder honors the same filters.
- **Next lead ›** opens the best untouched lead (respects the region/need chips,
  prefers High confidence) with its prep panel ready — dial, mark, repeat.
- **Backup** downloads all progress/notes as JSON; `rescan.cmd` also snapshots it to
  `out/backups/` before every rescan.
- **Still-in-business verification (open data, via Overture Maps)**: `enrich-overture.mjs`
  cross-checks every lead against Overture's Places theme (Meta + Microsoft + Foursquare +
  PinMeTo, monthly releases, no key, no quota). Its `operating_status` marks leads permanently
  or temporarily closed, `confidence` says how sure the record is, and websites / phones /
  emails backfill gaps. DuckDB reads the release's parquet straight from the public bucket
  with bounding-box pruning (`npm install --no-save duckdb`; the script skips itself without
  it). Runs every CI run; costs nothing when every lead was already checked against the
  current release. A live Google / Foursquare match refreshed in the last 45 days keeps its
  status; otherwise Overture's wins.
- **Still-in-business verification (live, via Foursquare)**: `enrich-fsq.mjs` checks
  every lead against Foursquare's free-tier places data (`FOURSQUARE_API_KEY` secret,
  no card needed) — `date_closed` present ⇒ permanently closed ⇒ removed from the
  board/CSV/checkups; matched leads show "Listed as operational (places data, record
  verified <date>)" in call prep; unmatched ones say "confirm when you call". Matching
  is anchored to each lead's own coordinates + name similarity across top-5 results.
- **Google ratings (dormant)**: Google billing was never activated ($30 prepay wall),
  so `enrich-ratings.mjs` self-skips. If billing ever goes live, the same
  `GOOGLE_PLACES_API_KEY` secret lights up ratings + Google's businessStatus, and
  Google data automatically overrides Foursquare's.
- **Monthly auto-rescan**: Windows Task Scheduler job "IgniteLeadRadar Rescan" runs
  [rescan.cmd](rescan.cmd) at 7 AM on the 1st (or next boot if the PC was off): backup →
  scan → deep audit → ratings → rebuild → deploy. After each rescan the board badges
  **new** leads, marks ones that got worse as **hotter**, and the header shows how many
  retired (fixed their site). Log: `out/rescan.log`. Remove with
  `schtasks /Delete /TN "IgniteLeadRadar Rescan"`.
- Progress filter chips + search also match notes; "Export CSV (with progress)" downloads
  the current view including your statuses and notes. `/leads.csv` is the raw scan.
- State lives in Netlify Blobs keyed by `business|town|state`, so **rescans and
  redeploys never touch your progress/notes** — new leads just show up as "To call".
- Architecture: static board (`site/public/`) + one open function
  (`site/functions/state.mjs`) behind `/api/state`. To re-add a passcode later, ask
  Claude to restore the auth check (a few lines in that function + an `env:set` +
  redeploy).

## Personalized audits + call prep

- **Prospect-facing checkup pages** — one per lead at `/a/<slug>.html` (unlisted,
  noindex, printable → Ctrl+P for a PDF to email). Co-branded Ignite/Ridge, letter grade,
  findings in plain English with "why it matters / the fix", vertical-specific intro, CTA.
  Contact info lives in the `CONTACT` block at the top of [build-audits.mjs](build-audits.mjs).
- **Call-prep panel (private)** — click any row on the unlocked board: scripted opener
  keyed to their worst finding, talking points, what to pitch (Ridge/Ignite/both), best
  call window + who answers by vertical, multi-location flag (same name in 2+ towns),
  and the checkup link with copy-to-send.
- **Deep audit pass** (`audit-deep.mjs`) enriches leads with passive public checks:
  TLS cert expiry/issuer, SPF/DMARC/MX records (email-spoofing exposure), SEO basics
  (title/description/H1), page weight, HSTS. No systems are probed — DNS + one page GET.

Full rebuild pipeline after a rescan:

```
node tools/lead-scanner/scan.mjs --pace 4000
node tools/lead-scanner/audit-deep.mjs
node tools/lead-scanner/enrich-overture.mjs   # needs: npm install --no-save duckdb
node tools/lead-scanner/build-audits.mjs
node tools/lead-scanner/build-board.mjs
cd tools/lead-scanner/site
npx netlify-cli deploy --prod --site 565e77e6-a859-4b59-aa14-c268aa57071c --no-build --dir public --functions functions
```

(the `--functions` flag is required — netlify.toml alone doesn't attach the function on
CLI deploys)

Other options:

- **Lead board artifact** — Claude also publishes `out/board.html` as a private
  claude.ai link. After a rescan, ask Claude to "rebuild and republish the lead board".
- **Google Sheet (live-connected)** — one-time 3-minute setup in
  [sheets-webhook.gs](sheets-webhook.gs) (paste into Apps Script, deploy as web app), then
  every scan run with `--webhook` appends new leads and skips ones already in the sheet, so
  your call-status notes survive rescans. Share the Sheet normally.
- **CSV import** — drag `out/leads.csv` into Google Sheets / Excel any time.

## Upgrade: Google Places mode

OSM's weakness: many rural businesses have no `website` tag even when a site exists, so
OSM "no website" rows are marked `Verify`. For a strong no-website signal:

1. Google Cloud Console → create project → enable **Places API (New)** → create an API key
   (billing account required; watch the per-SKU free tier, `websiteUri` lookups are a paid
   SKU past the monthly free quota).
2. `setx GOOGLE_PLACES_API_KEY "your-key"` (new terminal after), then:

```
node tools/lead-scanner/scan.mjs --google
```

## Etiquette / caveats

- Overpass is queried once per region with backoff; homepage fetches are one GET per
  domain, 10 concurrent, honest User-Agent. Don't hammer re-runs back-to-back.
- OSM data is community-maintained (ODbL) — coverage in rural Appalachia is decent but not
  complete, and `Verify` rows mean exactly that: confirm before pitching.
- This finds *signals*, not certainties. Always eyeball the site (Maps link is in each
  row) before a cold call.
