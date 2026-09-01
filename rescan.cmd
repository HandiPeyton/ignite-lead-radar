@echo off
rem Ignite Lead Radar — full monthly rescan + redeploy.
rem Safe to run by double-clicking any time. Logs to out\rescan.log.
setlocal
cd /d "%~dp0"
if not exist out mkdir out
if not exist out\backups mkdir out\backups

echo ==================================================== >> out\rescan.log
echo RESCAN START %date% %time% >> out\rescan.log

rem 0. Snapshot tracking state (progress + notes) before anything else
for /f %%a in ('powershell -NoProfile -Command "Get-Date -Format yyyyMMdd"') do set stamp=%%a
curl -s https://ignite-lead-radar.netlify.app/api/state -o "out\backups\state-%stamp%.json" >> out\rescan.log 2>&1
copy /Y "out\backups\state-%stamp%.json" "out\state-live.json" >nul

rem 1. Scan all six regions (OSM)
node scan.mjs --pace 4000 >> out\rescan.log 2>&1
if errorlevel 1 goto :fail

rem 2. Deep audit (TLS / SPF / DMARC / SEO)
node audit-deep.mjs >> out\rescan.log 2>&1

rem 3. Google ratings + Foursquare verification (each skips itself without its key)
node enrich-ratings.mjs >> out\rescan.log 2>&1
node enrich-fsq.mjs >> out\rescan.log 2>&1

rem 4. Build checkup pages + board
node build-audits.mjs >> out\rescan.log 2>&1
node build-board.mjs >> out\rescan.log 2>&1

rem 5. Deploy
cd site
call npx netlify-cli deploy --prod --site 565e77e6-a859-4b59-aa14-c268aa57071c --no-build --dir public --functions functions >> ..\out\rescan.log 2>&1
cd ..

echo RESCAN DONE %date% %time% >> out\rescan.log
exit /b 0

:fail
echo RESCAN FAILED at scan step %date% %time% >> out\rescan.log
exit /b 1
