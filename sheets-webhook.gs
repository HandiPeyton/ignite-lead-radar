/**
 * Google Sheets webhook for the Ignite Cyber lead scanner.
 *
 * Setup (≈3 minutes, one time):
 *  1. Go to sheets.new and name the spreadsheet (e.g. "Ignite Lead Radar").
 *  2. Extensions → Apps Script. Delete the sample code, paste this whole file.
 *  3. Deploy → New deployment → type "Web app".
 *       - Execute as: Me
 *       - Who has access: Anyone with the link
 *  4. Authorize when prompted, then copy the Web app URL.
 *  5. Run the scanner with it:
 *       node tools/lead-scanner/scan.mjs --webhook "https://script.google.com/macros/s/.../exec"
 *     (or set SHEET_WEBHOOK as an environment variable)
 *
 * Rows are de-duplicated by Business+Town, so re-running the scanner only
 * appends NEW leads — your Status/notes columns on existing rows are safe.
 * Share the spreadsheet itself with the normal Google Sheets Share button.
 */
function doPost(e) {
  var body = JSON.parse(e.postData.contents);
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('Leads') || ss.insertSheet('Leads');

  if (sheet.getLastRow() === 0) {
    sheet.appendRow(['Key'].concat(body.header));
    sheet.setFrozenRows(1);
    sheet.hideColumns(1); // Key column is internal
  }

  // Existing keys (col A) for dedupe
  var existing = {};
  if (sheet.getLastRow() > 1) {
    var keys = sheet.getRange(2, 1, sheet.getLastRow() - 1, 1).getValues();
    for (var i = 0; i < keys.length; i++) existing[keys[i][0]] = true;
  }

  // header: [Region, Town, State, Business, ...] → key from Business+Town+State
  var added = 0;
  var newRows = [];
  for (var r = 0; r < body.rows.length; r++) {
    var row = body.rows[r];
    var key = (String(row[3]) + '|' + String(row[1]) + '|' + String(row[2])).toLowerCase();
    if (existing[key]) continue;
    existing[key] = true;
    newRows.push([key].concat(row));
    added++;
  }
  if (newRows.length) {
    sheet.getRange(sheet.getLastRow() + 1, 1, newRows.length, newRows[0].length).setValues(newRows);
  }

  return ContentService
    .createTextOutput(JSON.stringify({ ok: true, added: added, skippedExisting: body.rows.length - added }))
    .setMimeType(ContentService.MimeType.JSON);
}
