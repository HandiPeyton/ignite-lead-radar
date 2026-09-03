// Shared helpers for the lead scanner build scripts.

export function djb2(str) {
  let h = 5381;
  for (let i = 0; i < str.length; i++) h = ((h << 5) + h + str.charCodeAt(i)) >>> 0;
  return h.toString(16).slice(0, 4);
}

export const keyOf = (l) => (l.name + '|' + l.town + '|' + l.st).toLowerCase();

// Stable, unguessable-enough slug for a lead's audit page.
export function slugOf(l) {
  const base = (l.name + '-' + l.town).toLowerCase()
    .replace(/&/g, ' and ').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60);
  return base + '-' + djb2(keyOf(l));
}

export function hostnameOf(url) {
  try { return new URL(url).hostname.replace(/^www\./, ''); } catch { return null; }
}

export const SOCIAL_RE = /facebook\.com|fb\.com|instagram\.com|linktr\.ee|m\.me\//i;

// Directory, review, ordering and aggregator pages that places data (Overture / Foursquare /
// Google) sometimes lists as a business's "website". Auditing one of these would grade a
// third party's page as if it were the prospect's own site.
export const DIRECTORY_RE = /(^|\/\/|\.)(yelp|mapquest|yellowpages|yp|superpages|bbb|angi|angieslist|homeadvisor|thumbtack|houzz|porch|manta|merchantcircle|alignable|nextdoor|tripadvisor|foursquare|doordash|grubhub|ubereats|seamless|toasttab|clover|square|opentable|resy|zomato|allmenus|menupages|restaurantji|healthgrades|zocdoc|vitals|webmd|findlaw|avvo|lawyers|justia|realtor|zillow|apartments|booking|expedia|hotels|airbnb|vrbo|groupon|indeed|glassdoor|bizapedia|dnb|zoominfo|cylex|hotfrog|chamberofcommerce|nicelocal|birdeye|google|goo|bing|apple|amazon|etsy|ebay|linkedin|youtube|tiktok|twitter|x|pinterest|yellowbook|citysearch|local|cityfos|dexknows|elocal|showmelocal|ezlocal|brownbook|hubbiz|us-business|wheree)\.(com|net|org|co|gl|io|site|biz)\b/i;

export function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
