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

export function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
