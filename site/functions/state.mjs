// Lead-tracking state API for the Ignite Lead Radar board.
// Storage: Netlify Blobs, one JSON doc keyed by lead ("name|town|st" lowercase).
// Open by design (Peyton's call): anyone with the board link can read/edit
// tracking — the unlisted URL is the only gate.
// Note: reads/writes are last-write-wins on the whole doc — fine for a one/two
// person call workflow; not built for heavy concurrent editing.
import { getStore } from '@netlify/blobs';

const STATUSES = new Set(['new', 'noanswer', 'callback', 'interested', 'quoted', 'won', 'lost', 'bad']);

export default async (req) => {
  // strong consistency: the doc is read-modify-write on every save, so a stale
  // read here would silently drop a recent save.
  const store = getStore({ name: 'lead-state', consistency: 'strong' });

  if (req.method === 'GET') {
    const data = (await store.get('all', { type: 'json' })) || {};
    return Response.json(data);
  }

  if (req.method === 'POST') {
    let body;
    try { body = await req.json(); } catch { body = null; }
    if (!body || typeof body.key !== 'string' || !body.key || body.key.length > 300) {
      return Response.json({ error: 'bad request' }, { status: 400 });
    }
    const data = (await store.get('all', { type: 'json' })) || {};
    const cur = data[body.key] || {};
    const next = {
      s: STATUSES.has(body.s) ? body.s : (cur.s || 'new'),
      n: typeof body.n === 'string' ? body.n.slice(0, 8000) : (cur.n || ''),
      d: typeof body.d === 'string' && /^(\d{4}-\d{2}-\d{2})?$/.test(body.d) ? body.d : (cur.d || ''),
      w: typeof body.w === 'string' && /^(https?:\/\/\S{4,300})?$/.test(body.w) ? body.w : (cur.w || ''),
      t: Date.now(),
    };
    data[body.key] = next;
    await store.setJSON('all', data);
    return Response.json({ ok: true, t: next.t });
  }

  return new Response('Method not allowed', { status: 405 });
};

export const config = { path: '/api/state' };
