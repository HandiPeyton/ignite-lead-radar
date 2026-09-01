// Serves weekly homepage screenshots from Netlify Blobs (store "shots")
// at /shot/<slug>.jpg for the checkup pages.
import { getStore } from '@netlify/blobs';

export default async (req) => {
  const slug = new URL(req.url).pathname.split('/').pop().replace(/\.jpg$/i, '');
  if (!/^[a-z0-9-]{3,90}$/.test(slug)) return new Response('bad request', { status: 400 });
  const store = getStore('shots');
  const buf = await store.get(slug, { type: 'arrayBuffer' });
  if (!buf) return new Response('not found', { status: 404 });
  return new Response(buf, {
    headers: {
      'Content-Type': 'image/jpeg',
      'Cache-Control': 'public, max-age=43200',
    },
  });
};

export const config = { path: '/shot/*' };
