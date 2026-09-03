// Fires the FULL scan at an exact time, because GitHub's own cron can run hours late
// under load while a workflow_dispatch through the API starts within seconds.
//
// Schedule is UTC: '0 6 3 9 *' = Sept 3, 06:00 UTC = 2:00 AM Eastern (daylight time).
// Needs GH_DISPATCH_TOKEN in the site's env vars: a fine-grained GitHub token for
// HandiPeyton/ignite-lead-radar with "Actions: Read and write". Without it the
// function logs and does nothing; the workflow's own cron remains the fallback.
// Remove this file (or change the schedule) once the one-off run has happened.

const REPO = 'HandiPeyton/ignite-lead-radar';
const WORKFLOW = 'rescan.yml';

export default async () => {
  const token = process.env.GH_DISPATCH_TOKEN;
  if (!token) {
    console.log('dispatch-full-scan: GH_DISPATCH_TOKEN not set — skipping (GitHub cron is the fallback).');
    return new Response('no token', { status: 200 });
  }
  const res = await fetch(`https://api.github.com/repos/${REPO}/actions/workflows/${WORKFLOW}/dispatches`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'Content-Type': 'application/json',
      'User-Agent': 'ignite-lead-radar-scheduler',
    },
    body: JSON.stringify({ ref: 'main', inputs: { mode: 'full' } }),
  });
  const text = await res.text();
  console.log(`dispatch-full-scan: GitHub responded ${res.status} ${text.slice(0, 200)}`);
  return new Response(res.status === 204 ? 'dispatched' : `github ${res.status}`, { status: 200 });
};

export const config = { schedule: '0 6 3 9 *' };
