#!/usr/bin/env node
/**
 * Generates a personalized, printable audit page per lead:
 *   site/public/a/<slug>.html
 * from out/leads.json (scan findings) + out/audits.json (deep pass).
 * Pages are unlisted (unguessable slug), public, prospect-safe: every claim
 * comes from the scan evidence, and only public information is referenced.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { slugOf, hostnameOf, SOCIAL_RE, escapeHtml as esc } from './lib.mjs';

const dir = path.dirname(fileURLToPath(import.meta.url));
const out = path.join(dir, 'out');
const CUR_YEAR = new Date().getFullYear();

// ---- EDIT ME: contact + brand block used on every audit page ----
const CONTACT = {
  brands: 'Ignite Cyber Solutions · Ridge Web Designs',
  tagline: 'One local team — Tri-Cities, TN/VA',
  phone: '(423) 863-9727',
  email: 'info@ridgewebdesigns.com',
  sites: ['ignitecybersolutions.com', 'ridgewebdesigns.com'],
};

const VERTICAL_ANGLE = {
  healthcare: 'Patients check a practice online before they ever call — and healthcare businesses handle data that attackers actively target.',
  veterinary: 'Pet owners pick a vet the same way they pick a restaurant now: they look online first.',
  legal: 'Clients research a firm before calling, and confidentiality makes a firm’s technology posture part of its reputation.',
  accounting: 'You handle the most sensitive financial data a family or business has — trust starts with how you show up online.',
  finance: 'Financial clients expect the basics to be airtight: a secure site and email that can’t be impersonated.',
  engineering: 'Commercial clients vet vendors online before they shortlist — the website is part of the bid.',
  manufacturing: 'Buyers and suppliers check you out online before they call — and manufacturers are now a top ransomware target.',
  realestate: 'Listings and leads live online; a dated or insecure site sends buyers to the next agent.',
  trades: 'Most service calls start with a phone search — the business that looks alive online gets the call.',
  construction: 'GCs and homeowners both check you out online before asking for a bid.',
  auto: 'Drivers search, read, and call — usually from a phone, usually the same day.',
  hospitality: 'Guests book with whoever looks trustworthy on a phone screen.',
  fitness: 'New members size up a gym online before they ever walk in.',
  food: 'Diners decide from a phone: hours, menu, photos — in about eight seconds.',
  retail: 'Shoppers check hours and stock online before they drive over.',
  professional: 'For a service business, the website is the first handshake.',
  other: 'For a local business, the website is the first handshake.',
};

// ---------- findings ----------
function buildFindings(l, deep, ds) {
  const F = [];
  const add = (sev, title, found, why, fix) => F.push({ sev, title, found, why, fix });
  const a = l.audit || {};
  const host = l.website ? hostnameOf(l.website) : null;

  if (!l.website) {
    add('crit', 'We couldn’t find a website for your business',
      `Searching public listings for ${l.name} in ${l.town} turned up a phone number but no website.`,
      'Most customers now check a business online before calling. With no site, those searches end at a competitor who has one.',
      'A simple, professional site — even a few pages — puts you back in those searches. Ridge Web Designs builds custom sites from $500.');
    return F;
  }
  if (SOCIAL_RE.test(l.website)) {
    add('crit', 'A Facebook page is standing in for a website',
      'Your only web presence we could find is a social media page.',
      'Facebook pages rank poorly in search, hide your info behind a login for many visitors, and you don’t control them — a policy change or lockout can erase your presence overnight.',
      'A real website you own, with your Facebook feeding it — not replacing it.');
    return F;
  }

  // Availability / security (from scan)
  if (a.status === 'down') {
    add('crit', 'The website listed for your business is unreachable',
      `Public listings point to ${host}, which didn’t respond on any variant we tried (www/non-www, secure and not).`,
      'If that’s your current site, every search leads to a dead end — which reads as "closed" to a new customer. If you’ve moved to a new site, the old address is still what many directories are sending people to.',
      'Get the current site back up (or the old domain forwarding to the new one) and correct the listings — usually quick work.');
  } else if (a.status === 'parked') {
    add('crit', 'Your domain is parked — the website is gone',
      `${host} currently shows a placeholder/parking page.`,
      'Customers who look you up see an abandoned domain, and the domain itself may be at risk of lapsing to someone else.',
      'Recover the domain and stand up a real site on it.');
  } else if (a.status === 'ssl-error') {
    const expired = deep?.certDaysLeft != null && deep.certDaysLeft < 0;
    add('crit', 'Your site’s security certificate is broken',
      expired
        ? `The SSL certificate for ${host} expired ${deep.certValidTo}.`
        : `Browsers can’t verify ${host}’s SSL certificate — it appears misconfigured or issued for a different domain.`,
      'Visitors get a full-screen "Not secure / your connection is not private" warning — most leave immediately.',
      'Replace the certificate and set it to auto-renew so this never recurs.');
  } else if (a.status === 'http-only') {
    add('imp', 'No HTTPS — the site runs unencrypted',
      `${host} serves over plain HTTP.`,
      'Browsers label the site "Not secure" in the address bar, and Google ranks unencrypted sites lower.',
      'Install a free certificate and redirect all traffic to HTTPS.');
  }
  if (deep && !deep.platform && deep.certDaysLeft != null && deep.certDaysLeft >= 0 && deep.certDaysLeft < 30 && a.status !== 'ssl-error') {
    add('imp', 'Security certificate about to expire',
      `The certificate for ${host} expires ${deep.certValidTo} (${deep.certDaysLeft} days).`,
      'When it lapses, every visitor sees a security warning instead of your site.',
      'Renew now and switch to auto-renewal.');
  }

  // Email spoofing (deep DNS)
  if (deep && !deep.platform && (deep.spf === false || deep.dmarc === false)) {
    const missing = [deep.spf === false ? 'SPF' : null, deep.dmarc === false ? 'DMARC' : null].filter(Boolean).join(' and ');
    add('imp', 'Your email domain can be impersonated',
      `${apex(host)} is missing ${missing} — the DNS records that stop forged email.`,
      'Scammers can send mail that looks like it’s from your business — a common setup for invoice fraud against your customers.',
      'Publish SPF and DMARC records: an hour of IT work that closes the door on spoofing.');
  }
  // Email policy quality (deep DNS). Only asserted on records that were actually
  // read; never duplicates the "can be impersonated" card above.
  if (deep && !deep.platform && deep.spf !== false && deep.dmarc !== false) {
    if (deep.dmarcPolicy === 'none') {
      const pct = typeof deep.dmarcPct === 'number' && deep.dmarcPct < 100 ? ` (and applies to only ${deep.dmarcPct}% of mail)` : '';
      add('rec', 'Your email policy is set to monitor only',
        `The DMARC record for ${apex(host)} is published with p=none${pct} — it asks receiving mail servers to report forged mail, not to block it.`,
        'Monitor mode is the right first step, but on its own it doesn’t stop anyone from sending mail as your domain — the record only watches.',
        'Once the reports look clean, move the policy to quarantine and then reject — a two-line DNS change, done in stages.');
    }
    if (deep.spfAll === '+all') {
      add('imp', 'Your SPF record allows anyone',
        `The SPF record for ${apex(host)} ends in "+all", which authorizes every mail server on the internet to send as your domain.`,
        'The record exists but does no filtering — forged mail from your domain passes the SPF check just like the real thing.',
        'Change the final qualifier to "~all" (softfail) or "-all" (fail) once your legitimate senders are listed — a one-word DNS edit.');
    } else if (deep.spfAll === '?all') {
      add('imp', 'Your SPF record doesn’t restrict senders',
        `The SPF record for ${apex(host)} ends in "?all" (neutral) — it makes no statement about unlisted senders, so forged mail gets the same result as if there were no SPF record at all.`,
        'The record exists but does no filtering — forged mail from your domain passes the SPF check just like the real thing.',
        'Change the final qualifier to "~all" (softfail) or "-all" (fail) once your legitimate senders are listed — a one-word DNS edit.');
    }
    if (typeof deep.spfLookups === 'number' && deep.spfLookups > 10) {
      add('imp', 'Your SPF record exceeds the 10-lookup limit',
        `Evaluating the SPF record for ${apex(host)} requires ${deep.spfLookups} DNS lookups; the SPF standard caps it at 10, past which receiving servers return a permanent error.`,
        'When the check errors, legitimate mail from your business can be rejected or sent to spam — and it happens silently, at the receiving end.',
        'Trim unused "include:" entries or flatten the record so it evaluates in 10 lookups or fewer.');
    }
  }
  // Self-hosted mail plus published remote-access hostnames: a legitimate setup that
  // simply deserves a scheduled review. Stated as fact, never as a vulnerability.
  if (deep && !deep.platform && deep.selfHostedMail === true && Array.isArray(deep.dnsHosts)) {
    const REMOTE = ['remote', 'rdp', 'vpn', 'owa', 'exchange', 'citrix'];
    const ra = deep.dnsHosts.filter((h) => REMOTE.includes(h));
    if (ra.length) {
      add('rec', 'Self-hosted email and remote access',
        `Mail for ${apex(host)} is delivered to a server on your own domain, and public DNS also lists remote-access names for it (${ra.map((h) => h + '.' + apex(host)).join(', ')}).`,
        'Running your own mail and remote access is a perfectly normal setup — it just means the patching, backups, and monitoring are on your side of the fence, and those are worth a security review on a schedule.',
        'A short review of the update, backup, and remote-access configuration — no changes assumed, just a second set of eyes.');
    }
  }

  // Mobile / freshness / tech (scan)
  if (a.status === 'ok' && a.viewport === false) {
    add('imp', 'Not built for phones',
      'The site is missing mobile-responsive setup, so phones show a shrunken desktop page.',
      'More than half of local searches happen on a phone; pinch-and-zoom sites lose those visitors.',
      'A responsive rebuild — modern sites adapt to every screen automatically.');
  }
  if (a.year && a.year <= CUR_YEAR - 3) {
    add('imp', `The site says © ${a.year}`,
      `The newest copyright date we found is ${a.year}.`,
      `To a visitor (and to Google), the site looks ${CUR_YEAR - a.year} years abandoned — fresh content is a ranking factor.`,
      'Update the site — or better, move to one that’s easy to keep current.');
  }
  for (const f of a.flags || []) {
    if (/FrontPage|frameset|Flash/i.test(f)) {
      add('imp', 'Built on 1990s-era technology',
        `The site uses ${f.replace(/ \(.*\)/, '')}.`,
        'This generation of sites renders poorly or not at all in modern browsers and phones, and can’t be secured.',
        'A ground-up rebuild — there’s no patching technology this old.');
    } else if (/WordPress/i.test(f)) {
      add('imp', 'Outdated WordPress',
        `The site reports ${f.replace(' (outdated)', '')} — years behind current.`,
        'Old WordPress versions are the single most-hacked thing on the small-business web; known exploits are automated.',
        'Update core/plugins or migrate — plus ongoing patching so it stays safe.');
    } else if (/GoDaddy|Wix|Weebly/i.test(f)) {
      add('rec', 'Running on a generic site builder',
        `The site appears to be built with ${f.replace(' builder', '').replace(' site builder', '')}’s template builder.`,
        'Builder sites look like everyone else’s, load slowly, and rank behind custom-built competitors.',
        'A custom site you own outright — no monthly builder lock-in.');
    } else if (/2000s-era HTML/.test(f)) {
      add('imp', 'The site is built with 2000s-era code',
        'The page uses legacy markup (font/center-tag styling) from the pre-smartphone web.',
        'Sites of this generation look two decades old next to competitors, and search engines treat them accordingly.',
        'A modern rebuild — this code predates responsive design entirely.');
    } else if (/Pre-2010 page framework/.test(f)) {
      add('imp', 'Pre-2010 page framework',
        'The site declares an XHTML/HTML4 doctype — a standard from before 2010.',
        'It still renders, but it marks the site as untouched for a decade-plus, and modern features can’t be added cleanly.',
        'Rebuild on today’s standards.');
    } else if (/Ancient jQuery/.test(f)) {
      add('rec', 'Very old code libraries',
        'The site loads a jQuery 1.x library from the early 2010s.',
        'Old libraries carry known security issues and break with modern browser features.',
        'Update the stack as part of a refresh.');
    } else if (/authoring tool/.test(f)) {
      add('imp', 'Exported from a 2000s design tool',
        'The page was generated by a desktop authoring tool of the Dreamweaver/GoLive era.',
        'Pages exported this way can’t be maintained or made mobile-friendly — every change fights the tool’s generated code.',
        'A ground-up rebuild.');
    } else if (/Table-based/.test(f)) {
      add('imp', 'Dated, table-based page design',
        'The page is laid out with HTML tables — the way sites were built before about 2008.',
        'It looks visibly dated on modern screens and behaves poorly on phones.',
        'A modern responsive layout.');
    }
  }
  if (a.freeEmail) {
    add('rec', 'Free personal email as the business address',
      `The site lists ${a.freeEmail}.`,
      `An @${apex(host)} address looks professional and keeps the account under the business’s control if staff change.`,
      'Set up branded email on your own domain — typically an afternoon.');
  }
  if (a.oldServer) {
    add('imp', 'Outdated server software',
      `The web server reports: ${a.oldServer}.`,
      'Software this old has published vulnerabilities and usually means nobody is maintaining the hosting.',
      'Move to maintained, updated hosting.');
  }

  // Domain / neglect / contact-path (deep, cached weekly)
  const expDays = deep?.exp && Number.isFinite(Date.parse(deep.exp))
    ? Math.round((Date.parse(deep.exp) - Date.now()) / 86400000) : null;
  const expNote = deep?.exp ? ` The registry’s expiration date for it is ${deep.exp}.` : '';
  // The lapsed/hold statuses are cached for days while `ok` is refreshed every run, so a
  // site that loaded overrides a stale flag: the crit cards fire only when the site is
  // down too. A past expiration date with a normal status is inconclusive — no card.
  if (deep && !deep.platform) {
    if (deep.domLapsed && !deep.ok) {
      const pending = deep.domLapsed === 'pendingdelete';
      add('crit', 'Your domain registration has lapsed',
        `The domain registry lists ${apex(host)} with the status "${pending ? 'pending delete' : 'redemption period'}".${expNote}`,
        pending
          ? 'Pending delete means the name is about to be released back to the public — once it drops, anyone can buy it, and your website and email addresses go with it.'
          : 'In the redemption period the name can still be recovered, but only through the registrar and usually for a fee. When that window closes the name is released and anyone can buy it.',
        'Contact your registrar immediately and ask to restore the domain — every day matters here. Then turn on auto-renew so it can’t happen again.');
    } else if (deep.domHold && !deep.ok) {
      add('crit', 'Your domain has been put on hold by the registrar',
        `The domain registry lists ${apex(host)} with a hold status — the name is suspended and doesn’t resolve.${expNote}`,
        'While a domain is on hold, the website and any email on it are dark for everyone. Holds usually come from a missed renewal, an unverified contact email, or a dispute.',
        'Contact your registrar today to find out why the hold was placed and what they need to lift it — often it’s a verification email nobody saw.');
    } else if (deep.domGrace) {
      add('rec', 'The registry shows your domain in its auto-renew grace status',
        `The domain registry lists ${apex(host)} with the status autoRenewPeriod, which appears once the expiration date passes — it can remain for weeks even after a registrar has already renewed.`,
        'If the renewal did not go through, the grace window is short, and when it closes the name moves toward deletion — taking the website and email with it.',
        'Confirm with your registrar that the renewal went through, and turn on auto-renew.');
    } else if (expDays !== null && expDays >= 0 && expDays < 45) {
      add('crit', 'Your domain registration expires very soon',
        `${apex(host)} is registered only through ${deep.exp} — ${expDays} days from now.`,
        'If it lapses, the website and any email on the domain go dark at once, and expired domains get snapped up by squatters within days.',
        'Renew now and turn on auto-renew — five minutes that prevents a very bad week.');
    }
  }
  // Broken internal links (deep pass; only HTTP 404/410 count as broken)
  const bl = deep?.brokenLinks;
  if (bl && typeof bl.broken === 'number' && typeof bl.checked === 'number' && bl.broken >= 2) {
    const pathOf = (s) => { try { const u = new URL(s); return u.pathname + u.search; } catch { return String(s); } };
    const samples = (Array.isArray(bl.sample) ? bl.sample : []).map(pathOf).filter((s) => s.startsWith('/')).slice(0, 2);
    add(bl.broken >= 5 ? 'imp' : 'rec', `${bl.broken} of your homepage’s links go to missing pages`,
      `We followed ${bl.checked} links from your homepage to pages on your own site; ${bl.broken} of them returned "page not found"${samples.length ? ` — for example ${samples.join(' and ')}` : ''}.`,
      'Every broken link is a visitor who gave up at the exact moment they wanted more — and search engines read dead links as a site nobody is maintaining.',
      'Fix or remove the dead links and set up redirects for any pages that moved — usually an hour of cleanup.');
  }
  if (deep?.wbSince) {
    add('imp', 'The site hasn’t changed in years',
      `The Internet Archive shows this homepage byte-for-byte identical since ${deep.wbSince}.`,
      'Customers and search engines both read a frozen site as an inactive business.',
      'A refresh with a site that’s easy to keep current.');
  }
  if (deep?.cFound && deep.cForm === false && deep.cMailto === false) {
    add('imp', 'The contact page can’t take a message',
      'Your contact page has no working form and no email link.',
      'Customers who want to reach you hit a dead end at the exact moment they’ve decided to get in touch.',
      'A working contact form (with spam protection) wired to your business email.');
  }
  if (deep?.ok && deep.localSchema === false) {
    add('rec', 'Missing local-business markup',
      'The site has no LocalBusiness structured data.',
      'This markup is how Google connects your site to your map listing, hours, and reviews — without it you’re easier to overlook in local search.',
      'Add schema markup — an hour of work.');
  }
  if (deep?.ok && deep.smOk === false) {
    add('rec', 'No sitemap for search engines',
      'The site has no sitemap.xml.',
      'A sitemap tells search engines what to index; small sites without one get crawled less and rank slower.',
      'Generate one — trivial on any modern platform.');
  }

  // Rendered performance (Sunday deep scan — real numbers from our own browser)
  if (ds) {
    if (ds.loadMs >= 5000) {
      add('imp', `Your website takes ${(ds.loadMs / 1000).toFixed(1)} seconds to load`,
        `We loaded your homepage in a real browser and timed it at ${(ds.loadMs / 1000).toFixed(1)} seconds${ds.weightKB >= 4000 ? `, pulling ${(ds.weightKB / 1024).toFixed(1)} MB` : ''}.`,
        'Studies put the drop-off at about half of visitors once a page passes 3 seconds — most of them leave before they ever see you.',
        'Optimize images and hosting, or rebuild lean — a local site should open in under two seconds.');
    }
    if (ds.mobileOverflow) {
      add('imp', 'Your site is visibly broken on phones',
        `Rendered on a real phone screen, your content runs about ${ds.overflowPx} pixels off the edge — visitors have to scroll sideways to read it.`,
        'Over half of local searches are on a phone; a site that spills off the screen reads as broken and they bounce.',
        'A responsive rebuild that fits every screen automatically.');
    }
    if (ds.imgKB >= 3500 && ds.loadMs < 5000) {
      add('rec', 'Oversized images are slowing you down',
        `Your homepage loads ${(ds.imgKB / 1024).toFixed(1)} MB of images across ${ds.imgCount} files.`,
        'Unoptimized photos are the most common cause of slow local sites, especially on cell connections.',
        'Compress and right-size images — often cuts load time in half with no visible quality loss.');
    }
    // Core Web Vitals from the same render. LCP only when the load-time card above
    // didn’t already fire, so the page never carries two speed cards.
    if (typeof ds.lcpMs === 'number' && ds.lcpMs > 4000 && !(ds.loadMs >= 5000)) {
      add('imp', `Your main content takes ${(ds.lcpMs / 1000).toFixed(1)} seconds to appear`,
        `Measured in a real browser, the largest visible element on your homepage appeared after ${(ds.lcpMs / 1000).toFixed(1)} seconds (Largest Contentful Paint). Google’s "poor" threshold is 4 seconds.`,
        'This is one of the Core Web Vitals Google uses in ranking, and it’s the moment a visitor decides whether the page is working at all.',
        'Optimize the hero image and hosting, or rebuild lean — the main content should appear inside 2.5 seconds.');
    }
    if (typeof ds.cls === 'number' && ds.cls > 0.25) {
      add('rec', 'The page jumps around while loading',
        `We measured a cumulative layout shift of ${ds.cls.toFixed(2)} on your homepage — Google’s "poor" threshold is 0.25.`,
        'Content that moves as it loads makes visitors mis-tap links and buttons, and it’s a Core Web Vitals ranking signal.',
        'Reserve space for images, ads, and embeds so nothing shifts after it appears — a straightforward fix.');
    }
    if (typeof ds.imgNoAlt === 'number' && typeof ds.imgTotal === 'number' && ds.imgTotal > 0
        && ds.imgNoAlt >= 5 && ds.imgNoAlt / ds.imgTotal >= 0.3) {
      add('rec', 'Images have no text alternatives',
        `${ds.imgNoAlt} of the ${ds.imgTotal} images on your homepage have no alt attribute at all.`,
        'Screen readers can’t describe those images and search engines can’t read them — it’s the kind of gap accessibility complaints cite, and it costs image-search visibility too.',
        'Add a short description to each meaningful image and mark decorative ones as such — a quick pass through the page.');
    }
    if (typeof ds.inputsNoLabel === 'number' && ds.inputsNoLabel >= 2) {
      add('rec', 'Form fields are missing labels',
        `${ds.inputsNoLabel} form field${ds.inputsNoLabel === 1 ? '' : 's'} on your homepage ${ds.inputsNoLabel === 1 ? 'has' : 'have'} no label a screen reader or browser can announce.`,
        'Unlabeled fields are hard to fill out with assistive technology and on phones with autofill — another gap accessibility complaints commonly cite.',
        'Attach a visible label (or an accessible name) to every field — minutes per form.');
    }
  }
  if (deep?.analytics === false && deep?.ok) {
    add('rec', 'You have no way to see who visits',
      'The site has no analytics installed (no Google Analytics, Tag Manager, or pixel).',
      'You’re flying blind — no idea how many people find you, what they look at, or where they drop off.',
      'Install analytics so every marketing dollar can be measured.');
  }

  // SEO basics (deep)
  if (deep?.ok) {
    if (!deep.title || deep.title.length < 8) {
      add('rec', 'Missing or weak page title',
        'The homepage title tag is empty or minimal.',
        'The title is the blue headline in Google results — without it you’re invisible for "near me" searches.',
        `Set a real title like "${l.name} — ${l.town}, ${l.st}".`);
    }
    if (deep.desc === false) {
      add('rec', 'No search description',
        'The homepage has no meta description.',
        'Google fills the gap with random page text — you lose control of your own first impression in results.',
        'Write a one-sentence description that sells the business.');
    }
    if (deep.h1 === false) {
      add('rec', 'No main heading on the homepage',
        'The page has no H1 heading.',
        'Search engines use the main heading to understand what the business does and where.',
        'Add one clear heading naming the service and the area.');
    }
    if ((deep.scripts || 0) > 25 || (deep.imgs || 0) > 45) {
      add('rec', 'Heavy homepage',
        `The homepage loads ${deep.scripts || 0} scripts and ${deep.imgs || 0} images.`,
        'Every extra second of load time costs visitors — especially on rural cell coverage.',
        'Slim the page down; local sites should load in under two seconds.');
    }
    if (deep.finalHttps && deep.hsts === false && a.status === 'ok') {
      add('rec', 'Missing modern security headers',
        'The site doesn’t enforce strict transport security (HSTS).',
        'A small hardening gap — easy for an attacker to exploit on public Wi-Fi.',
        'A one-line server configuration fix.');
    }
  }
  return F;
}
const apex = (h) => { const p = (h || '').split('.'); return p.length <= 2 ? h : p.slice(-2).join('.'); };

// ---------- grade ----------
// Score as before; then coherence caps so the letter can never contradict the cards:
// a Critical caps at C, an Important caps at B, recommendations alone never drop below B.
function grade(F) {
  let score = 100;
  for (const f of F) score -= f.sev === 'crit' ? 30 : f.sev === 'imp' ? 10 : 0;
  score -= Math.min(12, 4 * F.filter((f) => f.sev === 'rec').length); // recs are tune-ups: capped
  score = Math.max(5, score);
  let letter = score >= 90 ? 'A' : score >= 78 ? 'B' : score >= 64 ? 'C' : score >= 50 ? 'D' : 'F';
  const order = ['A', 'B', 'C', 'D', 'F'];
  const cap = (max) => { if (order.indexOf(letter) < order.indexOf(max)) letter = max; };
  if (F.some((f) => f.sev === 'crit')) cap('C');
  else if (F.some((f) => f.sev === 'imp')) cap('B');
  return { score, letter };
}
const GRADE_MEANING = {
  A: 'Solid. A few tune-ups at most.',
  B: 'Good bones, with something worth fixing.',
  C: 'Working, but with a problem customers can run into.',
  D: 'Costing you customers today.',
  F: 'Broken in a way customers see first.',
};

// ---------- page ----------
const SEV_LABEL = { crit: 'Critical', imp: 'Important', rec: 'Recommended' };

// "How to check this yourself" — only for findings a business owner can confirm safely on
// their own; the instruction must match what the card claims.
function verifyHint(f, host) {
  const t = f.title, a = apex(host || '');
  if (/unreachable/i.test(t)) return 'Open your website on your phone right now.';
  if (/parked/i.test(t)) return 'Type your web address into a phone browser and see what appears.';
  if (/certificate/i.test(t)) return 'Open the site in a browser and look at the padlock in the address bar.';
  if (/No HTTPS/i.test(t)) return 'Look at your address bar: it should read https:// with a padlock.';
  if (/impersonated|monitor only|SPF record/i.test(t)) return `Search “${a} SPF record lookup” — any free DNS checker shows the same records.`;
  if (/says ©/.test(t)) return 'Scroll to the bottom of your homepage and read the year.';
  if (/Not built for phones|broken on phones|jumps around/i.test(t)) return 'Open the homepage on a phone.';
  if (/takes .* seconds|main content takes/i.test(t)) return 'Load the homepage on a phone using cellular data, not Wi-Fi.';
  if (/links go to missing pages/i.test(t)) return 'Click the paths listed above from your homepage.';
  if (/registration has lapsed|on hold|auto-renew grace|registration expires/i.test(t)) return `Search “whois ${a}” and read the status and expiration lines.`;
  return '';
}

// Rough effort for the plan — words, not prices.
function effortOf(f) {
  const t = f.title;
  if (/couldn’t find a website|Facebook page|parked|1990s|2000s|Table-based|Pre-2010|authoring tool|site builder|Not built for phones|broken on phones/i.test(t)) return 'a small project';
  if (/unreachable|takes .* seconds|main content takes/i.test(t)) return 'a day';
  if (/says ©/.test(t)) return 'an hour';
  return 'an afternoon';
}

// Checks that PASSED, each provable from a field we hold. Never inferred.
function passes(l, deep, ds) {
  const a = l.audit || {};
  const out = [];
  if (a.status === 'ok' && ((a.finalUrl || '').startsWith('https://') || deep?.finalHttps)) out.push('Loads over HTTPS');
  if (a.status === 'ok' && a.viewport === true) out.push('Set up for phones (mobile viewport present)');
  if (deep?.spf === true && deep?.dmarc === true) {
    out.push(deep.dmarcPolicy === 'reject' || deep.dmarcPolicy === 'quarantine'
      ? 'Email protection records (SPF and DMARC) published and enforcing'
      : 'Email protection records (SPF and DMARC) published');
  }
  if (Array.isArray(deep?.dkim) && deep.dkim.length) out.push('Email signing (DKIM) found');
  if (deep?.mtaSts === true) out.push('Mail transport security (MTA-STS) in place');
  if (typeof deep?.certDaysLeft === 'number' && deep.certDaysLeft > 30) out.push(`Security certificate valid for ${deep.certDaysLeft} more days`);
  if (deep?.exp && Number.isFinite(Date.parse(deep.exp))) {
    const days = Math.round((Date.parse(deep.exp) - Date.now()) / 86400000);
    if (days > 60 && !deep.domLapsed && !deep.domHold && !deep.domGrace) out.push(`Domain registered through ${deep.exp}`);
  }
  if (deep?.brokenLinks && deep.brokenLinks.checked >= 5 && deep.brokenLinks.broken === 0) out.push(`No broken links among the ${deep.brokenLinks.checked} homepage links we checked`);
  if (ds && typeof ds.loadMs === 'number' && ds.loadMs > 0 && ds.loadMs < 3000) out.push(`Homepage loaded in ${(ds.loadMs / 1000).toFixed(1)} s in our browser test`);
  if (deep?.hsts === true) out.push('Strict transport security enabled');
  if (deep?.localSchema === true) out.push('Local-business markup present for search engines');
  if (deep?.smOk === true) out.push('Sitemap present');
  if (a.year && a.year >= CUR_YEAR - 1) out.push(`Copyright current (© ${a.year})`);
  return out.slice(0, 6);
}

// ---------- at a glance ----------
// Every pill is derived from a field we actually hold; a missing field is "Not checked",
// never a guess. The notes state the measurement, not an opinion.
const GLANCE_LABEL = { good: 'Good', warn: 'Needs attention', crit: 'Critical', na: 'Not checked' };
const fmtS = (ms) => (ms / 1000).toFixed(1) + ' s';

function glance(l, deep, ds) {
  const a = l.audit || {};
  const d = deep || {};
  const rows = [];
  const row = (key, icon, label, status, note) => rows.push({ key, icon, label, status, note });

  // Website availability — from the scan status only.
  {
    const s = a.status;
    if (s === 'ok') row('availability', 'globe', 'Website availability', 'good', 'The homepage loaded normally on our checks.');
    else if (s === 'http-only') row('availability', 'globe', 'Website availability', 'warn', 'The homepage loads, but only over unencrypted HTTP.');
    else if (s === 'down') row('availability', 'globe', 'Website availability', 'crit', 'No response on any address variant we tried (www / non-www, secure and not).');
    else if (s === 'parked') row('availability', 'globe', 'Website availability', 'crit', 'The address shows a parking placeholder instead of a website.');
    else if (s === 'ssl-error') row('availability', 'globe', 'Website availability', 'crit', 'Browsers report a security-certificate error before the page opens.');
    else row('availability', 'globe', 'Website availability', 'na', !l.website ? 'No website was found in public listings to test.' : 'Could not be tested from our side.');
  }

  // Security certificate — from the measured days-left; scan status as the only fallback.
  {
    const n = d.certDaysLeft;
    if (typeof n === 'number') {
      if (n < 0) row('certificate', 'shield', 'Security certificate', 'crit', `Expired ${d.certValidTo || Math.abs(n) + ' days ago'}.`);
      else if (n < 30) row('certificate', 'shield', 'Security certificate', 'warn', `Expires in ${n} day${n === 1 ? '' : 's'}${d.certValidTo ? ` (${d.certValidTo})` : ''}.`);
      else row('certificate', 'shield', 'Security certificate', 'good', `Valid for ${n} more days${d.certValidTo ? ` (through ${d.certValidTo})` : ''}.`);
    } else if (a.status === 'ssl-error') row('certificate', 'shield', 'Security certificate', 'crit', 'Browsers cannot verify the certificate presented by the site.');
    else if (a.status === 'http-only') row('certificate', 'shield', 'Security certificate', 'warn', 'No certificate in use — the site is not served over HTTPS.');
    else row('certificate', 'shield', 'Security certificate', 'na', 'Certificate expiry was not recorded in this review.');
  }

  // Email protection — from the SPF / DMARC lookups only. A missing record is 'warn', the
  // same severity as the 'imp' finding card it mirrors, so one fact never carries two labels.
  {
    const spf = d.spf, dmarc = d.dmarc;
    if (spf === false || dmarc === false) {
      const missing = [spf === false ? 'SPF' : null, dmarc === false ? 'DMARC' : null].filter(Boolean).join(' and ');
      row('email', 'mail', 'Email protection', 'warn', `Missing ${missing} — forged mail from the domain is not blocked.`);
    } else if (spf === true && dmarc === true) {
      if (d.dmarcPolicy === 'none') row('email', 'mail', 'Email protection', 'warn', 'SPF and DMARC are published, but DMARC is set to monitor only (p=none).');
      else if (d.spfAll === '+all' || d.spfAll === '?all') row('email', 'mail', 'Email protection', 'warn', `SPF and DMARC are published, but the SPF record ends in "${d.spfAll}" and restricts nothing.`);
      else if (typeof d.spfLookups === 'number' && d.spfLookups > 10) row('email', 'mail', 'Email protection', 'warn', `SPF and DMARC are published, but SPF needs ${d.spfLookups} DNS lookups (limit 10).`);
      else row('email', 'mail', 'Email protection', 'good', `SPF and DMARC published${d.dmarcPolicy === 'reject' || d.dmarcPolicy === 'quarantine' ? ` and enforcing (p=${d.dmarcPolicy})` : ''}.`);
    } else row('email', 'mail', 'Email protection', 'na', 'DNS email records were not read for this review.');
  }

  // Mobile — from the viewport tag; the rendered overflow measurement overrides it.
  {
    if (ds && ds.mobileOverflow === true) row('mobile', 'phone', 'Mobile', 'warn', `Rendered on a phone screen, content runs about ${ds.overflowPx || '?'} px off the edge.`);
    else if (a.viewport === true) row('mobile', 'phone', 'Mobile', 'good', 'Mobile viewport is set; the page adapts to phone screens.');
    else if (a.viewport === false) row('mobile', 'phone', 'Mobile', 'warn', 'No mobile viewport — phones show a shrunken desktop page.');
    else row('mobile', 'phone', 'Mobile', 'na', 'Mobile layout was not measured for this review.');
  }

  // Performance — from the rendered load time and largest-paint measurement.
  {
    const load = ds && typeof ds.loadMs === 'number' && ds.loadMs > 0 ? ds.loadMs : null;
    const lcp = ds && typeof ds.lcpMs === 'number' && ds.lcpMs > 0 ? ds.lcpMs : null;
    if (load === null && lcp === null) row('performance', 'gauge', 'Performance', 'na', 'Load time was not measured for this review.');
    else if (load !== null && load >= 5000) row('performance', 'gauge', 'Performance', 'warn', `Homepage took ${fmtS(load)} to load in our browser test.`);
    else if (lcp !== null && lcp > 4000) row('performance', 'gauge', 'Performance', 'warn', `${load !== null ? `Loaded in ${fmtS(load)}, but the` : 'The'} main content appeared at ${fmtS(lcp)} (Google's "poor" line is 4 s).`);
    else if (load !== null && load < 3000) row('performance', 'gauge', 'Performance', 'good', `Homepage loaded in ${fmtS(load)} in our browser test${lcp !== null ? `; main content at ${fmtS(lcp)}` : ''}.`);
    else if (load !== null) row('performance', 'gauge', 'Performance', 'warn', `Homepage loaded in ${fmtS(load)} — the target for a local site is under 3 s.`);
    else if (lcp <= 2500) row('performance', 'gauge', 'Performance', 'good', `Main content appeared at ${fmtS(lcp)} in our browser test.`);
    else row('performance', 'gauge', 'Performance', 'warn', `Main content appeared at ${fmtS(lcp)} — Google's target is 2.5 s.`);
  }

  // Search presence — from the SEO basics we read off the homepage.
  {
    const checks = [];
    if ('title' in d) checks.push(['page title', !!(d.title && d.title.length >= 8)]);
    if (typeof d.desc === 'boolean') checks.push(['search description', d.desc]);
    if (typeof d.h1 === 'boolean') checks.push(['main heading', d.h1]);
    if (typeof d.localSchema === 'boolean') checks.push(['local-business markup', d.localSchema]);
    if (typeof d.smOk === 'boolean') checks.push(['sitemap', d.smOk]);
    if (!checks.length) row('search', 'search', 'Search presence', 'na', 'Search basics were not read for this review.');
    else {
      const fail = checks.filter(([, ok]) => !ok).map(([n]) => n);
      if (fail.length) row('search', 'search', 'Search presence', 'warn', `Missing: ${fail.join(', ')}.`);
      else row('search', 'search', 'Search presence', 'good', `In place: ${checks.map(([n]) => n).join(', ')}.`);
    }
  }

  // Domain registration — from the registry status and expiration date.
  {
    const expDays = d.exp && Number.isFinite(Date.parse(d.exp)) ? Math.round((Date.parse(d.exp) - Date.now()) / 86400000) : null;
    const flag = d.domLapsed ? (d.domLapsed === 'pendingdelete' ? 'pending delete' : 'redemption period') : d.domHold ? 'registrar hold' : null;
    if (flag && !d.ok) row('domain', 'calendar', 'Domain registration', 'crit', `The registry lists the domain as "${flag}"${d.exp ? ` (expiration date ${d.exp})` : ''}.`);
    else if (flag) row('domain', 'calendar', 'Domain registration', 'warn', `The registry shows a "${flag}" status while the site still loads — confirm the renewal with your registrar.`);
    else if (d.domGrace) row('domain', 'calendar', 'Domain registration', 'warn', 'The registry shows auto-renew grace status — confirm the renewal went through.');
    else if (expDays !== null && expDays < 0) row('domain', 'calendar', 'Domain registration', 'warn', `The registry's expiration date (${d.exp}) has passed — confirm the renewal with your registrar.`);
    else if (expDays !== null && expDays < 45) row('domain', 'calendar', 'Domain registration', 'crit', `Registered only through ${d.exp} — ${expDays} days from now.`);
    else if (expDays !== null && expDays <= 60) row('domain', 'calendar', 'Domain registration', 'warn', `Registered through ${d.exp} — ${expDays} days from now; renew soon.`);
    else if (expDays !== null) row('domain', 'calendar', 'Domain registration', 'good', `Registered through ${d.exp}.`);
    else row('domain', 'calendar', 'Domain registration', 'na', 'Registry data was not read for this review.');
  }
  return rows;
}

// ---------- icons (20px inline SVG, stroke = currentColor) ----------
const ICON = {
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',
  shield: '<path d="M12 3l7 3v5c0 4.5-3 8.2-7 10-4-1.8-7-5.5-7-10V6z"/><path d="M9 12l2 2 4-4"/>',
  mail: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 7l9 6 9-6"/>',
  phone: '<rect x="7" y="2.5" width="10" height="19" rx="2"/><path d="M11 18h2"/>',
  gauge: '<path d="M4 17a8 8 0 1 1 16 0"/><path d="M12 17l4-6"/><circle cx="12" cy="17" r="1.2"/>',
  search: '<circle cx="11" cy="11" r="6.5"/><path d="M16 16l5 5"/>',
  calendar: '<rect x="3" y="5" width="18" height="16" rx="2"/><path d="M3 10h18M8 3v4M16 3v4"/>',
};
const icon = (name) => `<svg class="ico" viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICON[name] || ICON.globe}</svg>`;

// Which icon leads a finding card. Matched on the card title so manual pages get one too.
function categoryOf(f) {
  const t = f.title;
  if (/registration|on hold|auto-renew grace/i.test(t)) return 'calendar';
  if (/remote access|certificate|HTTPS|security|WordPress|server software|1990s|code libraries/i.test(t)) return 'shield';
  if (/impersonated|monitor only|SPF|\bemail\b|\bmail\b/i.test(t)) return 'mail';
  if (/\bphones?\b|jumps around/i.test(t)) return 'phone';
  if (/takes .* seconds|main content takes|slowing you down|heavy homepage/i.test(t)) return 'gauge';
  if (/title|description|heading|markup|sitemap|analytics|links go to|text alternatives|labels|says ©|hasn’t changed|contact page/i.test(t)) return 'search';
  return 'globe';
}

function page(l, F, deep, slug, opts = {}) {
  const shotSrc = opts.shotSrc || `/shot/${esc(slug)}.jpg`;
  const shotCaption = opts.shotCaption || 'Your homepage as visitors see it today';
  const g = l.website ? grade(F) : null;
  const host = l.website ? hostnameOf(l.website) : null;
  const ds = l.website ? (opts.ds || null) : null;
  const now = new Date();
  const dateStr = now.toLocaleDateString('en-US', { month: 'long', year: 'numeric' });
  const fullDate = now.toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' });
  const isoDate = now.toISOString().slice(0, 10);
  const counts = ['crit', 'imp', 'rec'].map((s) => [s, F.filter((f) => f.sev === s).length]);
  const sevRank = { crit: 0, imp: 1, rec: 2 };
  const ranked = [...F].sort((x, y) => sevRank[x.sev] - sevRank[y.sev]);
  const headline = ranked.slice(0, 3);
  const plan = ranked.slice(0, 3);
  const hasSite = !!(l.website && !SOCIAL_RE.test(l.website));
  const good = hasSite ? passes(l, deep, ds) : [];
  const rows = glance(l, deep, ds);
  const needLine = l.need === 'Both'
    ? 'The findings span both the website itself and the technology behind it — the two halves of how your business shows up and stays safe online.'
    : l.need === 'IT'
      ? 'Most of what we found is about the technology behind the business — the kind of thing an IT partner quietly keeps handled.'
      : 'Most of what we found is about the website itself — how the business looks and performs when customers find you.';
  const ringColor = g ? ((g.letter === 'A' || g.letter === 'B') ? '#047857' : g.letter === 'C' ? '#B45309' : '#B91C1C') : '#E3E8F0';
  const countLine = counts.filter(([, n]) => n).map(([s, n]) => `${n} ${SEV_LABEL[s].toLowerCase()}`).join(' · ') || 'no issues found';

  // Score ring: r=52 → circumference 326.73
  const C = 2 * Math.PI * 52;
  const dash = g ? (C * g.score / 100).toFixed(2) : '0';
  const ring = `
      <div class="ring" data-grade="${g ? g.letter : ''}" data-score="${g ? g.score : ''}">
        <svg viewBox="0 0 120 120" width="136" height="136" role="img" aria-label="${g ? `Score ${g.score} out of 100, grade ${g.letter}` : 'No score — no website found'}">
          <circle cx="60" cy="60" r="52" fill="none" stroke="#E3E8F0" stroke-width="7"/>
          <circle cx="60" cy="60" r="52" fill="none" stroke="${ringColor}" stroke-width="7" stroke-dasharray="${dash} ${C.toFixed(2)}" transform="rotate(-90 60 60)"/>
          <text class="rletter" x="60" y="66" text-anchor="middle">${g ? g.letter : '—'}</text>
          <text class="rscore" x="60" y="86" text-anchor="middle">${g ? `${g.score}/100` : 'no site'}</text>
        </svg>
        <div class="ringmeta">
          <b>${g ? esc(GRADE_MEANING[g.letter]) : 'We couldn’t find a website for your business.'}</b>
          <span>${g ? `<span class="mono">${F.length}</span> finding${F.length === 1 ? '' : 's'} · ${esc(countLine)}` : 'If you have one we missed, we’d like to check it — otherwise, that is the finding.'}</span>
        </div>
      </div>`;

  const glanceRows = rows.map((r) => `
        <tr data-check="${r.key}" data-status="${r.status}">
          <th scope="row">${icon(r.icon)}<span>${esc(r.label)}</span></th>
          <td class="st"><span class="pill p-${r.status}">${GLANCE_LABEL[r.status]}</span></td>
          <td class="note">${esc(r.note)}</td>
        </tr>`).join('');

  const cards = F.map((f) => {
    const v = verifyHint(f, host);
    return `
      <article class="card sev-${f.sev}" data-cat="${categoryOf(f)}">
        <div class="cardhead">${icon(categoryOf(f))}<span class="sevtag">${SEV_LABEL[f.sev]}</span></div>
        <h3>${esc(f.title)}</h3>
        <p class="found"><strong>What we found:</strong> ${esc(f.found)}</p>
        <p><strong>Why it matters:</strong> ${esc(f.why)}</p>
        <p class="fix"><strong>The fix:</strong> ${esc(f.fix)}</p>
        ${v ? `<p class="verify"><strong>Check it yourself:</strong> ${esc(v)}</p>` : ''}
      </article>`;
  }).join('\n');

  const summaryList = headline.map((f) => `<li class="s-${f.sev}"><span class="sevdot"></span><span>${esc(f.title)}</span></li>`).join('');
  const goodList = good.length
    ? `<ul class="good">${good.map((p) => `<li>${esc(p)}</li>`).join('')}</ul>`
    : `<p class="muted">${hasSite ? 'Nothing we could verify as working from public data alone — that changes once we can look together.' : 'There was no website to check, so there is nothing to list here yet.'}</p>`;
  const planList = plan.map((f) => `<li><div class="ptitle">${esc(f.title)}</div><div class="pfix">${esc(f.fix)}</div><span class="effort">${esc(effortOf(f))}</span></li>`).join('');

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<meta name="color-scheme" content="light">
<title>${esc(l.name)} — Website &amp; Technology Checkup</title>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Source+Serif+4:opsz,wght@8..60,600&family=Manrope:wght@400;600&family=JetBrains+Mono:wght@400;600&display=swap">
<style>
  :root {
    --paper: #FFFFFF; --ground: #F6F8FB; --ink: #0F172A; --muted: #475569; --rule: #E3E8F0;
    --accent: #0F766E; --accent-soft: #DDF3EE; --ember: #C2410C;
    --crit: #B91C1C; --crit-bg: #FDE8E8;
    --imp: #A8490A;  --imp-bg: #FDF1DC;
    --rec: #1D4ED8;  --rec-bg: #E4ECFB;
    --good: #047857; --good-bg: #DDF3EE;
    --serif: "Source Serif 4", Georgia, "Times New Roman", serif;
    --sans: "Manrope", "Segoe UI", system-ui, -apple-system, sans-serif;
    --mono: "JetBrains Mono", Consolas, "SFMono-Regular", Menlo, monospace;
  }
  * { box-sizing: border-box; }
  html { -webkit-text-size-adjust: 100%; background: var(--ground); }
  body { margin: 0; background: var(--paper); color: var(--ink); font: 400 16px/1.6 var(--sans); }
  .doc { max-width: 760px; margin: 0 auto; background: var(--paper); }
  .pad { padding: 0 20px; }
  p { margin: 0 0 12px; max-width: 66ch; }
  a { color: var(--accent); }
  .mono { font-family: var(--mono); font-variant-numeric: tabular-nums; }
  .muted { color: var(--muted); }
  strong { font-weight: 600; }

  /* cover band */
  .cover { padding: 26px 20px 24px; border-bottom: 1px solid var(--rule); }
  .brand { display: flex; justify-content: space-between; align-items: baseline; gap: 12px; flex-wrap: wrap; padding-bottom: 10px; position: relative; }
  .brand::after { content: ''; position: absolute; left: 0; bottom: 0; width: 64px; height: 2px; background: var(--ember); }
  .brand b { font: 600 13px/1.2 var(--sans); letter-spacing: .08em; text-transform: uppercase; color: var(--ink); }
  .brand small { font-size: 13px; color: var(--muted); }
  h1 { font: 600 clamp(28px, 5.2vw, 38px)/1.12 var(--serif); letter-spacing: -.01em; margin: 26px 0 18px; text-wrap: balance; }
  .coverbody { display: grid; grid-template-columns: 1fr; gap: 22px; align-items: start; }
  dl.who { margin: 0; display: grid; grid-template-columns: auto 1fr; gap: 6px 16px; font-size: 15px; }
  dl.who dt { color: var(--muted); font-size: 12.5px; letter-spacing: .06em; text-transform: uppercase; padding-top: 3px; }
  dl.who dd { margin: 0; font-weight: 600; overflow-wrap: anywhere; }
  dl.who dd.mono { font-weight: 400; font-size: 14px; }
  .ring { display: grid; grid-template-columns: auto 1fr; gap: 6px 16px; align-items: center; justify-self: start; }
  .ring svg { display: block; }
  .ring .rletter { font: 600 46px var(--serif); fill: var(--ink); }
  .ring .rscore { font: 400 11.5px var(--mono); fill: var(--muted); letter-spacing: .02em; }
  .ringmeta { display: grid; gap: 4px; max-width: 300px; }
  .ringmeta b { font: 600 16px/1.3 var(--sans); }
  .ringmeta span { font-size: 13.5px; color: var(--muted); line-height: 1.45; }

  /* at a glance */
  .glancewrap { padding: 22px 20px 6px; }
  .glancewrap h2 { margin-top: 0; }
  table.glance { width: 100%; border-collapse: collapse; font-size: 14.5px; background: var(--ground); border: 1px solid var(--rule); border-radius: 6px; overflow: hidden; }
  table.glance thead th { text-align: left; font: 600 11.5px/1.2 var(--sans); letter-spacing: .08em; text-transform: uppercase; color: var(--muted); padding: 10px 12px; border-bottom: 1px solid var(--rule); background: var(--paper); }
  table.glance tbody th, table.glance tbody td { padding: 10px 12px; border-bottom: 1px solid var(--rule); vertical-align: top; text-align: left; }
  table.glance tbody tr:last-child th, table.glance tbody tr:last-child td { border-bottom: 0; }
  table.glance tbody th { font-weight: 600; white-space: nowrap; }
  table.glance tbody th .ico { vertical-align: -5px; margin-right: 8px; color: var(--accent); }
  table.glance td.st { white-space: nowrap; }
  table.glance td.note { color: var(--muted); }
  .pill { display: inline-block; font: 600 11.5px/1.2 var(--sans); letter-spacing: .04em; padding: 4px 9px; border-radius: 999px; white-space: nowrap; }
  .p-good { color: var(--good); background: var(--good-bg); }
  .p-warn { color: var(--imp); background: var(--imp-bg); }
  .p-crit { color: var(--crit); background: var(--crit-bg); }
  .p-na   { color: var(--muted); background: var(--rule); }

  /* sections */
  section { padding: 22px 20px 8px; }
  section.ground { background: var(--ground); border-top: 1px solid var(--rule); border-bottom: 1px solid var(--rule); padding-bottom: 14px; }
  h2 { font: 600 22px/1.25 var(--serif); margin: 0 0 14px; display: flex; align-items: baseline; gap: 12px; letter-spacing: -.005em; }
  h2 .num { font: 400 13px/1 var(--mono); color: var(--accent); letter-spacing: .04em; min-width: 22px; }
  .lede { font-size: 17px; line-height: 1.55; margin-bottom: 14px; }
  ul.headline { list-style: none; margin: 0 0 16px; padding: 0; display: grid; gap: 8px; }
  ul.headline li { display: flex; gap: 10px; align-items: flex-start; font-weight: 600; line-height: 1.4; }
  ul.headline .sevdot { flex: none; width: 10px; height: 10px; border-radius: 50%; margin-top: 7px; background: var(--rec); }
  ul.headline .s-crit .sevdot { background: var(--crit); }
  ul.headline .s-imp .sevdot { background: var(--imp); }
  figure.exhibit { margin: 8px 0 12px; padding: 12px; background: var(--ground); border: 1px solid var(--rule); border-radius: 6px; }
  figure.exhibit img { width: 100%; border: 1px solid var(--rule); border-radius: 3px; display: block; background: #fff; }
  figure.exhibit figcaption { font-size: 13px; color: var(--muted); margin-top: 10px; }
  figure.exhibit figcaption b { font-family: var(--mono); font-weight: 600; color: var(--ink); margin-right: 8px; font-size: 12px; letter-spacing: .04em; }

  /* finding cards */
  .card { background: var(--paper); border: 1px solid var(--rule); border-radius: 6px; padding: 16px 18px 8px; margin-bottom: 12px; }
  .cardhead { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
  .cardhead .ico { color: var(--muted); }
  .sev-crit .cardhead .ico { color: var(--crit); }
  .sev-imp  .cardhead .ico { color: var(--imp); }
  .sev-rec  .cardhead .ico { color: var(--rec); }
  .sevtag { display: inline-block; font: 600 11px/1.2 var(--sans); letter-spacing: .08em; text-transform: uppercase; padding: 3px 8px; border-radius: 999px; }
  .sev-crit .sevtag { color: var(--crit); background: var(--crit-bg); }
  .sev-imp  .sevtag { color: var(--imp); background: var(--imp-bg); }
  .sev-rec  .sevtag { color: var(--rec); background: var(--rec-bg); }
  .card h3 { margin: 0 0 10px; font: 600 19px/1.3 var(--serif); text-wrap: balance; }
  .card p { margin: 0 0 9px; font-size: 15.5px; }
  .card .found { color: var(--ink); }
  .card .verify { font-size: 14px; color: var(--muted); border-top: 1px dashed var(--rule); padding-top: 9px; margin-top: 6px; }
  .card .verify strong { color: var(--ink); }

  /* what's working */
  ul.good { list-style: none; margin: 0 0 8px; padding: 0; display: grid; gap: 6px; }
  ul.good li { position: relative; padding-left: 26px; }
  ul.good li::before { content: ''; position: absolute; left: 2px; top: 6px; width: 11px; height: 6px; border-left: 2px solid var(--good); border-bottom: 2px solid var(--good); transform: rotate(-45deg); }

  /* plan */
  ol.plan { list-style: none; margin: 0 0 8px; padding: 0; counter-reset: step; display: grid; gap: 10px; }
  ol.plan li { position: relative; background: var(--ground); border: 1px solid var(--rule); border-radius: 6px; padding: 12px 16px 12px 56px; }
  ol.plan li::before { counter-increment: step; content: counter(step); position: absolute; left: 14px; top: 12px; width: 28px; height: 28px; border-radius: 50%; background: var(--ink); color: var(--paper); font: 600 14px/28px var(--mono); text-align: center; }
  ol.plan .ptitle { font-weight: 600; }
  ol.plan .pfix { color: var(--muted); font-size: 15px; margin-top: 2px; }
  ol.plan .effort { display: inline-block; margin-top: 8px; font: 600 11px/1.2 var(--sans); letter-spacing: .08em; text-transform: uppercase; color: var(--accent); background: var(--accent-soft); padding: 3px 8px; border-radius: 999px; }

  /* next step */
  .cta { border: 2px solid var(--accent); border-radius: 8px; padding: 20px 22px 18px; background: var(--paper); margin-bottom: 8px; }
  .cta .big { font: 600 18px/1.3 var(--serif); margin: 0 0 6px; }
  .cta .tel { display: inline-block; font: 600 clamp(26px, 6vw, 32px)/1.15 var(--mono); letter-spacing: .01em; color: var(--ink); text-decoration: none; margin: 4px 0 10px; }
  .cta p { margin: 0 0 6px; }
  .cta .reply { color: var(--muted); font-size: 15px; margin-top: 10px; border-top: 1px solid var(--rule); padding-top: 10px; }

  footer { padding: 18px 20px 40px; color: var(--muted); font-size: 12.5px; line-height: 1.6; border-top: 1px solid var(--rule); }
  footer .mono { color: var(--ink); }

  @media (max-width: 600px) {
    table.glance thead { display: none; }
    table.glance tbody tr { display: grid; grid-template-columns: 1fr auto; }
    table.glance tbody th, table.glance tbody td { border-bottom: 0; padding: 10px 12px 0; }
    table.glance tbody td.note { grid-column: 1 / -1; padding: 4px 12px 10px 40px; border-bottom: 1px solid var(--rule); font-size: 14px; }
    table.glance tbody tr:last-child td.note { border-bottom: 0; }
  }
  @media (min-width: 640px) {
    .cover { padding: 34px 32px 28px; }
    .coverbody { grid-template-columns: 1fr auto; gap: 28px; }
    .ring { justify-self: end; grid-template-columns: auto; justify-items: center; text-align: center; }
    .ringmeta { max-width: 220px; }
    .glancewrap, section { padding-left: 32px; padding-right: 32px; }
    footer { padding-left: 32px; padding-right: 32px; }
    .doc { border-left: 1px solid var(--rule); border-right: 1px solid var(--rule); }
  }
  @media print {
    @page { size: Letter; margin: 0.55in 0.6in; }
    html, body { background: #fff; }
    body { font-size: 12.5px; line-height: 1.5; }
    .doc { max-width: none; border: 0; }
    .cover { padding: 0 0 18px; }
    .glancewrap, section, footer { padding-left: 0; padding-right: 0; }
    section.ground { background: var(--ground); -webkit-print-color-adjust: exact; print-color-adjust: exact; padding-left: 12px; padding-right: 12px; }
    .pill, .sevtag, .effort, ol.plan li::before, .ring circle, .cardhead .ico { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    .coverbody { grid-template-columns: 1fr auto; }
    .card, table.glance tr, ol.plan li, figure.exhibit, .cta, .coverbody, .ring { break-inside: avoid; page-break-inside: avoid; }
    figure.exhibit img { width: auto; max-width: 100%; max-height: 7in; margin: 0 auto; }
    table.glance thead { display: table-header-group; }
    h2, h3 { break-after: avoid; page-break-after: avoid; }
    .card p { font-size: 12.5px; }
    a { color: inherit; text-decoration: none; }
  }
</style>
</head>
<body>
<div class="doc">
  <header class="cover">
    <div class="brand">
      <b>${CONTACT.brands.split(' · ').map(esc).join(' &nbsp;&middot;&nbsp; ')}</b>
      <small>${esc(CONTACT.tagline)}</small>
    </div>
    <h1>Website &amp; Technology Checkup</h1>
    <div class="coverbody">
      <dl class="who">
        <dt>Prepared for</dt><dd>${esc(l.name)}</dd>
        <dt>Town</dt><dd>${esc(l.town)}, ${esc(l.st)}</dd>
        ${host ? `<dt>Domain</dt><dd class="mono">${esc(host)}</dd>` : ''}
        <dt>Date</dt><dd class="mono">${esc(fullDate)}</dd>
      </dl>
      ${ring}
    </div>
  </header>

  <div class="glancewrap">
    <h2>At a glance</h2>
    <table class="glance">
      <thead><tr><th>Check</th><th>Status</th><th>Note</th></tr></thead>
      <tbody>${glanceRows}
      </tbody>
    </table>
  </div>

  <section id="s1">
    <h2><span class="num">1</span>Summary in 20 seconds</h2>
    <p class="lede">${esc(VERTICAL_ANGLE[l.vertical] || VERTICAL_ANGLE.other)}</p>
    <ul class="headline">${summaryList}</ul>
    <p>${esc(needLine)}</p>
    ${hasSite ? `<figure class="exhibit">
      <img src="${shotSrc}" alt="Screenshot of the ${esc(l.name)} website today" loading="lazy"
        onerror="this.closest('figure').style.display='none'"${opts.shotMaxWidth ? ` style="max-width:${opts.shotMaxWidth}px;margin:0 auto"` : ''}>
      <figcaption><b>EXHIBIT A</b>${esc(shotCaption)}</figcaption>
    </figure>` : ''}
  </section>

  <section id="s2" class="ground">
    <h2><span class="num">2</span>Findings</h2>
    ${cards}
  </section>

  <section id="s3">
    <h2><span class="num">3</span>What’s working</h2>
    ${goodList}
  </section>

  <section id="s4">
    <h2><span class="num">4</span>What we’d do first</h2>
    <ol class="plan">${planList}</ol>
  </section>

  <section id="s5">
    <h2><span class="num">5</span>Next step</h2>
    <div class="cta">
      <p class="big">${esc(CONTACT.brands)}</p>
      <a class="tel" href="tel:${CONTACT.phone.replace(/[^\d]/g, '')}">${esc(CONTACT.phone)}</a>
      <p>Call or text, or email <a href="mailto:${esc(CONTACT.email)}">${esc(CONTACT.email)}</a></p>
      <p>${CONTACT.sites.map((s) => `<a href="https://${esc(s)}">${esc(s)}</a>`).join(' &middot; ')}</p>
      <p class="reply">Or simply reply to the email this came with — we’ll pick it up from there.</p>
    </div>
  </section>

  <footer>
    <p><strong>Reviewed</strong> <span class="mono">${esc(isoDate)}</span> (${esc(fullDate)}).</p>
    <p><strong>Scope.</strong> This checkup looked only at publicly visible information — the public website, its security
    certificate, and public DNS and registry records. No systems were accessed or tested.</p>
    <p><strong>Method.</strong> Findings reflect what we could observe on that date; the “At a glance” statuses come only from
    measurements we recorded, and anything we did not measure is marked “Not checked”. Every item is easy to confirm together on a quick call.</p>
  </footer>
</div>
</body>
</html>`;
}

// ---------- main ----------
const leads = JSON.parse(fs.readFileSync(path.join(out, 'leads.json'), 'utf8'));
let audits = {};
try { audits = JSON.parse(fs.readFileSync(path.join(out, 'audits.json'), 'utf8')); } catch { /* deep pass not run */ }
let gstatus = {};
try { gstatus = JSON.parse(fs.readFileSync(path.join(out, 'ratings.json'), 'utf8')); } catch { /* no Google pass */ }
let deepscan = {};
try { deepscan = JSON.parse(fs.readFileSync(path.join(out, 'deepscan.json'), 'utf8')); } catch { /* no Sunday scan yet */ }

const adir = path.join(dir, 'site', 'public', 'a');
fs.rmSync(adir, { recursive: true, force: true });
fs.mkdirSync(adir, { recursive: true });

let built = 0;
const slugMap = {};
for (const l of leads) {
  const g = gstatus[(l.name + '|' + l.town + '|' + l.st).toLowerCase()];
  if (g && g.bs === 'CLOSED_PERMANENTLY') continue; // no checkup pages for closed businesses
  const host = l.website ? hostnameOf(l.website) : null;
  const deep = host ? audits[host] : null;
  const ds = host ? deepscan[host] : null;
  const F = buildFindings(l, deep, ds);
  if (!F.length) continue; // nothing to say — no audit page
  const slug = slugOf(l);
  fs.writeFileSync(path.join(adir, slug + '.html'), page(l, F, deep, slug, { ds }));
  slugMap[slug] = true;
  built++;
}
// ---------- manual checkups ----------
// Hand-reviewed pages for prospects the scanner can't judge well (corporate sites,
// wrong domain on file, findings that need a human). One JSON per page in
// site/manual/<slug>.json → rendered through the same template, so they match
// the automated pages exactly and survive every deploy:
//   { "lead": { name, town, st, website, vertical, need }, "findings": [ { sev, title, found, why, fix } ],
//     "shot": "data:image/png;base64,…" | "/shot/x.jpg" (optional), "shotCaption": "…", "shotMaxWidth": 390 }
const mdir = path.join(dir, 'site', 'manual');
let manual = 0;
if (fs.existsSync(mdir)) {
  for (const f of fs.readdirSync(mdir).filter((n) => n.endsWith('.json'))) {
    try {
      const m = JSON.parse(fs.readFileSync(path.join(mdir, f), 'utf8'));
      const slug = f.replace(/\.json$/, '');
      const F = (m.findings || []).filter((x) => x && x.sev && x.title);
      if (!m.lead || !F.length) { console.log(`manual: ${f} has no lead/findings — skipped`); continue; }
      fs.writeFileSync(path.join(adir, slug + '.html'),
        page(m.lead, F, null, slug, { shotSrc: m.shot, shotCaption: m.shotCaption, shotMaxWidth: m.shotMaxWidth }));
      slugMap[slug] = true;
      manual++;
    } catch (e) { console.log(`manual: ${f} failed — ${e.message}`); }
  }
}

fs.writeFileSync(path.join(out, 'audit-slugs.json'), JSON.stringify(slugMap));
console.log(`Built ${built} personalized audit pages${manual ? ` + ${manual} manual` : ''} → site/public/a/`);
