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

function page(l, F, deep, slug, opts = {}) {
  const shotSrc = opts.shotSrc || `/shot/${esc(slug)}.jpg`;
  const shotCaption = opts.shotCaption || 'Exhibit: your homepage as visitors see it today';
  const g = l.website ? grade(F) : null;
  const host = l.website ? hostnameOf(l.website) : null;
  const now = new Date();
  const dateStr = now.toLocaleDateString('en-US', { month: 'long', year: 'numeric' });
  const fullDate = now.toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' });
  const counts = ['crit', 'imp', 'rec'].map((s) => [s, F.filter((f) => f.sev === s).length]);
  const sevRank = { crit: 0, imp: 1, rec: 2 };
  const ranked = [...F].sort((x, y) => sevRank[x.sev] - sevRank[y.sev]);
  const headline = ranked.slice(0, 3);
  const plan = ranked.slice(0, 3);
  const good = l.website && !SOCIAL_RE.test(l.website) ? passes(l, deep, l.website ? (opts.ds || null) : null) : [];
  const needLine = l.need === 'Both'
    ? 'The findings span both the website itself and the technology behind it — the two halves of how your business shows up and stays safe online.'
    : l.need === 'IT'
      ? 'Most of what we found is about the technology behind the business — the kind of thing an IT partner quietly keeps handled.'
      : 'Most of what we found is about the website itself — how the business looks and performs when customers find you.';
  const gradeColor = g ? ((g.letter === 'A' || g.letter === 'B') ? 'var(--good)' : g.letter === 'C' ? 'var(--imp)' : 'var(--crit)') : 'var(--soft)';

  const cards = F.map((f) => {
    const v = verifyHint(f, host);
    return `
      <article class="card sev-${f.sev}">
        <div class="cardhead"><span class="sevtag">${SEV_LABEL[f.sev]}</span><h3>${esc(f.title)}</h3></div>
        <p class="found">${esc(f.found)}</p>
        <p><strong>Why it matters:</strong> ${esc(f.why)}</p>
        <p class="fix"><strong>The fix:</strong> ${esc(f.fix)}</p>
        ${v ? `<p class="verify"><strong>Check it yourself:</strong> ${esc(v)}</p>` : ''}
      </article>`;
  }).join('\n');

  const summaryList = headline.map((f) => `<li class="s-${f.sev}"><span class="dot"></span>${esc(f.title)}</li>`).join('');
  const goodList = good.length >= 2 ? `<h2 class="inline">What’s working</h2><ul class="good">${good.map((p) => `<li>${esc(p)}</li>`).join('')}</ul>` : '';
  const planList = plan.map((f) => `<li><div class="ptitle">${esc(f.title)}</div><div class="pfix">${esc(f.fix)}</div><span class="effort">${esc(effortOf(f))}</span></li>`).join('');

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>${esc(l.name)} — Website &amp; Technology Checkup</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Barlow+Condensed:wght@600;700&family=Barlow:wght@400;500;600&display=swap">
<style>
  :root {
    --paper: #FAF7F4; --card: #FFFFFF; --ink: #26211D; --soft: #6B6259; --faint: #9A928A;
    --line: #E3DAD1; --ember: #C2410C; --ember-soft: #FBE9DF;
    --crit: #A8321B; --crit-bg: #F9E3DC;
    --imp: #8A6D1C;  --imp-bg: #F5ECD4;
    --rec: #2F6FAB;  --rec-bg: #E1ECF5;
    --good: #177E70; --good-bg: #DDF0EC;
  }
  * { box-sizing: border-box; }
  html { -webkit-text-size-adjust: 100%; }
  body { margin: 0; background: var(--paper); color: var(--ink); font: 400 16px/1.55 "Barlow", "Segoe UI", sans-serif; }
  .sheet { max-width: 840px; margin: 0 auto; padding: 28px 20px 56px; }
  .brandrow { display: flex; justify-content: space-between; align-items: baseline; gap: 12px; flex-wrap: wrap;
    border-bottom: 2px solid var(--ink); padding-bottom: 10px; }
  .brandrow b { font: 700 17px/1 "Barlow Condensed", sans-serif; letter-spacing: .04em; text-transform: uppercase; }
  .brandrow b span { color: var(--ember); }
  .brandrow small { color: var(--soft); }
  h1 { font: 700 clamp(32px, 6vw, 44px)/1.02 "Barlow Condensed", "Arial Narrow", sans-serif; text-transform: uppercase; letter-spacing: .01em; margin: 24px 0 4px; text-wrap: balance; }
  .who { color: var(--soft); margin: 0 0 20px; font-size: 15px; }
  .who b { color: var(--ink); }

  .top { display: grid; grid-template-columns: 1fr; gap: 14px; margin-bottom: 8px; }
  .gradebox { background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 18px 20px; display: grid; grid-template-columns: auto 1fr; gap: 6px 16px; align-items: center; }
  .gletter { font: 700 64px/1 "Barlow Condensed", sans-serif; color: ${gradeColor}; grid-row: span 2; font-variant-numeric: tabular-nums; }
  .gmean { font: 600 17px/1.25 "Barlow", sans-serif; }
  .gmeta { font-size: 14px; color: var(--soft); }
  .gmeta b { color: var(--ink); }
  .summary { background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 16px 20px 14px; }
  h2 { font: 600 12.5px/1 "Barlow", sans-serif; text-transform: uppercase; letter-spacing: .12em; color: var(--soft); margin: 30px 0 12px; }
  h2.inline { margin: 14px 0 8px; }
  .summary h2:first-child { margin-top: 0; }
  ul.headline { list-style: none; margin: 0; padding: 0; }
  ul.headline li { display: flex; gap: 10px; align-items: flex-start; font-weight: 500; margin: 0 0 6px; line-height: 1.35; }
  ul.headline .dot { flex: none; width: 10px; height: 10px; border-radius: 50%; margin-top: 6px; background: var(--rec); }
  ul.headline .s-crit .dot { background: var(--crit); }
  ul.headline .s-imp .dot { background: var(--imp); }
  ul.good { list-style: none; margin: 0; padding: 0; display: grid; gap: 4px; }
  ul.good li { position: relative; padding-left: 20px; color: var(--soft); font-size: 15px; }
  ul.good li::before { content: ''; position: absolute; left: 0; top: 7px; width: 10px; height: 6px; border-left: 2px solid var(--good); border-bottom: 2px solid var(--good); transform: rotate(-45deg); }

  .shotwrap { margin: 16px 0 6px; padding: 10px; background: var(--card); border: 1px solid var(--line); border-radius: 8px; }
  .shotwrap img { width: 100%; border: 1px solid var(--line); border-radius: 4px; display: block; }
  .shotwrap figcaption { font-size: 12.5px; color: var(--soft); margin-top: 8px; text-align: center; letter-spacing: .02em; }
  .angle { margin: 18px 0 24px; padding: 14px 18px; border-left: 3px solid var(--ember); background: var(--card); border-radius: 0 6px 6px 0; }

  .card { background: var(--card); border: 1px solid var(--line); border-left-width: 5px; border-radius: 6px; padding: 14px 18px 6px; margin-bottom: 12px; }
  .card.sev-crit { border-left-color: var(--crit); }
  .card.sev-imp  { border-left-color: var(--imp); }
  .card.sev-rec  { border-left-color: var(--rec); }
  .cardhead { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-bottom: 6px; }
  .sevtag { display: inline-block; font: 600 10.5px/1.2 "Barlow", sans-serif; letter-spacing: .08em; text-transform: uppercase; padding: 3px 7px; border-radius: 3px; }
  .sev-crit .sevtag { color: var(--crit); background: var(--crit-bg); }
  .sev-imp  .sevtag { color: var(--imp); background: var(--imp-bg); }
  .sev-rec  .sevtag { color: var(--rec); background: var(--rec-bg); }
  .card h3 { margin: 0; font: 600 18px/1.25 "Barlow", sans-serif; text-wrap: balance; }
  .card p { margin: 0 0 9px; }
  .card .found { color: var(--soft); }
  .card .verify { font-size: 14px; color: var(--soft); border-top: 1px dashed var(--line); padding-top: 8px; margin-top: 4px; }
  .card .verify strong { color: var(--ink); font-weight: 600; }

  ol.plan { list-style: none; margin: 0; padding: 0; counter-reset: step; display: grid; gap: 10px; }
  ol.plan li { position: relative; background: var(--card); border: 1px solid var(--line); border-radius: 6px; padding: 12px 16px 12px 54px; }
  ol.plan li::before { counter-increment: step; content: counter(step); position: absolute; left: 14px; top: 10px; width: 28px; height: 28px; border-radius: 50%; background: var(--ink); color: var(--paper); font: 700 16px/28px "Barlow Condensed", sans-serif; text-align: center; }
  ol.plan .ptitle { font-weight: 600; }
  ol.plan .pfix { color: var(--soft); font-size: 15px; margin-top: 2px; }
  ol.plan .effort { display: inline-block; margin-top: 8px; font: 600 11px/1.2 "Barlow", sans-serif; letter-spacing: .08em; text-transform: uppercase; color: var(--ember); background: var(--ember-soft); padding: 3px 8px; border-radius: 3px; }

  .cta { margin-top: 30px; background: var(--ink); color: var(--paper); border-radius: 8px; padding: 22px 22px 20px; }
  .cta h2 { color: var(--paper); opacity: .7; margin: 0 0 8px; }
  .cta .big { font: 700 24px/1.2 "Barlow Condensed", sans-serif; margin: 0 0 10px; }
  .cta .tel { display: inline-block; font: 700 34px/1.1 "Barlow Condensed", sans-serif; letter-spacing: .02em; color: #F0956B; text-decoration: none; font-variant-numeric: tabular-nums; margin: 2px 0 8px; }
  .cta p { margin: 0 0 4px; }
  .cta a { color: #F0956B; text-decoration: none; }
  .cta .reply { color: var(--paper); opacity: .8; font-size: 15px; margin-top: 8px; }
  footer { margin-top: 24px; color: var(--soft); font-size: 12.5px; line-height: 1.6; border-top: 1px solid var(--line); padding-top: 12px; }

  @media (min-width: 720px) {
    .sheet { padding: 34px 26px 60px; }
    .top { grid-template-columns: 250px 1fr; }
  }
  @media print {
    body { background: #fff; font-size: 13px; }
    .sheet { padding: 0; max-width: none; }
    .top { grid-template-columns: 220px 1fr; }
    .cta { background: #fff; color: var(--ink); border: 2px solid var(--ink); }
    .cta a, .cta h2, .cta .tel, .cta .reply { color: var(--ink); }
    .card, .gradebox, .summary, ol.plan li, .shotwrap { break-inside: avoid; }
    h2 { break-after: avoid; }
  }
</style>
</head>
<body>
<div class="sheet">
  <div class="brandrow">
    <b>Ignite <span>/</span> Cyber Solutions &nbsp;&middot;&nbsp; Ridge Web Designs</b>
    <small>${esc(CONTACT.tagline)}</small>
  </div>

  <h1>Website &amp; Technology Checkup</h1>
  <p class="who">Prepared for <b>${esc(l.name)}</b> &middot; ${esc(l.town)}, ${esc(l.st)}${host ? ` &middot; ${esc(host)}` : ''} &middot; ${dateStr}</p>

  <div class="top">
    ${g ? `<div class="gradebox">
      <div class="gletter">${g.letter}</div>
      <div class="gmean">${esc(GRADE_MEANING[g.letter])}</div>
      <div class="gmeta"><b>${F.length} finding${F.length === 1 ? '' : 's'}</b> &middot; ${counts.filter(([, n]) => n).map(([s, n]) => `${n} ${SEV_LABEL[s].toLowerCase()}`).join(' · ') || 'no issues found'}</div>
    </div>` : `<div class="gradebox">
      <div class="gletter">?</div>
      <div class="gmean">We couldn’t find a website for your business.</div>
      <div class="gmeta">If you have one we missed, we’d love to check it — otherwise, that’s the finding.</div>
    </div>`}
    <div class="summary">
      <h2>In 20 seconds</h2>
      <ul class="headline">${summaryList}</ul>
      ${goodList}
    </div>
  </div>

  ${l.website && !SOCIAL_RE.test(l.website) ? `<figure class="shotwrap">
    <img src="${shotSrc}" alt="Screenshot of the ${esc(l.name)} website today" loading="lazy"
      onerror="this.closest('figure').style.display='none'"${opts.shotMaxWidth ? ` style="max-width:${opts.shotMaxWidth}px;margin:0 auto"` : ''}>
    <figcaption>${esc(shotCaption)}</figcaption>
  </figure>` : ''}

  <div class="angle">${esc(VERTICAL_ANGLE[l.vertical] || VERTICAL_ANGLE.other)}</div>

  <h2>What we found</h2>
  ${cards}

  <h2>What we’d do first</h2>
  <ol class="plan">${planList}</ol>

  <h2>Where this points</h2>
  <p>${esc(needLine)}</p>

  <div class="cta">
    <h2>Talk to a local team</h2>
    <p class="big">${esc(CONTACT.brands)}</p>
    <a class="tel" href="tel:${CONTACT.phone.replace(/[^\d]/g, '')}">${esc(CONTACT.phone)}</a>
    <p>Call or text, or email <a href="mailto:${esc(CONTACT.email)}">${esc(CONTACT.email)}</a></p>
    <p>${CONTACT.sites.map((s) => `<a href="https://${esc(s)}">${esc(s)}</a>`).join(' &middot; ')}</p>
    <p class="reply">Or simply reply to the email this came with — we’ll pick it up from there.</p>
  </div>

  <footer>
    Reviewed ${esc(fullDate)}. This checkup looked only at publicly visible information — your public website, its security
    certificate, and public DNS records. No systems were accessed or tested. Findings reflect what we could observe on that
    date and are easy to confirm together on a quick call.
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
