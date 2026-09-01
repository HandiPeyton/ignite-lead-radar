// Coverage model for the Ignite Cyber lead scanner.
//
// Coverage = EVERYTHING within RADIUS_MI of Bristol TN/VA. Towns are not
// hand-listed: scan.mjs pulls every city/town/village OSM knows inside the
// circle (per state, so each place carries its state), tiles the circle into
// a grid of bounding boxes, and queries every tile. Each business is labeled
// with its nearest place (town) and that place's state (region).

export const CENTER = { name: 'Bristol', lat: 36.595, lng: -82.189 };
export const RADIUS_MI = 200;
export const RADIUS_KM = RADIUS_MI * 1.609344;

// Regions are states. Key = board filter key; osm = admin_level-4 area name.
export const REGIONS = {
  tn: { label: 'Tennessee', osm: 'Tennessee' },
  va: { label: 'Virginia', osm: 'Virginia' },
  wv: { label: 'West Virginia', osm: 'West Virginia' },
  nc: { label: 'North Carolina', osm: 'North Carolina' },
  ky: { label: 'Kentucky', osm: 'Kentucky' },
  sc: { label: 'South Carolina', osm: 'South Carolina' },
  ga: { label: 'Georgia', osm: 'Georgia' },
};

// Grid tile size in degrees (~24 km squares at this latitude). Tiles that time
// out on Overpass are split in four automatically (dense metro cores).
export const TILE_LAT = 0.22;
export const TILE_LNG = 0.27;

// OSM tag selectors used to pull business POIs (each must have a name).
export const SELECTORS = [
  '["shop"]["name"]',
  '["office"]["name"]',
  '["craft"]["name"]',
  '["healthcare"]["name"]',
  '["amenity"~"^(dentist|doctors|clinic|veterinary|pharmacy|restaurant|cafe|nursing_home|car_repair|childcare)$"]["name"]',
  '["tourism"~"^(hotel|motel|guest_house|chalet|apartment|caravan_site)$"]["name"]',
  '["leisure"~"^(fitness_centre|sports_centre)$"]["name"]',
  '["man_made"="works"]["name"]',
];

// National/regional chains and franchises: not realistic buyers of a local
// website or a local MSP. Any OSM element with a `brand` tag is also skipped.
export const CHAIN_RE = new RegExp(
  [
    'walmart', 'mcdonald', 'subway', 'dollar general', 'dollar tree', 'family dollar',
    'cvs', 'walgreens', 'rite aid', 'autozone', "o'?reilly", 'advance auto', 'napa auto',
    'starbucks', 'burger king', "wendy'?s", 'taco bell', 'kfc', 'pizza hut', "domino'?s",
    'papa john', "hardee'?s", 'bojangles', "zaxby'?s", 'chick-fil-a', 'sonic drive',
    "arby'?s", 'dairy queen', 'little caesar', 'waffle house', 'cracker barrel', 'ihop',
    "applebee'?s", 'outback', 'olive garden', 'buffalo wild wings', "wing ?stop",
    'tractor supply', "lowe'?s", 'home depot', 'harbor freight', 'best buy', 'staples',
    'office depot', 'petsmart', 'petco', 'verizon', 'at&t', 't-mobile', 'u\\.?s\\.? cellular',
    'regions bank', 'truist', 'wells fargo', 'bank of america', 'first horizon', 'pnc bank',
    'fifth third', 'chase bank', 'woodforest', 'world finance', 'onemain',
    'food city', 'food lion', 'ingles', 'kroger', 'publix', 'aldi', 'lidl', 'save-a-lot',
    'piggly wiggly', 'harris teeter', 'goodwill', 'salvation army',
    'enterprise rent', 'hertz', 'u-?haul', 'ups store', 'fedex', 'usps', 'post office',
    'holiday inn', 'hampton inn', 'marriott', 'hilton', 'comfort (inn|suites)', 'quality inn',
    'super 8', 'days inn', 'motel 6', 'best western', 'econo ?lodge', 'red roof', 'fairfield inn',
    'courtyard', 'home2', 'candlewood', 'la quinta', 'sleep inn', 'baymont', 'tru by',
    'residence inn', 'springhill', 'towneplace', 'wingate', 'microtel', 'ramada', 'howard johnson',
    'shell', 'exxon', 'chevron', 'bp', 'marathon', 'speedway', "casey'?s", 'pilot travel',
    "love'?s travel", 'circle k', '7-eleven', 'sheetz', 'wawa', 'quiktrip', 'racetrac',
    'great clips', 'sport clips', 'supercuts', 'smartstyle', 'anytime fitness', 'planet fitness',
    'crunch fitness', "gold'?s gym", 'gnc', 'h&r block', 'jackson hewitt', 'liberty tax',
    'state farm', 'allstate', 'geico', 'progressive', 'nationwide', 'edward jones',
    "aaron'?s", 'rent-a-center', 'gamestop', 'bath & body', "victoria'?s secret",
    'belk', "kohl'?s", 'tj ?maxx', 'ross dress', 'burlington', 'old navy', 'shoe show',
    'hibbett', 'dunham', "dick'?s sporting", 'books-a-million', 'batteries plus',
    'sherwin-williams', 'ace hardware', 'true value', 'firestone', 'goodyear', 'jiffy lube',
    'valvoline', 'take 5', 'meineke', 'midas', 'aamco', 'caliber collision', 'gerber collision',
    'safelite', 'mattress firm', 'la-z-boy', 'ashley (furniture|homestore)', 'badcock',
    'big lots', "ollie'?s", 'hobby lobby', 'michaels', 'joann', 'party city',
    'krispy kreme', 'dunkin', 'panera', 'chipotle', 'five guys', 'jersey mike', 'firehouse subs',
    'jimmy john', "moe'?s southwest", "marco'?s pizza", 'hungry howie', 'cicis',
    'captain d', 'long john silver', 'bojangle', 'el paso mexican', 'la carreta',
    'holiday hair', 'regis', 'massage envy', 'european wax',
    'cookout', 'cook out', 'biscuitville', 'zaxby', 'culver', 'whataburger', 'popeyes',
    "chili'?s", 'red lobster', 'texas roadhouse', 'longhorn', 'golden corral', 'ruby tuesday',
    '^target$', "sam'?s club", 'costco', "bj'?s", 'trader joe', 'whole foods', 'sprouts',
    'bank of the ozarks', 'suntrust', 'bb&t', 'first citizens', 'south state bank',
    'quest diagnostics', 'labcorp', 'minuteclinic', 'fastmed', 'medexpress',
  ].join('|'),
  'i'
);

// Vertical buckets → used for IT-need weighting and audit prioritization.
export const IT_HEAVY = new Set([
  'healthcare', 'legal', 'accounting', 'finance', 'engineering',
  'manufacturing', 'veterinary', 'realestate',
]);

export const VERTICAL_PRIORITY = [
  'healthcare', 'legal', 'accounting', 'finance', 'engineering', 'manufacturing',
  'veterinary', 'realestate', 'trades', 'auto', 'hospitality', 'construction',
  'fitness', 'food', 'retail', 'professional', 'other',
];

export function classifyVertical(tags) {
  const amenity = tags.amenity || '';
  const office = tags.office || '';
  const shop = tags.shop || '';
  const craft = tags.craft || '';

  if (tags.healthcare || ['dentist', 'doctors', 'clinic', 'nursing_home', 'pharmacy'].includes(amenity)) return 'healthcare';
  if (amenity === 'veterinary') return 'veterinary';
  if (office === 'lawyer' || office === 'notary') return 'legal';
  if (office === 'accountant' || office === 'tax_advisor') return 'accounting';
  if (amenity === 'bank') return 'bank'; // excluded — no banks/credit unions; advisors & insurance stay
  if (['financial', 'financial_advisor', 'insurance'].includes(office)) return 'finance';
  if (['architect', 'engineer', 'engineering', 'surveyor'].includes(office)) return 'engineering';
  if (office === 'estate_agent') return 'realestate';
  if (office === 'it' || office === 'telecommunication') return 'itcompany'; // competitors — excluded
  if (tags.man_made === 'works') return 'manufacturing';
  if (['electrician', 'plumber', 'hvac', 'carpenter', 'roofer', 'painter', 'tiler', 'metal_construction', 'window_construction', 'landscaping', 'gardener'].includes(craft)) return 'trades';
  if (craft === 'builder' || office === 'construction' || office === 'construction_company') return 'construction';
  if (craft) return 'trades';
  if (['car_repair', 'car', 'car_parts', 'tyres', 'motorcycle'].includes(shop) || amenity === 'car_repair') return 'auto';
  if (tags.tourism) return 'hospitality';
  if (['fitness_centre', 'sports_centre'].includes(tags.leisure || '')) return 'fitness';
  if (['restaurant', 'cafe'].includes(amenity) || ['bakery', 'butcher', 'deli', 'confectionery'].includes(shop)) return 'food';
  if (amenity === 'childcare') return 'professional';
  if (shop) return 'retail';
  if (office) return 'professional';
  return 'other';
}
