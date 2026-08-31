// Region + town definitions for the Ignite Cyber lead scanner.
// Edit freely: add/remove towns, tweak radii (meters). Keys are used with --region.

export const REGIONS = {
  netn: {
    label: 'NE Tennessee',
    towns: [
      { name: 'Johnson City', st: 'TN', lat: 36.313, lng: -82.353, r: 12000 },
      { name: 'Kingsport', st: 'TN', lat: 36.548, lng: -82.562, r: 12000 },
      { name: 'Bristol', st: 'TN', lat: 36.57, lng: -82.215, r: 10000 },
      { name: 'Elizabethton', st: 'TN', lat: 36.349, lng: -82.211, r: 10000 },
      { name: 'Greeneville', st: 'TN', lat: 36.163, lng: -82.831, r: 15000 },
      { name: 'Erwin', st: 'TN', lat: 36.145, lng: -82.417, r: 12000 },
      { name: 'Rogersville', st: 'TN', lat: 36.407, lng: -83.006, r: 15000 },
      { name: 'Morristown', st: 'TN', lat: 36.214, lng: -83.295, r: 13000 },
      { name: 'Jonesborough', st: 'TN', lat: 36.294, lng: -82.473, r: 8000 },
    ],
  },
  swva: {
    label: 'SW Virginia',
    towns: [
      { name: 'Bristol', st: 'VA', lat: 36.618, lng: -82.17, r: 8000 },
      { name: 'Abingdon', st: 'VA', lat: 36.71, lng: -81.977, r: 12000 },
      { name: 'Marion', st: 'VA', lat: 36.835, lng: -81.515, r: 14000 },
      { name: 'Wytheville', st: 'VA', lat: 36.949, lng: -81.085, r: 15000 },
      { name: 'Galax', st: 'VA', lat: 36.661, lng: -80.924, r: 14000 },
      { name: 'Norton/Wise', st: 'VA', lat: 36.933, lng: -82.629, r: 16000 },
      { name: 'Big Stone Gap', st: 'VA', lat: 36.882, lng: -82.747, r: 10000 },
      { name: 'Lebanon', st: 'VA', lat: 36.9, lng: -82.08, r: 14000 },
      { name: 'Richlands', st: 'VA', lat: 37.093, lng: -81.812, r: 12000 },
      { name: 'Tazewell', st: 'VA', lat: 37.114, lng: -81.52, r: 14000 },
      { name: 'Christiansburg', st: 'VA', lat: 37.14, lng: -80.405, r: 13000 },
      { name: 'Blacksburg', st: 'VA', lat: 37.23, lng: -80.414, r: 10000 },
      { name: 'Radford', st: 'VA', lat: 37.132, lng: -80.577, r: 10000 },
      { name: 'Pulaski', st: 'VA', lat: 37.048, lng: -80.779, r: 12000 },
      { name: 'Roanoke', st: 'VA', lat: 37.271, lng: -79.941, r: 15000 },
    ],
  },
  swv: {
    label: 'Southern WV',
    towns: [
      { name: 'Bluefield', st: 'WV', lat: 37.27, lng: -81.222, r: 12000 },
      { name: 'Princeton', st: 'WV', lat: 37.366, lng: -81.103, r: 12000 },
      { name: 'Welch', st: 'WV', lat: 37.433, lng: -81.585, r: 15000 },
      { name: 'Beckley', st: 'WV', lat: 37.778, lng: -81.188, r: 14000 },
      { name: 'Oak Hill/Fayetteville', st: 'WV', lat: 37.972, lng: -81.149, r: 12000 },
      { name: 'Lewisburg', st: 'WV', lat: 37.802, lng: -80.446, r: 15000 },
      { name: 'Hinton', st: 'WV', lat: 37.674, lng: -80.889, r: 14000 },
      { name: 'Logan', st: 'WV', lat: 37.849, lng: -81.994, r: 14000 },
      { name: 'Williamson', st: 'WV', lat: 37.674, lng: -82.277, r: 14000 },
    ],
  },
  wnc: {
    label: 'Western NC',
    towns: [
      { name: 'Asheville', st: 'NC', lat: 35.595, lng: -82.552, r: 13000 },
      { name: 'Hendersonville', st: 'NC', lat: 35.319, lng: -82.461, r: 12000 },
      { name: 'Brevard', st: 'NC', lat: 35.233, lng: -82.734, r: 12000 },
      { name: 'Waynesville', st: 'NC', lat: 35.489, lng: -82.989, r: 13000 },
      { name: 'Sylva', st: 'NC', lat: 35.374, lng: -83.226, r: 13000 },
      { name: 'Franklin', st: 'NC', lat: 35.182, lng: -83.382, r: 14000 },
      { name: 'Murphy', st: 'NC', lat: 35.088, lng: -84.035, r: 16000 },
      { name: 'Boone', st: 'NC', lat: 36.217, lng: -81.675, r: 13000 },
      { name: 'West Jefferson', st: 'NC', lat: 36.404, lng: -81.493, r: 14000 },
      { name: 'Spruce Pine', st: 'NC', lat: 35.915, lng: -82.064, r: 14000 },
      { name: 'Marion', st: 'NC', lat: 35.684, lng: -82.009, r: 12000 },
      { name: 'Morganton', st: 'NC', lat: 35.745, lng: -81.685, r: 12000 },
      { name: 'Lenoir', st: 'NC', lat: 35.914, lng: -81.539, r: 12000 },
      { name: 'Hickory', st: 'NC', lat: 35.733, lng: -81.341, r: 13000 },
    ],
  },
  seky: {
    label: 'SE Kentucky',
    towns: [
      { name: 'Pikeville', st: 'KY', lat: 37.479, lng: -82.519, r: 13000 },
      { name: 'Prestonsburg', st: 'KY', lat: 37.666, lng: -82.772, r: 13000 },
      { name: 'Paintsville', st: 'KY', lat: 37.815, lng: -82.807, r: 12000 },
      { name: 'Hazard', st: 'KY', lat: 37.249, lng: -83.193, r: 14000 },
      { name: 'Whitesburg', st: 'KY', lat: 37.118, lng: -82.827, r: 13000 },
      { name: 'Harlan', st: 'KY', lat: 36.843, lng: -83.322, r: 14000 },
      { name: 'Middlesboro', st: 'KY', lat: 36.608, lng: -83.716, r: 13000 },
      { name: 'Barbourville', st: 'KY', lat: 36.866, lng: -83.889, r: 12000 },
      { name: 'Corbin', st: 'KY', lat: 36.949, lng: -84.097, r: 13000 },
      { name: 'London', st: 'KY', lat: 37.129, lng: -84.083, r: 13000 },
      { name: 'Williamsburg', st: 'KY', lat: 36.743, lng: -84.16, r: 12000 },
      { name: 'Somerset', st: 'KY', lat: 37.092, lng: -84.604, r: 13000 },
    ],
  },
  nsc: {
    label: 'Upstate/N SC',
    towns: [
      { name: 'Greenville', st: 'SC', lat: 34.852, lng: -82.394, r: 12000 },
      { name: 'Greer', st: 'SC', lat: 34.938, lng: -82.227, r: 10000 },
      { name: 'Spartanburg', st: 'SC', lat: 34.95, lng: -81.932, r: 13000 },
      { name: 'Anderson', st: 'SC', lat: 34.503, lng: -82.65, r: 13000 },
      { name: 'Easley', st: 'SC', lat: 34.83, lng: -82.601, r: 10000 },
      { name: 'Seneca/Clemson', st: 'SC', lat: 34.686, lng: -82.953, r: 14000 },
      { name: 'Gaffney', st: 'SC', lat: 35.072, lng: -81.65, r: 12000 },
      { name: 'Union', st: 'SC', lat: 34.715, lng: -81.624, r: 12000 },
      { name: 'Rock Hill', st: 'SC', lat: 34.925, lng: -81.025, r: 13000 },
      { name: 'Chester', st: 'SC', lat: 34.705, lng: -81.212, r: 12000 },
      { name: 'Laurens', st: 'SC', lat: 34.5, lng: -82.014, r: 12000 },
    ],
  },
};

// OSM tag selectors used to pull business POIs (each must have a name).
export const SELECTORS = [
  '["shop"]["name"]',
  '["office"]["name"]',
  '["craft"]["name"]',
  '["healthcare"]["name"]',
  '["amenity"~"^(dentist|doctors|clinic|veterinary|pharmacy|restaurant|cafe|nursing_home|bank|car_repair|childcare)$"]["name"]',
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
  if (['financial', 'financial_advisor', 'insurance'].includes(office) || amenity === 'bank') return 'finance';
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
