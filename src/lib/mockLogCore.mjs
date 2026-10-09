const DEFAULT_SEED = 20261009;
const DAY_SECONDS = 24 * 60 * 60;
const SPIKE_START = 3 * 60 * 60 + 10 * 60;
const SPIKE_END = 3 * 60 * 60 + 25 * 60;

const BROWSER_UAS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
  'Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1',
  'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36',
];

const ATTACK_IPS = {
  BRUTE_FORCE: ['203.0.113.10', '203.0.113.11', '203.0.113.12'],
  SQLI: ['203.0.113.10', '203.0.113.30'],
  TRAVERSAL: ['203.0.113.50', '203.0.113.51'],
  SCANNER_UA: ['203.0.113.70', '203.0.113.71'],
  SENSITIVE_PROBE: ['203.0.113.90', '203.0.113.91', '203.0.113.92'],
};

function mulberry32(seed) {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6D2B79F5) | 0;
    let value = state;
    value = Math.imul(value ^ (value >>> 15), value | 1);
    value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
    return ((value ^ (value >>> 14)) >>> 0) / 4294967296;
  };
}

function integer(random, maxExclusive) {
  return Math.floor(random() * maxExclusive);
}

function choose(random, values) {
  return values[integer(random, values.length)];
}

function timeOfDay(random, spike = false) {
  if (spike) return SPIKE_START + integer(random, SPIKE_END - SPIKE_START);
  const span = integer(random, (DAY_SECONDS - (SPIKE_END - SPIKE_START)));
  return span < SPIKE_START ? span : span + (SPIKE_END - SPIKE_START);
}

function normalTime(random) {
  const hourWeights = [
    1, 1, 1, 1, 1, 1, 1, 1,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    2, 2,
  ];
  const weight = integer(random, hourWeights.reduce((sum, value) => sum + value, 0));
  let total = 0;
  let hour = 0;
  for (; hour < hourWeights.length; hour += 1) {
    total += hourWeights[hour];
    if (weight < total) break;
  }
  return hour * 3600 + integer(random, 3600);
}

function visitorIps() {
  const ips = [];
  for (let host = 1; host <= 23; host += 1) ips.push(`198.51.100.${host}`);
  for (let host = 1; host <= 22; host += 1) ips.push(`192.0.2.${host}`);
  return ips;
}

function formatTimestamp(seconds) {
  const instant = new Date(Date.UTC(2026, 9, 8, 0, 0, seconds));
  const day = String(instant.getUTCDate()).padStart(2, '0');
  const month = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'][instant.getUTCMonth()];
  const year = instant.getUTCFullYear();
  const hour = String(instant.getUTCHours()).padStart(2, '0');
  const minute = String(instant.getUTCMinutes()).padStart(2, '0');
  const second = String(instant.getUTCSeconds()).padStart(2, '0');
  return `${day}/${month}/${year}:${hour}:${minute}:${second} +0000`;
}

function normalPath(random) {
  const choice = integer(random, 100);
  if (choice < 20) return '/';
  if (choice < 45) {
    return choose(random, [
      '/blog/how-to-select-a-plan',
      '/blog/security-basics',
      '/blog/choosing-a-host',
      '/blog/product-updates',
    ]);
  }
  if (choice < 60) {
    if (choice < 63) return '/cart';
    return choose(random, ['/shop/', '/shop/new-arrivals', '/shop/accessories', '/shop/item-42']);
  }
  if (choice < 80) {
    return choose(random, [
      '/wp-content/uploads/2026/09/product-1.jpg',
      '/wp-content/uploads/2026/09/banner.webp',
      '/wp-content/uploads/2026/10/catalog.png',
    ]);
  }
  if (choice < 92) return choose(random, ['/assets/site.css', '/assets/app.js', '/assets/theme.css']);
  if (choice < 95) return '/contact';
  return choose(random, ['/robots.txt', '/sitemap.xml', '/favicon.ico']);
}

function normalStatus(random, path) {
  if (path === '/robots.txt' || path === '/sitemap.xml' || path === '/favicon.ico') return 404;
  const value = integer(random, 100);
  if (value < 84) return 200;
  if (value < 93) return 304;
  if (value < 98) return 404;
  if (value === 98) return 500;
  return 301;
}

function makeLine(record, sequence) {
  if (record.malformed === 'binary') return `\u0000\u0001\x7F${sequence}\u0003`;
  if (record.malformed === 'truncated') {
    return `${record.ip} - - [08/Oct/2026:03:12:07 +0000] "${record.method} ${record.target}`;
  }
  return `${record.ip} - - [${formatTimestamp(record.seconds)}] "${record.method} ${record.target} ${record.protocol}" ${record.status} ${record.bytes} "${record.referer}" "${record.ua}"`;
}

function addNormalRecords(random, records) {
  const ips = visitorIps();
  for (let index = 0; index < 4000; index += 1) {
    let path = normalPath(random);
    let method = path === '/contact' || path === '/cart' ? 'POST' : 'GET';
    let query = '';
    let status = normalStatus(random, path);
    let ua = choose(random, BROWSER_UAS);
    let ip = choose(random, ips);
    let protocol = 'HTTP/1.1';
    let referer = choose(random, ['-', 'https://shop.example.com/', 'https://shop.example.com/blog/']);
    let seconds = normalTime(random);

    if (index < 20) {
      path = '/search';
      query = "q=o'brien";
      method = 'GET';
      status = 200;
    } else if (index < 40) {
      path = '/blog/how-to-select-a-plan';
      query = '';
      method = 'GET';
      status = 200;
    } else if (index >= 40 && index < 43) {
      path = '/wp-login.php';
      query = '';
      method = 'POST';
      status = 302;
      seconds = (11 + index - 40) * 3600 + 180;
      referer = 'https://shop.example.com/wp-login.php';
    }

    if (index < 10) ip = `2001:db8::${(index + 1).toString(16)}`;
    if (index >= 10 && index < 25) protocol = 'HTTP/2.0';
    if (index >= 3995) {
      records.push({
        seconds,
        ip,
        label: 'NORMAL',
        malformed: index === 3995 || index === 3996 ? 'binary' : 'truncated',
      });
      continue;
    }

    if (index >= 40 && index < 43) path = '/wp-login.php';
    const target = query ? `${path}?${query}` : path;
    records.push({
      seconds,
      ip,
      method,
      target,
      protocol,
      status,
      bytes: integer(random, 5000),
      referer,
      ua: index === 25 ? 'Googlebot/2.1 (+http://www.google.com/bot.html)'
        : index === 26 ? 'Bingbot/2.0 (+http://www.bing.com/bingbot.htm)'
          : ua,
      label: 'NORMAL',
    });
  }
}

function addBruteForceRecords(random, records) {
  const ips = ATTACK_IPS.BRUTE_FORCE;
  for (let attacker = 0; attacker < ips.length; attacker += 1) {
    const firstBurst = SPIKE_START + 45 + attacker * 300;
    for (let attempt = 0; attempt < 40; attempt += 1) {
      records.push({
        seconds: firstBurst + attempt,
        ip: ips[attacker],
        method: 'POST',
        target: '/wp-login.php',
        protocol: 'HTTP/1.1',
        status: 200,
        bytes: 4521,
        referer: '-',
        ua: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/128.0.0.0 Safari/537.36',
        label: 'BRUTE_FORCE',
      });
    }
    for (let burst = 0; burst < 2; burst += 1) {
      const start = (1 + attacker * 7 + burst * 3) * 3600 + attacker * 100 + burst * 120;
      for (let attempt = 0; attempt < 20; attempt += 1) {
        records.push({
          seconds: start + attempt,
          ip: ips[attacker],
          method: 'POST',
          target: '/wp-login.php',
          protocol: 'HTTP/1.1',
          status: 200,
          bytes: 4521,
          referer: '-',
          ua: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/128.0.0.0 Safari/537.36',
          label: 'BRUTE_FORCE',
        });
      }
    }
    const xmlrpcStart = (4 + attacker * 6) * 3600 + 500;
    for (let attempt = 0; attempt < 20; attempt += 1) {
      records.push({
        seconds: xmlrpcStart + attempt,
        ip: ips[attacker],
        method: 'POST',
        target: '/xmlrpc.php',
        protocol: 'HTTP/1.1',
        status: 200,
        bytes: 120,
        referer: '-',
        ua: 'python-requests/2.32.3',
        label: 'BRUTE_FORCE',
      });
    }
  }
}

function addSqliRecords(random, records) {
  const paths = ['/products.php?id=', '/index.php?cat=', '/wp-json/wp/v2/posts?search='];
  for (let index = 0; index < 250; index += 1) {
    const sqlmap = index < 150;
    const spike = index < 130;
    const payload = sqlmap
      ? choose(random, ['1 UNION SELECT user(),database()', '1 AND SLEEP(5)', "1' OR '1'='1"])
      : choose(random, ["%27 OR 1=1--", '1 UNION SELECT password FROM users', '1; SLEEP(5)']);
    records.push({
      seconds: timeOfDay(random, spike),
      ip: ATTACK_IPS.SQLI[index % 2],
      method: 'GET',
      target: `${choose(random, paths)}${payload.replaceAll(' ', '%20')}`,
      protocol: 'HTTP/1.1',
      status: 200,
      bytes: 100,
      referer: '-',
      ua: sqlmap ? 'sqlmap/1.7.2#stable (https://sqlmap.org)' : 'Mozilla/5.0 (compatible; manual test)',
      label: 'SQLI',
      ...(sqlmap ? { also: 'SCANNER_UA' } : {}),
    });
  }
}

function addTraversalRecords(random, records) {
  const targets = [
    '/../../etc/passwd',
    '/..%2f..%2fetc/passwd',
    '/%252e%252e%252fetc/passwd',
    '/..\\..\\windows\\win.ini',
  ];
  for (let index = 0; index < 100; index += 1) {
    records.push({
      seconds: timeOfDay(random, index < 50),
      ip: ATTACK_IPS.TRAVERSAL[index % 2],
      method: 'GET',
      target: choose(random, targets),
      protocol: 'HTTP/1.1',
      status: 404,
      bytes: 162,
      referer: '-',
      ua: 'Mozilla/5.0 (compatible; remote client)',
      label: 'TRAVERSAL',
    });
  }
}

function addScannerRecords(random, records) {
  const paths = ['/admin', '/backup', '/test', '/old', '/cgi-bin/status'];
  for (let index = 0; index < 150; index += 1) {
    records.push({
      seconds: timeOfDay(random, index < 50),
      ip: ATTACK_IPS.SCANNER_UA[index % 2],
      method: 'GET',
      target: choose(random, paths),
      protocol: 'HTTP/1.1',
      status: index % 50 === 0 ? 200 : 404,
      bytes: 162,
      referer: '-',
      ua: index % 2 === 0 ? 'Nikto/2.1.6' : 'gobuster/3.5',
      label: 'SCANNER_UA',
    });
  }
}

function addSensitiveRecords(random, records) {
  const paths = [
    '/.env',
    '/.git/HEAD',
    '/wp-config.php.bak',
    '/backup.sql',
    '/phpmyadmin/',
    '/.aws/credentials',
    '/config.php.old',
    '/server-status',
  ];
  for (let index = 0; index < 200; index += 1) {
    const gitHead = index < 3;
    records.push({
      seconds: timeOfDay(random, index < 100),
      ip: ATTACK_IPS.SENSITIVE_PROBE[index % 3],
      method: 'GET',
      target: choose(random, paths),
      protocol: 'HTTP/1.1',
      status: gitHead ? 200 : 404,
      bytes: gitHead ? 1200 : 162,
      referer: '-',
      ua: 'Mozilla/5.0 (compatible; remote client)',
      label: 'SENSITIVE_PROBE',
    });
  }
}

export function generateMockLog(seed = DEFAULT_SEED) {
  if (!Number.isFinite(seed)) throw new TypeError('seed must be a finite number');
  const random = mulberry32(seed);
  const records = [];

  addNormalRecords(random, records);
  addBruteForceRecords(random, records);
  addSqliRecords(random, records);
  addTraversalRecords(random, records);
  addScannerRecords(random, records);
  addSensitiveRecords(random, records);

  records.sort((left, right) => left.seconds - right.seconds);
  const text = records.map(makeLine).join('\n');
  const truth = records.map((record, index) => ({
    line: index + 1,
    label: record.label,
    ...(record.also ? { also: record.also } : {}),
    ...(record.malformed ? { malformed: true } : {}),
  }));

  return { text, truth };
}
