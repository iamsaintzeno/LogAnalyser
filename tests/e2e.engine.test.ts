/// <reference types="node" />
import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, basename, dirname } from 'node:path';
import { parseLine } from '../src/engine/parseLine';
import { analyze } from '../src/engine/analyze';
import type { LogEntry, ParseResult } from '../src/engine/types';

type Meta = Parameters<typeof analyze>[1];

// ---------- helpers ----------
// Entry id = physical line number (1-based) so mock-truth line numbers map directly.
function parseText(text: string) {
  const clean = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text; // the Worker must strip a BOM too
  const lines = clean.split('\n'); // keep '\r' on purpose: parseLine must trim it
  const entries: LogEntry[] = [];
  lines.forEach((line, i) => {
    if (line.trim() === '') return;
    const e = parseLine(line, i + 1);
    if (e) entries.push(e);
  });
  const total = lines.length;
  return { entries, total, parsed: entries.length, skipped: total - entries.length };
}

function run(text: string): { res: ParseResult; p: ReturnType<typeof parseText> } {
  const p = parseText(text);
  const meta = {
    fileName: 'fixture.log', fileSize: text.length, totalLines: p.total,
    parsedLines: p.parsed, skippedLines: p.skipped, createdAt: 0, durationMs: 0,
  } as unknown as Meta;
  return { res: analyze(p.entries, meta), p };
}

const L = (ip: string, time: string, method: string, target: string, status: number,
  ua = 'Mozilla/5.0 (X11; Linux x86_64)', tz = '+0000') =>
  `${ip} - - [08/Oct/2026:${time} ${tz}] "${method} ${target} HTTP/1.1" ${status} 512 "-" "${ua}"`;

const nonZero = (byType: Record<string, number>) =>
  Object.fromEntries(Object.entries(byType).filter(([, n]) => n > 0));

const bestMs = (fn: () => unknown, runs = 3) => {
  fn(); // warm-up so JIT start-up is not measured
  let best = Infinity;
  for (let i = 0; i < runs; i++) {
    const t = performance.now();
    fn();
    best = Math.min(best, performance.now() - t);
  }
  return best;
};

// ---------- 40-line fixture ----------
const BF = '198.51.100.10', SQ = '198.51.100.20', TR = '198.51.100.30', UA = '198.51.100.40', SP = '198.51.100.50';

const safe = [
  L('192.0.2.1', '03:00:01', 'GET', '/', 200),
  L('192.0.2.2', '03:00:05', 'GET', '/index.html', 200),
  L('192.0.2.3', '03:00:09', 'GET', '/about', 200),
  L('192.0.2.4', '03:00:14', 'GET', '/css/site.css', 200),
  L('192.0.2.5', '03:00:20', 'GET', '/js/app.js', 200),
  L('192.0.2.6', '03:00:27', 'GET', '/images/logo.png', 200),
  L('192.0.2.7', '03:00:33', 'GET', '/contact', 200),
  L('192.0.2.8', '03:00:41', 'GET', '/products', 200),
];
const bf = ['00', '05', '10', '15', '20', '25'].map((s) => L(BF, `03:10:${s}`, 'POST', '/wp-login.php', 200));
const sqli = [
  L(SQ, '03:12:00', 'GET', '/search.php?q=1%27%20OR%201%3D1--', 403),
  L(SQ, '03:12:03', 'GET', '/item.php?id=1+UNION+SELECT+username,password+FROM+users--', 403),
  L(SQ, '03:12:06', 'GET', '/item.php?id=1;DROP+TABLE+users--', 403),
];
const trav = [
  L(TR, '03:14:00', 'GET', '/download.php?file=../../../../tmp/report.txt', 404),
  L(TR, '03:14:04', 'GET', '/img.php?p=..%2f..%2f..%2ftmp%2fa.png', 404),
];
const scan = [
  L(UA, '03:16:00', 'GET', '/', 200, 'sqlmap/1.7.2#stable (https://sqlmap.org)'),
  L(UA, '03:16:02', 'GET', '/index.php', 200, 'Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:Port Scanner)'),
  L(UA, '03:16:04', 'GET', '/about', 200, 'sqlmap/1.7.2#stable (https://sqlmap.org)'),
  L(UA, '03:16:06', 'GET', '/contact', 200, 'Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:Port Scanner)'),
];
const sens = ['/.env', '/.git/HEAD', '/wp-config.php', '/.git/config', '/wp-config.php.bak'].map((p, i) =>
  L(SP, `03:18:0${i}`, 'GET', p, 404));
const malformed = ['this is not a log line at all', '<<< garbage >>>', '---'];

const FIXTURE: string[] = [
  '# access log rotated 2026-10-08',            // 1
  ...safe.slice(0, 4),                          // 2-5
  '',                                           // 6
  ...bf,                                        // 7-12
  malformed[0],                                 // 13
  ...sqli,                                      // 14-16
  '# comment two',                              // 17
  ...safe.slice(4, 8),                          // 18-21
  '',                                           // 22
  ...trav,                                      // 23-24
  malformed[1],                                 // 25
  '',                                           // 26
  ...scan,                                      // 27-30
  '# comment three',                            // 31
  ...sens,                                      // 32-36
  '',                                           // 37
  malformed[2],                                 // 38
  '# end of file',                              // 39
  '',                                           // 40
];

// Expected table (scores from the B9 formula: weight * min(1 + 0.5*log2(n), 2.5), rounded)
const EXPECTED = [
  { ip: BF, byType: { BRUTE_FORCE: 6 },     main: 'BRUTE_FORCE',     score: 34, rating: 'MEDIUM' }, // 15*2.2925
  { ip: SQ, byType: { SQLI: 3 },            main: 'SQLI',            score: 45, rating: 'MEDIUM' }, // 25*1.7925
  { ip: TR, byType: { TRAVERSAL: 2 },       main: 'TRAVERSAL',       score: 38, rating: 'MEDIUM' }, // 25*1.5
  { ip: UA, byType: { SCANNER_UA: 4 },      main: 'SCANNER_UA',      score: 30, rating: 'MEDIUM' }, // 15*2.0
  { ip: SP, byType: { SENSITIVE_PROBE: 5 }, main: 'SENSITIVE_PROBE', score: 65, rating: 'HIGH' },   // 30*2.161
];

describe('B11 e2e: 40-line fixture', () => {
  it('fixture has exactly 40 lines', () => {
    expect(FIXTURE).toHaveLength(40);
  });

  const text = FIXTURE.join('\n');
  const { res, p } = run(text);

  it('line accounting: 28 parsed, 12 skipped (3 malformed, 4 comments, 5 blank)', () => {
    expect(p.total).toBe(40);
    expect(p.parsed).toBe(28);
    expect(p.skipped).toBe(12);
    expect(res.session.parsedLines).toBe(28);
    expect(res.session.skippedLines).toBe(12);
  });

  it('20 threat events in total', () => {
    expect(res.events).toHaveLength(20);
    expect(res.session.threatCount).toBe(20);
  });

  for (const exp of EXPECTED) {
    it(`${exp.ip}: ${exp.main} score ${exp.score} ${exp.rating}`, () => {
      const s = res.session.summaries.find((x) => x.ip === exp.ip);
      expect(s, `no summary for ${exp.ip}`).toBeDefined();
      expect(nonZero(s!.byType)).toEqual(exp.byType);
      expect(s!.mainThreat).toBe(exp.main);
      expect(s!.score).toBe(exp.score);
      expect(s!.rating).toBe(exp.rating);
    });
  }

  it('the 8 safe IPs are never flagged', () => {
    for (let i = 1; i <= 8; i++) {
      const s = res.session.summaries.find((x) => x.ip === `192.0.2.${i}`);
      if (s) {
        expect(s.threatHits).toBe(0);
        expect(s.rating).toBe('LOW');
      }
    }
  });
});

describe('B11 e2e: line endings, BOM, blanks, comments', () => {
  it('CRLF + BOM + blank + comment lines give the same per-IP results as LF', () => {
    const base = run(FIXTURE.join('\n')).res;
    const crlfText = '\uFEFF' + [safe[0], ...FIXTURE.slice(1)].join('\r\n');
    const crlf = run(crlfText).res;
    const sig = (r: ParseResult) =>
      r.session.summaries.map((s) => [s.ip, s.score, s.rating, s.threatHits]).sort((a, b) => String(a[0]).localeCompare(String(b[0])));
    expect(sig(crlf)).toEqual(sig(base));
    expect(crlf.events).toHaveLength(20);
    expect(crlf.entries.every((e) => !e.raw.includes('\r'))).toBe(true);
  });

  it('parseLine trims a trailing \\r', () => {
    const e = parseLine(safe[0] + '\r', 1);
    expect(e).not.toBeNull();
    expect(e!.ua).toBe('Mozilla/5.0 (X11; Linux x86_64)');
  });

  it('blank, whitespace-only and comment lines return null or are skipped', () => {
    expect(parseLine('', 1)).toBeNull();
    expect(parseLine('# a comment', 2)).toBeNull();
  });

  it('INFO: parseLine directly on a BOM-prefixed line (the Worker must strip the BOM)', () => {
    const e = parseLine('\uFEFF' + safe[0], 1);
    if (e === null) console.log('INFO: parseLine returns null for a BOM-prefixed line -> Rushi\'s Worker must strip \\uFEFF from the first chunk');
    expect(true).toBe(true);
  });
});

describe('B11 e2e: long lines and ReDoS guard', () => {
  it('a line of 8,193+ chars is skipped and counted in skippedLines', () => {
    const base = L('203.0.113.7', '04:00:00', 'GET', '/', 200, '');
    const tooLong = L('203.0.113.7', '04:00:01', 'GET', '/', 200, 'x'.repeat(8300));
    expect(tooLong.length).toBeGreaterThan(8192);
    expect(parseLine(tooLong, 2)).toBeNull();
    const { res, p } = run([base, tooLong].join('\n'));
    expect(p.parsed).toBe(1);
    expect(p.skipped).toBe(1);
    expect(res.session.skippedLines).toBe(1);
  });

  it('a line of exactly 8,192 chars is still parsed', () => {
    const head = L('203.0.113.8', '04:00:02', 'GET', '/', 200, '');
    const exact = L('203.0.113.8', '04:00:02', 'GET', '/', 200, 'x'.repeat(8192 - head.length));
    expect(exact.length).toBe(8192);
    expect(parseLine(exact, 1)).not.toBeNull();
  });

  it('ReDoS: 8,000 x "a" and repeated "%25" parse in < 20 ms', () => {
    const aLine = 'a'.repeat(8000);
    const pctLine = '%25'.repeat(2666);
    const longPath = L('203.0.113.9', '04:00:03', 'GET', '/' + 'a'.repeat(7000), 200);
    const pctQuery = L('203.0.113.9', '04:00:04', 'GET', '/search?q=' + '%25'.repeat(2000), 200);
    expect(bestMs(() => parseLine(aLine, 1))).toBeLessThan(20);
    expect(bestMs(() => parseLine(pctLine, 1))).toBeLessThan(20);
    expect(bestMs(() => parseLine(longPath, 1))).toBeLessThan(20);
    expect(bestMs(() => parseLine(pctQuery, 1))).toBeLessThan(20);
  });

  it('ReDoS: full parse + rules on pathological valid lines stays under 200 ms', () => {
    const lines = [
      L('203.0.113.9', '04:00:03', 'GET', '/' + 'a'.repeat(7000), 200),
      L('203.0.113.9', '04:00:04', 'GET', '/search?q=' + '%25'.repeat(2000), 200),
      L('203.0.113.9', '04:00:05', 'GET', '/x?q=' + "'".repeat(3000), 200),
      L('203.0.113.9', '04:00:06', 'GET', '/' + '../'.repeat(2000), 200),
    ].join('\n');
    expect(bestMs(() => run(lines))).toBeLessThan(200);
  });
});

describe('B11 e2e: timezone', () => {
  it('+0530 and +0000 differ by 19,800,000 ms', () => {
    const utc = parseLine(L('203.0.113.1', '03:12:07', 'GET', '/', 200, 'x', '+0000'), 1);
    const ist = parseLine(L('203.0.113.1', '03:12:07', 'GET', '/', 200, 'x', '+0530'), 2);
    expect(utc).not.toBeNull();
    expect(ist).not.toBeNull();
    expect(utc!.ts - ist!.ts).toBe(19_800_000);
  });

  it('negative offset -0800 is 8 h after UTC', () => {
    const utc = parseLine(L('203.0.113.1', '03:12:07', 'GET', '/', 200, 'x', '+0000'), 1);
    const pst = parseLine(L('203.0.113.1', '03:12:07', 'GET', '/', 200, 'x', '-0800'), 2);
    expect(pst!.ts - utc!.ts).toBe(8 * 3600 * 1000);
  });
});

// ---------- mock-truth.json accuracy (Book 4 C4) ----------
function findFile(dir: string, name: string, depth = 0): string | null {
  if (depth > 6) return null;
  let items: string[];
  try { items = readdirSync(dir); } catch { return null; }
  const skip = new Set(['node_modules', '.git', 'dist', '.vite']);
  for (const it of items) {
    if (skip.has(it)) continue;
    try { if (statSync(join(dir, it)).isFile() && it === name) return join(dir, it); } catch { /* ignore */ }
  }
  for (const it of items) {
    if (skip.has(it)) continue;
    const p = join(dir, it);
    try {
      if (statSync(p).isDirectory()) {
        const hit = findFile(p, name, depth + 1);
        if (hit) return hit;
      }
    } catch { /* ignore */ }
  }
  return null;
}

type Truth = { lineNo: number; attack: boolean; label: string };
const NORMAL_RE = /^(|normal|benign|none|clean|safe|legit|legitimate|false|0|null)$/i;
const LINE_KEYS = ['line', 'lineNo', 'line_no', 'lineNumber', 'index', 'n', 'id'];
const LABEL_KEYS = ['label', 'type', 'types', 'attackType', 'attack_type', 'threat', 'category', 'expected', 'attack'];
const FLAG_KEYS = ['isAttack', 'is_attack', 'malicious', 'attack'];

function labelOf(v: unknown): { attack: boolean; label: string } {
  if (v === null || v === undefined || v === false || v === 0) return { attack: false, label: 'normal' };
  if (v === true) return { attack: true, label: 'attack' };
  if (Array.isArray(v)) return v.length ? { attack: true, label: v.join('+') } : { attack: false, label: 'normal' };
  const s = String(v).trim();
  return NORMAL_RE.test(s) ? { attack: false, label: 'normal' } : { attack: true, label: s };
}

function fromRecord(r: Record<string, unknown>): Truth | null {
  const lk = LINE_KEYS.find((k) => typeof r[k] === 'number');
  if (!lk) return null;
  const flagKey = FLAG_KEYS.find((k) => typeof r[k] === 'boolean');
  const labKey = LABEL_KEYS.find((k) => k in r && typeof r[k] !== 'boolean');
  const lab = labKey ? labelOf(r[labKey]) : { attack: false, label: 'normal' };
  const attack = flagKey ? (r[flagKey] as boolean) : lab.attack;
  return { lineNo: r[lk] as number, attack, label: attack ? (lab.label === 'normal' ? 'attack' : lab.label) : 'normal' };
}

function normalizeTruth(json: unknown): Truth[] {
  if (Array.isArray(json)) {
    if (json.length && json.every((x) => x && typeof x === 'object' && !Array.isArray(x))) {
      const rows = json.map((x) => fromRecord(x as Record<string, unknown>));
      if (rows.every((r) => r !== null)) return rows as Truth[];
    } else {
      return json.map((x, i) => ({ lineNo: i + 1, ...labelOf(x) }));
    }
  } else if (json && typeof json === 'object') {
    const obj = json as Record<string, unknown>;
    for (const key of ['lines', 'labels', 'truth', 'entries', 'records', 'attacks', 'rows']) {
      if (Array.isArray(obj[key])) return normalizeTruth(obj[key]);
    }
    const keys = Object.keys(obj);
    if (keys.length && keys.every((k) => /^\d+$/.test(k))) {
      return keys.map((k) => {
        const v = obj[k];
        if (v && typeof v === 'object' && !Array.isArray(v)) {
          return fromRecord({ line: Number(k), ...(v as Record<string, unknown>) }) as Truth;
        }
        return { lineNo: Number(k), ...labelOf(v) };
      });
    }
  }
  throw new Error('Unrecognised mock-truth.json shape: ' + JSON.stringify(json).slice(0, 400));
}

const typeOf = (label: string) => {
  const s = label.toLowerCase();
  if (/brute|login|auth/.test(s)) return 'BRUTE_FORCE';
  if (/sql/.test(s)) return 'SQLI';
  if (/travers|lfi|\.\./.test(s)) return 'TRAVERSAL';
  if (/scan|ua|sqlmap|nikto|agent/.test(s)) return 'SCANNER_UA';
  if (/sensitive|probe|env|git|config/.test(s)) return 'SENSITIVE_PROBE';
  return label;
};

const truthPath = findFile(process.cwd(), 'mock-truth.json');

describe.skipIf(!truthPath)('B11 e2e: accuracy on the Book 4 mock log', () => {
  it('recall >= 95% on attack lines and false-positive rate <= 1% on normal lines', () => {
    const json = JSON.parse(readFileSync(truthPath!, 'utf8').replace(/^\uFEFF/, ''));

    // locate the mock log next to the truth file (or via a field inside it)
    const dir = dirname(truthPath!);
    let logPath: string | null = null;
    const hint = json && typeof json === 'object'
      ? (json.logFile ?? json.log ?? json.file ?? json.fileName) : undefined;
    if (typeof hint === 'string') logPath = findFile(process.cwd(), basename(hint));
    if (!logPath) {
      const cands = readdirSync(dir).filter((f) => /\.(log|txt)$/i.test(f));
      const pick = cands.find((f) => /mock|demo|sample|access/i.test(f)) ?? cands[0];
      if (pick) logPath = join(dir, pick);
    }
    expect(logPath, `no mock log found next to ${truthPath}`).toBeTruthy();

    const text = readFileSync(logPath!, 'utf8');
    const { res, p } = run(text);
    const flagged = new Set(res.events.map((e) => e.entryId));

    // truth: rows not listed are normal; handle 0-based numbering
    const rows = normalizeTruth(json);
    const shift = rows.length && Math.min(...rows.map((r) => r.lineNo)) === 0 ? 1 : 0;
    const truth = new Map<number, Truth>();
    rows.forEach((r) => truth.set(r.lineNo + shift, r));

    const physical = text.replace(/^\uFEFF/, '').split('\n');
    let TP = 0, FN = 0, FP = 0, TN = 0;
    const perType = new Map<string, { hit: number; miss: number }>();
    const missed: string[] = [];
    const falsePos: string[] = [];

    physical.forEach((line, i) => {
      const lineNo = i + 1;
      if (line.trim() === '' || line.startsWith('#')) return;
      const t = truth.get(lineNo);
      const isAttack = !!t && t.attack;
      const isFlagged = flagged.has(lineNo);
      if (isAttack) {
        const key = typeOf(t!.label);
        const slot = perType.get(key) ?? { hit: 0, miss: 0 };
        if (isFlagged) { TP++; slot.hit++; } else { FN++; slot.miss++; if (missed.length < 10) missed.push(`#${lineNo} [${t!.label}] ${line.slice(0, 160)}`); }
        perType.set(key, slot);
      } else if (isFlagged) {
        FP++; if (falsePos.length < 10) falsePos.push(`#${lineNo} ${line.slice(0, 160)}`);
      } else {
        TN++;
      }
    });

    const recall = TP + FN === 0 ? 0 : TP / (TP + FN);
    const fpr = FP + TN === 0 ? 0 : FP / (FP + TN);

    console.log(`\nMock log: ${logPath} (${p.total} lines, ${p.parsed} parsed, ${p.skipped} skipped)`);
    console.log('CONFUSION MATRIX (line level)');
    console.table({
      'actual attack': { 'flagged': TP, 'not flagged': FN },
      'actual normal': { 'flagged': FP, 'not flagged': TN },
    });
    console.log(`recall = ${(recall * 100).toFixed(2)}%   false-positive rate = ${(fpr * 100).toFixed(2)}%`);
    console.table(Object.fromEntries([...perType.entries()].map(([k, v]) => [k,
      { detected: v.hit, missed: v.miss, recall: `${((v.hit / (v.hit + v.miss)) * 100).toFixed(1)}%` }])));
    if (missed.length) console.log('MISSED ATTACKS (first 10):\n' + missed.join('\n'));
    if (falsePos.length) console.log('FALSE POSITIVES (first 10):\n' + falsePos.join('\n'));

    expect(TP + FN, 'no attack lines found in truth file - check the shape/numbering').toBeGreaterThan(0);
    expect(recall).toBeGreaterThanOrEqual(0.95);
    expect(fpr).toBeLessThanOrEqual(0.01);
  });
});