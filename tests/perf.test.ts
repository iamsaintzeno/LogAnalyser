import { describe, it, expect } from 'vitest';
import { analyze } from '../src/engine/analyze';
import type { LogEntry } from '../src/engine/types';

const T0 = Date.UTC(2026, 0, 1, 0, 0, 0);
const PATHS = ['/', '/index.html', '/about', '/api/items', '/blog/post-1', '/static/app.js', '/contact', '/products/42'];
const BAD = ['/.env', '/wp-login.php', '/phpmyadmin/', '/search?q=1 union select 1', '/x?f=../../etc/passwd'];

function gen(n: number): LogEntry[] {
  const out: LogEntry[] = [];
  for (let i = 0; i < n; i++) {
    const bad = i % 20 === 0;
    const raw = bad ? BAD[i % BAD.length] : PATHS[i % PATHS.length];
    const q = raw.indexOf('?');
    out.push({
      id: i,
      ip: `10.${(i * 7) % 250}.${(i * 13) % 250}.${(i % 200) + 1}`,
      ts: T0 + i * 800,
      method: raw.startsWith('/wp-login') ? 'POST' : 'GET',
      path: q === -1 ? raw : raw.slice(0, q),
      query: q === -1 ? '' : raw.slice(q + 1),
      proto: 'HTTP/1.1',
      status: bad ? 404 : 200,
      bytes: 512,
      referer: '',
      ua: i % 50 === 0 ? 'sqlmap/1.7' : 'Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0 Safari/537.36',
      raw: '',
    });
  }
  return out;
}

const BUDGET_MS = Number(process.env.PERF_BUDGET_MS) || 1500;

describe('performance', () => {
  it('100,000 entries analysed in under 1.5 s', () => {
    const entries = gen(100000);
    const t = performance.now();
    const r = analyze(entries, { fileName: 'perf.log', fileSize: 1, totalLines: 100000 });
    const ms = performance.now() - t;
    console.log(`analyze 100k entries: ${ms.toFixed(0)} ms, ${r.events.length} events`);
    expect(r.events.length).toBeGreaterThan(0);
    expect(ms).toBeLessThan(BUDGET_MS);
  });
});

