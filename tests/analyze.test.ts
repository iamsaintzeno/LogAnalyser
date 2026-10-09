import { describe, it, expect } from 'vitest';
import { analyze, createAnalyzer } from '../src/engine/analyze';
import { runRules, runRulesDetailed } from '../src/engine/runRules';
import type { LogEntry } from '../src/engine/types';

const T0 = Date.UTC(2026, 0, 1, 3, 0, 0);
const META = { fileName: 't.log', fileSize: 1, totalLines: 0, createdAt: 1, id: 'x' };
let nextId = 1;

function mk(ip: string, path: string, o: Partial<LogEntry> = {}): LogEntry {
  return { id: nextId++, ip, ts: T0, method: 'GET', path, query: '', proto: 'HTTP/1.1', status: 404, bytes: 0, referer: '', ua: 'Mozilla/5.0 Chrome/120', raw: '', ...o };
}

describe('runRules', () => {
  it('flags sensitive file, sqli, scanner UA, traversal', () => {
    const entries = [
      mk('1.1.1.1', '/.env'),
      mk('2.2.2.2', '/search', { query: 'id=1 UNION SELECT 1,2,3--', status: 200 }),
      mk('3.3.3.3', '/', { ua: 'sqlmap/1.7' }),
      mk('4.4.4.4', '/download', { query: 'file=../../../../etc/passwd' }),
      mk('5.5.5.5', '/index.html', { status: 200 }),
    ];
    const ev = runRules(entries);
    const types = ev.map((e) => e.type).sort();
    expect(types).toEqual(['SCANNER_UA', 'SENSITIVE_PROBE', 'SQLI', 'TRAVERSAL']);
    expect(ev.find((e) => e.ip === '5.5.5.5')).toBeUndefined();
  });

  it('brute force: 6 failed logins in a minute', () => {
    const entries = Array.from({ length: 6 }, (_, i) => mk('9.9.9.9', '/wp-login.php', { method: 'POST', status: 200, ts: T0 + i * 1000 }));
    const ev = runRules(entries);
    expect(ev.filter((e) => e.type === 'BRUTE_FORCE').length).toBe(6);
  });

  it('allowlisted IP is skipped', () => {
    const ev = runRules([mk('1.1.1.1', '/.env')], [], new Set(['1.1.1.1']));
    expect(ev.length).toBe(0);
  });

  it('override can disable a rule', () => {
    const ev = runRules([mk('1.1.1.1', '/.env')], [{ ruleId: 'R4_SENSITIVE_PROBE', enabled: false }]);
    expect(ev.length).toBe(0);
  });

  it('override changes brute-force threshold', () => {
    const entries = Array.from({ length: 3 }, (_, i) => mk('9.9.9.9', '/wp-login.php', { method: 'POST', status: 200, ts: T0 + i * 1000 }));
    expect(runRules(entries).length).toBe(0);
    expect(runRules(entries, [{ ruleId: 'R1_BRUTE_FORCE', enabled: true, threshold: 3 }]).length).toBe(3);
  });

  it('unknown ruleId override is ignored', () => {
    expect(() => runRules([mk('1.1.1.1', '/.env')], [{ ruleId: 'NOPE', enabled: false }])).not.toThrow();
  });

  it('event ids are `${entryId}:${ruleId}`', () => {
    const e = mk('1.1.1.1', '/.env');
    expect(runRules([e])[0].id).toBe(`${e.id}:R4_SENSITIVE_PROBE`);
  });

  it('a broken entry never crashes the run', () => {
    const bad = { id: 999, ip: '1.1.1.1', ts: T0, status: 200, ua: '', query: '' } as unknown as LogEntry;
    Object.defineProperty(bad, 'path', { get() { throw new Error('boom'); } });
    const r = runRulesDetailed([bad, mk('2.2.2.2', '/.env')]);
    expect(r.ruleErrors).toBeGreaterThan(0);
    expect(r.events.length).toBe(1);
  });
});

describe('analyze', () => {
  it('builds summaries, scores, timeline and session', () => {
    const entries = [
      mk('1.1.1.1', '/.env', { status: 200 }),
      mk('1.1.1.1', '/index.html', { status: 200, ts: T0 + 60000 }),
      mk('1.1.1.1', '/', { ua: 'nikto/2.1', ts: T0 + 120000 }),
      mk('7.7.7.7', '/home', { status: 200 }),
    ];
    const r = analyze(entries, { ...META, totalLines: 5, skippedLines: 1 });
    expect(r.session.summaries.length).toBe(1);
    const s = r.session.summaries[0];
    expect(s.ip).toBe('1.1.1.1');
    expect(s.totalHits).toBe(3); // all entries of that IP, not just flagged
    expect(s.threatHits).toBe(2);
    expect(s.firstSeen).toBe(T0);
    expect(s.lastSeen).toBe(T0 + 120000);
    // SENSITIVE 30 + SCANNER 15 + exposed 10 = 55
    expect(s.score).toBe(55);
    expect(s.rating).toBe('MEDIUM');
    expect(s.mainThreat).toBe('SENSITIVE_PROBE');
    expect(r.session.threatCount).toBe(2);
    expect(r.session.skippedLines).toBe(1);
    expect(r.session.parsedLines).toBe(4);
    expect(r.entries.length).toBe(2); // flagged only
    expect(r.session.timeline.length).toBe(1);
    expect(r.session.timeline[0].total).toBe(2);
    expect(r.session.timeline[0].t % 300000).toBe(0);
  });

  it('streaming createAnalyzer in chunks gives the same result as analyze', () => {
    const entries = [
      ...Array.from({ length: 6 }, (_, i) => mk('9.9.9.9', '/wp-login.php', { method: 'POST', status: 200, ts: T0 + i * 1000 })),
      mk('9.9.9.9', '/wp-login.php', { method: 'POST', status: 302, ts: T0 + 20000 }),
      mk('1.1.1.1', '/.env'),
      mk('2.2.2.2', '/', { ua: 'gobuster/3.5' }),
    ];
    const whole = analyze(entries, META);
    const a = createAnalyzer();
    a.push(entries.slice(0, 3));
    a.push(entries.slice(3, 6));
    a.push(entries.slice(6));
    const streamed = a.finish(META);
    expect(streamed.session.summaries).toEqual(whole.session.summaries);
    expect(streamed.events).toEqual(whole.events);
    const nine = whole.session.summaries.find((s) => s.ip === '9.9.9.9')!;
    // 7 events (6 failures + 1 takeover): 15 * min(1+0.5*log2(7), 2.5) = 36.1 + 20 takeover = 56
    expect(nine.byType.BRUTE_FORCE).toBe(7);
    expect(nine.score).toBe(56);
  });

  it('empty input is fine', () => {
    const r = analyze([], META);
    expect(r.events).toEqual([]);
    expect(r.session.summaries).toEqual([]);
    expect(r.session.timeline).toEqual([]);
  });

  it('flagged entries are capped at 20,000', () => {
    const entries = Array.from({ length: 21000 }, (_, i) => mk('1.1.1.1', '/.env', { ts: T0 + i }));
    expect(analyze(entries, META).entries.length).toBe(20000);
  });
});
