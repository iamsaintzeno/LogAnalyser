import { describe, it, expect } from 'vitest';
import { bruteForceRule, isAuthFailure } from '../src/engine/rules/bruteForce';
import type { LogEntry, RuleConfig } from '../src/engine/types';

const cfg: RuleConfig = { enabled: true, weight: 15 };
let nextId = 1;

function mk(ip: string, sec: number, path: string, status: number, method = 'POST'): LogEntry {
  return { id: nextId++, ip, ts: sec * 1000, method, path, query: '', proto: 'HTTP/1.1', status, bytes: 0, referer: '', ua: '', raw: '' };
}
function fails(ip: string, secs: number[], path = '/wp-login.php', status = 200, method = 'POST'): LogEntry[] {
  return secs.map((s) => mk(ip, s, path, status, method));
}
const run = (entries: LogEntry[], c = cfg) => bruteForceRule.evaluateAll(entries, c);

describe('brute force rule', () => {
  it('4 failures in 60s -> 0 events', () => {
    expect(run(fails('1.1.1.1', [0, 10, 20, 30]))).toHaveLength(0);
  });

  it('5 failures in 60s -> 5 events, severity 2', () => {
    const ev = run(fails('1.1.1.1', [0, 10, 20, 30, 40]));
    expect(ev).toHaveLength(5);
    expect(ev.every((e) => e.severity === 2 && e.type === 'BRUTE_FORCE')).toBe(true);
    expect(ev[0].evidence).toBe('5 failed auth requests in 60s');
  });

  it('5 failures spread over 5 minutes -> 0 events', () => {
    expect(run(fails('1.1.1.1', [0, 75, 150, 225, 300]))).toHaveLength(0);
  });

  it('two IPs interleaved: only the one with 5 is flagged', () => {
    const a = fails('1.1.1.1', [0, 2, 4, 6, 8]);
    const b = fails('2.2.2.2', [1, 3, 5, 7]);
    const ev = run([...a, ...b]);
    expect(ev).toHaveLength(5);
    expect(ev.every((e) => e.ip === '1.1.1.1')).toBe(true);
  });

  it('xmlrpc multicall x6 -> 6 events', () => {
    expect(run(fails('3.3.3.3', [0, 1, 2, 3, 4, 5], '/xmlrpc.php', 200))).toHaveLength(6);
  });

  it('successful 302 right after a burst -> takeover event', () => {
    const entries = [...fails('4.4.4.4', [0, 1, 2, 3, 4]), mk('4.4.4.4', 60, '/wp-login.php', 302)];
    const ev = run(entries);
    expect(ev).toHaveLength(6);
    const t = ev.find((e) => e.evidence.includes('takeover'));
    expect(t?.severity).toBe(3);
  });

  it('successful 302 too late -> no takeover event', () => {
    const entries = [...fails('4.4.4.4', [0, 1, 2, 3, 4]), mk('4.4.4.4', 300, '/wp-login.php', 302)];
    expect(run(entries)).toHaveLength(5);
  });

  it('unsorted input still works', () => {
    expect(run(fails('5.5.5.5', [40, 0, 30, 10, 20]))).toHaveLength(5);
  });

  it('threshold and windowSec overrides are respected', () => {
    const three = fails('6.6.6.6', [0, 4, 8]);
    expect(run(three)).toHaveLength(0);
    expect(run(three, { ...cfg, threshold: 3, windowSec: 10 })).toHaveLength(3);
    expect(run(fails('7.7.7.7', [0, 30]), { ...cfg, threshold: 2, windowSec: 10 })).toHaveLength(0);
  });

  it('15 failures in 15s -> severity 3', () => {
    const secs = Array.from({ length: 15 }, (_, i) => i);
    const ev = run(fails('8.8.8.8', secs));
    expect(ev).toHaveLength(15);
    expect(ev.every((e) => e.severity === 3)).toBe(true);
  });

  it('disabled rule returns nothing', () => {
    expect(run(fails('1.1.1.1', [0, 1, 2, 3, 4]), { ...cfg, enabled: false })).toHaveLength(0);
  });

  it('non-auth paths are ignored', () => {
    expect(run(fails('9.9.9.9', [0, 1, 2, 3, 4, 5], '/api/items', 401))).toHaveLength(0);
  });

  it('isAuthFailure covers the documented cases', () => {
    expect(isAuthFailure(mk('1.1.1.1', 0, '/wp-login.php', 200, 'GET'))).toBe(false);
    expect(isAuthFailure(mk('1.1.1.1', 0, '/login', 401, 'GET'))).toBe(true);
    expect(isAuthFailure(mk('1.1.1.1', 0, '/login', 200, 'POST'))).toBe(true);
    expect(isAuthFailure(mk('1.1.1.1', 0, '/xmlrpc.php', 405, 'POST'))).toBe(true);
    expect(isAuthFailure(mk('1.1.1.1', 0, '/wp-login.php', 302, 'POST'))).toBe(false);
  });
});

