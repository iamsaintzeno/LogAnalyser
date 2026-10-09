import { describe, it, expect } from 'vitest';
import { sqliRule, traversalRule } from '../src/engine/rules/injection';
import type { LogEntry } from '../src/engine/types';

function mk(target: string, status = 200): LogEntry {
  const q = target.indexOf('?');
  const path = q === -1 ? target : target.slice(0, q);
  const query = q === -1 ? '' : target.slice(q + 1);
  return { id: 1, ip: '1.2.3.4', ts: 0, method: 'GET', path, query, proto: 'HTTP/1.1', status, bytes: 0, referer: '', ua: '', raw: '' };
}

describe('SQL injection rule', () => {
  it.each([
    '/?id=1%27%20OR%201%3D1--',
    '/?id=1 UNION SELECT 1,2,3',
    '/?id=1/**/UNION/**/SELECT/**/user()',
    "/?q=1' AND SLEEP(5)--",
  ])('flags %s', (target) => {
    const ev = sqliRule.evaluate(mk(target));
    expect(ev).not.toBeNull();
    expect(ev?.severity).toBe(3);
    expect(ev?.type).toBe('SQLI');
    expect(ev?.ruleId).toBe('R2A_SQLI');
  });

  it('evidence starts with the rule name', () => {
    const ev = sqliRule.evaluate(mk('/?id=1 UNION SELECT 1,2,3'));
    expect(ev?.evidence.startsWith('UNION SELECT: ')).toBe(true);
    expect(ev?.evidence).toContain('union select');
  });

  it('flags 2 weak signals (quote + comment) with severity 2', () => {
    expect(sqliRule.evaluate(mk("/?id=1'--"))?.severity).toBe(2);
  });

  it('flags 1 weak signal when status is 500', () => {
    expect(sqliRule.evaluate(mk("/search?q=o'brien", 500))?.severity).toBe(2);
  });
});

describe('Path traversal rule', () => {
  it.each([
    '/index.php?page=../../../../etc/passwd',
    '/..%2f..%2fetc/passwd',
    '/%252e%252e%252fetc%252fpasswd',
    '/download?f=..\\..\\windows\\win.ini',
  ])('flags %s with severity 3', (target) => {
    const ev = traversalRule.evaluate(mk(target));
    expect(ev).not.toBeNull();
    expect(ev?.severity).toBe(3);
    expect(ev?.type).toBe('TRAVERSAL');
  });

  it('double encoding is mentioned in the evidence', () => {
    const ev = traversalRule.evaluate(mk('/%252e%252e%252fetc%252fpasswd'));
    expect(ev?.evidence).toContain('double encoded');
  });

  it('traversal without a system file is severity 2', () => {
    expect(traversalRule.evaluate(mk('/a/../b'))?.severity).toBe(2);
  });
});

describe('safe URLs are NOT flagged by either rule', () => {
  it.each([
    "/search?q=o'brien",
    '/blog/how-to-select-a-plan',
    '/?s=union+station',
    '/products?category=select',
    '/wp-content/uploads/2024/a..b.jpg',
    '/?q=1--2',
    '/search?q=o%27brien',
  ])('%s', (target) => {
    expect(sqliRule.evaluate(mk(target))).toBeNull();
    expect(traversalRule.evaluate(mk(target))).toBeNull();
  });
});
