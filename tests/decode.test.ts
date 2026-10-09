import { describe, it, expect } from 'vitest';
import { normalizeTarget, isDoubleEncoded } from '../src/engine/decode';

describe('normalizeTarget', () => {
  it('decodes a SQL injection payload', () => {
    const r = normalizeTarget('/', 'id=1%27%20OR%201%3D1--');
    expect(r.decoded).toContain("' or 1=1--");
    expect(r.layers).toBe(1);
  });

  it('decodes double-encoded traversal and counts 2 layers', () => {
    const r = normalizeTarget('/..%252f..%252fetc%252fpasswd', '');
    expect(r.decoded).toContain('../../etc/passwd');
    expect(r.layers).toBe(2);
    expect(isDoubleEncoded(r.layers)).toBe(true);
  });

  it('collapses SQL inline comments', () => {
    const r = normalizeTarget('/', 'id=1 UNION/**/SELECT/**/user()');
    expect(r.decoded).toContain('union select');
  });

  it('does not throw on malformed percent sequences', () => {
    expect(() => normalizeTarget('/x%E0%A4%A', '')).not.toThrow();
    expect(() => normalizeTarget('/%', 'a=%zz%')).not.toThrow();
  });

  it('removes NUL bytes', () => {
    const r = normalizeTarget('/a%00.php', '');
    expect(r.decoded).toBe('/a.php');
  });

  it('turns + into space only in the query', () => {
    expect(normalizeTarget('/s', 'q=a+b').decoded).toBe('/s?q=a b');
    expect(normalizeTarget('/a+b', '').decoded).toBe('/a+b');
  });

  it('converts backslashes and keeps raw untouched', () => {
    const r = normalizeTarget('/download', 'f=..\\..\\windows\\win.ini');
    expect(r.decoded).toContain('../../windows/win.ini');
    expect(r.raw).toBe('/download?f=..\\..\\windows\\win.ini');
  });

  it('caps output at 4096 characters', () => {
    expect(normalizeTarget('/' + 'a'.repeat(10000), '').decoded.length).toBeLessThanOrEqual(4096);
  });

  it('plain text has 0 layers', () => {
    const r = normalizeTarget('/index.html', '');
    expect(r.layers).toBe(0);
    expect(isDoubleEncoded(r.layers)).toBe(false);
  });
});
