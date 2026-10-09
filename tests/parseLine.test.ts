import { describe, it, expect } from 'vitest';
import { parseLine, parseTimestamp } from '../src/engine/parseLine';

const SAMPLE = '203.0.113.45 - - [08/Oct/2026:03:12:07 +0000] "POST /wp-login.php HTTP/1.1" 200 4521 "https://example.com/wp-login.php" "Mozilla/5.0 (X11; Linux x86_64)"';

describe('parseLine', () => {
  it('1: parses a combined log line', () => {
    const e = parseLine(SAMPLE, 7);
    expect(e).not.toBeNull();
    expect(e).toMatchObject({
      id: 7,
      ip: '203.0.113.45',
      ts: 1791429127000,
      method: 'POST',
      path: '/wp-login.php',
      query: '',
      proto: 'HTTP/1.1',
      status: 200,
      bytes: 4521,
      referer: 'https://example.com/wp-login.php',
      ua: 'Mozilla/5.0 (X11; Linux x86_64)',
    });
  });

  it('2: parses a common log line without referer and UA', () => {
    const e = parseLine('203.0.113.9 - - [08/Oct/2026:03:12:07 +0000] "GET /index.html?a=1&b=2 HTTP/1.0" 200 -', 1);
    expect(e).toMatchObject({ path: '/index.html', query: 'a=1&b=2', proto: 'HTTP/1.0', bytes: 0, referer: '', ua: '' });
  });

  it('3: parses an IPv6 client', () => {
    const e = parseLine('2001:db8::1 - - [08/Oct/2026:03:12:07 +0000] "GET / HTTP/1.1" 200 10 "-" "curl/8.0"', 1);
    expect(e?.ip).toBe('2001:db8::1');
    expect(e?.ua).toBe('curl/8.0');
    expect(e?.referer).toBe('');
  });

  it('4: handles an empty request ("-" 408)', () => {
    const e = parseLine('1.2.3.4 - - [08/Oct/2026:03:12:07 +0000] "-" 408 0 "-" "-"', 1);
    expect(e).toMatchObject({ method: 'UNKNOWN', path: '/', status: 408, bytes: 0 });
  });

  it('5: handles a binary garbage request', () => {
    const line = String.raw`1.2.3.4 - - [08/Oct/2026:03:12:07 +0000] "\x16\x03\x01\x02\x00" 400 150 "-" "-"`;
    const e = parseLine(line, 1);
    expect(e).toMatchObject({ method: 'UNKNOWN', path: '/', status: 400 });
  });

  it('6: does not crash on a URL with spaces', () => {
    const e = parseLine('1.2.3.4 - - [08/Oct/2026:03:12:07 +0000] "GET /my page.html HTTP/1.1" 404 0 "-" "-"', 1);
    expect(e).not.toBeNull();
    expect(e?.status).toBe(404);
  });

  it('7: converts +0530 and -0800 timestamps exactly', () => {
    expect(parseTimestamp('08/Oct/2026:03:12:07 +0000')).toBe(1791429127000);
    expect(parseTimestamp('08/Oct/2026:03:12:07 +0530')).toBe(1791429127000 - 19800000);
    expect(parseTimestamp('08/Oct/2026:03:12:07 -0800')).toBe(1791429127000 + 28800000);
  });

  it('8: rejects an invalid month', () => {
    expect(parseTimestamp('08/Foo/2026:03:12:07 +0000')).toBeNull();
    expect(parseLine('1.2.3.4 - - [08/Foo/2026:03:12:07 +0000] "GET / HTTP/1.1" 200 1', 1)).toBeNull();
  });

  it('9: rejects a truncated line', () => {
    expect(parseLine('203.0.113.45 - - [08/Oct/2026:03:12:07 +0000] "GET /x', 1)).toBeNull();
  });

  it('10: returns null for a 20,000 character line', () => {
    expect(parseLine('a'.repeat(20000), 1)).toBeNull();
  });

  it('11: skips empty lines and comments, trims trailing CR', () => {
    expect(parseLine('', 1)).toBeNull();
    expect(parseLine('# comment', 1)).toBeNull();
    expect(parseLine(SAMPLE + '\r', 1)?.ua).toBe('Mozilla/5.0 (X11; Linux x86_64)');
  });

  it('12: rejects an invalid IP', () => {
    expect(parseLine('999.1.1.1 - - [08/Oct/2026:03:12:07 +0000] "GET / HTTP/1.1" 200 1', 1)).toBeNull();
  });
});
