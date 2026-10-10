import { describe, expect, it } from 'vitest';
import { MAX_LOG_LINE_LENGTH, parseLogLine } from '../src/engine/parseLine';

describe('Apache/Nginx Common and Combined line parsing', () => {
  it('parses a Common format line with its timestamp converted to UTC', () => {
    const line = '203.0.113.10 - alice [15/Jan/2026:12:34:56 +0000] "GET /login?next=%2Fhome HTTP/1.1" 404 123';

    expect(parseLogLine(line, 7)).toEqual({
      id: 7,
      ip: '203.0.113.10',
      ts: Date.UTC(2026, 0, 15, 12, 34, 56),
      method: 'GET',
      path: '/login',
      query: 'next=%2Fhome',
      proto: 'HTTP/1.1',
      status: 404,
      bytes: 123,
      referer: '',
      ua: '',
      raw: line,
    });
  });

  it('parses Combined format fields, escaped quotes, and an IPv6 client address', () => {
    const line = '2001:db8::1 - - [15/Jan/2026:12:34:56 -0700] "POST /search?q=one HTTP/1.1" 200 - "https://site.test/a\\"b" "Agent \\"X\\""';
    const parsed = parseLogLine(line, 8);

    expect(parsed).not.toBeNull();
    expect(parsed).toMatchObject({
      id: 8,
      ip: '2001:db8::1',
      ts: Date.UTC(2026, 0, 15, 19, 34, 56),
      method: 'POST',
      path: '/search',
      query: 'q=one',
      proto: 'HTTP/1.1',
      status: 200,
      bytes: 0,
      referer: 'https://site.test/a"b',
      ua: 'Agent "X"',
    });
    expect(parsed?.raw).toBe(line);
  });

  it('returns null for malformed Common or incomplete Combined lines', () => {
    expect(parseLogLine('not an access log line', 1)).toBeNull();
    expect(parseLogLine('203.0.113.1 - - [31/Feb/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 1', 2)).toBeNull();
    expect(parseLogLine('203.0.113.1 - - [15/Jan/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 1 "referer only"', 3)).toBeNull();
  });

  it('rejects overlong input before parsing and accepts a line at the configured limit', () => {
    const prefix = '203.0.113.1 - - [15/Jan/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "';
    const suffix = '"';
    const exactLimitLine = `${prefix}${'a'.repeat(MAX_LOG_LINE_LENGTH - prefix.length - suffix.length)}${suffix}`;

    expect(exactLimitLine).toHaveLength(MAX_LOG_LINE_LENGTH);
    expect(parseLogLine(exactLimitLine, 4)?.ua.length).toBe(MAX_LOG_LINE_LENGTH - prefix.length - suffix.length);
    expect(parseLogLine(`${exactLimitLine}x`, 5)).toBeNull();
  });
});
