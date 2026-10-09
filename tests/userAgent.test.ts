import { describe, it, expect } from 'vitest';
import { userAgentRule, SCANNER_TOKENS } from '../src/engine/rules/userAgent';
import type { LogEntry } from '../src/engine/types';

function mk(ua: string, path = '/', status = 200, method = 'GET'): LogEntry {
  return { id: 1, ip: '1.2.3.4', ts: 0, method, path, query: '', proto: 'HTTP/1.1', status, bytes: 0, referer: '', ua, raw: '' };
}

const CHROME = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36';

describe('scanner user agent rule', () => {
  it.each([
    ['sqlmap/1.7', 'sqlmap user agent'],
    ['Nikto/2.1.6', 'nikto user agent'],
    ['Mozilla/5.00 (Nikto/2.1.6) (Evasions:None)', 'nikto user agent'],
    ['gobuster/3.5', 'gobuster user agent'],
  ])('strong match: %s', (ua, evidence) => {
    const ev = userAgentRule.evaluate(mk(ua));
    expect(ev?.severity).toBe(3);
    expect(ev?.type).toBe('SCANNER_UA');
    expect(ev?.evidence).toBe(evidence);
  });

  it('nmap followed by a space is detected', () => {
    const ev = userAgentRule.evaluate(mk('Nmap Scripting Engine'));
    expect(ev?.severity).toBe(3);
    expect(ev?.evidence).toBe('nmap user agent');
  });

  it("'Snmapp' is NOT detected (word boundary)", () => {
    expect(userAgentRule.evaluate(mk('Snmapp/1.0', '/x', 404))).toBeNull();
  });

  it('python-requests on GET /api/items 200 -> no event', () => {
    expect(userAgentRule.evaluate(mk('python-requests/2.31', '/api/items', 200))).toBeNull();
  });

  it('python-requests on POST /wp-login.php 200 -> event, severity 1', () => {
    const ev = userAgentRule.evaluate(mk('python-requests/2.31', '/wp-login.php', 200, 'POST'));
    expect(ev?.severity).toBe(1);
    expect(ev?.evidence).toBe('python-requests user agent');
  });

  it('curl on a 404 -> event', () => {
    const ev = userAgentRule.evaluate(mk('curl/8.0', '/x', 404));
    expect(ev?.severity).toBe(1);
    expect(ev?.evidence).toBe('curl user agent');
  });

  it('Java client on a 404 -> evidence has no version digits', () => {
    expect(userAgentRule.evaluate(mk('Java/11.0.1', '/x', 404))?.evidence).toBe('java user agent');
  });

  it('wget on /.env with 200 -> event (probing path)', () => {
    expect(userAgentRule.evaluate(mk('Wget/1.21', '/.env', 200))?.severity).toBe(1);
  });

  it('empty UA on /.env 404 -> event', () => {
    const ev = userAgentRule.evaluate(mk('', '/.env', 404));
    expect(ev?.severity).toBe(1);
    expect(ev?.evidence).toBe('Empty user agent');
  });

  it('empty UA on / with 200 -> no event', () => {
    expect(userAgentRule.evaluate(mk('', '/', 200))).toBeNull();
  });

  it('normal Chrome UA -> no event, even on a 404 probe', () => {
    expect(userAgentRule.evaluate(mk(CHROME, '/wp-login.php', 404))).toBeNull();
  });

  it('SCANNER_TOKENS is lower-case and includes the main tools', () => {
    expect(SCANNER_TOKENS).toContain('sqlmap');
    expect(SCANNER_TOKENS).toContain('nikto');
    expect(SCANNER_TOKENS.every((t) => t === t.toLowerCase())).toBe(true);
  });

  it('event has the right ids', () => {
    const ev = userAgentRule.evaluate(mk('sqlmap/1.7'));
    expect(ev).toMatchObject({ id: '1:R3_SCANNER_UA', entryId: 1, ip: '1.2.3.4', ruleId: 'R3_SCANNER_UA' });
  });
});
