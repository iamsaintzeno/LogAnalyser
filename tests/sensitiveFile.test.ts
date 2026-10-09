import { describe, it, expect } from 'vitest';
import { sensitiveFileRule } from '../src/engine/rules/sensitiveFile';
import type { LogEntry } from '../src/engine/types';

function mk(path: string, status = 404, query = ''): LogEntry {
  return { id: 1, ip: '1.2.3.4', ts: 0, method: 'GET', path, query, proto: 'HTTP/1.1', status, bytes: 0, referer: '', ua: 'x', raw: '' };
}

describe('sensitive file rule', () => {
  it.each([
    '/.env',
    '/.env.production',
    '/.git/HEAD',
    '/wp-config.php.bak',
    '/backup.sql',
    '/phpmyadmin/index.php',
    '/%2e%65nv',
    '/WP-CONFIG.PHP',
  ])('probe detected: %s (404 -> severity 2)', (p) => {
    const ev = sensitiveFileRule.evaluate(mk(p, 404));
    expect(ev).not.toBeNull();
    expect(ev?.type).toBe('SENSITIVE_PROBE');
    expect(ev?.ruleId).toBe('R4_SENSITIVE_PROBE');
    expect(ev?.severity).toBe(2);
  });

  it('200 means the file is exposed -> severity 3 + EXPOSED evidence', () => {
    const ev = sensitiveFileRule.evaluate(mk('/.env', 200));
    expect(ev?.severity).toBe(3);
    expect(ev?.evidence.startsWith('EXPOSED:')).toBe(true);
  });

  it('206 also counts as exposed', () => {
    expect(sensitiveFileRule.evaluate(mk('/backup.sql', 206))?.severity).toBe(3);
  });

  it('403 is an attempted probe', () => {
    expect(sensitiveFileRule.evaluate(mk('/.git/config', 403))?.severity).toBe(2);
  });

  it.each([
    '/environment-news',
    '/blog/git-tutorial',
    '/wp-content/uploads/2024/report.zip',
    '/assets/app.js.map',
    '/index.html',
    '/static/files/archive.zip',
  ])('SAFE: %s is not flagged', (p) => {
    expect(sensitiveFileRule.evaluate(mk(p, 200))).toBeNull();
  });

  it('a normal zip outside the safe folders IS flagged', () => {
    expect(sensitiveFileRule.evaluate(mk('/downloads/site-copy.zip', 200))).not.toBeNull();
  });

  it('query string is ignored', () => {
    expect(sensitiveFileRule.evaluate(mk('/search', 200, 'q=.env'))).toBeNull();
  });

  it('event id and fields are filled', () => {
    const ev = sensitiveFileRule.evaluate(mk('/.env'));
    expect(ev?.id).toBe('1:R4_SENSITIVE_PROBE');
    expect(ev?.entryId).toBe(1);
    expect(ev?.ip).toBe('1.2.3.4');
  });
});
