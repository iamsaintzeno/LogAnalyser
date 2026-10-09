import { describe, expect, it } from 'vitest';
import type { LogEntry } from '../src/contracts';
import { decodeOnceSafely } from '../src/engine/decode';
import { BRUTE_FORCE_MIN_REQUESTS, BRUTE_FORCE_WINDOW_MS, findBruteForceEntries } from '../src/engine/rules/bruteForce';
import { matchesSqlInjection } from '../src/engine/rules/injection';
import { SENSITIVE_PATHS, matchesSensitivePath } from '../src/engine/rules/sensitiveFile';
import { matchesTraversal } from '../src/engine/rules/traversal';
import { SCANNER_USER_AGENT_TOKENS, findScannerToken, matchesScannerUserAgent } from '../src/engine/rules/userAgent';
import { runRules } from '../src/engine/runRules';

function entry(index: number, changes: Partial<LogEntry> = {}): LogEntry {
  return {
    id: index,
    ip: '203.0.113.1',
    ts: 1_000_000 + index,
    method: 'GET',
    path: '/home',
    query: '',
    proto: 'HTTP/1.1',
    status: 200,
    bytes: 10,
    referer: '',
    ua: 'Browser',
    raw: `line-${index}`,
    ...changes,
  };
}

function failedPosts(count: number, timestampFor: (index: number) => number = (index) => 100_000 + index): LogEntry[] {
  return Array.from({ length: count }, (_, index) => entry(index + 1, {
    ts: timestampFor(index),
    method: 'POST',
    status: index % 2 === 0 ? 401 : 403,
  }));
}

describe('approved detection rules', () => {
  it('marks the exact ten-request threshold, groups by IP and exact path, and requires failed POSTs', () => {
    expect(BRUTE_FORCE_MIN_REQUESTS).toBe(10);
    const nine = failedPosts(9);
    expect(findBruteForceEntries(nine).size).toBe(0);
    expect(findBruteForceEntries(failedPosts(10)).size).toBe(10);

    const splitByPath = failedPosts(9).concat(entry(10, {
      ts: 200_000,
      method: 'POST',
      status: 401,
      path: '/different',
    }));
    expect(findBruteForceEntries(splitByPath).size).toBe(0);
    const splitByIP = failedPosts(9).concat(entry(10, {
      ts: 200_000,
      method: 'POST',
      status: 401,
      ip: '203.0.113.2',
    }));
    expect(findBruteForceEntries(splitByIP).size).toBe(0);

    const nonPost = failedPosts(9).concat(entry(10, { ts: 200_000, status: 401 }));
    expect(findBruteForceEntries(nonPost).size).toBe(0);
    const nonFailure = failedPosts(9).concat(entry(10, { ts: 200_000, method: 'POST', status: 200 }));
    expect(findBruteForceEntries(nonFailure).size).toBe(0);
  });

  it('includes the five-minute endpoint and excludes requests one millisecond beyond it', () => {
    const atBoundary = failedPosts(10, (index) => index === 9 ? 100_000 + BRUTE_FORCE_WINDOW_MS : 100_000 + index);
    const beyondBoundary = failedPosts(10, (index) => index === 9 ? 100_001 + BRUTE_FORCE_WINDOW_MS : 100_000 + index);

    expect(findBruteForceEntries(atBoundary).size).toBe(10);
    expect(findBruteForceEntries(beyondBoundary).size).toBe(0);
  });

  it('matches the approved SQL indicators without case sensitivity', () => {
    for (const query of ['id=UNION SELECT password', 'id=or 1=1', 'id=1--', 'id=/*comment*/']) {
      expect(matchesSqlInjection(entry(1, { query }))).toBe(true);
    }
    expect(matchesSqlInjection(entry(2, { query: 'id=ordinary-value' }))).toBe(false);
    expect(matchesSqlInjection(entry(3, { query: 'color 1=1' }))).toBe(false);
  });

  it('uses the explicit scanner-token and sensitive-path lists', () => {
    expect(SCANNER_USER_AGENT_TOKENS).toEqual([
      'sqlmap', 'nikto', 'nmap', 'masscan', 'zgrab', 'gobuster', 'ffuf', 'dirbuster', 'wpscan', 'nuclei',
    ]);
    for (const token of SCANNER_USER_AGENT_TOKENS) {
      expect(findScannerToken(`Test ${token.toUpperCase()} agent`)).toBe(token);
    }
    expect(matchesScannerUserAgent(entry(1, { ua: 'ordinary browser' }))).toBe(false);

    expect(SENSITIVE_PATHS).toEqual([
      '/.env', '/.git/config', '/wp-config.php', '/config.php', '/etc/passwd',
      '/phpinfo.php', '/server-status', '/adminer.php', '/backup.zip', '/config.json',
    ]);
    for (const path of SENSITIVE_PATHS) expect(matchesSensitivePath(entry(1, { path }))).toBe(true);
    expect(matchesSensitivePath(entry(2, { path: '/public/config.json.bak' }))).toBe(false);
  });

  it('decodes traversal once, preserves malformed text safely, and keeps double encoding encoded', () => {
    expect(decodeOnceSafely('/%2e%2e/%ZZ')).toBe('/../%ZZ');
    expect(matchesTraversal(entry(1, { query: 'next=%2e%2e%2fsecret' }))).toBe(true);
    expect(matchesTraversal(entry(2, { path: '/%252e%252e%252fsecret' }))).toBe(false);
    expect(decodeOnceSafely('/%E0%A4%A')).toBe('/%E0%A4%A');
    expect(matchesTraversal(entry(3, { path: '/%E0%A4%A' }))).toBe(false);
  });

  it('allows independently matching rules to emit multiple types for the same request', () => {
    const repeated = failedPosts(10, (index) => 200_000 + index).map((item) => ({
      ...item,
      path: '/.env',
      query: 'q=UNION SELECT../secret',
      ua: 'sqlmap',
    }));
    const events = runRules(repeated);
    const types = [...new Set(events.filter((event) => event.entryId === 1).map((event) => event.type))].sort();

    expect(types).toEqual(['BRUTE_FORCE', 'SCANNER_UA', 'SENSITIVE_PROBE', 'SQLI', 'TRAVERSAL']);
    expect(events.filter((event) => event.entryId === 1)).toHaveLength(5);
  });

  it('does not run rules on entries beyond the parser line-size limit', () => {
    const oversized = entry(1, { ua: 'sqlmap', raw: 'x'.repeat(8_193) });
    expect(runRules([oversized])).toEqual([]);
  });
});
