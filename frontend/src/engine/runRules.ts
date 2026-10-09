import type { LogEntry, ThreatEvent, ThreatType } from '../contracts';
import { WEIGHTS } from '../contracts';
import { MAX_LOG_LINE_LENGTH } from './parseLine';
import { findBruteForceEntries } from './rules/bruteForce';
import { matchesSqlInjection } from './rules/injection';
import { matchesSensitivePath } from './rules/sensitiveFile';
import { matchesTraversal } from './rules/traversal';
import { findScannerToken } from './rules/userAgent';

const RULE_IDS: Record<ThreatType, string> = {
  BRUTE_FORCE: 'BRUTE_FORCE_10_IN_5M',
  SQLI: 'SQLI_INDICATOR',
  TRAVERSAL: 'PATH_TRAVERSAL',
  SCANNER_UA: 'KNOWN_SCANNER_USER_AGENT',
  SENSITIVE_PROBE: 'SENSITIVE_PATH_PROBE',
};

const EVIDENCE: Record<ThreatType, string> = {
  BRUTE_FORCE: 'Repeated failed POST requests matched the rolling IP and path window.',
  SQLI: 'The request target matched a SQL injection indicator.',
  TRAVERSAL: 'The request target contained a parent-directory traversal sequence.',
  SCANNER_UA: 'The user agent matched a known scanner token.',
  SENSITIVE_PROBE: 'The request path matched a sensitive-file probe path.',
};

function severityFor(type: ThreatType): 1 | 2 | 3 {
  const weight = WEIGHTS[type];
  return weight >= 30 ? 3 : weight >= 25 ? 2 : 1;
}

function createThreat(entry: LogEntry, type: ThreatType): ThreatEvent {
  return {
    id: `${entry.id}:${type}`,
    entryId: entry.id,
    ip: entry.ip,
    ts: entry.ts,
    type,
    ruleId: RULE_IDS[type],
    severity: severityFor(type),
    evidence: EVIDENCE[type],
  };
}

/** Applies all approved rules. A request can produce more than one event. */
export function runRules(entries: LogEntry[]): ThreatEvent[] {
  const boundedEntries = entries.filter((entry) =>
    entry.raw.length <= MAX_LOG_LINE_LENGTH &&
    entry.path.length <= MAX_LOG_LINE_LENGTH &&
    entry.query.length <= MAX_LOG_LINE_LENGTH &&
    entry.ua.length <= MAX_LOG_LINE_LENGTH,
  );
  const bruteForceEntries = findBruteForceEntries(boundedEntries);
  const events: ThreatEvent[] = [];

  for (const entry of boundedEntries) {
    if (bruteForceEntries.has(entry)) events.push(createThreat(entry, 'BRUTE_FORCE'));
    if (matchesSqlInjection(entry)) events.push(createThreat(entry, 'SQLI'));
    if (matchesTraversal(entry)) events.push(createThreat(entry, 'TRAVERSAL'));
    if (findScannerToken(entry.ua) !== null) events.push(createThreat(entry, 'SCANNER_UA'));
    if (matchesSensitivePath(entry)) events.push(createThreat(entry, 'SENSITIVE_PROBE'));
  }

  return events;
}
