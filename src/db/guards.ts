import type {
  AttackerIPSummary,
  BlocklistRule,
  ParsedLogSession,
  RiskRating,
  ThreatEvent,
  ThreatType,
  TimelineBucket,
} from '../contracts';

const THREAT_TYPES: readonly ThreatType[] = [
  'BRUTE_FORCE',
  'SQLI',
  'TRAVERSAL',
  'SCANNER_UA',
  'SENSITIVE_PROBE',
];
const THREAT_TYPE_SET = new Set<string>(THREAT_TYPES);
const RISK_RATINGS: readonly RiskRating[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const RISK_RATING_SET = new Set<string>(RISK_RATINGS);
const BLOCKLIST_FORMATS = new Set([
  'iptables',
  'htaccess24',
  'htaccess22',
  'nginx',
  'plain',
]);
const MAX_STRING_LENGTH = 2_000;
const MAX_SUMMARIES = 500;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isString(value: unknown): value is string {
  return typeof value === 'string' && value.length <= MAX_STRING_LENGTH;
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value);
}

function isThreatType(value: unknown): value is ThreatType {
  return typeof value === 'string' && THREAT_TYPE_SET.has(value);
}

function isThreatCounts(value: unknown): value is Record<ThreatType, number> {
  if (!isRecord(value) || Object.keys(value).length !== THREAT_TYPES.length) {
    return false;
  }

  return THREAT_TYPES.every((type) => isFiniteNumber(value[type]));
}

function isAttackerIPSummary(value: unknown): value is AttackerIPSummary {
  return (
    isRecord(value) &&
    isString(value.ip) &&
    isFiniteNumber(value.totalHits) &&
    isFiniteNumber(value.threatHits) &&
    isThreatCounts(value.byType) &&
    isThreatType(value.mainThreat) &&
    isFiniteNumber(value.score) &&
    typeof value.rating === 'string' &&
    RISK_RATING_SET.has(value.rating) &&
    isFiniteNumber(value.firstSeen) &&
    isFiniteNumber(value.lastSeen)
  );
}

function isTimelineBucket(value: unknown): value is TimelineBucket {
  return (
    isRecord(value) &&
    isFiniteNumber(value.t) &&
    isFiniteNumber(value.total) &&
    isThreatCounts(value.byType)
  );
}

function isUuid(value: unknown): value is string {
  return (
    isString(value) &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)
  );
}

export function isParsedLogSession(value: unknown): value is ParsedLogSession {
  return (
    isRecord(value) &&
    isUuid(value.id) &&
    isString(value.fileName) &&
    isFiniteNumber(value.fileSize) &&
    isFiniteNumber(value.createdAt) &&
    isFiniteNumber(value.totalLines) &&
    isFiniteNumber(value.parsedLines) &&
    isFiniteNumber(value.skippedLines) &&
    isFiniteNumber(value.threatCount) &&
    isFiniteNumber(value.durationMs) &&
    Array.isArray(value.summaries) &&
    value.summaries.length <= MAX_SUMMARIES &&
    value.summaries.every(isAttackerIPSummary) &&
    Array.isArray(value.timeline) &&
    value.timeline.every(isTimelineBucket)
  );
}

export function isThreatEvent(value: unknown): value is ThreatEvent {
  return (
    isRecord(value) &&
    isString(value.id) &&
    isFiniteNumber(value.entryId) &&
    isString(value.ip) &&
    isFiniteNumber(value.ts) &&
    isThreatType(value.type) &&
    isString(value.ruleId) &&
    (value.severity === 1 || value.severity === 2 || value.severity === 3) &&
    isString(value.evidence)
  );
}

export function isBlocklistRule(value: unknown): value is BlocklistRule {
  return (
    isRecord(value) &&
    isString(value.ip) &&
    typeof value.format === 'string' &&
    BLOCKLIST_FORMATS.has(value.format) &&
    isString(value.reason) &&
    isFiniteNumber(value.score) &&
    typeof value.enabled === 'boolean'
  );
}
