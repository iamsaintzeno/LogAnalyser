import type {
  AttackerIPSummary,
  LogEntry,
  ParseResult,
  RiskRating,
  ThreatEvent,
  ThreatType,
  TimelineBucket,
} from '../contracts';

const threatTypes: ThreatType[] = [
  'BRUTE_FORCE',
  'SQLI',
  'TRAVERSAL',
  'SCANNER_UA',
  'SENSITIVE_PROBE',
];

const ratings: RiskRating[] = [
  'CRITICAL', 'CRITICAL', 'CRITICAL',
  'HIGH', 'HIGH', 'HIGH',
  'MEDIUM', 'MEDIUM', 'MEDIUM',
  'LOW', 'LOW', 'LOW',
];

const baseTime = Date.UTC(2026, 0, 15, 12, 0, 0);

const summaries: AttackerIPSummary[] = ratings.map((rating, index) => {
  const byType = Object.fromEntries(
    threatTypes.map((type, typeIndex) => [type, (index + typeIndex) % 4 + 1]),
  ) as Record<ThreatType, number>;
  const threatHits = Object.values(byType).reduce((sum, count) => sum + count, 0);

  return {
    ip: `203.0.113.${index + 1}`,
    totalHits: threatHits + index,
    threatHits,
    byType,
    mainThreat: threatTypes[index % threatTypes.length],
    score: 100 - index * 7,
    rating,
    firstSeen: baseTime + index * 60_000,
    lastSeen: baseTime + (index + 48) * 60_000,
  };
});

const events: ThreatEvent[] = Array.from({ length: 60 }, (_, index) => {
  const attackerIndex = index % summaries.length;
  const type = threatTypes[index % threatTypes.length];
  return {
    id: `mock-event-${index + 1}`,
    entryId: index + 1,
    ip: summaries[attackerIndex].ip,
    ts: baseTime + index * 30_000,
    type,
    ruleId: `MOCK_${type}`,
    severity: (index % 3 + 1) as 1 | 2 | 3,
    evidence: `Mock ${type.toLowerCase()} match`,
  };
});

const entries: LogEntry[] = Array.from({ length: 120 }, (_, index) => ({
  id: index + 1,
  ip: summaries[index % summaries.length].ip,
  ts: baseTime + index * 15_000,
  method: index % 4 === 0 ? 'POST' : 'GET',
  path: `/mock/${threatTypes[index % threatTypes.length].toLowerCase()}`,
  query: index % 2 === 0 ? 'id=1' : '',
  proto: 'HTTP/1.1',
  status: index % 3 === 0 ? 404 : 200,
  bytes: 128 + index,
  referer: 'https://example.test/mock',
  ua: 'MockLogAnalyzer/1.0',
  raw: `203.0.113.${(index % summaries.length) + 1} - - [15/Jan/2026:12:00:00 +0000] "GET /mock/${index} HTTP/1.1" 404 128`,
}));

const timeline: TimelineBucket[] = Array.from({ length: 48 }, (_, index) => {
  const total = index === 34 ? 42 : index % 7 === 0 ? 6 : 2;
  const byType = Object.fromEntries(
    threatTypes.map((type, typeIndex) => [type, index === 34 ? 8 + typeIndex : index % 7 === 0 ? 2 : 1]),
  ) as Record<ThreatType, number>;
  return { t: baseTime + index * 5 * 60_000, total, byType };
});

export const mockResult: ParseResult = {
  session: {
    id: 'mock-session-1',
    fileName: 'mock-access.log',
    fileSize: 0,
    createdAt: baseTime,
    totalLines: 120,
    parsedLines: 120,
    skippedLines: 0,
    threatCount: events.length,
    durationMs: 12,
    summaries,
    timeline,
  },
  events,
  entries,
};
