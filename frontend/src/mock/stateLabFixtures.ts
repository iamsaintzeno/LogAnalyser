import type {
  AttackerIPSummary,
  LogEntry,
  ParseResult,
  ThreatEvent,
  ThreatType,
  TimelineBucket,
} from '../contracts';
import { mockResult } from './mockResult';

const TYPES: ThreatType[] = ['BRUTE_FORCE', 'SQLI', 'TRAVERSAL', 'SCANNER_UA', 'SENSITIVE_PROBE'];
const BASE_TIME = Date.UTC(2026, 0, 15, 12, 0, 0);

function counts(type: ThreatType, count = 1): Record<ThreatType, number> {
  return { BRUTE_FORCE: 0, SQLI: 0, TRAVERSAL: 0, SCANNER_UA: 0, SENSITIVE_PROBE: 0, [type]: count };
}

function summary(ip: string, index: number, type = TYPES[index % TYPES.length]): AttackerIPSummary {
  const rating = index % 4 === 0 ? 'CRITICAL' : index % 4 === 1 ? 'HIGH' : index % 4 === 2 ? 'MEDIUM' : 'LOW';
  return {
    ip,
    totalHits: 1 + (index % 20),
    threatHits: 1,
    byType: counts(type),
    mainThreat: type,
    score: 100 - (index % 100),
    rating,
    firstSeen: BASE_TIME + index * 60_000,
    lastSeen: BASE_TIME + index * 60_000 + 30_000,
  };
}

function event(ip: string, index: number, type = TYPES[index % TYPES.length], ts = BASE_TIME + index * 30_000): ThreatEvent {
  return {
    id: `lab-event-${index}`,
    entryId: index + 1,
    ip,
    ts,
    type,
    ruleId: `LAB_${type}`,
    severity: (index % 3 + 1) as 1 | 2 | 3,
    evidence: `State Lab ${type} fixture`,
  };
}

function entry(ip: string, index: number, values: Partial<LogEntry> = {}): LogEntry {
  return {
    id: index + 1,
    ip,
    ts: BASE_TIME + index * 30_000,
    method: 'GET',
    path: `/lab/${index}`,
    query: '',
    proto: 'HTTP/1.1',
    status: 404,
    bytes: 100,
    referer: 'https://example.test/',
    ua: 'StateLab/1.0',
    raw: `${ip} - - [15/Jan/2026:12:00:00 +0000] "GET /lab/${index} HTTP/1.1" 404 100`,
    ...values,
  };
}

function timelineFor(events: ThreatEvent[]): TimelineBucket[] {
  const byTime = new Map<number, TimelineBucket>();
  for (const item of events) {
    const t = Math.floor(item.ts / 300_000) * 300_000;
    const bucket = byTime.get(t) ?? {
      t,
      total: 0,
      byType: counts(item.type, 0),
    };
    bucket.total += 1;
    bucket.byType[item.type] += 1;
    byTime.set(t, bucket);
  }
  return [...byTime.values()].sort((left, right) => left.t - right.t);
}

function result(name: string, summaries: AttackerIPSummary[], events: ThreatEvent[], entries: LogEntry[], timeline = timelineFor(events)): ParseResult {
  return {
    session: {
      ...mockResult.session,
      id: `lab-${name}`,
      fileName: `${name}.log`,
      totalLines: Math.max(events.length, entries.length),
      parsedLines: Math.max(events.length, entries.length),
      skippedLines: 0,
      threatCount: events.length,
      summaries,
      timeline,
    },
    events,
    entries,
  };
}

const cleanBase = result('clean', [], [], [], []);
const clean: ParseResult = {
  ...cleanBase,
  session: { ...cleanBase.session, totalLines: 120, parsedLines: 120 },
};
const oneIP = '203.0.113.9';
const oneEvent = event(oneIP, 0);
const oneAttacker = result('one-attacker', [summary(oneIP, 0)], [oneEvent], [entry(oneIP, 0)]);

const manySummaries: AttackerIPSummary[] = [];
const manyEvents: ThreatEvent[] = [];
const manyEntries: LogEntry[] = [];
for (let index = 0; index < 5_000; index += 1) {
  const ip = `198.18.${Math.floor(index / 256)}.${index % 256}`;
  const threatType = TYPES[index % TYPES.length];
  manySummaries.push(summary(ip, index, threatType));
  manyEvents.push(event(ip, index, threatType));
  manyEntries.push(entry(ip, index));
}
const manyAttackers = result('five-thousand-attackers', manySummaries, manyEvents, manyEntries);

const timelineSingle = result(
  'single-bucket',
  [summary(oneIP, 0)],
  [oneEvent],
  [entry(oneIP, 0)],
  [{ t: BASE_TIME, total: 1, byType: counts(oneEvent.type) }],
);
const thirtyDayEvents = Array.from({ length: 1_441 }, (_, index) => (
  event('203.0.113.30', index, 'BRUTE_FORCE', BASE_TIME + index * 30 * 60_000)
));
const thirtyDaySummary: AttackerIPSummary = {
  ...summary('203.0.113.30', 0, 'BRUTE_FORCE'),
  totalHits: thirtyDayEvents.length,
  threatHits: thirtyDayEvents.length,
  byType: counts('BRUTE_FORCE', thirtyDayEvents.length),
  lastSeen: thirtyDayEvents[thirtyDayEvents.length - 1].ts,
};
const thirtyDayTimeline = result('thirty-day-timeline', [thirtyDaySummary], thirtyDayEvents, []);

const ipv6 = '2001:db8::1';
const ipv6Event = event(ipv6, 0);
const ipv6Fixture = result('ipv6', [summary(ipv6, 0)], [ipv6Event], [entry(ipv6, 0)]);

const xssIP = '203.0.113.66';
const xssEvent = event(xssIP, 0);
const xssEntry = entry(xssIP, 0, {
  path: '/<img src=x onerror=alert(1)>',
  query: 'q=<svg onload=alert(2)>',
  ua: '<script>alert("ua")</script>',
  referer: '<img src=x onerror=alert("referer")>',
  raw: 'GET /<script>alert("raw")</script>',
});
const xssFixture = result('xss-strings', [summary(xssIP, 0)], [xssEvent], [xssEntry]);

// ISO values with different numeric offsets become epoch milliseconds; the UI formats those in the browser's local timezone.
const zoneTimes = [
  Date.parse('2026-01-15T12:00:00+00:00'),
  Date.parse('2026-01-15T12:00:00-03:00'),
  Date.parse('2026-01-15T12:00:00+09:00'),
];
const timezoneEvents = zoneTimes.map((ts, index) => event(`203.0.113.${20 + index}`, index, TYPES[index], ts));
const timezoneSummaries = timezoneEvents.map((item, index) => ({
  ...summary(item.ip, index, item.type),
  firstSeen: item.ts,
  lastSeen: item.ts,
}));
const timezoneEntries = timezoneEvents.map((item, index) => entry(item.ip, index, { ts: item.ts }));
const timezones = result('timezone-offsets', timezoneSummaries, timezoneEvents, timezoneEntries);

const skippedLines: ParseResult = {
  ...result('all-skipped', [], [], [], []),
  session: { ...result('all-skipped', [], [], [], []).session, totalLines: 123, parsedLines: 0, skippedLines: 123 },
};

export const stateLabFixtures = {
  clean,
  oneAttacker,
  manyAttackers,
  timelineSingle,
  thirtyDayTimeline,
  ipv6Fixture,
  xssFixture,
  skippedLines,
  timezones,
} as const;
