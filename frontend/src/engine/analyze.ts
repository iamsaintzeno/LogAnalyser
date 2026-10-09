import type {
  AttackerIPSummary,
  LogEntry,
  ParseResult,
  ParsedLogSession,
  ThreatEvent,
  ThreatType,
  TimelineBucket,
} from '../contracts';
import { WEIGHTS } from '../contracts';
import { MAX_LOG_LINE_LENGTH } from './parseLine';
import { runRules } from './runRules';
import { ratingForScore, scoreThreatEvents } from './score';

const FIVE_MINUTES = 5 * 60_000;
const FLAGGED_ENTRY_LIMIT = 20_000;
const THREAT_TYPES: readonly ThreatType[] = Object.freeze([
  'BRUTE_FORCE', 'SQLI', 'TRAVERSAL', 'SCANNER_UA', 'SENSITIVE_PROBE',
]);

export interface AnalysisMetadata {
  id: string;
  fileName: string;
  fileSize: number;
  totalLines: number;
  createdAt: number;
  durationMs: number;
}

function emptyTypeCounts(): Record<ThreatType, number> {
  return { BRUTE_FORCE: 0, SQLI: 0, TRAVERSAL: 0, SCANNER_UA: 0, SENSITIVE_PROBE: 0 };
}

function createTimeline(events: ThreatEvent[]): TimelineBucket[] {
  const buckets = new Map<number, TimelineBucket>();
  for (const event of events) {
    const t = Math.floor(event.ts / FIVE_MINUTES) * FIVE_MINUTES;
    const bucket = buckets.get(t) ?? { t, total: 0, byType: emptyTypeCounts() };
    bucket.byType[event.type] += 1;
    bucket.total += 1;
    buckets.set(t, bucket);
  }
  return [...buckets.values()].sort((left, right) => left.t - right.t);
}

function createSummaries(entries: LogEntry[], events: ThreatEvent[]): AttackerIPSummary[] {
  const requestsByIP = new Map<string, { totalHits: number; firstSeen: number; lastSeen: number }>();
  for (const entry of entries) {
    const summary = requestsByIP.get(entry.ip);
    if (!summary) {
      requestsByIP.set(entry.ip, { totalHits: 1, firstSeen: entry.ts, lastSeen: entry.ts });
    } else {
      summary.totalHits += 1;
      summary.firstSeen = Math.min(summary.firstSeen, entry.ts);
      summary.lastSeen = Math.max(summary.lastSeen, entry.ts);
    }
  }

  const eventsByIP = new Map<string, ThreatEvent[]>();
  for (const event of events) {
    const ipEvents = eventsByIP.get(event.ip) ?? [];
    ipEvents.push(event);
    eventsByIP.set(event.ip, ipEvents);
  }

  const summaries: AttackerIPSummary[] = [];
  for (const [ip, ipEvents] of eventsByIP) {
    const requests = requestsByIP.get(ip);
    if (!requests) continue;
    const byType = emptyTypeCounts();
    for (const event of ipEvents) byType[event.type] += 1;
    const mainThreat = THREAT_TYPES.reduce((current, type) =>
      byType[type] > byType[current] ? type : current,
    THREAT_TYPES[0]);
    const score = scoreThreatEvents(ipEvents);
    summaries.push({
      ip,
      totalHits: requests.totalHits,
      threatHits: ipEvents.length,
      byType,
      mainThreat,
      score,
      rating: ratingForScore(score),
      firstSeen: requests.firstSeen,
      lastSeen: requests.lastSeen,
    });
  }

  return summaries.sort((left, right) => right.score - left.score || right.threatHits - left.threatHits || left.ip.localeCompare(right.ip));
}

/** Builds a contract-shaped result from parsed lines. All metadata is supplied by the caller. */
export function analyzeEntries(entries: LogEntry[], metadata: AnalysisMetadata): ParseResult {
  const parsedEntries = entries.filter((entry) => entry.raw.length <= MAX_LOG_LINE_LENGTH);
  const events = runRules(parsedEntries);
  const eventEntryIds = new Set(events.map((event) => event.entryId));
  const flaggedEntries = parsedEntries.filter((entry) => eventEntryIds.has(entry.id)).slice(0, FLAGGED_ENTRY_LIMIT);
  const totalLines = Math.max(0, metadata.totalLines);
  const parsedLines = parsedEntries.length;
  const session: ParsedLogSession = {
    id: metadata.id,
    fileName: metadata.fileName,
    fileSize: metadata.fileSize,
    createdAt: metadata.createdAt,
    totalLines,
    parsedLines,
    skippedLines: Math.max(0, totalLines - parsedLines),
    threatCount: events.length,
    durationMs: metadata.durationMs,
    summaries: createSummaries(parsedEntries, events),
    timeline: createTimeline(events),
  };

  return { session, events, entries: flaggedEntries };
}

export { WEIGHTS };
