import type {
  AttackerIPSummary,
  LogEntry,
  ParseResult,
  ParsedLogSession,
  RiskRating,
  ThreatEvent,
  ThreatType,
  TimelineBucket,
} from './index.ts';
import type { WorkerResponse } from './messages.ts';

const threatTypes: readonly ThreatType[] = [
  'BRUTE_FORCE',
  'SQLI',
  'TRAVERSAL',
  'SCANNER_UA',
  'SENSITIVE_PROBE',
];
const riskRatings: readonly RiskRating[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const errorCodes = [
  'EMPTY_FILE',
  'NO_VALID_LINES',
  'TOO_LARGE',
  'READ_FAILED',
  'ENGINE_CRASH',
  'CANCELLED',
] as const;

function isJsonValue(value: unknown, ancestors = new Set<object>()): boolean {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return true;
  if (typeof value === 'number') return Number.isFinite(value);
  if (typeof value !== 'object' || ancestors.has(value)) return false;

  ancestors.add(value);
  let valid = true;

  if (Array.isArray(value)) {
    let indexCount = 0;
    for (const key of Reflect.ownKeys(value)) {
      if (key === 'length') continue;
      if (typeof key !== 'string' || !/^(0|[1-9]\d*)$/.test(key)) {
        valid = false;
        break;
      }
      const index = Number(key);
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (
        !Number.isSafeInteger(index)
        || index >= value.length
        || !descriptor
        || !descriptor.enumerable
        || !('value' in descriptor)
        || !isJsonValue(descriptor.value, ancestors)
      ) {
        valid = false;
        break;
      }
      indexCount += 1;
    }
    valid = valid && indexCount === value.length;
  } else {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      valid = false;
    } else {
      for (const key of Reflect.ownKeys(value)) {
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (
          typeof key !== 'string'
          || !descriptor
          || !descriptor.enumerable
          || !('value' in descriptor)
          || !isJsonValue(descriptor.value, ancestors)
        ) {
          valid = false;
          break;
        }
      }
    }
  }

  ancestors.delete(value);
  return valid;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isString(value: unknown): value is string {
  return typeof value === 'string';
}

function isNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value);
}

function isThreatType(value: unknown): value is ThreatType {
  return typeof value === 'string' && threatTypes.includes(value as ThreatType);
}

function hasThreatCounts(value: unknown): value is Record<ThreatType, number> {
  return isRecord(value) && threatTypes.every((type) => isNumber(value[type]));
}

function isLogEntry(value: unknown): value is LogEntry {
  return isRecord(value)
    && isNumber(value.id)
    && isString(value.ip)
    && isNumber(value.ts)
    && isString(value.method)
    && isString(value.path)
    && isString(value.query)
    && isString(value.proto)
    && isNumber(value.status)
    && isNumber(value.bytes)
    && isString(value.referer)
    && isString(value.ua)
    && isString(value.raw);
}

function isThreatEvent(value: unknown): value is ThreatEvent {
  return isRecord(value)
    && isString(value.id)
    && isNumber(value.entryId)
    && isString(value.ip)
    && isNumber(value.ts)
    && isThreatType(value.type)
    && isString(value.ruleId)
    && (value.severity === 1 || value.severity === 2 || value.severity === 3)
    && isString(value.evidence);
}

function isAttackerIPSummary(value: unknown): value is AttackerIPSummary {
  return isRecord(value)
    && isString(value.ip)
    && isNumber(value.totalHits)
    && isNumber(value.threatHits)
    && hasThreatCounts(value.byType)
    && isThreatType(value.mainThreat)
    && isNumber(value.score)
    && typeof value.rating === 'string'
    && riskRatings.includes(value.rating as RiskRating)
    && isNumber(value.firstSeen)
    && isNumber(value.lastSeen);
}

function isTimelineBucket(value: unknown): value is TimelineBucket {
  return isRecord(value)
    && isNumber(value.t)
    && isNumber(value.total)
    && hasThreatCounts(value.byType);
}

function isParsedLogSession(value: unknown): value is ParsedLogSession {
  return isRecord(value)
    && isString(value.id)
    && isString(value.fileName)
    && isNumber(value.fileSize)
    && isNumber(value.createdAt)
    && isNumber(value.totalLines)
    && isNumber(value.parsedLines)
    && isNumber(value.skippedLines)
    && isNumber(value.threatCount)
    && isNumber(value.durationMs)
    && Array.isArray(value.summaries)
    && value.summaries.every(isAttackerIPSummary)
    && Array.isArray(value.timeline)
    && value.timeline.every(isTimelineBucket);
}

function isParseResult(value: unknown): value is ParseResult {
  return isRecord(value)
    && isParsedLogSession(value.session)
    && Array.isArray(value.events)
    && value.events.every(isThreatEvent)
    && Array.isArray(value.entries)
    && value.entries.length <= 20_000
    && value.entries.every(isLogEntry);
}

export function isWorkerResponse(value: unknown): value is WorkerResponse {
  if (!isJsonValue(value) || !isRecord(value)) return false;

  switch (value.type) {
    case 'READY':
      return isNumber(value.contractVersion);
    case 'PROGRESS':
      return isString(value.requestId)
        && isNumber(value.bytesRead)
        && isNumber(value.totalBytes)
        && isNumber(value.lines)
        && isNumber(value.skipped);
    case 'RESULT':
      return isString(value.requestId) && isParseResult(value.result);
    case 'ERROR':
      return isString(value.requestId)
        && typeof value.code === 'string'
        && errorCodes.includes(value.code as (typeof errorCodes)[number])
        && isString(value.message);
    default:
      return false;
  }
}
