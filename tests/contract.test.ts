import { describe, expect, it } from 'vitest';
import type { ParseResult } from '../src/contracts/index.ts';
import { isWorkerResponse } from '../src/contracts/guards.ts';

const counts = {
  BRUTE_FORCE: 1,
  SQLI: 0,
  TRAVERSAL: 0,
  SCANNER_UA: 0,
  SENSITIVE_PROBE: 0,
};

const sampleResult: ParseResult = {
  session: {
    id: 'session-1',
    fileName: 'access.log',
    fileSize: 100,
    createdAt: 1_700_000_000_000,
    totalLines: 1,
    parsedLines: 1,
    skippedLines: 0,
    threatCount: 1,
    durationMs: 5,
    summaries: [{
      ip: '192.0.2.1',
      totalHits: 1,
      threatHits: 1,
      byType: counts,
      mainThreat: 'BRUTE_FORCE',
      score: 15,
      rating: 'MEDIUM',
      firstSeen: 1_700_000_000_000,
      lastSeen: 1_700_000_000_000,
    }],
    timeline: [{
      t: 1_700_000_000_000,
      total: 1,
      byType: counts,
    }],
  },
  events: [{
    id: 'event-1',
    entryId: 1,
    ip: '192.0.2.1',
    ts: 1_700_000_000_000,
    type: 'BRUTE_FORCE',
    ruleId: 'brute-force',
    severity: 1,
    evidence: 'Repeated login attempts',
  }],
  entries: [{
    id: 1,
    ip: '192.0.2.1',
    ts: 1_700_000_000_000,
    method: 'POST',
    path: '/login',
    query: '',
    proto: 'HTTP/1.1',
    status: 401,
    bytes: 100,
    referer: '-',
    ua: 'Example client',
    raw: '192.0.2.1 POST /login',
  }],
};

describe('isWorkerResponse', () => {
  it('accepts valid messages of every response type', () => {
    const responses: unknown[] = [
      { type: 'READY', contractVersion: 1 },
      {
        type: 'PROGRESS',
        requestId: 'request-1',
        bytesRead: 50,
        totalBytes: 100,
        lines: 2,
        skipped: 0,
      },
      { type: 'RESULT', requestId: 'request-1', result: sampleResult },
      {
        type: 'ERROR',
        requestId: 'request-1',
        code: 'READ_FAILED',
        message: 'Could not read the file',
      },
    ];

    for (const response of responses) {
      expect(isWorkerResponse(response)).toBe(true);
    }
  });

  it('accepts a result with exactly 20,000 entries', () => {
    const entries = Array.from(
      { length: 20_000 },
      (_, index) => ({ ...sampleResult.entries[0], id: index + 1 }),
    );

    expect(
      isWorkerResponse({ type: 'RESULT', requestId: 'request-1', result: { ...sampleResult, entries } }),
    ).toBe(true);
  });

  it('rejects malformed messages and invalid result data', () => {
    const invalidResponses: unknown[] = [
      null,
      { type: 'UNKNOWN' },
      { type: 'READY', contractVersion: '1' },
      { type: 'PROGRESS', requestId: 'request-1', bytesRead: 1 },
      {
        type: 'ERROR',
        requestId: 'request-1',
        code: 'NOT_A_CODE',
        message: 'Invalid',
      },
      {
        type: 'RESULT',
        requestId: 'request-1',
        result: { ...sampleResult, entries: new Array(20_001).fill(sampleResult.entries[0]) },
      },
      {
        type: 'RESULT',
        requestId: 'request-1',
        result: {
          ...sampleResult,
          entries: [{ ...sampleResult.entries[0], raw: () => 'not cloneable' }],
        },
      },
    ];

    for (const response of invalidResponses) {
      expect(isWorkerResponse(response)).toBe(false);
    }
  });
});
