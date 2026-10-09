import { describe, expect, it } from 'vitest';
import type { LogEntry, ParseResult } from '../src/contracts/index.ts';
import type { WorkerRequest, WorkerResponse } from '../src/contracts/messages.ts';
import {
  attachParserWorker,
  type AnalysisMetadata,
  createParserEngine,
  type ParserEngine,
  type ParserWorkerScope,
} from '../src/workers/parser.worker.ts';

function makeEntry(id: number): LogEntry {
  return {
    id,
    ip: '192.0.2.1',
    ts: 1_700_000_000_000,
    method: 'GET',
    path: '/',
    query: '',
    proto: 'HTTP/1.1',
    status: 200,
    bytes: 10,
    referer: '-',
    ua: 'test',
    raw: 'valid',
  };
}

function makeResult(entries: LogEntry[]): ParseResult {
  return {
    session: {
      id: 'session-1',
      fileName: 'sample.log',
      fileSize: 5,
      createdAt: 1_700_000_000_000,
      totalLines: 1,
      parsedLines: entries.length,
      skippedLines: 0,
      threatCount: 0,
      durationMs: 1,
      summaries: [],
      timeline: [],
    },
    events: [],
    entries,
  };
}

function createHarness(engine: ParserEngine) {
  const messages: WorkerResponse[] = [];
  const terminalWaiters = new Map<string, ((response: WorkerResponse) => void)[]>();
  const scope: ParserWorkerScope = {
    onmessage: null,
    postMessage(message) {
      messages.push(message);
      if (message.type === 'RESULT' || message.type === 'ERROR') {
        const waiters = terminalWaiters.get(message.requestId);
        waiters?.forEach((resolve) => resolve(message));
        terminalWaiters.delete(message.requestId);
      }
    },
  };

  attachParserWorker(scope, engine);

  return {
    messages,
    ready: messages[0],
    waitForTerminal(requestId: string) {
      const existing = messages.find((message) => (
        (message.type === 'RESULT' || message.type === 'ERROR')
        && message.requestId === requestId
      ));
      if (existing) return Promise.resolve(existing);

      return new Promise<WorkerResponse>((resolve) => {
        const waiters = terminalWaiters.get(requestId) ?? [];
        waiters.push(resolve);
        terminalWaiters.set(requestId, waiters);
      });
    },
    send(request: WorkerRequest) {
      scope.onmessage?.({ data: request } as MessageEvent<WorkerRequest>);
    },
  };
}

describe('parser worker scaffold', () => {
  it('integrates the backend parser and analyzer through the C1 text request', async () => {
    const engine = createParserEngine();
    const line = '203.0.113.45 - - [08/Oct/2026:03:12:07 +0000] "GET /products.php?id=1%20UNION%20SELECT%20password%20FROM%20users HTTP/1.1" 200 100 "-" "Mozilla/5.0"';
    const parsedEntry = engine.parseLine(line, 1);

    expect(parsedEntry).not.toBeNull();
    if (!parsedEntry) throw new Error('Expected the backend parser to accept the sample line');

    const directAnalyzer = engine.createAnalyzer({ overrides: [], allowIps: [] });
    directAnalyzer.push([parsedEntry]);
    expect(directAnalyzer.finish({
      fileName: 'sample.log',
      fileSize: line.length,
      totalLines: 1,
      parsedLines: 1,
      skippedLines: 0,
      startedAt: 1_700_000_000_000,
    }).events.some((event) => event.type === 'SQLI')).toBe(true);

    const harness = createHarness(engine);
    harness.send({
      type: 'ANALYZE_TEXT',
      requestId: 'real-engine-request',
      text: line,
      fileName: 'sample.log',
      overrides: [],
      allowIps: ['203.0.113.45'],
    });

    await expect(harness.waitForTerminal('real-engine-request')).resolves.toMatchObject({
      type: 'RESULT',
      result: {
        session: { totalLines: 1, parsedLines: 1, skippedLines: 0 },
        events: [],
        entries: [],
      },
    });
  });

  it('announces readiness and runs text through the injected engine bindings', async () => {
    const lineNumbers: number[] = [];
    const receivedEntries: LogEntry[] = [];
    const engine: ParserEngine = {
      parseLine(line, lineNo) {
        lineNumbers.push(lineNo);
        return line === 'valid' ? makeEntry(lineNo) : null;
      },
      createAnalyzer() {
        return {
          push(batch) {
            receivedEntries.push(...batch);
          },
          finish() {
            return makeResult(receivedEntries);
          },
        };
      },
    };
    const harness = createHarness(engine);

    expect(harness.ready).toEqual({ type: 'READY', contractVersion: 1 });
    harness.send({
      type: 'ANALYZE_TEXT',
      requestId: 'request-1',
      text: `${'x'.repeat(8_193)}\nvalid`,
      fileName: 'sample.log',
      overrides: [],
      allowIps: [],
    });

    const terminal = await harness.waitForTerminal('request-1');
    expect(terminal.type).toBe('RESULT');
    expect(lineNumbers).toEqual([2]);
    expect(receivedEntries).toHaveLength(1);
    expect(harness.messages.filter((message) => (
      message.type === 'RESULT' || message.type === 'ERROR'
    ))).toHaveLength(1);
  });

  it('removes a UTF-8 BOM split across chunks after an empty initial chunk', async () => {
    const encoded = new TextEncoder().encode('\uFEFFvalid');
    const parsedLines: string[] = [];
    const engine: ParserEngine = {
      parseLine(line, lineNo) {
        parsedLines.push(line);
        return line === 'valid' ? makeEntry(lineNo) : null;
      },
      createAnalyzer() {
        return {
          push: () => undefined,
          finish: () => makeResult([makeEntry(1)]),
        };
      },
    };
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(0));
        controller.enqueue(encoded.slice(0, 1));
        controller.enqueue(encoded.slice(1, 2));
        controller.enqueue(encoded.slice(2));
        controller.close();
      },
    });
    const file = {
      name: 'bom.log',
      size: encoded.byteLength,
      stream: () => stream,
    } as File;
    const harness = createHarness(engine);

    harness.send({
      type: 'ANALYZE_FILE',
      requestId: 'bom-request',
      file,
      overrides: [],
      allowIps: [],
    });

    await expect(harness.waitForTerminal('bom-request')).resolves.toMatchObject({
      type: 'RESULT',
    });
    expect(parsedLines).toEqual(['valid']);
  });

  it('returns the contract error for empty text input', async () => {
    const engine: ParserEngine = {
      parseLine: () => null,
      createAnalyzer: () => ({
        push: () => undefined,
        finish: () => makeResult([]),
      }),
    };
    const harness = createHarness(engine);
    harness.send({
      type: 'ANALYZE_TEXT',
      requestId: 'empty-request',
      text: '',
      fileName: 'empty.log',
      overrides: [],
      allowIps: [],
    });

    await expect(harness.waitForTerminal('empty-request')).resolves.toMatchObject({
      type: 'ERROR',
      requestId: 'empty-request',
      code: 'EMPTY_FILE',
    });
  });

  it('cancels an active file stream and sends one terminal error', async () => {
    let streamCancelled = false;
    const stream = new ReadableStream<Uint8Array>({
      pull() {},
      cancel() {
        streamCancelled = true;
      },
    });
    const engine: ParserEngine = {
      parseLine: () => null,
      createAnalyzer: () => ({
        push: () => undefined,
        finish: () => makeResult([]),
      }),
    };
    const harness = createHarness(engine);
    const file = {
      name: 'blocked.log',
      size: 100,
      stream: () => stream,
    } as File;

    harness.send({
      type: 'ANALYZE_FILE',
      requestId: 'cancel-request',
      file,
      overrides: [],
      allowIps: [],
    });
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    harness.send({ type: 'CANCEL', requestId: 'cancel-request' });

    await expect(harness.waitForTerminal('cancel-request')).resolves.toMatchObject({
      type: 'ERROR',
      requestId: 'cancel-request',
      code: 'CANCELLED',
    });
    expect(streamCancelled).toBe(true);
    expect(harness.messages.filter((message) => (
      message.type === 'RESULT' || message.type === 'ERROR'
    ))).toHaveLength(1);
  });

  it('does not open a file stream when the file exceeds the size limit', async () => {
    const engine: ParserEngine = {
      parseLine: () => null,
      createAnalyzer: () => ({
        push: () => undefined,
        finish: () => makeResult([]),
      }),
    };
    const harness = createHarness(engine);
    let streamOpened = false;
    const file = {
      name: 'too-large.log',
      size: 200 * 1024 * 1024 + 1,
      stream() {
        streamOpened = true;
        throw new Error('stream should not be opened');
      },
    } as File;

    harness.send({
      type: 'ANALYZE_FILE',
      requestId: 'large-request',
      file,
      overrides: [],
      allowIps: [],
    });

    await expect(harness.waitForTerminal('large-request')).resolves.toMatchObject({
      type: 'ERROR',
      code: 'TOO_LARGE',
    });
    expect(streamOpened).toBe(false);
  });

  it('sends engine batches of at most 2,000 entries and forwards the options', async () => {
    const batchSizes: number[] = [];
    let analyzerOptions: { overrides: unknown[]; allowIps: string[] } | undefined;
    const engine: ParserEngine = {
      parseLine: (_line, lineNo) => makeEntry(lineNo),
      createAnalyzer(options) {
        analyzerOptions = options;
        return {
          push(batch) {
            batchSizes.push(batch.length);
          },
          finish(metadata) {
            expect(metadata).toMatchObject({
              fileName: 'batch.log',
              totalLines: 2_001,
              skippedLines: 0,
            });
            return makeResult([]);
          },
        };
      },
    };
    const harness = createHarness(engine);
    const overrides = [{ ruleId: 'test-rule', enabled: false }];
    const allowIps = ['192.0.2.10'];
    harness.send({
      type: 'ANALYZE_TEXT',
      requestId: 'batch-request',
      text: `${'valid\n'.repeat(2_000)}valid`,
      fileName: 'batch.log',
      overrides,
      allowIps,
    });

    await expect(harness.waitForTerminal('batch-request')).resolves.toMatchObject({
      type: 'RESULT',
    });
    expect(batchSizes).toEqual([2_000, 1]);
    expect(analyzerOptions).toEqual({ overrides, allowIps });
  });

  it('reports engine exceptions as a single ENGINE_CRASH without a stack', async () => {
    const engine: ParserEngine = {
      parseLine: () => {
        throw new Error('parser failed');
      },
      createAnalyzer: () => ({
        push: () => undefined,
        finish: () => makeResult([]),
      }),
    };
    const harness = createHarness(engine);
    harness.send({
      type: 'ANALYZE_TEXT',
      requestId: 'engine-error-request',
      text: 'line',
      fileName: 'sample.log',
      overrides: [],
      allowIps: [],
    });

    const response = await harness.waitForTerminal('engine-error-request');
    expect(response).toMatchObject({
      type: 'ERROR',
      code: 'ENGINE_CRASH',
      message: 'parser failed',
    });
    expect(response.type === 'ERROR' ? response.message : '').not.toContain('Error:');
    expect(harness.messages.filter((message) => (
      message.type === 'RESULT' || message.type === 'ERROR'
    ))).toHaveLength(1);
  });

  it('reports stream read failures using the READ_FAILED contract code', async () => {
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.error(new Error('read failed'));
      },
    });
    const engine: ParserEngine = {
      parseLine: () => null,
      createAnalyzer: () => ({
        push: () => undefined,
        finish: () => makeResult([]),
      }),
    };
    const harness = createHarness(engine);
    const file = {
      name: 'unreadable.log',
      size: 1,
      stream: () => stream,
    } as File;
    harness.send({
      type: 'ANALYZE_FILE',
      requestId: 'read-error-request',
      file,
      overrides: [],
      allowIps: [],
    });

    const response = await harness.waitForTerminal('read-error-request');
    expect(response).toMatchObject({
      type: 'ERROR',
      code: 'READ_FAILED',
      message: 'read failed',
    });
    expect(harness.messages.filter((message) => (
      message.type === 'RESULT' || message.type === 'ERROR'
    ))).toHaveLength(1);
  });

  it('reports stream creation failures using READ_FAILED', async () => {
    const engine: ParserEngine = {
      parseLine: () => null,
      createAnalyzer: () => ({
        push: () => undefined,
        finish: () => makeResult([]),
      }),
    };
    const harness = createHarness(engine);
    const file = {
      name: 'unreadable.log',
      size: 1,
      stream() {
        throw new Error('stream unavailable');
      },
    } as File;

    harness.send({
      type: 'ANALYZE_FILE',
      requestId: 'stream-creation-error',
      file,
      overrides: [],
      allowIps: [],
    });

    await expect(harness.waitForTerminal('stream-creation-error')).resolves.toMatchObject({
      type: 'ERROR',
      code: 'READ_FAILED',
      message: 'stream unavailable',
    });
  });

  it('splits oversized and valid physical lines without renumbering them', async () => {
    const receivedLineNumbers: number[] = [];
    let metadata: AnalysisMetadata | undefined;
    const engine: ParserEngine = {
      parseLine(line, lineNo) {
        receivedLineNumbers.push(lineNo);
        return line === 'valid' ? makeEntry(lineNo) : null;
      },
      createAnalyzer() {
        return {
          push: () => undefined,
          finish(value) {
            metadata = value;
            return makeResult([]);
          },
        };
      },
    };
    const harness = createHarness(engine);
    harness.send({
      type: 'ANALYZE_TEXT',
      requestId: 'line-number-request',
      text: `${'x'.repeat(8_193)}\nvalid\ninvalid`,
      fileName: 'sample.log',
      overrides: [],
      allowIps: [],
    });

    await harness.waitForTerminal('line-number-request');
    expect(receivedLineNumbers).toEqual([2, 3]);
    expect(metadata).toMatchObject({
      totalLines: 3,
      skippedLines: 2,
    });
  });

  it('sends progress no more frequently than every 100 ms', async () => {
    const engine: ParserEngine = {
      parseLine: () => null,
      createAnalyzer: () => ({
        push: () => undefined,
        finish: () => makeResult([]),
      }),
    };
    const harness = createHarness(engine);
    const chunkCount = 220;
    let chunksSent = 0;
    const stream = new ReadableStream<Uint8Array>({
      async pull(controller) {
        await new Promise<void>((resolve) => setTimeout(resolve, 1));
        if (chunksSent === chunkCount) {
          controller.close();
          return;
        }
        chunksSent += 1;
        controller.enqueue(new Uint8Array([10]));
      },
    });
    const file = {
      name: 'progress.log',
      size: chunkCount,
      stream: () => stream,
    } as File;
    const progressTimes: number[] = [];
    const originalPostMessage = harness.messages.push.bind(harness.messages);
    harness.messages.push = (...messages) => {
      for (const message of messages) {
        if (message.type === 'PROGRESS') progressTimes.push(Date.now());
      }
      return originalPostMessage(...messages);
    };

    harness.send({
      type: 'ANALYZE_FILE',
      requestId: 'progress-request',
      file,
      overrides: [],
      allowIps: [],
    });
    await harness.waitForTerminal('progress-request');

    expect(progressTimes.length).toBeGreaterThan(1);
    for (let index = 1; index < progressTimes.length; index += 1) {
      expect(progressTimes[index] - progressTimes[index - 1]).toBeGreaterThanOrEqual(100);
    }
  }, 5_000);

  it('cancels the previous request before running a replacement request', async () => {
    let streamCancelled = false;
    let markAnalyzerCreated: (() => void) | undefined;
    const analyzerCreated = new Promise<void>((resolve) => {
      markAnalyzerCreated = resolve;
    });
    const engine: ParserEngine = {
      parseLine: (line, lineNo) => (line === 'valid' ? makeEntry(lineNo) : null),
      createAnalyzer: () => {
        markAnalyzerCreated?.();
        return {
          push: () => undefined,
          finish: () => makeResult([makeEntry(1)]),
        };
      },
    };
    const stream = new ReadableStream<Uint8Array>({
      pull() {},
      cancel() {
        streamCancelled = true;
      },
    });
    const harness = createHarness(engine);
    const file = {
      name: 'blocked.log',
      size: 1,
      stream: () => stream,
    } as File;

    harness.send({
      type: 'ANALYZE_FILE',
      requestId: 'replaced-request',
      file,
      overrides: [],
      allowIps: [],
    });
    await analyzerCreated;
    harness.send({
      type: 'ANALYZE_TEXT',
      requestId: 'replacement-request',
      text: 'valid',
      fileName: 'sample.log',
      overrides: [],
      allowIps: [],
    });

    await expect(harness.waitForTerminal('replaced-request')).resolves.toMatchObject({
      type: 'ERROR',
      code: 'CANCELLED',
    });
    await expect(harness.waitForTerminal('replacement-request')).resolves.toMatchObject({
      type: 'RESULT',
    });
    expect(streamCancelled).toBe(true);
    expect(harness.messages.filter((message) => (
      message.type === 'RESULT' || message.type === 'ERROR'
    ))).toHaveLength(2);
  });

  it('ignores a request that reuses an active request ID', async () => {
    let analyzerCount = 0;
    let analyzerCreated: (() => void) | undefined;
    const started = new Promise<void>((resolve) => {
      analyzerCreated = resolve;
    });
    const engine: ParserEngine = {
      parseLine: () => null,
      createAnalyzer: () => {
        analyzerCount += 1;
        analyzerCreated?.();
        return {
          push: () => undefined,
          finish: () => makeResult([]),
        };
      },
    };
    const stream = new ReadableStream<Uint8Array>({ pull() {} });
    const file = {
      name: 'blocked.log',
      size: 1,
      stream: () => stream,
    } as File;
    const harness = createHarness(engine);

    harness.send({
      type: 'ANALYZE_FILE',
      requestId: 'reused-request',
      file,
      overrides: [],
      allowIps: [],
    });
    await started;
    harness.send({
      type: 'ANALYZE_TEXT',
      requestId: 'reused-request',
      text: 'valid',
      fileName: 'replacement.log',
      overrides: [],
      allowIps: [],
    });
    harness.send({ type: 'CANCEL', requestId: 'reused-request' });

    await expect(harness.waitForTerminal('reused-request')).resolves.toMatchObject({
      type: 'ERROR',
      code: 'CANCELLED',
    });
    expect(analyzerCount).toBe(1);
    expect(harness.messages.filter((message) => (
      (message.type === 'RESULT' || message.type === 'ERROR')
      && message.requestId === 'reused-request'
    ))).toHaveLength(1);
  });
});
