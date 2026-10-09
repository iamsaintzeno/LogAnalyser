import { describe, expect, it } from 'vitest';
import type { LogEntry, ParseResult } from '../src/contracts/index.ts';
import type { WorkerRequest, WorkerResponse } from '../src/contracts/messages.ts';
import {
  attachParserWorker,
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
  let resolveTerminal: ((response: WorkerResponse) => void) | undefined;
  const terminal = new Promise<WorkerResponse>((resolve) => {
    resolveTerminal = resolve;
  });
  const scope: ParserWorkerScope = {
    onmessage: null,
    postMessage(message) {
      messages.push(message);
      if (message.type === 'RESULT' || message.type === 'ERROR') {
        resolveTerminal?.(message);
      }
    },
  };

  attachParserWorker(scope, engine);

  return {
    messages,
    ready: messages[0],
    terminal,
    send(request: WorkerRequest) {
      scope.onmessage?.({ data: request } as MessageEvent<WorkerRequest>);
    },
  };
}

describe('parser worker scaffold', () => {
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

    const terminal = await harness.terminal;
    expect(terminal.type).toBe('RESULT');
    expect(lineNumbers).toEqual([2]);
    expect(receivedEntries).toHaveLength(1);
    expect(harness.messages.filter((message) => (
      message.type === 'RESULT' || message.type === 'ERROR'
    ))).toHaveLength(1);
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

    await expect(harness.terminal).resolves.toMatchObject({
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

    await expect(harness.terminal).resolves.toMatchObject({
      type: 'ERROR',
      requestId: 'cancel-request',
      code: 'CANCELLED',
    });
    expect(streamCancelled).toBe(true);
    expect(harness.messages.filter((message) => (
      message.type === 'RESULT' || message.type === 'ERROR'
    ))).toHaveLength(1);
  });
});
