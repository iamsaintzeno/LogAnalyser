import { describe, expect, it, vi } from 'vitest';
import type { WorkerRequest, WorkerResponse } from '../src/contracts/messages.ts';
import {
  ParserWorkerClient,
  createParserWorker,
  type ParserWorkerTransport,
} from '../src/workers/parserWorkerClient.ts';

class FakeWorker implements ParserWorkerTransport {
  readonly requests: WorkerRequest[] = [];
  readonly listeners = new Set<(event: MessageEvent<WorkerResponse>) => void>();
  readonly errorListeners = new Set<(event: ErrorEvent) => void>();
  terminated = false;

  postMessage(message: WorkerRequest): void {
    this.requests.push(message);
  }

  addEventListener(type: 'message', listener: (event: MessageEvent<WorkerResponse>) => void): void;
  addEventListener(type: 'error', listener: (event: ErrorEvent) => void): void;
  addEventListener(
    type: 'message' | 'error',
    listener: ((event: MessageEvent<WorkerResponse>) => void) | ((event: ErrorEvent) => void),
  ): void {
    if (type === 'message') this.listeners.add(listener as (event: MessageEvent<WorkerResponse>) => void);
    else this.errorListeners.add(listener as (event: ErrorEvent) => void);
  }

  removeEventListener(type: 'message', listener: (event: MessageEvent<WorkerResponse>) => void): void;
  removeEventListener(type: 'error', listener: (event: ErrorEvent) => void): void;
  removeEventListener(
    type: 'message' | 'error',
    listener: ((event: MessageEvent<WorkerResponse>) => void) | ((event: ErrorEvent) => void),
  ): void {
    if (type === 'message') this.listeners.delete(listener as (event: MessageEvent<WorkerResponse>) => void);
    else this.errorListeners.delete(listener as (event: ErrorEvent) => void);
  }

  terminate(): void {
    this.terminated = true;
  }

  respond(response: WorkerResponse): void {
    const event = { data: response } as MessageEvent<WorkerResponse>;
    for (const listener of this.listeners) listener(event);
  }

  fail(message: string): void {
    const event = { message } as ErrorEvent;
    for (const listener of this.errorListeners) listener(event);
  }
}

describe('parser worker client', () => {
  it('creates the parser as a module worker from its dedicated entry point', () => {
    const calls: unknown[][] = [];
    class WorkerMock {
      constructor(...args: [URL, WorkerOptions]) {
        calls.push(args);
      }
    }
    vi.stubGlobal('Worker', WorkerMock);

    try {
      createParserWorker();
    } finally {
      vi.unstubAllGlobals();
    }

    expect(calls).toHaveLength(1);
    const workerUrl = calls[0]?.[0];
    expect(workerUrl).toBeInstanceOf(URL);
    if (!(workerUrl instanceof URL)) throw new Error('Expected a URL for the worker entry point');
    expect(workerUrl.pathname).toContain('parser.worker.entry.ts');
    expect(calls[0]?.[1]).toEqual({ type: 'module' });
  });

  it('creates unique request IDs and sends matching contract requests', () => {
    const worker = new FakeWorker();
    const client = new ParserWorkerClient(worker);
    const firstId = client.analyzeText('sample', 'sample.log', [], []);
    const secondId = client.analyzeText('sample 2', 'sample-2.log', [], []);

    expect(firstId).not.toBe(secondId);
    expect(worker.requests).toEqual([
      {
        type: 'ANALYZE_TEXT',
        requestId: firstId,
        text: 'sample',
        fileName: 'sample.log',
        overrides: [],
        allowIps: [],
      },
      {
        type: 'ANALYZE_TEXT',
        requestId: secondId,
        text: 'sample 2',
        fileName: 'sample-2.log',
        overrides: [],
        allowIps: [],
      },
    ]);
  });

  it('forwards readiness and known request responses but ignores unknown IDs', () => {
    const worker = new FakeWorker();
    const client = new ParserWorkerClient(worker);
    const received: WorkerResponse[] = [];
    client.subscribe((response) => received.push(response));
    const requestId = client.analyzeText('sample', 'sample.log', [], []);

    worker.respond({ type: 'READY', contractVersion: 1 });
    worker.respond({
      type: 'PROGRESS',
      requestId: 'unknown-request',
      bytesRead: 1,
      totalBytes: 1,
      lines: 1,
      skipped: 0,
    });
    worker.respond({
      type: 'PROGRESS',
      requestId,
      bytesRead: 1,
      totalBytes: 1,
      lines: 1,
      skipped: 0,
    });
    worker.respond({
      type: 'ERROR',
      requestId,
      code: 'READ_FAILED',
      message: 'read failed',
    });

    expect(received.map((response) => response.type)).toEqual(['READY', 'PROGRESS', 'ERROR']);
  });

  it('forwards worker runtime errors and detaches the handler when terminated', () => {
    const worker = new FakeWorker();
    const client = new ParserWorkerClient(worker);
    const errors: string[] = [];
    client.subscribeError((message) => errors.push(message));

    worker.fail('worker initialization failed');
    expect(errors).toEqual(['worker initialization failed']);

    client.terminate();
    expect(worker.errorListeners.size).toBe(0);
  });

  it('cancels only known requests and removes listeners when terminated', () => {
    const worker = new FakeWorker();
    const client = new ParserWorkerClient(worker);
    const requestId = client.analyzeText('sample', 'sample.log', [], []);

    client.cancel('unknown-request');
    client.cancel(requestId);
    expect(worker.requests.at(-1)).toEqual({ type: 'CANCEL', requestId });

    client.terminate();
    expect(worker.terminated).toBe(true);
    expect(worker.listeners.size).toBe(0);
    expect(() => client.analyzeText('after close', 'sample.log', [], [])).toThrow(
      'Parser worker client has been terminated',
    );
  });
});
