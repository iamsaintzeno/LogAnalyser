import { describe, expect, it } from 'vitest';
import type { WorkerRequest, WorkerResponse } from '../src/contracts/messages';
import {
  attachParserWorker,
  createParserEngine,
  type ParserWorkerScope,
} from '../src/workers/parser.worker';

function createHarness() {
  const messages: WorkerResponse[] = [];
  const scope: ParserWorkerScope = {
    onmessage: null,
    postMessage(message) { messages.push(message); },
  };
  attachParserWorker(scope, createParserEngine());
  return {
    messages,
    send(request: WorkerRequest) {
      scope.onmessage?.({ data: request } as MessageEvent<WorkerRequest>);
    },
    async waitForTerminal(requestId: string) {
      for (let attempt = 0; attempt < 100; attempt += 1) {
        const terminal = messages.find((message) =>
          (message.type === 'RESULT' || message.type === 'ERROR') && message.requestId === requestId,
        );
        if (terminal) return terminal;
        await new Promise((resolve) => setTimeout(resolve, 0));
      }
      throw new Error(`No terminal response for ${requestId}`);
    },
  };
}

const sqlInjectionLine = '203.0.113.45 - - [08/Oct/2026:03:12:07 +0000] "GET /products.php?id=1-- HTTP/1.1" 200 100 "-" "Mozilla/5.0"';

describe('parser worker integration', () => {
  it('reports readiness and returns engine results with real skipped-line progress', async () => {
    const harness = createHarness();
    expect(harness.messages[0]).toEqual({ type: 'READY', contractVersion: 1 });

    const text = `malformed\n${sqlInjectionLine}`;
    const bytes = new TextEncoder().encode(text);
    const file = {
      name: 'sample.log',
      size: bytes.byteLength,
      stream: () => new ReadableStream<Uint8Array>({
        start(controller) { controller.enqueue(bytes); controller.close(); },
      }),
    } as File;
    harness.send({ type: 'ANALYZE_FILE', requestId: 'analysis-1', file, overrides: [], allowIps: [] });
    const response = await harness.waitForTerminal('analysis-1');

    if (response.type === 'ERROR') throw new Error(`${response.code}: ${response.message}`);
    expect(response).toMatchObject({ type: 'RESULT' });
    expect(harness.messages).toContainEqual(expect.objectContaining({
      type: 'PROGRESS', skipped: 1, lines: 2,
    }));
    if (response.type === 'RESULT') {
      expect(response.result.session).toMatchObject({ totalLines: 2, parsedLines: 1, skippedLines: 1 });
      expect(response.result.events.map((event) => event.type)).toContain('SQLI');
    }
  });

  it('cancels an active stream with one typed terminal response', async () => {
    const harness = createHarness();
    const stream = new ReadableStream<Uint8Array>({ pull() {} });
    const file = { name: 'pending.log', size: 20, stream: () => stream } as File;
    harness.send({ type: 'ANALYZE_FILE', requestId: 'cancel-1', file, overrides: [], allowIps: [] });
    await new Promise((resolve) => setTimeout(resolve, 0));
    harness.send({ type: 'CANCEL', requestId: 'cancel-1' });

    const response = await harness.waitForTerminal('cancel-1');
    expect(response).toMatchObject({ type: 'ERROR', code: 'CANCELLED', requestId: 'cancel-1' });
    expect(harness.messages.filter((message) =>
      (message.type === 'RESULT' || message.type === 'ERROR') && message.requestId === 'cancel-1',
    )).toHaveLength(1);
  });
});
