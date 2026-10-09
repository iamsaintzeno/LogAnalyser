import type { RuleOverride } from '../contracts/index.ts';
import type { WorkerRequest, WorkerResponse } from '../contracts/messages.ts';

type AnalysisRequest = Exclude<WorkerRequest, { type: 'CANCEL' }>;
type AnalysisRequestInput =
  | Omit<Extract<AnalysisRequest, { type: 'ANALYZE_FILE' }>, 'requestId'>
  | Omit<Extract<AnalysisRequest, { type: 'ANALYZE_TEXT' }>, 'requestId'>;
type WorkerResponseListener = (response: WorkerResponse) => void;

let nextRequestId = 0;

export interface ParserWorkerTransport {
  postMessage(message: WorkerRequest): void;
  addEventListener(type: 'message', listener: (event: MessageEvent<WorkerResponse>) => void): void;
  removeEventListener(type: 'message', listener: (event: MessageEvent<WorkerResponse>) => void): void;
  terminate(): void;
}

export function createParserWorker(): Worker {
  return new Worker(new URL('./parser.worker.entry.ts', import.meta.url), { type: 'module' });
}

export class ParserWorkerClient {
  private readonly requestIds = new Set<string>();
  private readonly listeners = new Set<WorkerResponseListener>();
  private closed = false;

  constructor(private readonly worker: ParserWorkerTransport = createParserWorker()) {
    worker.addEventListener('message', this.handleMessage);
  }

  subscribe(listener: WorkerResponseListener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  analyzeFile(file: File, overrides: RuleOverride[], allowIps: string[]): string {
    return this.sendAnalysis({ type: 'ANALYZE_FILE', file, overrides, allowIps });
  }

  analyzeText(
    text: string,
    fileName: string,
    overrides: RuleOverride[],
    allowIps: string[],
  ): string {
    return this.sendAnalysis({ type: 'ANALYZE_TEXT', text, fileName, overrides, allowIps });
  }

  cancel(requestId: string): void {
    if (!this.closed && this.requestIds.has(requestId)) {
      this.worker.postMessage({ type: 'CANCEL', requestId });
    }
  }

  terminate(): void {
    if (this.closed) return;
    this.closed = true;
    this.worker.removeEventListener('message', this.handleMessage);
    this.worker.terminate();
    this.requestIds.clear();
    this.listeners.clear();
  }

  private sendAnalysis(request: AnalysisRequestInput): string {
    if (this.closed) throw new Error('Parser worker client has been terminated');
    const requestId = `parser-${++nextRequestId}`;
    this.requestIds.add(requestId);
    try {
      this.worker.postMessage({ ...request, requestId });
    } catch (error) {
      this.requestIds.delete(requestId);
      throw error;
    }
    return requestId;
  }

  private readonly handleMessage = (event: MessageEvent<WorkerResponse>): void => {
    const response = event.data;
    if (response.type !== 'READY' && !this.requestIds.has(response.requestId)) return;
    if (response.type === 'RESULT' || response.type === 'ERROR') {
      this.requestIds.delete(response.requestId);
    }
    for (const listener of this.listeners) listener(response);
  };
}
