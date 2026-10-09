import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { CONTRACT_VERSION, type WorkerRequest, type WorkerResponse } from '../src/contracts/messages';
import { UploadPage } from '../src/pages/UploadPage';
import { mockResult } from '../src/mock/mockResult';
import { useAnalyzerStore } from '../src/store/useAnalyzerStore';

class FakeWorker {
  requests: WorkerRequest[] = [];
  listeners = new Set<(event: MessageEvent<WorkerResponse>) => void>();

  postMessage(request: WorkerRequest) { this.requests.push(request); }
  addEventListener(_type: 'message', listener: (event: MessageEvent<WorkerResponse>) => void) {
    this.listeners.add(listener);
    queueMicrotask(() => this.respond({ type: 'READY', contractVersion: CONTRACT_VERSION }));
  }
  removeEventListener(_type: 'message', listener: (event: MessageEvent<WorkerResponse>) => void) {
    this.listeners.delete(listener);
  }
  terminate() {}
  respond(response: WorkerResponse) {
    for (const listener of this.listeners) listener({ data: response } as MessageEvent<WorkerResponse>);
  }
}

let worker: FakeWorker;

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  useAnalyzerStore.getState().reset();
});

describe('upload worker flow', () => {
  it('uses worker progress and ignores a cancelled upload result after a replacement starts', async () => {
    class WorkerMock {
      constructor() {
        worker = new FakeWorker();
        return worker as unknown as Worker;
      }
    }
    vi.stubGlobal('Worker', WorkerMock);

    render(<UploadPage />);
    await waitFor(() => expect(screen.queryByText('Starting the local parser…')).toBeNull());
    const input = document.querySelector('input[type="file"]');
    expect(input).not.toBeNull();
    if (!(input instanceof HTMLInputElement)) throw new Error('Expected the file input');

    const firstFile = new File(['first'], 'first.log', { type: 'text/plain' });
    fireEvent.change(input, { target: { files: [firstFile] } });
    const firstRequest = worker.requests.find((request) => request.type === 'ANALYZE_FILE');
    expect(firstRequest?.type).toBe('ANALYZE_FILE');
    if (firstRequest?.type !== 'ANALYZE_FILE') throw new Error('Expected first analysis request');

    worker.respond({
      type: 'PROGRESS', requestId: firstRequest.requestId,
      bytesRead: 3, totalBytes: 5, lines: 4, skipped: 2,
    });
    expect(await screen.findByText('Skipped 2 lines')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));

    const secondFile = new File(['second'], 'second.log', { type: 'text/plain' });
    const replacementInput = document.querySelector('input[type="file"]');
    if (!(replacementInput instanceof HTMLInputElement)) throw new Error('Expected replacement file input');
    fireEvent.change(replacementInput, { target: { files: [secondFile] } });
    const analysisRequests = worker.requests.filter((request) => request.type === 'ANALYZE_FILE');
    const secondRequest = analysisRequests[1];
    expect(secondRequest?.type).toBe('ANALYZE_FILE');
    if (secondRequest?.type !== 'ANALYZE_FILE') throw new Error('Expected replacement analysis request');

    worker.respond({ type: 'RESULT', requestId: firstRequest.requestId, result: mockResult });
    expect(useAnalyzerStore.getState().status).toBe('parsing');
    expect(useAnalyzerStore.getState().result).toBeNull();

    worker.respond({
      type: 'PROGRESS', requestId: secondRequest.requestId,
      bytesRead: 6, totalBytes: 6, lines: 9, skipped: 1,
    });
    expect(await screen.findByText('Skipped 1 lines')).toBeTruthy();
    worker.respond({ type: 'RESULT', requestId: secondRequest.requestId, result: mockResult });

    await waitFor(() => expect(useAnalyzerStore.getState().status).toBe('done'));
    expect(useAnalyzerStore.getState().result).toBe(mockResult);
    expect(worker.requests).toContainEqual({ type: 'CANCEL', requestId: firstRequest.requestId });
  });

  it('maps typed worker errors to the existing store error state', async () => {
    class WorkerMock {
      constructor() {
        worker = new FakeWorker();
        return worker as unknown as Worker;
      }
    }
    vi.stubGlobal('Worker', WorkerMock);
    render(<UploadPage />);
    await waitFor(() => expect(screen.queryByText('Starting the local parser…')).toBeNull());
    const input = document.querySelector('input[type="file"]');
    if (!(input instanceof HTMLInputElement)) throw new Error('Expected the file input');
    fireEvent.change(input, { target: { files: [new File(['x'], 'sample.log')] } });
    const request = worker.requests.find((item) => item.type === 'ANALYZE_FILE');
    if (request?.type !== 'ANALYZE_FILE') throw new Error('Expected analysis request');
    worker.respond({
      type: 'ERROR', requestId: request.requestId, code: 'NO_VALID_LINES',
      message: 'No valid Apache/Nginx log lines found',
    });

    expect(await screen.findByRole('alert')).toHaveTextContent('No valid Apache/Nginx log lines found');
    expect(useAnalyzerStore.getState().status).toBe('error');
  });
});
