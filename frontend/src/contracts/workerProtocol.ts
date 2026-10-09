import type { ParseResult } from './index';

/** Messages between the browser UI and the local parser worker. */
export type WorkerRequest =
  | { type: 'ANALYZE_FILE'; requestId: number; file: File }
  | { type: 'CANCEL'; requestId: number };

export type WorkerResponse =
  | { type: 'PROGRESS'; requestId: number; bytesRead: number; totalBytes: number; lines: number }
  | { type: 'RESULT'; requestId: number; result: ParseResult }
  | { type: 'ERROR'; requestId: number; message: string };
