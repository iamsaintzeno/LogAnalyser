import type { ParseResult, RuleOverride } from './index.ts';

export const CONTRACT_VERSION = 1;

export type WorkerRequest =
  | { type: 'ANALYZE_FILE'; requestId: string; file: File; overrides: RuleOverride[]; allowIps: string[] }
  | { type: 'ANALYZE_TEXT'; requestId: string; text: string; fileName: string; overrides: RuleOverride[]; allowIps: string[] }
  | { type: 'CANCEL'; requestId: string };

export type WorkerResponse =
  | { type: 'READY'; contractVersion: number }
  | { type: 'PROGRESS'; requestId: string; bytesRead: number; totalBytes: number; lines: number; skipped: number }
  | { type: 'RESULT'; requestId: string; result: ParseResult }
  | { type: 'ERROR'; requestId: string; code: 'EMPTY_FILE' | 'NO_VALID_LINES' | 'TOO_LARGE' | 'READ_FAILED' | 'ENGINE_CRASH' | 'CANCELLED'; message: string };
