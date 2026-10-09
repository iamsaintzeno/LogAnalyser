import { create } from 'zustand';
import type { ParseResult } from '../contracts';

export type AnalyzerStatus = 'idle' | 'parsing' | 'done' | 'error';

export interface AnalyzerProgress {
  bytesRead: number;
  totalBytes: number;
  lines: number;
}

interface AnalyzerState {
  status: AnalyzerStatus;
  progress: AnalyzerProgress;
  result: ParseResult | null;
  error: string | null;
  startParsing: (fileName: string, size: number) => void;
  setProgress: (progress: AnalyzerProgress) => void;
  setResult: (result: ParseResult) => void;
  setError: (error: string) => void;
  reset: () => void;
}

const emptyProgress = (): AnalyzerProgress => ({ bytesRead: 0, totalBytes: 0, lines: 0 });

export const useAnalyzerStore = create<AnalyzerState>((set) => ({
  status: 'idle',
  progress: emptyProgress(),
  result: null,
  error: null,
  startParsing: (_fileName, size) =>
    set({ status: 'parsing', progress: { bytesRead: 0, totalBytes: size, lines: 0 }, result: null, error: null }),
  setProgress: (progress) => set({ progress }),
  setResult: (result) => set({ status: 'done', result, error: null }),
  setError: (error) => set({ status: 'error', error }),
  reset: () => set({ status: 'idle', progress: emptyProgress(), result: null, error: null }),
}));
