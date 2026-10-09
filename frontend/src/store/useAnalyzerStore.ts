import { create } from 'zustand';
import type { BlocklistRule, ParseResult, ThreatType } from '../contracts';

export interface FilterState {
  types: ThreatType[];
  from: number | null;
  to: number | null;
  minScore: number;
  ipQuery: string;
}

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
  blocklist: BlocklistRule[];
  addToBlocklist: (ip: string) => void;
  filters: FilterState;
  updateFilters: (filters: Partial<FilterState>) => void;
  resetFilters: () => void;
  startParsing: (fileName: string, size: number) => void;
  setProgress: (progress: AnalyzerProgress) => void;
  setResult: (result: ParseResult) => void;
  setError: (error: string) => void;
  reset: () => void;
}

const emptyProgress = (): AnalyzerProgress => ({ bytesRead: 0, totalBytes: 0, lines: 0 });
const emptyFilters = (): FilterState => ({ types: [], from: null, to: null, minScore: 0, ipQuery: '' });

export const useAnalyzerStore = create<AnalyzerState>((set) => ({
  status: 'idle',
  progress: emptyProgress(),
  result: null,
  error: null,
  blocklist: [],
  addToBlocklist: (ip) => set((state) => {
    if (state.blocklist.some((rule) => rule.ip === ip)) return state;
    const score = state.result?.session.summaries.find((summary) => summary.ip === ip)?.score ?? 0;
    return {
      blocklist: [...state.blocklist, {
        ip,
        format: 'plain',
        reason: 'Added from attacker details',
        score,
        enabled: true,
      }],
    };
  }),
  filters: emptyFilters(),
  updateFilters: (filters) => set((state) => ({ filters: { ...state.filters, ...filters } })),
  resetFilters: () => set({ filters: emptyFilters() }),
  startParsing: (_fileName, size) =>
    set({ status: 'parsing', progress: { bytesRead: 0, totalBytes: size, lines: 0 }, result: null, error: null }),
  setProgress: (progress) => set({ progress }),
  setResult: (result) => set({ status: 'done', result, error: null }),
  setError: (error) => set({ status: 'error', error }),
  reset: () => set({ status: 'idle', progress: emptyProgress(), result: null, error: null }),
}));
