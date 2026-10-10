import { createStore } from 'zustand/vanilla';
import { subscribeWithSelector } from 'zustand/middleware';
import type { ParseResult, RuleOverride, ThreatType } from '../contracts';

export interface ProgressState {
  bytesRead: number;
  totalBytes: number;
  lines: number;
}

export interface FilterState {
  types: ThreatType[];
  from: number | null;
  to: number | null;
  minScore: number;
  ipQuery: string;
}

export type AnalyzerStatus = 'idle' | 'parsing' | 'done' | 'error';

const SETTINGS_KEY = 'logguard.settings.v1';
const PROGRESS_UPDATE_INTERVAL_MS = 100;

interface PersistedSettings {
  allowIps: string[];
  ruleOverrides: RuleOverride[];
}

interface LoadedSettings extends PersistedSettings {
  persistenceOk: boolean;
}

export interface AnalyzerState {
  status: AnalyzerStatus;
  progress: ProgressState;
  result: ParseResult | null;
  error: string | null;
  filters: FilterState;
  selectedIp: string | null;
  blocklistSelection: Record<string, boolean>;
  blocklistMinScore: number;
  allowIps: string[];
  ruleOverrides: RuleOverride[];
  persistenceOk: boolean;
  startParsing: () => void;
  setProgress: (progress: ProgressState) => void;
  setResult: (result: ParseResult) => void;
  setError: (error: string) => void;
  reset: () => void;
  setFilters: (filters: Partial<FilterState>) => void;
  resetFilters: () => void;
  selectIp: (ip: string | null) => void;
  addToBlocklist: (ip: string) => void;
  removeFromBlocklist: (ip: string) => void;
  setBlocklistMinScore: (score: number) => void;
  addAllowIp: (ip: string) => void;
  removeAllowIp: (ip: string) => void;
  setRuleOverride: (override: RuleOverride) => void;
  resetOverrides: () => void;
  loadSession: (session: ParseResult) => void;
}

const EMPTY_PROGRESS: ProgressState = {
  bytesRead: 0,
  totalBytes: 0,
  lines: 0,
};

const DEFAULT_FILTERS: FilterState = {
  types: [],
  from: null,
  to: null,
  minScore: 0,
  ipQuery: '',
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isValidIpv4(ip: string): boolean {
  const octets = ip.split('.');
  return (
    octets.length === 4 &&
    octets.every((octet) => /^\d{1,3}$/.test(octet) && Number(octet) <= 255)
  );
}

function isValidIpv6(ip: string): boolean {
  if (!ip.includes(':') || ip.includes(':::')) {
    return false;
  }

  let address = ip.toLowerCase();
  if (address.includes('.')) {
    const lastColon = address.lastIndexOf(':');
    if (lastColon < 0 || !isValidIpv4(address.slice(lastColon + 1))) {
      return false;
    }
    address = `${address.slice(0, lastColon)}:0:0`;
  }

  if (!/^[\da-f:]+$/.test(address)) {
    return false;
  }

  const compressionIndex = address.indexOf('::');
  if (compressionIndex !== -1 && address.indexOf('::', compressionIndex + 2) !== -1) {
    return false;
  }

  const groups = address.split(':');
  if (compressionIndex !== -1) {
    const explicitGroups = groups.filter(Boolean);
    return (
      explicitGroups.length < 8 &&
      explicitGroups.every((group) => group.length <= 4)
    );
  }

  return groups.length === 8 && groups.every((group) => /^[\da-f]{1,4}$/.test(group));
}

function isValidIp(ip: string): boolean {
  return isValidIpv4(ip) || isValidIpv6(ip);
}

function isRuleOverride(value: unknown): value is RuleOverride {
  if (!isRecord(value) || typeof value.ruleId !== 'string' || typeof value.enabled !== 'boolean') {
    return false;
  }

  return ['weight', 'threshold', 'windowSec'].every(
    (key) => value[key] === undefined || (typeof value[key] === 'number' && Number.isFinite(value[key])),
  );
}

function loadPersistedSettings(): LoadedSettings {
  try {
    const rawSettings = localStorage.getItem(SETTINGS_KEY);
    if (rawSettings === null) {
      return { allowIps: [], ruleOverrides: [], persistenceOk: true };
    }

    const parsed: unknown = JSON.parse(rawSettings);
    if (
      !isRecord(parsed) ||
      !Array.isArray(parsed.allowIps) ||
      !parsed.allowIps.every((ip) => typeof ip === 'string' && isValidIp(ip)) ||
      !Array.isArray(parsed.ruleOverrides) ||
      !parsed.ruleOverrides.every(isRuleOverride)
    ) {
      return { allowIps: [], ruleOverrides: [], persistenceOk: false };
    }

    return {
      allowIps: parsed.allowIps,
      ruleOverrides: parsed.ruleOverrides,
      persistenceOk: true,
    };
  } catch {
    return { allowIps: [], ruleOverrides: [], persistenceOk: false };
  }
}

let lastProgressUpdateAt = Number.NEGATIVE_INFINITY;
let pendingProgress: ProgressState | null = null;
let progressTimer: ReturnType<typeof setTimeout> | undefined;

function clearPendingProgress(): void {
  if (progressTimer !== undefined) {
    clearTimeout(progressTimer);
  }
  progressTimer = undefined;
  pendingProgress = null;
  lastProgressUpdateAt = Number.NEGATIVE_INFINITY;
}

function flushPendingProgress(apply: (progress: ProgressState) => void): void {
  const remaining =
    PROGRESS_UPDATE_INTERVAL_MS - (Date.now() - lastProgressUpdateAt);
  if (remaining > 0) {
    progressTimer = setTimeout(() => flushPendingProgress(apply), remaining);
    return;
  }

  progressTimer = undefined;
  const latestProgress = pendingProgress;
  pendingProgress = null;
  if (latestProgress !== null) {
    lastProgressUpdateAt = Date.now();
    apply(latestProgress);
  }
}

function createInitialState(settings: LoadedSettings) {
  return {
    status: 'idle' as const,
    progress: EMPTY_PROGRESS,
    result: null,
    error: null,
    filters: DEFAULT_FILTERS,
    selectedIp: null,
    blocklistSelection: {},
    blocklistMinScore: 60,
    allowIps: settings.allowIps,
    ruleOverrides: settings.ruleOverrides,
    persistenceOk: settings.persistenceOk,
  };
}

const initialSettings = loadPersistedSettings();

export const analyzerStore = createStore<AnalyzerState>()(
  subscribeWithSelector((set, get) => ({
    ...createInitialState(initialSettings),
    startParsing: () => {
      clearPendingProgress();
      set({
        status: 'parsing',
        progress: EMPTY_PROGRESS,
        result: null,
        error: null,
      });
    },
    setProgress: (progress) => {
      const now = Date.now();
      const elapsed = now - lastProgressUpdateAt;
      if (elapsed >= PROGRESS_UPDATE_INTERVAL_MS) {
        if (progressTimer !== undefined) {
          clearTimeout(progressTimer);
        }
        progressTimer = undefined;
        pendingProgress = null;
        lastProgressUpdateAt = now;
        set({ progress });
        return;
      }

      pendingProgress = progress;
      if (progressTimer === undefined) {
        progressTimer = setTimeout(() => {
          flushPendingProgress((latestProgress) => set({ progress: latestProgress }));
        }, PROGRESS_UPDATE_INTERVAL_MS - elapsed);
      }
    },
    setResult: (result) => {
      clearPendingProgress();
      set({ status: 'done', result, error: null });
    },
    setError: (error) => {
      clearPendingProgress();
      set({ status: 'error', error, result: null });
    },
    reset: () => {
      clearPendingProgress();
      const state = get();
      set({
        ...createInitialState({
          allowIps: state.allowIps,
          ruleOverrides: state.ruleOverrides,
          persistenceOk: state.persistenceOk,
        }),
      });
    },
    setFilters: (filters) => set((state) => ({ filters: { ...state.filters, ...filters } })),
    resetFilters: () => set({ filters: DEFAULT_FILTERS }),
    selectIp: (selectedIp) => set({ selectedIp }),
    addToBlocklist: (ip) =>
      set((state) => ({
        blocklistSelection: { ...state.blocklistSelection, [ip]: true },
      })),
    removeFromBlocklist: (ip) =>
      set((state) => {
        const blocklistSelection = { ...state.blocklistSelection };
        delete blocklistSelection[ip];
        return { blocklistSelection };
      }),
    setBlocklistMinScore: (blocklistMinScore) => set({ blocklistMinScore }),
    addAllowIp: (ip) => {
      if (!isValidIp(ip)) {
        throw new TypeError(`Invalid IP address: ${ip}`);
      }
      set((state) => ({
        allowIps: state.allowIps.includes(ip) ? state.allowIps : [...state.allowIps, ip],
      }));
    },
    removeAllowIp: (ip) =>
      set((state) => ({ allowIps: state.allowIps.filter((allowedIp) => allowedIp !== ip) })),
    setRuleOverride: (override) =>
      set((state) => {
        const existingIndex = state.ruleOverrides.findIndex(
          (current) => current.ruleId === override.ruleId,
        );
        if (existingIndex === -1) {
          return { ruleOverrides: [...state.ruleOverrides, override] };
        }

        const ruleOverrides = [...state.ruleOverrides];
        ruleOverrides[existingIndex] = override;
        return { ruleOverrides };
      }),
    resetOverrides: () => set({ ruleOverrides: [] }),
    loadSession: (session) => {
      clearPendingProgress();
      set({
        status: 'done',
        progress: {
          bytesRead: session.session.fileSize,
          totalBytes: session.session.fileSize,
          lines: session.session.totalLines,
        },
        result: session,
        error: null,
      });
    },
  })),
);

analyzerStore.subscribe(
  (state) => [state.allowIps, state.ruleOverrides] as const,
  ([allowIps, ruleOverrides]) => {
    let persistenceOk = false;
    try {
      localStorage.setItem(SETTINGS_KEY, JSON.stringify({ allowIps, ruleOverrides }));
      persistenceOk = true;
    } catch {
      persistenceOk = false;
    }

    if (analyzerStore.getState().persistenceOk !== persistenceOk) {
      analyzerStore.setState({ persistenceOk });
    }
  },
  {
    equalityFn: (previous, next) =>
      previous[0] === next[0] && previous[1] === next[1],
  },
);

export const useAnalyzerStore = analyzerStore;
