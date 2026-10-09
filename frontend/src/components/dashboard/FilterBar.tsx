import { useEffect, useState } from 'react';
import type { ThreatType } from '../../contracts';
import { useAnalyzerStore } from '../../store/useAnalyzerStore';

const THREAT_TYPES: Array<{ type: ThreatType; label: string }> = [
  { type: 'BRUTE_FORCE', label: 'Brute force' },
  { type: 'SQLI', label: 'SQL injection' },
  { type: 'TRAVERSAL', label: 'Path traversal' },
  { type: 'SCANNER_UA', label: 'Hacking tool' },
  { type: 'SENSITIVE_PROBE', label: 'Sensitive file probe' },
];

function toLocalDateTimeValue(timestamp: number): string {
  const date = new Date(timestamp);
  const part = (value: number) => String(value).padStart(2, '0');
  return `${date.getFullYear()}-${part(date.getMonth() + 1)}-${part(date.getDate())}T${part(date.getHours())}:${part(date.getMinutes())}:${part(date.getSeconds())}`;
}

function parseDateTimeValue(value: string): number | null {
  if (!value) return null;
  const timestamp = new Date(value).getTime();
  return Number.isNaN(timestamp) ? null : timestamp;
}

export interface FilterBarProps {
  typeCounts: Record<ThreatType, number>;
  firstTimestamp: number;
  lastTimestamp: number;
  shownIPs: number;
  totalIPs: number;
}

export function FilterBar({ typeCounts, firstTimestamp, lastTimestamp, shownIPs, totalIPs }: FilterBarProps) {
  const filters = useAnalyzerStore((state) => state.filters);
  const updateFilters = useAnalyzerStore((state) => state.updateFilters);
  const resetFilters = useAnalyzerStore((state) => state.resetFilters);
  const [minScoreDraft, setMinScoreDraft] = useState(filters.minScore);
  const [ipQueryDraft, setIPQueryDraft] = useState(filters.ipQuery);
  const invalidRange = filters.from !== null && filters.to !== null && filters.from > filters.to;

  useEffect(() => {
    const timeout = window.setTimeout(() => {
      updateFilters({ minScore: minScoreDraft, ipQuery: ipQueryDraft });
    }, 200);
    return () => window.clearTimeout(timeout);
  }, [ipQueryDraft, minScoreDraft, updateFilters]);

  useEffect(() => {
    setMinScoreDraft(filters.minScore);
    setIPQueryDraft(filters.ipQuery);
  }, [filters.minScore, filters.ipQuery]);

  function toggleType(type: ThreatType) {
    const currentTypes = filters.types.length === 0
      ? THREAT_TYPES.map(({ type: item }) => item)
      : filters.types;
    const nextTypes = currentTypes.includes(type)
      ? currentTypes.filter((item) => item !== type)
      : [...currentTypes, type];

    updateFilters({ types: nextTypes.length === THREAT_TYPES.length ? [] : nextTypes });
  }

  function handleReset() {
    setMinScoreDraft(0);
    setIPQueryDraft('');
    resetFilters();
  }

  const minValue = toLocalDateTimeValue(firstTimestamp);
  const maxValue = toLocalDateTimeValue(lastTimestamp);
  const fromValue = filters.from === null ? minValue : toLocalDateTimeValue(filters.from);
  const toValue = filters.to === null ? maxValue : toLocalDateTimeValue(filters.to);

  return (
    <section aria-label="Filter attackers and timeline" className="space-y-4 rounded-lg border border-slate-200 p-4">
      <div className="flex flex-wrap gap-2">
        {THREAT_TYPES.map(({ type, label }) => {
          const active = filters.types.length === 0 || filters.types.includes(type);
          return (
            <button
              aria-pressed={active}
              className={`rounded-full border px-3 py-1.5 text-sm ${active ? 'border-cyan-600 bg-cyan-50 text-cyan-900' : 'border-slate-300 text-slate-600'}`}
              key={type}
              onClick={() => toggleType(type)}
              type="button"
            >
              {label} [{typeCounts[type]}]
            </button>
          );
        })}
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        <label className="space-y-1 text-sm">
          <span className="block font-medium">From</span>
          <input
            className="w-full rounded border border-slate-300 px-3 py-2"
            max={maxValue}
            min={minValue}
            onChange={(event) => updateFilters({ from: parseDateTimeValue(event.currentTarget.value) })}
            type="datetime-local"
            step={1}
            value={fromValue}
          />
        </label>
        <label className="space-y-1 text-sm">
          <span className="block font-medium">To</span>
          <input
            className="w-full rounded border border-slate-300 px-3 py-2"
            max={maxValue}
            min={minValue}
            onChange={(event) => updateFilters({ to: parseDateTimeValue(event.currentTarget.value) })}
            type="datetime-local"
            step={1}
            value={toValue}
          />
        </label>
      </div>

      {invalidRange && (
        <p className="text-sm text-red-700" role="alert">From must be earlier than or equal to To. The time range is not applied.</p>
      )}

      <div className="grid gap-4 sm:grid-cols-2 sm:items-end">
        <label className="space-y-2 text-sm">
          <span className="flex items-center justify-between gap-3">
            <span className="font-medium">Min risk score</span>
            <output aria-live="polite">{minScoreDraft}</output>
          </span>
          <input
            className="w-full accent-cyan-600"
            max={100}
            min={0}
            onChange={(event) => setMinScoreDraft(Number(event.currentTarget.value))}
            step={5}
            type="range"
            value={minScoreDraft}
          />
        </label>
        <label className="space-y-1 text-sm">
          <span className="block font-medium">Search IP</span>
          <input
            autoComplete="off"
            className="w-full rounded border border-slate-300 px-3 py-2 font-mono"
            onChange={(event) => setIPQueryDraft(event.currentTarget.value)}
            placeholder="IP prefix"
            type="text"
            value={ipQueryDraft}
          />
        </label>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3">
        <button
          className="rounded border border-slate-300 px-3 py-2 text-sm font-medium hover:bg-slate-50"
          onClick={handleReset}
          type="button"
        >
          Reset filters
        </button>
        <p className="rounded-full bg-slate-100 px-3 py-1 text-sm" role="status">
          {shownIPs} of {totalIPs} IPs shown
        </p>
      </div>
    </section>
  );
}
