import type { LogEntry, ThreatEvent, RuleOverride, ParseResult, ParsedLogSession } from './types';
import { buildConfigs, weightsFrom, runLineRules, runWindowRules, dedupeEvents, WINDOW_PREFILTER } from './runRules';
import { aggregate, buildTimeline, type IpStat } from './aggregate';

export interface AnalyzeMeta {
  fileName: string;
  fileSize: number;
  totalLines: number;
  skippedLines?: number;
  parsedLines?: number;
  durationMs?: number;
  createdAt?: number;
  id?: string;
}

export const MAX_FLAGGED_ENTRIES = 20000;
const MAX_FLAGGED_KEPT = 100000; // memory guard while streaming

export interface Analyzer {
  push(entries: LogEntry[]): void;
  finish(meta: AnalyzeMeta): ParseResult;
  ruleErrors(): number;
}

// Streaming accumulator. Per-line rules run in push(); window rules (brute force) run in finish().
export function createAnalyzer(overrides: RuleOverride[] = [], allowIps: Set<string> = new Set()): Analyzer {
  const cfgs = buildConfigs(overrides);
  const weights = weightsFrom(cfgs);
  const errors = { n: 0 };
  const ipStats = new Map<string, IpStat>();
  const events: ThreatEvent[] = [];
  const windowBuf: LogEntry[] = [];
  const flagged = new Map<number, LogEntry>();
  let seen = 0;

  function markFlags(ev: ThreatEvent, status: number | undefined): void {
    const st = ipStats.get(ev.ip);
    if (!st) return;
    if (ev.type === 'BRUTE_FORCE' && ev.evidence.startsWith('Possible account takeover')) st.takeover = true;
    if ((ev.type === 'SENSITIVE_PROBE' || ev.type === 'SQLI') && status !== undefined && status >= 200 && status < 300) st.exposed = true;
  }

  return {
    push(entries: LogEntry[]): void {
      for (const e of entries) {
        if (allowIps.has(e.ip)) continue;
        seen++;
        let st = ipStats.get(e.ip);
        if (!st) {
          st = { total: 0, first: e.ts, last: e.ts, exposed: false, takeover: false };
          ipStats.set(e.ip, st);
        }
        st.total++;
        if (e.ts < st.first) st.first = e.ts;
        if (e.ts > st.last) st.last = e.ts;

        if (WINDOW_PREFILTER.test(e.path)) windowBuf.push(e);

        const evs = runLineRules(e, cfgs, errors);
        if (evs.length) {
          for (const ev of evs) {
            events.push(ev);
            markFlags(ev, e.status);
          }
          if (flagged.size < MAX_FLAGGED_KEPT) flagged.set(e.id, e);
        }
      }
    },

    finish(meta: AnalyzeMeta): ParseResult {
      const byId = new Map<number, LogEntry>();
      for (const e of windowBuf) byId.set(e.id, e);

      const winEvents = runWindowRules(windowBuf, cfgs, errors);
      for (const ev of winEvents) {
        markFlags(ev, undefined);
        const e = byId.get(ev.entryId);
        if (e && flagged.size < MAX_FLAGGED_KEPT) flagged.set(e.id, e);
      }

      const all = dedupeEvents(events.concat(winEvents)).sort((a, b) => a.ts - b.ts || (a.id < b.id ? -1 : 1));

      const summaries = aggregate(all, ipStats, weights);
      const timeline = buildTimeline(all);

      // flagged entries only: highest severity first, capped, then back in time order
      const maxSev = new Map<number, number>();
      for (const ev of all) maxSev.set(ev.entryId, Math.max(maxSev.get(ev.entryId) ?? 0, ev.severity));
      const outEntries = [...flagged.values()]
        .filter((e) => maxSev.has(e.id))
        .sort((a, b) => (maxSev.get(b.id) ?? 0) - (maxSev.get(a.id) ?? 0) || a.ts - b.ts)
        .slice(0, MAX_FLAGGED_ENTRIES)
        .sort((a, b) => a.ts - b.ts);

      const createdAt = meta.createdAt ?? Date.now();
      const parsedLines = meta.parsedLines ?? seen;
      const session: ParsedLogSession = {
        id: meta.id ?? `s_${createdAt.toString(36)}`,
        fileName: meta.fileName,
        fileSize: meta.fileSize,
        createdAt,
        totalLines: meta.totalLines,
        parsedLines,
        skippedLines: meta.skippedLines ?? Math.max(0, meta.totalLines - parsedLines),
        threatCount: all.length,
        durationMs: meta.durationMs ?? 0,
        summaries,
        timeline,
      };
      return { session, events: all, entries: outEntries };
    },

    ruleErrors: () => errors.n,
  };
}

export function analyze(
  entries: LogEntry[],
  meta: AnalyzeMeta,
  overrides: RuleOverride[] = [],
  allowIps: Set<string> = new Set(),
): ParseResult {
  const a = createAnalyzer(overrides, allowIps);
  a.push(entries);
  return a.finish(meta);
}
