import type { LogEntry, ThreatEvent, ThreatType, RuleOverride, Rule, WindowRule, RuleConfig } from './types';
import { WEIGHTS, BRUTE_FORCE } from './constants';
import { bruteForceRule } from './rules/bruteForce';
import { sqliRule, traversalRule } from './rules/injection';
import { userAgentRule } from './rules/userAgent';
import { sensitiveFileRule } from './rules/sensitiveFile';

export const LINE_RULES: Rule[] = [sqliRule, traversalRule, userAgentRule, sensitiveFileRule];
export const WINDOW_RULES: WindowRule[] = [bruteForceRule];

export const RULE_TYPE_BY_ID: Record<string, ThreatType> = {
  R1_BRUTE_FORCE: 'BRUTE_FORCE',
  R2A_SQLI: 'SQLI',
  R2B_TRAVERSAL: 'TRAVERSAL',
  R3_SCANNER_UA: 'SCANNER_UA',
  R4_SENSITIVE_PROBE: 'SENSITIVE_PROBE',
};

// Only entries on login-like paths can matter to the brute-force rule, so the streaming
// analyzer keeps just these in memory for the window pass.
export const WINDOW_PREFILTER = /^\/(?:wp-login|xmlrpc|wp-admin\/admin-ajax|administrator|user\/login|login|admin\/login|users\/sign_in)/i;

export function buildConfigs(overrides: RuleOverride[] = []): Map<string, RuleConfig> {
  const cfgs = new Map<string, RuleConfig>();
  for (const id of Object.keys(RULE_TYPE_BY_ID)) {
    cfgs.set(id, {
      enabled: true,
      weight: WEIGHTS[RULE_TYPE_BY_ID[id]],
      threshold: id === 'R1_BRUTE_FORCE' ? BRUTE_FORCE.THRESHOLD : undefined,
      windowSec: id === 'R1_BRUTE_FORCE' ? BRUTE_FORCE.WINDOW_SEC : undefined,
    });
  }
  for (const o of overrides) {
    const c = cfgs.get(o.ruleId);
    if (!c) continue; // unknown ruleId: ignore
    c.enabled = o.enabled !== false;
    if (typeof o.weight === 'number' && Number.isFinite(o.weight)) c.weight = o.weight;
    if (typeof o.threshold === 'number' && Number.isFinite(o.threshold)) c.threshold = o.threshold;
    if (typeof o.windowSec === 'number' && Number.isFinite(o.windowSec)) c.windowSec = o.windowSec;
  }
  return cfgs;
}

export function weightsFrom(cfgs: Map<string, RuleConfig>): Record<ThreatType, number> {
  const w = { ...WEIGHTS } as Record<ThreatType, number>;
  for (const [id, c] of cfgs) w[RULE_TYPE_BY_ID[id]] = c.weight;
  return w;
}

// Run every per-line rule on one entry. A rule bug never crashes the run.
export function runLineRules(e: LogEntry, cfgs: Map<string, RuleConfig>, errors: { n: number }): ThreatEvent[] {
  const out: ThreatEvent[] = [];
  for (const r of LINE_RULES) {
    if (cfgs.get(r.id)?.enabled === false) continue;
    try {
      const ev = r.evaluate(e);
      if (ev) out.push(ev);
    } catch {
      errors.n++;
    }
  }
  return out;
}

export function runWindowRules(entries: LogEntry[], cfgs: Map<string, RuleConfig>, errors: { n: number }): ThreatEvent[] {
  const out: ThreatEvent[] = [];
  for (const r of WINDOW_RULES) {
    const cfg = cfgs.get(r.id);
    if (!cfg || cfg.enabled === false) continue;
    try {
      for (const ev of r.evaluateAll(entries, cfg)) out.push(ev);
    } catch {
      errors.n++;
    }
  }
  return out;
}

// One entry gets at most one event per ThreatType (keep the highest severity).
export function dedupeEvents(events: ThreatEvent[]): ThreatEvent[] {
  const best = new Map<string, ThreatEvent>();
  for (const ev of events) {
    const key = `${ev.entryId}:${ev.type}`;
    const prev = best.get(key);
    if (!prev || ev.severity > prev.severity) best.set(key, ev);
  }
  return [...best.values()];
}

export function runRulesDetailed(
  entries: LogEntry[],
  overrides: RuleOverride[] = [],
  allowIps: Set<string> = new Set(),
): { events: ThreatEvent[]; ruleErrors: number } {
  const cfgs = buildConfigs(overrides);
  const errors = { n: 0 };
  const kept: LogEntry[] = [];
  const events: ThreatEvent[] = [];
  for (const e of entries) {
    if (allowIps.has(e.ip)) continue;
    kept.push(e);
    for (const ev of runLineRules(e, cfgs, errors)) events.push(ev);
  }
  for (const ev of runWindowRules(kept, cfgs, errors)) events.push(ev);
  const deduped = dedupeEvents(events).sort((a, b) => a.ts - b.ts || (a.id < b.id ? -1 : 1));
  return { events: deduped, ruleErrors: errors.n };
}

export function runRules(entries: LogEntry[], overrides: RuleOverride[] = [], allowIps: Set<string> = new Set()): ThreatEvent[] {
  return runRulesDetailed(entries, overrides, allowIps).events;
}
