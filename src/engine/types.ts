export type {
  ThreatType,
  RiskRating,
  LogEntry,
  ThreatEvent,
  AttackerIPSummary,
  TimelineBucket,
  ParsedLogSession,
  BlocklistRule,
  RuleOverride,
  ParseResult,
} from '../contracts';

import type { ThreatType, LogEntry, ThreatEvent } from '../contracts';

export interface RuleConfig {
  enabled: boolean;
  weight: number;
  threshold?: number;
  windowSec?: number;
}

export interface Rule {
  id: string;
  type: ThreatType;
  evaluate(entry: LogEntry): ThreatEvent | null;
}

export interface WindowRule {
  id: string;
  type: ThreatType;
  evaluateAll(entries: LogEntry[], cfg: RuleConfig): ThreatEvent[];
}
