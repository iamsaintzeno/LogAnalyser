export type ThreatType =
  | 'BRUTE_FORCE'
  | 'SQLI'
  | 'TRAVERSAL'
  | 'SCANNER_UA'
  | 'SENSITIVE_PROBE';

export type RiskRating = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export type BlocklistFormat =
  | 'iptables'
  | 'htaccess24'
  | 'htaccess22'
  | 'nginx'
  | 'plain';

export interface LogEntry {
  id: number;
  ip: string;
  ts: number; // epoch ms UTC
  method: string;
  path: string;
  query: string;
  proto: string;
  status: number;
  bytes: number;
  referer: string;
  ua: string;
  raw: string;
}

export interface ThreatEvent {
  id: string;
  entryId: number;
  ip: string;
  ts: number;
  type: ThreatType;
  ruleId: string;
  severity: 1 | 2 | 3;
  evidence: string;
}

export interface AttackerIPSummary {
  ip: string;
  totalHits: number;
  threatHits: number;
  byType: Record<ThreatType, number>;
  mainThreat: ThreatType;
  score: number;
  rating: RiskRating;
  firstSeen: number;
  lastSeen: number;
}

export interface TimelineBucket {
  t: number; // bucket start, 5-min
  total: number;
  byType: Record<ThreatType, number>;
}

export interface ParsedLogSession {
  id: string;
  fileName: string;
  fileSize: number;
  createdAt: number;
  totalLines: number;
  parsedLines: number;
  skippedLines: number;
  threatCount: number;
  durationMs: number;
  summaries: AttackerIPSummary[];
  timeline: TimelineBucket[];
}

export interface BlocklistRule {
  ip: string;
  format: BlocklistFormat;
  reason: string;
  score: number;
  enabled: boolean;
}

export interface RuleOverride {
  ruleId: string;
  enabled: boolean;
  weight?: number;
  threshold?: number;
  windowSec?: number;
}

export interface LogEntryRow extends LogEntry {
  sessionId: string;
}

export interface ThreatEventRow extends ThreatEvent {
  sessionId: string;
}

export interface BlocklistRuleRow extends BlocklistRule {
  sessionId: string;
}

export interface ParseResult {
  session: ParsedLogSession;
  events: ThreatEvent[];
  entries: LogEntry[]; // flagged only, max 20,000
}

export const WEIGHTS: Record<ThreatType, number> = {
  SENSITIVE_PROBE: 30,
  SQLI: 25,
  TRAVERSAL: 25,
  SCANNER_UA: 15,
  BRUTE_FORCE: 15,
};
