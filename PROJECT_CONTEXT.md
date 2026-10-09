# PROJECT_CONTEXT.md

## ENGINE

### Shared contract (do not rename these types)

```ts
export type ThreatType = 'BRUTE_FORCE' | 'SQLI' | 'TRAVERSAL' | 'SCANNER_UA' | 'SENSITIVE_PROBE';
export type RiskRating = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export interface LogEntry { id: number; ip: string; ts: number /* epoch ms UTC */; method: string; path: string; query: string; proto: string; status: number; bytes: number; referer: string; ua: string; raw: string; }
export interface ThreatEvent { id: string; entryId: number; ip: string; ts: number; type: ThreatType; ruleId: string; severity: 1 | 2 | 3; evidence: string; }
export interface AttackerIPSummary { ip: string; totalHits: number; threatHits: number; byType: Record<ThreatType, number>; mainThreat: ThreatType; score: number; rating: RiskRating; firstSeen: number; lastSeen: number; }
export interface TimelineBucket { t: number /* bucket start, 5-min */; total: number; byType: Record<ThreatType, number>; }
export interface ParsedLogSession { id: string; fileName: string; fileSize: number; createdAt: number; totalLines: number; parsedLines: number; skippedLines: number; threatCount: number; durationMs: number; summaries: AttackerIPSummary[]; timeline: TimelineBucket[]; }
export interface BlocklistRule { ip: string; format: 'iptables' | 'htaccess24' | 'htaccess22' | 'nginx' | 'plain'; reason: string; score: number; enabled: boolean; }
export interface RuleOverride { ruleId: string; enabled: boolean; weight?: number; threshold?: number; windowSec?: number; }
export interface ParseResult { session: ParsedLogSession; events: ThreatEvent[]; entries: LogEntry[] /* flagged only, max 20,000 */; }
export const WEIGHTS: Record<ThreatType, number> = { SENSITIVE_PROBE: 30, SQLI: 25, TRAVERSAL: 25, SCANNER_UA: 15, BRUTE_FORCE: 15 };
```

### Pipeline

Every log line goes through: parse -> decode -> run 4 rules -> count per IP -> score 0-100 -> blocklist.

### Files (all under src/engine/)

-