# FRONTEND

Assumption: the scaffold prompt sets the stack to React + TypeScript with Vite, Tailwind CSS, Recharts, and Zustand. Versions are not specified. The visual style is not sure; verify it against the approved design brief before adding styling beyond the listed layout and risk colors.

Folders:

```text
src/
  components/
  pages/
  store/
  lib/
  mock/
  contracts/
```

Screens: **Upload** is the file-selection screen; **Dashboard** is the analysis-results screen.

Use these shared contract types exactly; if they change later, update this file first:

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

Risk colors: CRITICAL `red-500`, HIGH `orange-500`, MEDIUM `yellow-400`, LOW `green-500`.

No network calls of any kind: no fetch to external hosts, no CDN fonts, and no analytics. Attacker-controlled path, user-agent, query, and referer values are always rendered as plain text, never as HTML. Never use `dangerouslySetInnerHTML`.

# INTEGRATION & DEPLOY

Data path: selected `File` → `useAnalyzeFile` hook → `parser.worker.ts` → `postMessage` protocol → `useAnalyzerStore` → Dashboard. The main thread never parses lines; line parsing belongs in the worker.

Worker message types are defined in `src/contracts/messages.ts`; keep them in sync with the sequence and payload table in `docs/CONTRACT.md`. Requests are `ANALYZE_FILE`, `ANALYZE_TEXT`, or `CANCEL`. Responses are `READY`, `PROGRESS`, `RESULT`, or `ERROR`. Send only structured-clone-safe data; never include functions. Emit progress no more often than every 100 ms and exactly one terminal response (`RESULT` or `ERROR`) per request ID. Ignore responses for unknown request IDs. `ParseResult.entries` must contain no more than 20,000 rows.

Zero network: no fetch, XHR, WebSocket, `sendBeacon`, or EventSource to any non-same-origin URL. Fetch to same-origin `/sample` files is the only allowed exception. Do not add external data, analytics, or remote assets.

Deploy only to static hosting; do not add a backend or environment secrets. The target host is not sure; verify it in the deployment request or hosting settings. Fallback: run `npm run preview` on localhost and provide a recorded video. The command is specified by the request; verify it exists in `package.json` when the app is scaffolded.

# DATA & STATE

Database choice: not sure; no database is specified in the current project context. Verify the approved `DB_CHOICE` before choosing a storage method. Keep the data layer small and use these files:

```text
src/db/
  db.ts
  repo.ts
  seed.ts
  exporters.ts
  importers.ts
src/store/
  useAnalyzerStore.ts
  selectors.ts
```

Store no raw full log text. Store only flagged `LogEntry` rows, with no more than 20,000 per session. A **Clear all data** feature must remove all stored analyzer data. Nothing leaves the browser. Stored attacker-controlled strings are data, never HTML.

Persistence can fail, including in private browsing or when storage is full. Such failures must not crash the app: switch to memory-only storage and show a small notice. Verify the selected storage method’s failure behavior in its documentation and test private mode and a full-storage case.

# ENGINE

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

Keep these contract type and field names unchanged. Pipeline files: `src/engine/parseLine.ts` parses lines; `src/engine/decode.ts` decodes; `src/engine/rules/{bruteForce,injection,userAgent,sensitiveFile}.ts` check threats; `src/engine/runRules.ts` runs checks; `src/engine/score.ts` scores risk; `src/engine/blocklist.ts` formats blocklist output; `src/engine/analyze.ts` orchestrates. Put tests in `tests/*.test.ts`.

Use pure functions: no DOM, network, or global mutable state. Run in a Web Worker. Never use `eval` or `new Function`. Logs are attacker-controlled: cap each line at 8,192 characters before any regex, and use only linear-time regexes with no nested quantifiers to prevent ReDoS.
