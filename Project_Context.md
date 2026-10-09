ROLE: Technical writer for AI coding agents.
TASK: Write the "INTEGRATION & DEPLOY" section of PROJECT_CONTEXT.md (max 300 words): data path File -> useAnalyzeFile hook -> parser.worker.ts -> postMessage protocol -> useAnalyzerStore -> Dashboard; message types (see C1); the rule "main thread never parses lines"; the rule "zero network: no fetch/XHR/WebSocket/sendBeacon/EventSource to any non-same-origin URL; fetch to same-origin /sample files allowed only"; deploy target static hosting only ({{FRONTEND_HOST}}), no backend, no env secrets; fallback = localhost `npm run preview` + recorded video. Contract:
{{PASTE SHARED CONTRACT}}
RULES: Be specific and concrete. Do not invent facts, statistics, library versions or API details - if
you are not sure, say "not sure" and tell me how to verify. State your assumptions. Use simple words;
assume I am a beginner.
CHANGE POLICY: If you think my plan, scope, stack or code should change, or you want to do more than I
asked (extra features, refactors, new libraries, deleting or renaming files), do NOT do it silently.
List each idea under the heading SUGGESTED CHANGES (what, why, effort in minutes, risk) and ask me to
approve or reject each one. Do only what I asked until I answer.


## DATA & STATE

### Technology Stack
- TypeScript for type-safe development.
- Zustand for live application state.
- Dexie with IndexedDB for persistent browser-local storage.
- Verify installed dependency versions in package.json before implementation.

### Folder Structure
- src/db/db.ts: Initialize the IndexedDB database and define tables.
- src/db/repo.ts: Save, load, list, and delete analysis sessions.
- src/db/seed.ts: Provide built-in sample analysis data.
- src/db/exporters.ts: Export results as JSON and CSV.
- src/db/importers.ts: Import and validate JSON files.
- src/store/useAnalyzerStore.ts: Manage live application state.
- src/store/selectors.ts: Filter and aggregate analysis results.

### Privacy and Data Rules
1. Never store complete raw log text. Store only flagged log entries, capped at 20,000 per session.
2. Keep log analysis and persistence inside the browser. Never transmit logs or analysis results to external servers.
3. Provide a Clear All Data feature that removes saved sessions and application-specific persisted settings.
4. Treat attacker-controlled strings as untrusted data, never as trusted HTML.
5. Validate imported records before saving them.
6. If IndexedDB fails or storage is full, continue using in-memory state and display a small notice.
7. Persistence failures must never crash the application.
8. Preserve the shared interfaces and field names in src/contracts/index.ts. Coordinate contract changes with the team.
9. Local storage does not eliminate all privacy risks. IP addresses may constitute personal data under applicable laws.