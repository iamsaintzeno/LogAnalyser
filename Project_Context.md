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