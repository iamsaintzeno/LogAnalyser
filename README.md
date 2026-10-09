# Log Security Analyzer

A browser-only tool for analyzing web server logs and showing suspicious activity. The project is planned to keep log processing in the browser, so logs do not need to be sent to a backend.

## Planned features

- Select a log file on the **Upload** screen.
- Analyze it in a Web Worker, then view findings on the **Dashboard**.
- Show threat events, attacker summaries, and a timeline.
- Export blocklist rules.

These features describe the project plan; the app is not implemented in this repository yet.

## Privacy and safety

- No backend and no sending log data off the browser.
- Do not store full raw logs. Store flagged entries only, capped at 20,000 per session.
- Render attacker-controlled log values as plain text, never as HTML.

## Project guidance

See [PROJECT_CONTEXT.md](./PROJECT_CONTEXT.md) for the planned stack, shared data types, architecture, and implementation rules.
