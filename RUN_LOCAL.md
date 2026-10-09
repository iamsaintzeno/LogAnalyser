# Run locally
1. Install Node.js and npm.
2. On Windows, double-click `run_local.bat`.
3. On macOS/Linux, run `sh run_local.sh`.
4. The scripts install dependencies only when the matching `node_modules` folder is missing.
5. The app builds and opens at `http://127.0.0.1:4173`.
6. To run checks manually: `npm test`, `npm test --prefix frontend`, then `npm run build`.
7. Check the production output with `npm run check:offline`.
