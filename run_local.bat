@echo off
setlocal
cd /d "%~dp0"

if not exist "node_modules" (
  call npm ci || exit /b 1
)
if not exist "frontend\node_modules" (
  call npm ci --prefix frontend || exit /b 1
)
call npm run build || exit /b 1
start "" /B npm run preview --prefix frontend -- --host 127.0.0.1 --port 4173 --strictPort
timeout /t 2 /nobreak >nul
start "" http://127.0.0.1:4173
