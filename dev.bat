@echo off
setlocal EnableExtensions

set "ROOT=%~dp0"
set "BACKEND_URL=http://127.0.0.1:8765"
set "FRONTEND_URL=http://localhost:5173"
cd /d "%ROOT%"
set "PYTHONPATH=%ROOT%src;%PYTHONPATH%"

if /i "%~1"=="--check" (
  set "DEV_NO_PAUSE=1"
  goto :check
)
if /i "%~1"=="--backend" goto :backend_only
if /i "%~1"=="--frontend" goto :frontend_only
if not "%~1"=="" goto :usage

call :check_python || goto :error
call :check_frontend || goto :error

call :start_backend || goto :error

echo [dev.bat] Starting frontend at %FRONTEND_URL%
start "thspypc-frontend 5173" "%ComSpec%" /d /k "cd /d ""%ROOT%web"" && pnpm.cmd dev"

echo.
echo ============================================================
echo Backend status: %BACKEND_URL%/api/status
echo Frontend:       %FRONTEND_URL%
echo Stop: close the backend and frontend command windows.
echo ============================================================
echo.
pause
exit /b 0

:backend_only
call :check_python || goto :error
call :start_backend || goto :error
exit /b 0

:frontend_only
call :check_frontend || goto :error
echo [dev.bat] Starting frontend at %FRONTEND_URL%
start "thspypc-frontend 5173" "%ComSpec%" /d /k "cd /d ""%ROOT%web"" && pnpm.cmd dev"
exit /b 0

:check
call :check_python || goto :error
call :check_frontend || goto :error
echo [dev.bat] Check passed. No processes were started.
exit /b 0

:check_python
rem Candidate chain: project venv first (uv-managed 3.14 does not register
rem with the py launcher), then fall back to py -3.14. Only an interpreter
rem that actually passes the version+dependency probe gets selected.
set "PY_CMD="
if exist "%ROOT%.venv\Scripts\python.exe" (
  "%ROOT%.venv\Scripts\python.exe" -c "import sys; assert sys.version_info >= (3, 14); import fastapi, uvicorn, websockets, thspypc" >nul 2>&1
  if not errorlevel 1 set "PY_CMD=%ROOT%.venv\Scripts\python.exe"
)
if defined PY_CMD exit /b 0
where py.exe >nul 2>&1
if errorlevel 1 (
  echo [dev.bat] ERROR: neither .venv nor py.exe is usable.
  exit /b 1
)
py -3.14 -c "import sys; assert sys.version_info >= (3, 14); import fastapi, uvicorn, websockets, thspypc" >nul 2>&1
if errorlevel 1 (
  echo [dev.bat] ERROR: Python 3.14 or backend dependencies are unavailable.
  echo [dev.bat] Run: py -3.14 -m pip install -e .[server]
  exit /b 1
)
set "PY_CMD=py -3.14"
exit /b 0

:check_frontend
where pnpm.cmd >nul 2>&1
if errorlevel 1 (
  echo [dev.bat] ERROR: pnpm.cmd was not found.
  exit /b 1
)
if not exist "%ROOT%web\node_modules\" (
  echo [dev.bat] web\node_modules is missing. Running pnpm install...
  pushd "%ROOT%web"
  call pnpm.cmd install
  if errorlevel 1 (
    popd
    echo [dev.bat] ERROR: pnpm install failed.
    exit /b 1
  )
  popd
)
exit /b 0

:start_backend
powershell.exe -NoProfile -Command "$cs=@(Get-NetTCPConnection -LocalPort 8765 -State Listen -ErrorAction SilentlyContinue); if($cs.Count -eq 0){exit 10}; $c=$cs[0]; $p=Get-CimInstance Win32_Process -Filter ('ProcessId=' + $c.OwningProcess) -ErrorAction SilentlyContinue; if($null -eq $p){exit 11}; if($p.CommandLine -notlike '*thspypc.server*'){Write-Host ('[dev.bat] Port 8765 owner: PID ' + $p.ProcessId + ' ' + $p.CommandLine); exit 12}; Write-Host ('[dev.bat] Stopping existing backend PID ' + $p.ProcessId + ' to load current code.'); try {Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop} catch {exit 13}; $limit=(Get-Date).AddSeconds(5); do {Start-Sleep -Milliseconds 100; $left=@(Get-NetTCPConnection -LocalPort 8765 -State Listen -ErrorAction SilentlyContinue)} while($left.Count -gt 0 -and (Get-Date) -lt $limit); if($left.Count -gt 0){exit 14}; exit 0"
set "BACKEND_CHECK=%ERRORLEVEL%"
if "%BACKEND_CHECK%"=="0" (
  echo [dev.bat] Existing backend stopped successfully.
)
if "%BACKEND_CHECK%"=="10" (
  echo [dev.bat] Port 8765 is free.
)
if "%BACKEND_CHECK%"=="11" (
  echo [dev.bat] ERROR: could not inspect the process listening on port 8765.
  exit /b 1
)
if "%BACKEND_CHECK%"=="12" (
  echo [dev.bat] ERROR: port 8765 is occupied by a process other than thspypc.server.
  exit /b 1
)
if "%BACKEND_CHECK%"=="13" (
  echo [dev.bat] ERROR: could not stop the existing thspypc.server process.
  exit /b 1
)
if "%BACKEND_CHECK%"=="14" (
  echo [dev.bat] ERROR: existing backend did not release port 8765 within 5 seconds.
  exit /b 1
)
if not "%BACKEND_CHECK%"=="0" if not "%BACKEND_CHECK%"=="10" (
  echo [dev.bat] ERROR: backend detection failed with code %BACKEND_CHECK%.
  exit /b 1
)
rem Remove stale backend consoles previously created by this script. This is
rem intentionally scoped by window title and never targets arbitrary cmd.exe.
taskkill.exe /F /T /FI "WINDOWTITLE eq thspypc-backend 8765*" >nul 2>&1
echo [dev.bat] Starting backend at %BACKEND_URL%
start "thspypc-backend 8765" "%ComSpec%" /d /k "cd /d ""%ROOT%"" && set ""PYTHONPATH=%ROOT%src"" && %PY_CMD% -m thspypc.server --host 127.0.0.1 --port 8765"
exit /b 0

:usage
echo Usage: dev.bat [--check ^| --backend ^| --frontend]
exit /b 2

:error
echo [dev.bat] Startup checks failed.
if not defined DEV_NO_PAUSE pause
exit /b 1
