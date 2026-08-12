#!/usr/bin/env bash
# Start the thspypc backend and web frontend for local development.
#
# Usage:
#   ./dev.sh             restart backend, then run backend + frontend
#   ./dev.sh --backend   restart and run only the backend
#   ./dev.sh --frontend  run only the frontend
#   ./dev.sh --check     validate dependencies without starting/stopping

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACK_PORT=8765
FRONT_PORT=5173
BACKEND_URL="http://127.0.0.1:${BACK_PORT}"
FRONTEND_URL="http://localhost:${FRONT_PORT}"

cd "$ROOT"

PYTHON_CMD=()
BACK_PID=""
FRONT_PID=""

select_python() {
  if command -v py >/dev/null 2>&1 && py -3.14 -c 'import sys' >/dev/null 2>&1; then
    PYTHON_CMD=(py -3.14)
  elif command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD=(python3)
  elif command -v python >/dev/null 2>&1; then
    PYTHON_CMD=(python)
  else
    echo "[dev.sh] ERROR: Python 3.10 or newer was not found." >&2
    return 1
  fi

  if ! PYTHONPATH="$ROOT/src" "${PYTHON_CMD[@]}" -c \
      'import sys; assert sys.version_info >= (3, 10); import fastapi, uvicorn, thspypc' \
      >/dev/null 2>&1; then
    echo "[dev.sh] ERROR: Python or backend dependencies are unavailable." >&2
    echo "[dev.sh] Install the server dependencies for the selected Python." >&2
    return 1
  fi
}

check_frontend() {
  if ! command -v pnpm >/dev/null 2>&1; then
    echo "[dev.sh] ERROR: pnpm was not found." >&2
    return 1
  fi
  if [[ ! -d "$ROOT/web/node_modules" ]]; then
    echo "[dev.sh] web/node_modules is missing. Running pnpm install..."
    (cd "$ROOT/web" && pnpm install) || {
      echo "[dev.sh] ERROR: pnpm install failed." >&2
      return 1
    }
  fi
}

stop_backend_windows() {
  powershell.exe -NoProfile -Command '
    $connections = @(Get-NetTCPConnection -LocalPort 8765 -State Listen -ErrorAction SilentlyContinue)
    if ($connections.Count -eq 0) { exit 10 }
    $connection = $connections[0]
    $process = Get-CimInstance Win32_Process -Filter ("ProcessId=" + $connection.OwningProcess) -ErrorAction SilentlyContinue
    if ($null -eq $process) { exit 11 }
    if ($process.CommandLine -notlike "*thspypc.server*") {
      Write-Host ("[dev.sh] Port 8765 owner: PID " + $process.ProcessId + " " + $process.CommandLine)
      exit 12
    }
    Write-Host ("[dev.sh] Stopping existing backend PID " + $process.ProcessId + " to load current code.")
    try { Stop-Process -Id $process.ProcessId -Force -ErrorAction Stop } catch { exit 13 }
    $limit = (Get-Date).AddSeconds(5)
    do {
      Start-Sleep -Milliseconds 100
      $left = @(Get-NetTCPConnection -LocalPort 8765 -State Listen -ErrorAction SilentlyContinue)
    } while ($left.Count -gt 0 -and (Get-Date) -lt $limit)
    if ($left.Count -gt 0) { exit 14 }
    exit 0
  '
}

unix_listener_pid() {
  local pid=""
  if command -v lsof >/dev/null 2>&1; then
    pid="$(lsof -nP -tiTCP:"$BACK_PORT" -sTCP:LISTEN 2>/dev/null | head -n 1)"
  elif command -v ss >/dev/null 2>&1; then
    pid="$(ss -ltnp "sport = :$BACK_PORT" 2>/dev/null | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' | head -n 1)"
  elif command -v fuser >/dev/null 2>&1; then
    pid="$(fuser "${BACK_PORT}/tcp" 2>/dev/null | awk '{print $1}')"
  else
    return 2
  fi
  [[ -n "$pid" ]] || return 1
  printf '%s\n' "$pid"
}

stop_backend_unix() {
  local pid="" rc=0 command_line="" deadline=0
  pid="$(unix_listener_pid)" || rc=$?
  if (( rc == 1 )); then
    return 10
  fi
  if (( rc != 0 )); then
    echo "[dev.sh] ERROR: lsof, ss, or fuser is required to inspect port $BACK_PORT." >&2
    return 11
  fi

  command_line="$(ps -p "$pid" -o args= 2>/dev/null || true)"
  if [[ "$command_line" != *"thspypc.server"* ]]; then
    echo "[dev.sh] ERROR: port $BACK_PORT is occupied by PID $pid: $command_line" >&2
    return 12
  fi

  echo "[dev.sh] Stopping existing backend PID $pid to load current code."
  kill "$pid" 2>/dev/null || return 13
  deadline=$((SECONDS + 5))
  while kill -0 "$pid" 2>/dev/null && (( SECONDS < deadline )); do
    sleep 0.1
  done
  if kill -0 "$pid" 2>/dev/null; then
    kill -KILL "$pid" 2>/dev/null || true
  fi
  sleep 0.1
  if unix_listener_pid >/dev/null 2>&1; then
    return 14
  fi
  return 0
}

restart_existing_backend() {
  local rc=0
  if command -v powershell.exe >/dev/null 2>&1; then
    stop_backend_windows || rc=$?
  else
    stop_backend_unix || rc=$?
  fi

  case "$rc" in
    0)
      echo "[dev.sh] Existing backend stopped successfully."
      ;;
    10)
      echo "[dev.sh] Port $BACK_PORT is free."
      ;;
    12)
      echo "[dev.sh] ERROR: port $BACK_PORT belongs to another program; refusing to stop it." >&2
      return 1
      ;;
    14)
      echo "[dev.sh] ERROR: backend did not release port $BACK_PORT within 5 seconds." >&2
      return 1
      ;;
    *)
      echo "[dev.sh] ERROR: backend detection/stop failed with code $rc." >&2
      return 1
      ;;
  esac
}

run_backend() {
  PYTHONPATH="$ROOT/src" "${PYTHON_CMD[@]}" -m thspypc.server \
    --host 127.0.0.1 --port "$BACK_PORT"
}

run_frontend() {
  cd "$ROOT/web"
  pnpm dev
}

cleanup() {
  local pid
  trap - EXIT INT TERM
  for pid in "$BACK_PID" "$FRONT_PID"; do
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
    fi
  done
  wait 2>/dev/null || true
}

mode="${1:-all}"
case "$mode" in
  all|--backend|--check)
    select_python || exit 1
    ;;
esac
case "$mode" in
  all|--frontend|--check)
    check_frontend || exit 1
    ;;
esac

case "$mode" in
  --check)
    echo "[dev.sh] Check passed. No processes were started or stopped."
    exit 0
    ;;
  --backend)
    restart_existing_backend || exit 1
    echo "[dev.sh] Starting backend at $BACKEND_URL"
    exec env PYTHONPATH="$ROOT/src" "${PYTHON_CMD[@]}" -m thspypc.server \
      --host 127.0.0.1 --port "$BACK_PORT"
    ;;
  --frontend)
    echo "[dev.sh] Starting frontend at $FRONTEND_URL"
    cd "$ROOT/web"
    exec pnpm dev
    ;;
  all)
    restart_existing_backend || exit 1
    echo "[dev.sh] Starting backend at $BACKEND_URL"
    run_backend &
    BACK_PID=$!
    echo "[dev.sh] Starting frontend at $FRONTEND_URL"
    run_frontend &
    FRONT_PID=$!
    trap cleanup EXIT INT TERM
    printf '\nBackend status: %s/api/status\nFrontend:       %s\nStop: press Ctrl+C.\n\n' \
      "$BACKEND_URL" "$FRONTEND_URL"
    wait "$BACK_PID" "$FRONT_PID"
    ;;
  *)
    echo "Usage: ./dev.sh [--check | --backend | --frontend]" >&2
    exit 2
    ;;
esac
