#!/usr/bin/env bash
# Start the thspypc backend and web frontend for local development.
#
# Usage:
#   ./dev.sh             restart backend, then open backend + frontend windows
#   ./dev.sh --backend   restart and open only the backend window
#   ./dev.sh --frontend  open only the frontend window
#   ./dev.sh --check     validate dependencies without starting/stopping

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACK_PORT=8765
FRONT_PORT=5173
BACKEND_URL="http://127.0.0.1:${BACK_PORT}"
FRONTEND_URL="http://localhost:${FRONT_PORT}"

cd "$ROOT" || exit 1
PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
export PYTHONPATH

PYTHON_CMD=()
PNPM_CMD=""

usage() {
  echo "Usage: dev.sh [--check | --backend | --frontend]"
  exit 2
}

error() {
  echo "[dev.sh] Startup checks failed."
  exit 1
}

check_python() {
  local python_path=""
  if command -v py >/dev/null 2>&1; then
    PYTHON_CMD=(py -3.14)
  elif [[ -x "$ROOT/.venv/bin/python3" ]]; then
    PYTHON_CMD=("$ROOT/.venv/bin/python3")
  elif [[ -f "$ROOT/.venv/Scripts/python.exe" ]]; then
    PYTHON_CMD=("$ROOT/.venv/Scripts/python.exe")
  elif python_path="$(type -P python3 2>/dev/null)" && [[ -n "$python_path" ]]; then
    PYTHON_CMD=("$python_path")
  elif python_path="$(type -P python 2>/dev/null)" && [[ -n "$python_path" ]]; then
    PYTHON_CMD=("$python_path")
  else
    echo "[dev.sh] ERROR: Python 3.14 was not found."
    return 1
  fi

  if ! "${PYTHON_CMD[@]}" -c \
      'import sys; assert sys.version_info >= (3, 14); import fastapi, uvicorn, websockets, thspypc' \
      >/dev/null 2>&1; then
    echo "[dev.sh] ERROR: Python 3.14 or backend dependencies are unavailable."
    if [[ "${PYTHON_CMD[0]}" == "py" ]]; then
      echo "[dev.sh] Run: py -3.14 -m pip install -e .[server]"
    else
      echo "[dev.sh] Run: uv sync --extra server"
    fi
    return 1
  fi
}

check_frontend() {
  local pnpm_path=""
  pnpm_path="$(type -P pnpm 2>/dev/null || true)"
  if [[ -z "$pnpm_path" ]]; then
    echo "[dev.sh] ERROR: pnpm was not found."
    return 1
  fi
  PNPM_CMD="$pnpm_path"
  if [[ ! -d "$ROOT/web/node_modules" ]]; then
    echo "[dev.sh] web/node_modules is missing. Running pnpm install..."
    (cd "$ROOT/web" && "$PNPM_CMD" install) || {
      echo "[dev.sh] ERROR: pnpm install failed."
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
    pid="$(lsof -nP -tiTCP:"$BACK_PORT" -sTCP:LISTEN 2>/dev/null | awk 'NR==1 {print $1}')"
  elif command -v ss >/dev/null 2>&1; then
    pid="$(ss -ltnp "sport = :$BACK_PORT" 2>/dev/null | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' | awk 'NR==1 {print}')"
  elif command -v fuser >/dev/null 2>&1; then
    pid="$(fuser "${BACK_PORT}/tcp" 2>/dev/null | awk '{print $NF}')"
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
    return 11
  fi

  command_line="$(ps -p "$pid" -o args= 2>/dev/null || true)"
  if [[ "$command_line" != *"thspypc.server"* ]]; then
    echo "[dev.sh] Port $BACK_PORT owner: PID $pid $command_line"
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
  local rc=0 delay="${DEV_BACKEND_RESTART_DELAY:-5}"
  if command -v powershell.exe >/dev/null 2>&1; then
    stop_backend_windows || rc=$?
  else
    stop_backend_unix || rc=$?
  fi

  case "$rc" in
    0)
      echo "[dev.sh] Existing backend stopped successfully."
      if [[ "$delay" =~ ^[0-9]+$ ]] && (( delay > 0 )); then
        echo "[dev.sh] Waiting ${delay}s for the server to release the previous session..."
        sleep "$delay"
      fi
      ;;
    10)
      echo "[dev.sh] Port $BACK_PORT is free."
      ;;
    11)
      echo "[dev.sh] ERROR: could not inspect the process listening on port $BACK_PORT."
      return 1
      ;;
    12)
      echo "[dev.sh] ERROR: port $BACK_PORT is occupied by a process other than thspypc.server."
      return 1
      ;;
    13)
      echo "[dev.sh] ERROR: could not stop the existing thspypc.server process."
      return 1
      ;;
    14)
      echo "[dev.sh] ERROR: existing backend did not release port $BACK_PORT within 5 seconds."
      return 1
      ;;
    *)
      echo "[dev.sh] ERROR: backend detection failed with code $rc."
      return 1
      ;;
  esac
}

cleanup_stale_backend_consoles() {
  # Remove stale backend consoles previously created by dev.bat/dev.sh. This is
  # intentionally scoped by window title and never targets arbitrary cmd.exe.
  if command -v taskkill.exe >/dev/null 2>&1; then
    taskkill.exe //F //T //FI "WINDOWTITLE eq thspypc-backend 8765*" >/dev/null 2>&1 || true
  fi
}

shell_quote() {
  printf '%q' "$1"
}

create_runner() {
  local tag="$1" title="$2" workdir="$3"
  shift 3
  local runner_dir="" runner="" arg=""
  runner_dir="$(mktemp -d "${TMPDIR:-/tmp}/thspypc-dev.XXXXXX")" || return 1
  runner="$runner_dir/$tag.command"
  {
    printf '%s\n' '#!/bin/bash'
    printf '%s\n' 'runner_dir="$(cd "$(dirname "$0")" && pwd)"'
    printf '%s\n' 'cleanup_runner() { rm -rf "$runner_dir"; }'
    printf '%s\n' 'trap cleanup_runner EXIT'
    printf 'export PATH=%s\n' "$(shell_quote "$PATH")"
    printf '%s %s %s\n' 'printf' "'\e]0;%s\a'" "$(shell_quote "$title")"
    printf 'cd %s || exit 1\n' "$(shell_quote "$workdir")"
    printf '%s\n' 'trap - EXIT'
    printf '%s\n' 'rm -rf "$runner_dir" || true'
    printf 'exec'
    for arg in "$@"; do
      printf ' %s' "$(shell_quote "$arg")"
    done
    printf '\n'
  } > "$runner"
  chmod +x "$runner"
  printf '%s\n' "$runner"
}

open_terminal_window() {
  local title="$1" workdir="$2" tag="$3"
  shift 3
  local runner="" uname_s="" winroot="" winrunner="" log_dir=""
  runner="$(create_runner "$tag" "$title" "$workdir" "$@")" || return 1
  uname_s="$(uname -s)"

  case "$uname_s" in
    Darwin)
      if ! open -a Terminal "$runner"; then
        if ! osascript -e "tell application \"Terminal\" to do script \"exec bash '$runner'\"" >/dev/null 2>&1; then
          echo "[dev.sh] ERROR: could not open a new Terminal window."
          return 1
        fi
      fi
      ;;
    MINGW*|MSYS*|CYGWIN*)
      winroot="$(cygpath -m "$ROOT" 2>/dev/null || true)"
      winrunner="$(cygpath -m "$runner" 2>/dev/null || true)"
      if [[ -z "$winroot" || -z "$winrunner" ]] || ! MSYS_NO_PATHCONV=1 cmd.exe /c start "$title" cmd.exe /k "cd /d \"$winroot\" && bash -lc \"$winrunner\""; then
        echo "[dev.sh] ERROR: could not open a new Windows command window."
        return 1
      fi
      ;;
    *)
      if command -v gnome-terminal >/dev/null 2>&1; then
        gnome-terminal --title="$title" -- bash "$runner"
      elif command -v xfce4-terminal >/dev/null 2>&1; then
        xfce4-terminal --title="$title" --command="bash $runner"
      elif command -v konsole >/dev/null 2>&1; then
        konsole --new-tab -p tabtitle="$title" -e bash "$runner"
      elif command -v x-terminal-emulator >/dev/null 2>&1; then
        x-terminal-emulator -e bash "$runner"
      else
        log_dir="$ROOT/.dev-logs"
        mkdir -p "$log_dir"
        echo "[dev.sh] No terminal emulator found; writing logs to $log_dir/$tag.log"
        nohup bash "$runner" >"$log_dir/$tag.log" 2>&1 &
      fi
      ;;
  esac
}

start_backend_window() {
  local backend_args
  backend_args=(env "PYTHONPATH=$ROOT/src" "${PYTHON_CMD[@]}" -m thspypc.server --host 127.0.0.1 --port "$BACK_PORT")
  open_terminal_window "thspypc-backend 8765" "$ROOT" "backend" "${backend_args[@]}"
}

start_frontend_window() {
  local frontend_args
  frontend_args=("$PNPM_CMD" dev)
  open_terminal_window "thspypc-frontend 5173" "$ROOT/web" "frontend" "${frontend_args[@]}"
}

mode="${1:-all}"
mode="$(printf '%s' "$mode" | tr '[:upper:]' '[:lower:]')"
case "$mode" in
  all|--check|--backend|--frontend)
    ;;
  *)
    usage
    ;;
esac

case "$mode" in
  all|--check|--backend)
    check_python || error
    ;;
esac
case "$mode" in
  all|--check|--frontend)
    check_frontend || error
    ;;
esac

case "$mode" in
  --check)
    echo "[dev.sh] Check passed. No processes were started."
    exit 0
    ;;
  --backend)
    restart_existing_backend || error
    cleanup_stale_backend_consoles
    echo "[dev.sh] Starting backend at $BACKEND_URL"
    start_backend_window || error
    exit 0
    ;;
  --frontend)
    echo "[dev.sh] Starting frontend at $FRONTEND_URL"
    start_frontend_window || error
    exit 0
    ;;
  all)
    restart_existing_backend || error
    cleanup_stale_backend_consoles
    echo "[dev.sh] Starting backend at $BACKEND_URL"
    start_backend_window || error
    echo "[dev.sh] Starting frontend at $FRONTEND_URL"
    start_frontend_window || error
    echo
    echo ============================================================
    echo "Backend status: $BACKEND_URL/api/status"
    echo "Frontend:       $FRONTEND_URL"
    echo "Stop: close the backend and frontend terminal windows."
    echo ============================================================
    echo
    exit 0
    ;;
esac
