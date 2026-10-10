#!/bin/sh
# kubernetes-mcp-proxy.sh - up/down/status for BOTH the upstream
# kubernetes-mcp-server (HTTP mode) and the policy proxy in front of it.
set -eu
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
: "${KMP_PORT:=3720}"
: "${KMP_UPSTREAM_PORT:=8081}"
: "${KMP_TOML:=$DIR/kubernetes-mcp-server.toml}"
: "${KMP_BIN:=kubernetes-mcp-server}"
: "${KMP_PROXY:=node $DIR/kubernetes-mcp-proxy.mjs}"
: "${KMP_LOG:=/tmp/opencode/kubernetes-mcp-proxy.log}"

upstream_pid() { pgrep -f "^(.*/)?kubernetes-mcp-server --config " 2>/dev/null || true; }
proxy_pid() { pgrep -f "^(.*/)?node [^ ]*/kubernetes-mcp-proxy\.mjs$" 2>/dev/null || true; }

wait_up() { # url -> 0 when it answers HTTP
  i=0
  while [ $i -lt 50 ]; do
    curl -s -o /dev/null "$1" 2>/dev/null && return 0
    i=$((i + 1)); sleep 0.1
  done
  return 1
}

case "${1:-}" in
  up)
    if [ -n "$(upstream_pid)" ] && [ -n "$(proxy_pid)" ]; then
      echo "already up (upstream $(upstream_pid), proxy $(proxy_pid))"; exit 0
    fi
    mkdir -p "$(dirname "$KMP_LOG")"
    if [ -z "$(upstream_pid)" ]; then
      command -v "$KMP_BIN" >/dev/null || { echo "kubernetes-mcp-server binary not found (KMP_BIN)"; exit 1; }
      nohup "$KMP_BIN" --config "$KMP_TOML" >>"$KMP_LOG" 2>&1 &
      wait_up "http://127.0.0.1:$KMP_UPSTREAM_PORT/healthz" || { echo "upstream failed to listen on :$KMP_UPSTREAM_PORT (see $KMP_LOG)"; exit 1; }
    fi
    if [ -z "$(proxy_pid)" ]; then
      PORT="$KMP_PORT" UPSTREAM_URL="http://127.0.0.1:$KMP_UPSTREAM_PORT/mcp" LOG="$KMP_LOG" \
        nohup $KMP_PROXY >>"$KMP_LOG" 2>&1 &
      wait_up "http://127.0.0.1:$KMP_PORT/mcp" || { echo "proxy failed to listen on :$KMP_PORT (see $KMP_LOG)"; exit 1; }
    fi
    echo "up: upstream $(upstream_pid) on :$KMP_UPSTREAM_PORT, proxy $(proxy_pid) on :$KMP_PORT"
    ;;
  down)
    p=$(proxy_pid); u=$(upstream_pid)
    [ -n "$p" ] && kill $p 2>/dev/null || true
    [ -n "$u" ] && kill $u 2>/dev/null || true
    echo "down (stopped proxy:$p upstream:$u)"
    ;;
  status)
    u=$(upstream_pid); p=$(proxy_pid)
    echo "upstream: ${u:-down} on :$KMP_UPSTREAM_PORT"
    echo "proxy:    ${p:-down} on :$KMP_PORT"
    ;;
  *)
    echo "usage: $0 {up|down|status}" >&2; exit 2 ;;
esac
