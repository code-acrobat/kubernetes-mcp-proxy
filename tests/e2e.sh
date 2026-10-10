#!/bin/sh
# e2e.sh - offline policy test against tests/stub-upstream.mjs (no cluster needed).
# Usage: tests/e2e.sh   (run from the repo root or anywhere)
set -eu
DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP=${TMPDIR:-/tmp}/kmp-e2e-$$
mkdir -p "$TMP"
STUB_LOG="$TMP/stub-calls.log"; : > "$STUB_LOG"
PROXY_LOG="$TMP/proxy.log"; : > "$PROXY_LOG"

cleanup() {
  [ -n "${PROXY_PID:-}" ] && kill "$PROXY_PID" 2>/dev/null || true
  [ -n "${STUB_PID:-}" ] && kill "$STUB_PID" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

fail() { echo "FAIL: $*" >&2; echo "--- proxy log ---"; cat "$PROXY_LOG" >&2; exit 1; }
pass() { echo "ok: $*"; }

STUB_LOG="$STUB_LOG" nohup node "$DIR/tests/stub-upstream.mjs" >"$TMP/stub.out" 2>&1 &
STUB_PID=$!
PORT=1720 UPSTREAM_URL=http://127.0.0.1:18081/mcp \
  RULES="$DIR/kubernetes-mcp-proxy.rules.json" LOG="$PROXY_LOG" \
  nohup node "$DIR/kubernetes-mcp-proxy.mjs" >"$TMP/proxy.out" 2>&1 &
PROXY_PID=$!
i=0; while [ $i -lt 50 ]; do
  curl -s -o /dev/null http://127.0.0.1:1720/mcp 2>/dev/null && break
  i=$((i+1)); sleep 0.1
done
[ $i -lt 50 ] || fail "proxy did not start: $(cat "$TMP/proxy.out")"

B='content-type: application/json'
A='accept: application/json, text/event-stream'
call() { # id json -> $TMP/out-id
  curl -sS -o "$TMP/out-$1" -X POST http://127.0.0.1:1720/mcp -H "$B" -H "$A" ${SID:+-H "mcp-session-id: $SID"} -d "$2"
  grep -q '^data: ' "$TMP/out-$1" && sed -n 's/^data: //p' "$TMP/out-$1" > "$TMP/data-$1" || cp "$TMP/out-$1" "$TMP/data-$1"
}
txt() { jq -r '.result.content[0].text' "$TMP/data-$1"; }

# --- handshake (must pass through untouched) ---
curl -sS -D "$TMP/h" -o /dev/null -X POST http://127.0.0.1:1720/mcp -H "$B" -H "$A" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e","version":"0"}}}'
grep -qi '^mcp-session-id: STUBSESSION' "$TMP/h" || fail "initialize: session header not forwarded"
pass "initialize forwarded with session header"
curl -sS -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:1720/mcp -H "$B" -H "$A" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}' | grep -q 202 || fail "initialized notification not forwarded"
pass "notification forwarded (202)"

# --- response filtering: pods_list (text-only YAML) ---
call 2 '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"pods_list","arguments":{}}}'
txt 2 | grep -q 'app-in-default' || fail "pods_list: default pod missing"
txt 2 | grep -q 'coredns-abc' && fail "pods_list: kube-system pod leaked"
pass "pods_list filtered to default only"

# --- response filtering: namespaces_list (Namespace identity = metadata.name) ---
call 3 '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"namespaces_list","arguments":{}}}'
txt 3 | grep -q 'name: default' || fail "namespaces_list: default missing"
txt 3 | grep -q 'kube-system' && fail "namespaces_list: kube-system leaked"
pass "namespaces_list filtered to default only"

# --- response filtering: events_list (capitalized Namespace key) ---
call 4 '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"events_list","arguments":{}}}'
txt 4 | grep -q 'app-in-default' || fail "events_list: default event missing"
txt 4 | grep -q 'coredns-abc' && fail "events_list: kube-system event leaked"
pass "events_list filtered to default only"

# --- response filtering: structuredContent list (+ kind defense-in-depth) ---
call 5 '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"resources_list","arguments":{"apiVersion":"v1","kind":"Pod"}}}'
jq -e '.result.structuredContent.items | length == 1' "$TMP/data-5" >/dev/null || fail "resources_list: expected 1 structured item, got $(jq -c '.result.structuredContent.items' "$TMP/data-5")"
jq -e '.result.structuredContent.items[0].Namespace == "default"' "$TMP/data-5" >/dev/null || fail "resources_list: wrong item kept"
jq -e '.result.content[0].text | fromjson | length == 1' "$TMP/data-5" >/dev/null || fail "resources_list: text not rewritten from filtered structured"
pass "resources_list structured+text filtered (Secret row dropped by kind too)"

# --- response filtering: single out-of-scope object -> -32000 ---
call 6 '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"resources_get","arguments":{"apiVersion":"v1","kind":"Pod","name":"coredns-abc"}}}'
jq -e '.error.code == -32000' "$TMP/data-6" >/dev/null || fail "resources_get kube-system: expected -32000, got $(jq -c . "$TMP/data-6")"
pass "single out-of-scope object blocked as -32000"

# --- request-side denials (must never reach upstream) ---
: > "$STUB_LOG"
call 7 '{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"pods_exec","arguments":{"name":"x","command":["id"]}}}'
jq -e '.error.code == -32000' "$TMP/data-7" >/dev/null || fail "pods_exec not blocked"
call 8 '{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"resources_list","arguments":{"apiVersion":"v1","kind":"Secret"}}}'
jq -e '.error.code == -32000' "$TMP/data-8" >/dev/null || fail "resources_list Secret not blocked"
call 9 '{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"resources_create_or_update","arguments":{"resource":"apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\n  namespace: default\n"}}}'
jq -e '.error.code == -32000' "$TMP/data-9" >/dev/null || fail "create Secret manifest not blocked"
call 10 '{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"resources_create_or_update","arguments":{"resource":"{\"apiVersion\":\"v1\",\"kind\":\"ConfigMap\",\"metadata\":{\"name\":\"c\",\"namespace\":\"kube-system\"}}"}}}'
jq -e '.error.code == -32000' "$TMP/data-10" >/dev/null || fail "create ConfigMap in kube-system not blocked"
call 11 '{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"resources_create_or_update","arguments":{"resource":"apiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\nmetadata:\n  name: b\n  namespace: default\nsubjects:\n- kind: ServiceAccount\n  name: default\n  namespace: kube-system\n"}}}'
jq -e '.error.code == -32000' "$TMP/data-11" >/dev/null || fail "create RoleBinding not blocked (RBAC kind)"
call 12 '{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"pods_list_in_namespace","arguments":{"namespace":"kube-system"}}}'
jq -e '.error.code == -32000' "$TMP/data-12" >/dev/null || fail "pods_list_in_namespace kube-system not blocked"
call 13 '[{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"pods_list","arguments":{}}}]'
jq -e '.error.code == -32000' "$TMP/data-13" >/dev/null || fail "batch with tools/call not blocked"
[ ! -s "$STUB_LOG" ] || fail "blocked calls leaked to upstream: $(tr '\n' ' ' < "$STUB_LOG")"
pass "request-side denials (exec/Secret/manifests/RBAC/ns/batch) never reached upstream"

# --- browser guard ---
code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:1720/mcp \
  -H "$B" -H "$A" -H 'origin: https://evil.example' -d '{}')
[ "$code" = 403 ] || fail "browser origin not rejected (got $code)"
pass "browser request rejected 403"

echo "ALL PASSED"
