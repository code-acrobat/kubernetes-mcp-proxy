#!/bin/sh
# validate.sh - offline checks: syntax + rules vs committed tools-list snapshot.
# No network, no cluster. Snapshot: tools-list@<version>.json (normalized:
# name, prop types/enums, required). See AGENTS.md for the refresh procedure.
set -eu
DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
fail() { echo "FAIL: $*" >&2; exit 1; }
[ $# -ge 1 ] && SNAPSHOT="$DIR/$1" || SNAPSHOT=$(ls "$DIR"/tools-list@*.json | head -1)
[ -f "$SNAPSHOT" ] || fail "no tools-list snapshot next to the repo"

node --check "$DIR/kubernetes-mcp-proxy.mjs" || fail "proxy syntax"
node --check "$DIR/tests/stub-upstream.mjs" || fail "stub syntax"
sh -n "$DIR/kubernetes-mcp-proxy.sh" || fail "control script syntax"
sh -n "$DIR/tests/e2e.sh" || fail "e2e syntax"

jq -e . "$DIR/kubernetes-mcp-proxy.rules.json" >/dev/null || fail "rules json"

# schema must pin an upstream tag: the proxy locks tools/call without one
jq -e '.schema | test("@v[0-9]")' "$DIR/kubernetes-mcp-proxy.rules.json" >/dev/null \
  || fail "rules: schema must pin an @vX.Y.Z upstream tag"

# rules must reference only tools present in the snapshot, and only real args
jq -n --slurpfile R "$DIR/kubernetes-mcp-proxy.rules.json" --slurpfile L "$SNAPSHOT" '
  ($L[0] | map({key: .name, value: .props}) | from_entries) as $tools
  | [
      ($R[0].deny_tools // [])[] | select($tools[.] == null) | "deny_tools: unknown tool \(.)"
    ] + [
      ($R[0].deny_calls // [])[] | .tool as $t
      | (if $tools[$t] == null then "deny_calls: unknown tool \($t)" else empty end),
      (if $tools[$t] != null then
        (.if // {} | keys[]) | select($tools[$t][.] == null) | "deny_calls: \($t) has no argument \(.)"
       else empty end)
    ]
  | if length == 0 then "rules valid against snapshot" else .[] , error("invalid rules") end
' | grep -q 'rules valid' || fail "rules vs snapshot"

grep -Eq '^port = "8081"$' "$DIR/kubernetes-mcp-server.toml" || fail "toml: port"
grep -Eq '^bind_address = "127.0.0.1"$' "$DIR/kubernetes-mcp-server.toml" || fail "toml: bind_address must be loopback"
grep -Eq '^list_output = "yaml"$' "$DIR/kubernetes-mcp-server.toml" || fail "toml: list_output must be yaml (response filter depends on it)"

# default rules sanity: the core policy knobs must exist and be non-empty
jq -e '(.deny_kinds | length) > 0 and (.allowed_namespaces | length) > 0
  and (.deny_tools | index("configuration_view") != null)
  and (.deny_kinds | index("Secret") != null)' "$DIR/kubernetes-mcp-proxy.rules.json" \
  || fail "rules: insecure defaults (check deny_kinds/allowed_namespaces/deny_tools)"

echo "validate: OK (snapshot: $(basename "$SNAPSHOT"))"
