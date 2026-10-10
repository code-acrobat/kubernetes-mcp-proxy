# Rules vs live tools/list validation for kubernetes-mcp-proxy.
# Usage: jq -n --slurpfile R <rules.json> --slurpfile L <tools/list response.json> -f validate.jq
# deny_kinds / allowed_namespaces cannot be checked against tools/list
# (free-string kinds, cluster-state namespaces) - see SKILL.md Step 2/6.
($L[0].result.tools | map({key: .name, value: .inputSchema}) | from_entries) as $S
| [
    (select((($R[0].schema // "") | test("@v[0-9]")) | not)
      | "schema: must pin an @vX.Y.Z upstream tag"),
    ($R[0].deny_tools[]? | select($S[.] == null) | "deny_tools: unknown tool \(.)"),
    ($R[0].deny_calls[]? | select($S[.tool] == null) | "deny_calls: unknown tool \(.tool)"),
    ($R[0].deny_calls[]? | select($S[.tool] != null) | . as $r
      | ($r.if // {}) | to_entries[] | . as $p
      | select($S[$r.tool].properties[$p.key] == null)
      | "\($r.tool): unknown argument \($p.key)"),
    ($R[0].deny_calls[]? | select($S[.tool] != null) | . as $r
      | ($r.if // {}) | to_entries[] | . as $p
      | ($S[$r.tool].properties[$p.key].enum // []) as $e
      | select(($e | length) > 0 and ($e | index($p.value) | not))
      | "\($r.tool): \($p.key)=\($p.value) not in enum \($e)")
  ]
| if length == 0 then "rules valid against live schema" else .[] end
