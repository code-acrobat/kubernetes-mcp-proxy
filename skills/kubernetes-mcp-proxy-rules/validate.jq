# Rules vs live tools/list validation for kubernetes-mcp-proxy.
# Usage: jq -n --slurpfile R <rules.json> --slurpfile L <tools/list response.json> \
#            --slurpfile S <tools-list@tag.json> -f validate.jq
# L = live capture, S = committed full-tag snapshot; union with live
# winning. The shipped upstream runs read_only = true, which hides the
# write tools from the live list while rules legitimately name them
# (deny_tools: pods_exec/pods_run); a tool in neither source is a real
# typo. deny_kinds / allowed_namespaces cannot be checked against
# tools/list (free-string kinds, cluster-state namespaces) - see
# SKILL.md Step 2/6.
($L[0].result.tools | map({key: .name, value: .inputSchema}) | from_entries) as $live
| (($S[0] // []) | map({key: .name, value: {properties: (.props // {})}}) | from_entries) as $full
| ($full + $live) as $T
| [
    (select((($R[0].schema // "") | test("@v[0-9]")) | not)
      | "schema: must pin an @vX.Y.Z upstream tag"),
    ($R[0].deny_tools[]? | select($T[.] == null) | "deny_tools: unknown tool \(.)"),
    ($R[0].deny_calls[]? | select($T[.tool] == null) | "deny_calls: unknown tool \(.tool)"),
    ($R[0].deny_calls[]? | select($T[.tool] != null) | . as $r
      | ($r.if // {}) | to_entries[] | . as $p
      | select($T[$r.tool].properties[$p.key] == null)
      | "\($r.tool): unknown argument \($p.key)"),
    ($R[0].deny_calls[]? | select($T[.tool] != null) | . as $r
      | ($r.if // {}) | to_entries[] | . as $p
      | ($T[$r.tool].properties[$p.key].enum // []) as $e
      | select(($e | length) > 0 and ($e | index($p.value) | not))
      | "\($r.tool): \($p.key)=\($p.value) not in enum \($e)")
  ]
| if length == 0 then "rules valid against live schema" else .[] end
