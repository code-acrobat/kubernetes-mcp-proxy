# AGENTS.md - development notes

User-facing docs: README.md. This file is the invariant record for anyone
changing the code. Reference architecture: the sibling `github-mcp-proxy`
repo (same request-flow philosophy, same rules grammar roots).

## Invariants (do not break without discussion)

- **Request flow** (buffer body -> browser guard -> parse -> policy ->
  forward): Origin or Sec-Fetch-Site header => 403. Unparseable body =>
  pass through. Batch with any tools/call => whole batch blocked (fail
  closed; note this differs from github-mcp-proxy which passes batches -
  the go-sdk rejects batches on modern protocols anyway, and a smuggled
  tools/call inside a batch must not slip past policy). Non-tools/call
  methods (initialize, notifications, tools/list) => forwarded untouched.
- **Blocked call => local 200 JSON-RPC error** `code:-32000,
  message:"blocked by kubernetes-mcp-proxy policy: <reason>"`, never
  forwarded (also true for post-filter single-object rejections).
- **Response filtering runs on every forwarded tools/call**. SSE frames
  are parsed; only the frame whose `id` matches the request is rewritten,
  other frames (notifications) are re-emitted byte-identical. Upstream
  `isError` results pass unfiltered.
- **Text regeneration rule**: when structuredContent items were dropped,
  `content[0].text` is replaced by the pretty-printed filtered
  structuredContent (text must never contradict structured). Text-only
  tools are filtered by YAML item-block removal (original text of
  surviving items is preserved verbatim).
- **Namespace identity order** (response side): `item.Namespace` (table
  row key) -> `item.metadata.namespace` -> for kind `Namespace`:
  `metadata.name` -> events format: capital-N `  Namespace:` at indent 2.
  Cluster-scoped items (no namespace) pass. Kind check: `deny_kinds` vs
  the item's `kind` (defense in depth; request side already blocks the
  kind argument).
- **Rules load once at startup.** No reload endpoint. Edit file, restart
  (down && up). Missing rules file = forward everything (fail open,
  logged). Malformed entries dropped + logged, never half-applied.
- **HOP headers stripped** both directions conceptually: request strips
  host, authorization, connection, keep-alive, transfer-encoding, upgrade,
  proxy-*. Accept is NEVER stripped (go-sdk streamable requires
  `application/json` + `text/event-stream` both present). Mcp-Session-Id
  and MCP-Protocol-Version pass through.
- **Upstream is loopback-only** (`bind_address = "127.0.0.1"`) and the
  go-sdk localhost protection stays on (never set
  `disable_localhost_protection`). The proxy strips the client Host header
  so node re-sets it to the loopback target.
- **`list_output = "yaml"` is mandatory** upstream: the text filter parses
  `- `-prefixed YAML item blocks; the table parser is only a fallback for
  `pods_top`/`nodes_top` (their output is tabwriter regardless). Do not
  "optimize" the upstream to table output.
- **No new runtime dependencies.** Node stdlib only (same house rule as
  github-mcp-proxy).

## Rules grammar

```json
{
  "schema": "containers/kubernetes-mcp-server@vX.Y.Z",
  "deny_tools": ["tool_name"],
  "deny_calls": [{ "tool": "name", "if": { "arg": "value" }, "reason": "..." }],
  "deny_kinds": ["Secret"],
  "allowed_namespaces": ["default"]
}
```

`deny_calls` is github-mcp-proxy compatible (subset match on `if`).
Extensions: `deny_kinds` (kind argument + create-manifest sniff +
response items) and `allowed_namespaces` (request namespace arguments +
response items; omit for `*`).

Create-manifest sniffing (`resources_create_or_update`, any `resource`
string argument): JSON manifests are parsed exactly (`kind`,
`metadata.namespace`). YAML manifests: first top-level `kind:` line;
namespace taken only from inside the first top-level `metadata:` block
(indented following lines) so `subjects[].namespace` in a RoleBinding
cannot impersonate the object's namespace. Unparseable manifest =>
refused (fail closed).

## tools-list snapshot / drift check

Deny rules fail open on upstream drift. Procedure on every upstream bump:

1. Start upstream (`kubernetes-mcp-proxy.sh up`), initialize, then
   `tools/list` through the proxy; extract `data:` frames.
2. Normalize (names, arg types/enums, required only):

   ```sh
   jq -S '[.result.tools[] | {name,
     props: ((.inputSchema.properties // {}) | with_entries(.value =
       {type: .value.type} + (if .value.enum then {enum: .value.enum} else {} end))),
     required: (.inputSchema.required // [])}]' tools.json > tools.norm.json
   ```

3. `diff tools-list@<old>.json tools.norm.json` - report new/changed/
   removed tools, agree rule changes, then replace the snapshot with
   `tools-list@<new-tag>.json` and update the rules `schema` field.
4. `sh tests/validate.sh` must pass (it cross-checks rules against the
   snapshot and pins toml invariants).

## Tests

- `tests/validate.sh` - offline: `node --check`, `sh -n`, rules vs
  snapshot, toml loopback/yaml pins, insecure-default sanity.
- `tests/e2e.sh` - offline: real proxy against `tests/stub-upstream.mjs`
  (SSE canned responses); asserts handshake passthrough, all four response
  filter paths, request-side denials never reach upstream, browser 403.
  This is the one runnable check - keep it green.
- Live: point at a real cluster (minikube) and check pods_list /
  namespaces_list / events_list only show allowed namespaces, Secret
  list/get/exec/configuration_view are -32000.

## Layout / repo rules

- MIT, own git repo, no remote unless the owner adds one.
- Log default: `/tmp/opencode/kubernetes-mcp-proxy.log`.
- Ports: proxy 3720, upstream 8081 (override: PORT / UPSTREAM_URL env for
  the proxy, KMP_* env for the control script).
- Do not run the control script's pkill patterns inside a command that
  also contains the literal upstream command line (the shell matches
  itself); kill by the anchored patterns in the script instead.
