# kubernetes-mcp-proxy

A policy proxy in front of
[`containers/kubernetes-mcp-server`](https://github.com/containers/kubernetes-mcp-server)
(HTTP mode), modeled after
[github-mcp-proxy](https://github.com/code-acrobat/github-mcp-proxy).
It enforces a small, secure default policy:

- **Secret-holding kinds are invisible**: `Secret`, `ConfigMap`, and the
  usual secret-carrying CRDs (`SealedSecret`, `ExternalSecret`,
  `SecretStore`/`ClusterSecretStore`, `SecretProviderClass`) can neither be
  listed, read, created, updated, deleted nor scaled. RBAC kinds
  (`Role`/`RoleBinding`/`ClusterRole`/`ClusterRoleBinding`) are denied by
  default too - a writable RoleBinding would bypass every other rule.
- **Namespace scoping**: only `allowed_namespaces` (default: `["default"]`)
  can be targeted *and* seen. Requests naming another namespace are refused.
- **"All namespaces" lookups honor the policy**: tools like `pods_list`
  (no namespace argument = whole cluster) are answered, but the response is
  *filtered* - out-of-scope items are removed before the client sees them.
- **Escape hatches closed**: `pods_exec`, `pods_run`, `configuration_view`
  (kubeconfig exposure) and `nodes_log` are denied outright.

Everything runs on loopback. The proxy is not authentication - it is a
policy gate for a single-user machine (same threat model as
github-mcp-proxy).

## How it works

```
opencode/any MCP client
        |  http://127.0.0.1:3720/mcp
        v
kubernetes-mcp-proxy  (node, zero-dep, one file)
  request:  deny_tools / deny_calls / deny_kinds / allowed_namespaces
            (also sniffs `kind` + `metadata.namespace` out of
             resources_create_or_update manifests)
  response: filters list & get results - YAML text, structuredContent,
            tables - so cluster-wide lookups only return allowed parts
        |  http://127.0.0.1:8081/mcp
        v
kubernetes-mcp-server (HTTP mode, loopback, list_output = "yaml")
        |
        v
   your cluster (kubeconfig)
```

Blocked calls are answered locally with a JSON-RPC error
(`code: -32000, "blocked by kubernetes-mcp-proxy policy: ..."`) and are
never forwarded. Filtered responses come back with out-of-scope items
removed; a single out-of-scope object (`resources_get`) becomes the same
`-32000` error.

## Files

| file | role |
|------|------|
| `kubernetes-mcp-proxy.mjs` | the proxy (node >= 18, zero deps) |
| `kubernetes-mcp-proxy.sh` | `up` / `down` / `status` for both processes |
| `kubernetes-mcp-proxy.rules.json` | the policy (see below) |
| `kubernetes-mcp-server.toml` | hardened upstream config (loopback, `list_output = "yaml"`) |
| `tools-list@v0.0.67.json` | normalized snapshot of upstream tools (drift marker) |
| `tests/validate.sh` | offline: syntax + rules-vs-snapshot |
| `tests/e2e.sh` | offline: full policy behavior against a stub upstream |

## Install

```sh
cp kubernetes-mcp-proxy.mjs kubernetes-mcp-proxy.sh \
   kubernetes-mcp-proxy.rules.json kubernetes-mcp-server.toml ~/.local/bin/
# upstream binary (example):
#   curl -sSL -o ~/.local/bin/kubernetes-mcp-server \
#     https://github.com/containers/kubernetes-mcp-server/releases/download/v0.0.67/kubernetes-mcp-server-linux-amd64
#   chmod +x ~/.local/bin/kubernetes-mcp-server
~/.local/bin/kubernetes-mcp-proxy.sh up     # starts upstream :8081 + proxy :3720
~/.local/bin/kubernetes-mcp-proxy.sh status
```

Log: `/tmp/opencode/kubernetes-mcp-proxy.log`.
Kill switch: `kubernetes-mcp-proxy.sh down` (or just kill the proxy - the
upstream stays loopback-only).

Point your MCP client at the proxy, not at the upstream:

```json
{ "mcp": { "kubernetes": { "type": "remote", "url": "http://127.0.0.1:3720/mcp" } } }
```

If you run opencode inside an omac sandbox, grant the port
(`~/.config/omac/sandbox-profiles/default.json`):

```json
{ "network": { "open_port": [3720] } }
```

## The rules file

```json
{
  "schema": "containers/kubernetes-mcp-server@v0.0.67",
  "deny_tools": ["pods_exec", "pods_run", "configuration_view", "nodes_log"],
  "deny_calls": [{ "tool": "pods_delete", "if": { "namespace": "default" }, "reason": "..." }],
  "deny_kinds": ["Secret", "ConfigMap", "..."],
  "allowed_namespaces": ["default"]
}
```

- `schema` - upstream release the rules were written against (drift marker).
- `deny_tools` - tool blocked outright.
- `deny_calls` - exact tool + subset match on arguments (every `if` pair
  must equal the call's arguments; extra arguments do not stop a match).
- `deny_kinds` - blocked as `kind` arguments, sniffed from
  `resources_create_or_update` manifests, *and* filtered from responses.
- `allowed_namespaces` - the only namespaces that can be targeted or seen.
  Omit to allow every namespace (response namespace filter off; kind filter
  stays on); `[]` denies every namespace.

Rules are read **once at startup** - edit the file, then restart
(`kubernetes-mcp-proxy.sh down && ... up`). A missing rules file forwards
everything (fail open, same as github-mcp-proxy); a malformed entry is
dropped and logged, never applied half-way.

To widen the namespace scope:

```json
"allowed_namespaces": ["default", "dev"]
```

## Security notes

- **Loopback only, no auth**: any local process can talk to `:3720` /
  `:8081`. That is the same model as github-mcp-proxy - fine on a
  single-user machine, not a multi-tenant host.
- **Workloads can still leak denied kinds**: a Pod in an allowed namespace
  can mount a Secret and print it via `pods_log`. The ceiling is upstream
  `read_only = true` (kills every write) plus real RBAC; the proxy narrows
  the MCP surface, it does not replace the Kubernetes authorizer.
- **`pods_log` can print secret material** that a workload has mounted;
  it is not denied by default because it is the main debugging tool.
  Add it to `deny_tools` if that trade-off is not yours to make.
- **Events can name denied resources**: an event that references a Secret
  carries only its kind and name (values never appear), and the event's
  own namespace is still filtered. Name-only disclosure; add `events_list`
  to `deny_tools` if even that is too much.
- **Deny rules fail open on drift**: if upstream renames a tool, a
  `deny_tools` entry silently stops matching. Run `tests/validate.sh`
  (rules vs committed `tools-list@<version>.json`) after any upstream
  bump, and refresh the snapshot (procedure in AGENTS.md).
- **Create-manifest sniffing is line-based for YAML** (top-level `kind`,
  `namespace` inside the first `metadata:` block). Exotic styles (flow
  mappings) are refused rather than forwarded unverified. JSON manifests
  are parsed exactly.
- **Upstream must run with `list_output = "yaml"`** (the shipped TOML):
  the response filter parses YAML item blocks; table output is only a
  fallback for `pods_top`/`nodes_top`.
- The proxy buffers tools/call responses (up to 16 MiB) to filter them.
  It does not configure upstream `confirmation_rules`, so no
  server-initiated requests can interleave and stall the buffer.

## Tests

```sh
sh tests/validate.sh   # offline, no cluster
sh tests/e2e.sh        # offline, stub upstream
```

Live smoke test (needs a cluster, e.g. minikube):

```sh
kubernetes-mcp-proxy.sh up
# initialize + tools/call pods_list {} through http://127.0.0.1:3720/mcp
# -> only allowed namespaces remain in the YAML
```
