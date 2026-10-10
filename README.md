# kubernetes-mcp-proxy

A policy proxy in front of
[`containers/kubernetes-mcp-server`](https://github.com/containers/kubernetes-mcp-server)
(HTTP mode). It enforces a small, secure default policy:

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
policy gate for a single-user machine: any local process can reach it,
it filters operations, not identity.

## How it works

```
any MCP client
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
| `kubernetes-mcp-server.toml` | hardened upstream config (loopback, `list_output = "yaml"`, `denied_resources` backstop for the deny_kinds kinds) |
| `tools-list@v0.0.67.json` | normalized snapshot of upstream tools (drift marker) |
| `tests/validate.sh` | offline: syntax + rules-vs-snapshot |
| `tests/e2e.sh` | offline: full policy behavior against a stub upstream |
| `skills/kubernetes-mcp-proxy-rules/` | AI-assisted install/refresh workflow (skill: live-schema check + validated install) |

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

Log: `/tmp/kubernetes-mcp-proxy.log`.
Kill switch: `kubernetes-mcp-proxy.sh down` (or just kill the proxy - the
upstream stays loopback-only).

Point your MCP client at the proxy, not at the upstream:

```json
{ "mcp": { "kubernetes": { "type": "remote", "url": "http://127.0.0.1:3720/mcp" } } }
```

## Sandboxing

The proxy makes most sense when the MCP client itself runs sandboxed:
grant the sandbox **only** the proxy port (`3720`) - never the upstream
port (`8081`) and never the kubeconfig file. Then even a confused or
compromised client cannot bypass the policy layer. Any sandbox with
per-port network allowlists works; for example omac (oh-my-agentic-coder,
its `network.open_port` setting), Firejail, or bubblewrap:

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

- `schema` - upstream release the rules were written against, pinned as
  `containers/kubernetes-mcp-server@vX.Y.Z`. **Enforced at startup**: the
  proxy asks upstream for its version (`initialize` -> `serverInfo`) and
  locks every `tools/call` (error -32000 with a refresh hint) on mismatch
  until the rules are refreshed and the proxy restarted. `initialize` and
  `tools/list` keep passing so the new schema can be captured through the
  proxy. An unset/unversioned `schema` also locks (see Upgrading).
- `deny_tools` - tool blocked outright.
- `deny_calls` - exact tool + subset match on arguments (every `if` pair
  must equal the call's arguments; extra arguments do not stop a match).
- `deny_kinds` - blocked as `kind` arguments, sniffed from
  `resources_create_or_update` manifests, *and* filtered from responses.
- `allowed_namespaces` - the only namespaces that can be targeted or seen.
  Omit to allow every namespace (response namespace filter off; kind filter
  stays on); `[]` denies every namespace.

Rules are read **once at startup** - edit the file, then restart
(`kubernetes-mcp-proxy.sh down && ... up`). A missing or unversioned
rules file locks every tools/call (schema lock, above); a malformed
entry is dropped and logged, never applied half-way.

To widen the namespace scope:

```json
"allowed_namespaces": ["default", "dev"]
```

To make it stricter than the defaults (defense-in-depth lines enterprises
typically want on top of a hosted/shared MCP):

- add `pods_log` (and any other tool you distrust) to `deny_tools`
- `deny_calls` for conditional rules, e.g.
  `{"tool": "pods_delete", "if": {"namespace": "default"}, "reason": "deletes are platform-team only"}`
- narrow `allowed_namespaces` to one namespace (`[]` denies every namespace)
- set `read_only = true` in the upstream TOML: every write is refused
  at the source, policy or not (`disable_destructive = true` keeps
  reads but blocks delete/update)

## Security notes

- **Loopback only, no auth**: any local process can talk to `:3720` /
  `:8081`. Fine on a single-user machine, not on a multi-tenant host.
- **Workloads can still leak denied kinds** (verified on a dev
  cluster): a Pod in an allowed namespace can mount a Secret
  (`envFrom`/`secretKeyRef` - creating it needs no `get` on the
  Secret; the kubelet fetches it) and print it via `pods_log`. No
  deny rule fires because no denied object is ever touched through
  the MCP. The ceiling is upstream `read_only = true` (refuses the
  write that starts the chain) or cluster admission policy
  restricting secret volumes; RBAC on the kubeconfig alone does not
  close this chain. The proxy narrows the MCP surface, it does not
  replace the Kubernetes authorizer.
- **`pods_log` can print secret material** that a workload has mounted;
  it is not denied by default because it is the main debugging tool.
  Add it to `deny_tools` if that trade-off is not yours to make.
- **Events can name denied resources**: an event that references a Secret
  carries only its kind and name (values never appear), and the event's
  own namespace is still filtered. Name-only disclosure; add `events_list`
  to `deny_tools` if even that is too much.
- **Rule typos fail open at call time**: the schema lock compares
  version *strings*, not tool schemas - a `deny_tools`/`deny_calls`
  entry that names a tool or argument the pinned tag does not have
  (typo, hand-edit, custom build reporting an unchanged version)
  matches nothing and therefore blocks nothing. `tests/validate.sh`
  catches this offline by cross-checking the rules against the
  committed `tools-list@<version>.json` snapshot; refresh the snapshot
  whenever the pinned tag changes (procedure in AGENTS.md).
- **Version drift locks the proxy**: the rules `schema` tag is checked
  against the live upstream version at startup. A Renovate-style bump of
  the binary without refreshing rules+snapshot locks every `tools/call`
  (with a hint) instead of silently running the old policy against new
  tools. Argument-level drift inside a matching tag still fails open -
  `tests/validate.sh` (rules vs committed snapshot) is the offline
  check; the full process is in Upgrading below.
- **The deny list is explicit, not exhaustive**: `deny_kinds` covers the
  common secret-holding kinds; a CRD this project has never seen passes
  until someone adds it. Mitigations: the same kinds are ALSO denied by
  the upstream itself (`[[denied_resources]]` in the shipped TOML), so
  direct `:8081` access or a proxy bug still cannot read them; the
  schema lock refuses new upstream toolsets until reviewed. Namespace
  scoping exists only in the proxy - the ceiling for that is RBAC on
  the kubeconfig the upstream uses. Trial on a dev cluster first (next
  section).
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

## Upgrading (new upstream release)

The proxy is pinned to one upstream tag (rules `schema` field). The
intended flow is Renovate-style: the org pins the upstream binary, a
human reviews the upstream changelog, bumps the pin - and the proxy
stays in lockstep as an extra defense layer. When the binary is bumped,
the running proxy **locks every `tools/call`** until the policy is
re-synchronized. Process:

1. **Read the upstream changelog**:
   [containers/kubernetes-mcp-server releases](https://github.com/containers/kubernetes-mcp-server/releases)
   (and the Go MCP SDK bump if mentioned). Note any Kubernetes version
   support changes - they decide which kinds/APIs the tools can see.
2. **Install the new binary** (same command as Install, new tag) and
   `kubernetes-mcp-proxy.sh down && ... up`. The proxy now logs
   `schema LOCKED` and every tools/call returns -32000 with a hint;
   `initialize` and `tools/list` still pass through.
3. **Capture the new schema through the locked proxy**: initialize
   (grab `Mcp-Session-Id`), then `tools/list`, extract the `data:`
   frames, normalize (jq one-liner in AGENTS.md).
4. **Diff against the committed snapshot** (`tools-list@<old-tag>.json`)
   and review - this is the human review step:
   - **New tools**: any escape hatches (exec/run/log/port-forward
     style), anything reading kubeconfig or cloud credentials, any new
     secret-holding CRD kind? Add to `deny_tools` / `deny_kinds`.
   - **Changed arguments**: new namespace-like args must be covered by
     the namespace checks; new manifest-string args (like `resource`)
     need the same sniffing; new kind enums may need `deny_kinds`
     entries; new all-namespaces booleans are caught by the response
     filter but confirm it.
   - **Removed tools**: drop stale `deny_tools` entries (validate.sh
     fails otherwise).
5. **Bump the rules `schema` field** to the new tag, apply the rule
   changes from step 4, save the normalized snapshot as
   `tools-list@<new-tag>.json` (delete the old one).
6. **Run `sh tests/validate.sh`** (rules vs snapshot, toml pins) and
   `sh tests/e2e.sh` (policy behavior against the stub).
7. **Restart and verify live**: `kubernetes-mcp-proxy.sh down && ... up`,
   confirm the log line `schema ok: upstream matches rules ...`, then
   smoke-test: a denied kind (Secret list -> -32000) and a filtered
   list (`pods_list {}` -> only allowed namespaces).

## Recommended rollout: dev cluster first

The defaults are a reviewed best guess, not a proof of completeness -
new CRDs that store secrets appear faster than deny lists. Trial before
production:

1. Point the upstream's kubeconfig at a **dev cluster**, keep the
   default rules, `kubernetes-mcp-proxy.sh up`.
2. Probe the surface through the proxy (`:3720`):
   - `resources_list` with `kind: Secret` -> `-32000`
   - `pods_list {}` -> only allowed namespaces in the YAML
   - `resources_create_or_update` with a Secret manifest -> `-32000`
   - direct `:8081` Secret list -> refused by upstream
     (`denied_resources` backstop)
3. Watch `/tmp/kubernetes-mcp-proxy.log` while developers use
   it for a few days - every blocked call and filtered response is
   logged; review what was *not* blocked.
4. Inventory the secret-holding CRDs actually installed (SealedSecrets,
   ExternalSecrets, Vault providers, ...) and extend `deny_kinds` +
   the TOML `denied_resources` mirror before widening
   `allowed_namespaces` or enabling more toolsets.
5. Move to the production kubeconfig only after that; keep clients on
   `:3720` and put namespace-scoped RBAC on the upstream's kubeconfig -
   that is the one boundary the proxy cannot provide itself.
