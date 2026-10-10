---
name: kubernetes-mcp-proxy-rules
description: Install, review, or refresh the policy rules for kubernetes-mcp-proxy - capture the live kubernetes-mcp-server tool schema, diff it against the committed snapshot, validate deny rules before install (rules fail open on typos), complete the refresh after a schema-locked upstream bump, and verify the proxy after changes. Use when the user wants to set up, review, or change kubernetes-mcp-proxy rules, upgrade the pinned upstream binary, or re-validate the policy after kubernetes-mcp-server changed.
---

# kubernetes-mcp-proxy rules setup

The proxy enforces the rules file (`kubernetes-mcp-proxy.rules.json`,
installed next to the proxy or in a repo checkout) on every `tools/call`:
deny tools, deny argument patterns, deny secret-holding kinds (including
create-manifests), scope namespaces, and filter responses. This skill
discusses the policy, checks it against the server's live schema,
installs it, and verifies the result.

## Why the live-schema check is mandatory

The startup schema lock compares version *strings* only (rules `schema`
@tag vs upstream `serverInfo.version`). It cannot see content: a rule
naming a tool or argument the pinned tag does not have (typo,
hand-edit) matches nothing and therefore **blocks nothing - fail open at
call time**. Every setup, including re-runs, validates the rules against
the live `tools/list` below before installing.

## Step 1 - prerequisites

- `kubernetes-mcp-proxy.sh status` must report both processes up (else
  `up` first). Ports: proxy `3720`, upstream `8081` (env overrides:
  `PORT`/`UPSTREAM_URL`, `KMP_*`).
- Check the log (`/tmp/kubernetes-mcp-proxy.log`): expect
  `schema ok: upstream matches rules vX.Y.Z`. If it says
  `schema LOCKED`, the upstream binary was bumped without a rules
  refresh - continue anyway: `initialize` and `tools/list` still pass
  through the locked proxy, so the capture/diff/validate steps below
  are exactly the refresh that clears the lock (Step 6).
- Rules file, repo checkout (for the committed snapshot), and this
  skill directory present.

## Step 2 - discuss the policy

The shipped defaults: `deny_tools` = pods_exec, pods_run,
configuration_view, nodes_log; `deny_kinds` = Secret, ConfigMap,
SealedSecret, ExternalSecret, SecretStore, ClusterSecretStore,
SecretProviderClass, Role, RoleBinding, ClusterRole, ClusterRoleBinding;
`allowed_namespaces` = ["default"]. Ask the user:

1. **Namespaces** - which are allowed? (`[]` denies every namespace;
   omit the field to allow all - rarely what anyone wants.)
2. **Cluster CRD inventory** - secret-holding CRDs this list never saw
   pass until added. Check what is actually installed:
   `kubectl get crd -o name | grep -iE 'secret|vault|sealed|extern'`
   and offer to add matches to `deny_kinds` (and the upstream TOML
   `[[denied_resources]]` mirror - keep them in sync).
3. **Logs** - may `pods_log` stay allowed for this deployment?
   Application logs routinely print connection strings, tokens, stack
   traces and PII, and everything returned through the MCP ends up at
   your LLM provider. Keep `pods_log` only if the provider may see
   whatever these apps print - assume they will. Anything you would
   not hand to that provider deliberately does not belong in logs:
   add `pods_log` to `deny_tools` (humans keep `kubectl logs`
   directly). A **no-training agreement with the provider is a must**,
   not a nice-to-have, before any real workload's logs or data flow
   through an MCP to an LLM.
4. **Strictness** - conditional rules via `deny_calls`? The shipped
   TOML runs `read_only = true` (safe default: writes refused at the
   source); does the user need writes? Commenting it out re-opens the
   workload ferret chain (README, "Workloads can still leak denied
   kinds").

Custom rules are fine: start from the shipped defaults and edit with
the user using the grammar at the bottom.

## Step 3 - capture the live schema

Probe through the proxy (`:3720`; works even when locked). Accept must
list both mimetypes - the go-sdk rejects the request otherwise:

```sh
curl -sS -D /tmp/kmp-h -o /dev/null -X POST http://127.0.0.1:3720/mcp \
  -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"rules-check","version":"0"}}}'
SID=$(grep -i '^mcp-session-id:' /tmp/kmp-h | tr -d '\r' | awk '{print $2}')
curl -sS -o /dev/null -X POST http://127.0.0.1:3720/mcp \
  -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' \
  -H "mcp-session-id: $SID" -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'
curl -sS -o /tmp/kmp-tools.raw -X POST http://127.0.0.1:3720/mcp \
  -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' \
  -H "mcp-session-id: $SID" -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
grep -q '^data: ' /tmp/kmp-tools.raw \
  && sed -n 's/^data: //p' /tmp/kmp-tools.raw > /tmp/kmp-tools.json \
  || cp /tmp/kmp-tools.raw /tmp/kmp-tools.json
```

## Step 4 - diff against the committed snapshot

In the repo checkout, normalize the live capture (names, argument
types/enums, required only) and diff against `tools-list@<tag>.json`:

```sh
jq -S '[.result.tools[] | {name,
  props: ((.inputSchema.properties // {}) | with_entries(.value =
    {type: .value.type} + (if .value.enum then {enum: .value.enum} else {} end))),
  required: (.inputSchema.required // [])}]' /tmp/kmp-tools.json > /tmp/kmp-live.norm
diff <repo>/tools-list@<tag>.json /tmp/kmp-live.norm
```

Report the deltas to the user with the security reading, and agree any
rule changes **before** installing:

- **new tools**: escape hatches (exec/run/log/port-forward style)?
  kubeconfig or credential readers? -> `deny_tools`
- **new/changed arguments**: namespace-like args (covered by the
  namespace checks?), manifest-string args (need the sniff - only
  `resource` is sniffed today), new kind enums, all-namespaces booleans
  (response filter covers them - confirm)
- **removed tools**: drop stale `deny_tools` entries - EXCEPT with the
  shipped `read_only = true` upstream: then the live list lacks the
  write tools (`pods_delete`, `pods_exec`, `pods_run`,
  `resources_create_or_update`, `resources_delete`, `resources_scale`)
  while the snapshot (full tag inventory) still has them. That delta
  is the shipped config, not upstream drift - keep those entries, they
  bite again the moment `read_only` is relaxed.

## Step 5 - validate the rules against the live schema

Unknown tools, unknown `if` arguments, and values that fell out of an
enum are reported instead of silently never matching. The validator
lives next to this file:

```sh
jq -n --slurpfile R <rules-file> --slurpfile L /tmp/kmp-tools.json \
  --slurpfile S <repo>/tools-list@<tag>.json \
  -f <path-to-this-dir>/validate.jq
```

The committed snapshot is passed as well (union, live wins): the
shipped upstream runs `read_only = true`, which hides the write tools
from the live `tools/list` while rules legitimately name them. A tool
in *neither* source is a real typo.

Fix every reported line (adjust the rule or drop it), then re-run until
it prints `rules valid against live schema`. (`deny_kinds` and
`allowed_namespaces` cannot be checked against `tools/list` - kinds are
free strings, namespaces are cluster state; Step 2's inventory and
Step 6's behavior probes cover them.)

## Step 6 - install and verify

```sh
cp <rules-file> <install-dir>/kubernetes-mcp-proxy.rules.json   # e.g. ~/.local/bin or the repo
kubernetes-mcp-proxy.sh down && kubernetes-mcp-proxy.sh up
grep -E 'rules:|schema ' /tmp/kubernetes-mcp-proxy.log | tail -2
# expect: rules: N deny_tools, M deny_calls, K deny_kinds, allowed_namespaces ...
#         schema ok: upstream matches rules vX.Y.Z   (a prior LOCKED line is gone now)
```

If the snapshot moved (Step 4): save the new normalized capture as
`tools-list@<new-tag>.json` in the repo, delete the stale snapshot,
set the rules `schema` field to the same tag, and run the repo tests:

```sh
sh tests/validate.sh && sh tests/e2e.sh
```

Behavior probes through the proxy (`:3720`) - all must hold:

- `resources_list` with `{"apiVersion":"v1","kind":"Secret"}` ->
  JSON-RPC error -32000 "blocked by kubernetes-mcp-proxy policy"
- `pods_list` with `{}` -> YAML contains only allowed namespaces
  (out-of-scope items filtered, not just hidden by luck)
- `resources_create_or_update` with a Secret manifest (any namespace)
  -> -32000
- `resources_create_or_update` with a plain manifest (e.g. a Pod) ->
  upstream error `unknown tool ...` (the shipped `read_only = true`
  removes the write tools from upstream; if this SUCCEEDS, read_only
  was switched off - confirm that was deliberate)
- direct to upstream `:8081`, same Secret list -> refused by upstream
  itself ("resource not allowed", the `denied_resources` backstop)

Behavior probes are deliberately **non-invasive**: they only attempt
operations that must be *blocked*, plus the upstream backstop and
`read_only` checks. Do NOT run adversarial data-exfiltration tests
against customer clusters. The known chain (create an echo Pod in an
allowed namespace mounting a Secret, read it back via `pods_log`) is
only possible when upstream `read_only` is switched off - the shipped
default closes it - and testing it belongs in repo-level e2e on a dev
cluster only (README, "Workloads can still leak denied kinds").

## Rule grammar

```json
{
  "schema": "containers/kubernetes-mcp-server@vX.Y.Z",
  "deny_tools": ["tool_name"],
  "deny_calls": [{ "tool": "name", "if": { "arg": "value" }, "reason": "..." }],
  "deny_kinds": ["Secret"],
  "allowed_namespaces": ["default"]
}
```

- `schema` - upstream tag the rules were written against. **Enforced at
  startup**: mismatch (or unset) locks every `tools/call` with a
  refresh hint until rules are refreshed and the proxy restarted;
  `initialize`/`tools/list` keep passing so the new schema can be
  captured through the proxy.
- `deny_tools` - tool blocked outright; checked first.
- `deny_calls` - exact tool plus subset match on `if` (every listed
  pair must equal the call's argument; extra arguments do not stop a
  match). First matching rule wins. `reason` lands in the error/log.
- `deny_kinds` - blocked as the `kind` argument, sniffed out of
  `resources_create_or_update` manifests (JSON exact; YAML line-based,
  unparseable => refused), and filtered from responses. Keep the
  upstream TOML `[[denied_resources]]` mirror in sync (GVK-exact).
- `allowed_namespaces` - the only namespaces that can be targeted or
  seen; omit for `*`, `[]` denies all.
- Rules load once at startup - edit, then restart. Malformed entries
  are dropped and logged, never applied half-way.
- Scope: MCP path only. The upstream (`:8081`) is loopback with the
  `denied_resources` backstop but no namespace scoping - its ceiling is
  RBAC on the kubeconfig. Shell `kubectl` bypasses the proxy entirely.
