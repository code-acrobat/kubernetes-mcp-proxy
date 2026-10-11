# Threat model

What kubernetes-mcp-proxy defends, from whom, what it explicitly does
**not** defend, and how security reports against it are judged. This is
the rubric for [ADVERSARIAL-TESTS.md](ADVERSARIAL-TESTS.md), for any
external review (the OSS Scanner enrollment points `threat_model` at
this file), and for anyone deciding whether the proxy fits their
deployment.

## Deployment assumption

Single-user machine. The proxy listens on loopback
(`127.0.0.1:3720`), the upstream on `127.0.0.1:8081`, and every local
process is the same principal: there is no authentication because the
machine's login boundary is the identity layer. Deployments that need
more (multi-tenant hosts, shared workstations) are out of scope for
this file and must add their own boundary (per-user VMs, filtered
port grants, RBAC - see README, Sandboxing).

## Assets

1. **Values of denied kinds** - `Secret`, `ConfigMap`, secret-carrying
   CRDs, and RBAC material must never cross the MCP boundary, in
   either direction.
2. **Out-of-scope cluster state** - anything outside
   `allowed_namespaces` must never be returned, including through
   all-namespaces lookups.
3. **Credentials** - kubeconfig contents (`configuration_view` and
   tools like it) must not be exposed.
4. **Cluster state integrity** - with the shipped
   `read_only = true`, the MCP channel must not mutate the cluster at
   all.
5. **The data flow to the LLM provider** - everything returned
   through an MCP ends up in a provider's logs; the policy is the
   throttle on that flow.

## Adversaries in scope

| adversary | defended by |
|-----------|-------------|
| confused or prompt-injected MCP client driving the tools | `deny_tools` / `deny_calls` / `deny_kinds` / namespace scoping / response filter |
| policy mistakes (typos, stale rules, hand-edits) | startup schema lock, `tests/validate.sh`, the rules skill's live-schema validation |
| upstream binary bumped without review (supply-chain/drift) | schema lock - every `tools/call` refused until rules + snapshot are refreshed |
| proxy bypassed by calling the upstream port directly | upstream `[[denied_resources]]` mirror (GVK-exact), loopback-only binding |
| any local process talking to `:3720` | **not defended - by design** (see out of scope) |

## In-scope findings (what counts as a vulnerability)

A report is in scope if it demonstrates any of:

- a call the policy denies succeeding through the proxy (bypass of
  `deny_tools`, `deny_calls`, `deny_kinds`, or the namespace checks)
- out-of-scope data surviving a response filter (an item from a
  denied kind or a non-allowed namespace reaching the client in any
  representation: YAML text, structuredContent, tables)
- the schema lock being bypassable (`tools/call` succeeding while
  locked, or a rules/upstream version mismatch not locking)
- the create-manifest sniffer being evaded (a denied kind or
  out-of-scope namespace entering through
  `resources_create_or_update` in an encoding the sniff does not
  refuse)
- a fail-open path: unexpected input handled by forwarding instead
  of refusing (batch containing a denied call, unparseable manifest,
  missing/invalid rules)
- the shipped files drifting apart (rules `deny_kinds` vs the TOML
  `denied_resources` mirror)

Findings must include a repro against the pinned pair: the rules
`schema` tag and the matching `kubernetes-mcp-server` version.
Reports against other versions are informational until reproduced.

## Out of scope (by design - not findings)

- **Loopback has no authentication.** Any local process can reach
  `:3720` and `:8081`. Single-user model; on a shared host this is a
  deployment requirement, not a proxy bug.
- **Shell `kubectl`** bypasses the MCP entirely. The proxy governs
  the MCP channel only; whoever holds the kubeconfig is trusted.
- **Data exfiltration through workloads.** With writes enabled
  (`read_only` off), a Pod in an allowed namespace can mount a
  Secret (the kubelet fetches it - no `get` needed) and print it.
  No rules file can close this chain; the shipped default refuses
  the write that starts it (`read_only = true`). Verified in
  ADVERSARIAL-TESTS.md.
- **Application log content** returned by `pods_log`. A deliberate
  trade-off (main debugging tool); deny the tool if the trade is not
  yours. Everything returned reaches the LLM provider - see the
  rules skill's policy discussion.
- **Event entries naming denied resources** - kind and name only;
  values never appear, and the event's own namespace is still
  filtered.
- **Unknown secret-holding CRDs** not yet in `deny_kinds`. The deny
  list is explicit, not exhaustive; mitigated (schema lock, backstop
  mirror, rules-skill CRD inventory) but not complete by itself.
- **Vulnerabilities in the upstream binary, the kubelet, or the
  Kubernetes API.** The proxy is not their security boundary; it
  assumes a trusted upstream it pins by version.
- **LLM provider retention.** Data that passes the policy still
  reaches the provider - an operator concern the proxy cannot
  filter.

## Severity guidance for reports

- **High** - any in-scope finding above with a working repro
  (denied call succeeding, out-of-scope data delivered, lock or
  sniffer bypassed).
- **Medium** - fail-open reachable only through exotic but legal
  input; a real inconsistency between the shipped rules and TOML
  mirror; response-filter misses in a representation the tests do
  not cover, where data is plausibly reachable.
- **Low / informational** - hardening suggestions; issues requiring
  an already-compromised upstream or kubeconfig (trusted by design);
  anything in the out-of-scope list.

## What the proxy is

A defense-in-depth filter for one MCP channel on one machine: it
narrows what an agent can ask a cluster for and what answers come
back. It is not an authorizer (RBAC remains the cluster's job), not
authentication, not a multi-tenant boundary, and not a content
firewall for everything an application or an LLM might emit.
