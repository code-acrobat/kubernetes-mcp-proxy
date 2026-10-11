#!/usr/bin/env node
// kubernetes-mcp-proxy - policy proxy in front of kubernetes-mcp-server (HTTP mode).
// Request side:  deny_tools / deny_calls / deny_kinds (incl. create manifests) / allowed_namespaces.
// Response side: filters list & get results (YAML text, structuredContent, tables) so
// "all namespaces" lookups only return allowed namespaces.
// Schema lock: rules pin one upstream tag; mismatch/unset => every tools/call denied
// (drift alarm for Renovate-style bumps; initialize/tools/list keep passing).
// Zero deps. Node >= 18. See README.md; rules grammar in AGENTS.md.
import { readFileSync, appendFileSync } from "node:fs";
import { join } from "node:path";
import http from "node:http";

const PORT = Number(process.env.PORT || 3720);
const TARGET = new URL(process.env.UPSTREAM_URL || "http://127.0.0.1:8081/mcp");
const RULES_PATH =
  process.env.RULES || join(import.meta.dirname, "kubernetes-mcp-proxy.rules.json");
const LOG = process.env.LOG || "/tmp/kubernetes-mcp-proxy.log";
// ponytail: fixed buffer cap; stream-through if this ever becomes a problem.
const MAX_BODY = 16 * 1024 * 1024;

function log(msg) {
  try {
    appendFileSync(LOG, `${new Date().toISOString()} ${msg}\n`);
  } catch {
    console.error(`[kubernetes-mcp-proxy] ${msg}`);
  }
}

// --- rules (read once at startup; edit file then restart; deny fails open on missing file) ---
let rules = {
  schema: "(none)",
  deny_tools: [],
  deny_calls: [],
  deny_kinds: [],
  allowed_namespaces: null, // null = allow every namespace
};
try {
  const raw = JSON.parse(readFileSync(RULES_PATH, "utf8"));
  const str = (v) => (typeof v === "string" && v ? v : null);
  const arr = (v) => (Array.isArray(v) ? v.map(str).filter(Boolean) : []);
  rules.schema = str(raw.schema) || "(unset)";
  rules.deny_tools = arr(raw.deny_tools);
  rules.deny_kinds = arr(raw.deny_kinds);
  if (Array.isArray(raw.allowed_namespaces)) rules.allowed_namespaces = arr(raw.allowed_namespaces); // [] = deny every namespace
  if (Array.isArray(raw.deny_calls)) {
    const bad = [];
    for (const r of raw.deny_calls) {
      if (r && str(r.tool) && r.if && typeof r.if === "object") rules.deny_calls.push(r);
      else bad.push(JSON.stringify(r));
    }
    if (bad.length) log(`rules: dropped ${bad.length} malformed deny_calls: ${bad.join(" ")}`);
  }
} catch (e) {
  log(`rules: cannot read ${RULES_PATH} (${e.message}) - NO POLICY LOADED (tools/call will be locked)`);
}
const denyTools = new Set(rules.deny_tools);
const denyKinds = new Set(rules.deny_kinds);
const allowedNs = rules.allowed_namespaces ? new Set(rules.allowed_namespaces) : null;
log(
  `rules: ${denyTools.size} deny_tools, ${rules.deny_calls.length} deny_calls, ${denyKinds.size} deny_kinds, allowed_namespaces ${
    allowedNs ? [...allowedNs].join(",") : "*"
  } (schema ${rules.schema})`
);

// --- schema lock: tight version coupling with the pinned upstream tag ---
// Orgs pin the upstream binary and bump it after human review (Renovate-style).
// The proxy verifies once at startup that upstream's initialize serverInfo.version
// matches the rules schema @tag. On mismatch/unset/unreachable: every tools/call
// is denied locally with a refresh hint; initialize and tools/list keep passing
// so the new schema can be captured through the proxy. Restart to re-verify.
const expectTag = /@([^@]+)$/.exec(rules.schema)?.[1] ?? null;
let lockReason = null;
{
  const norm = (v) => String(v).replace(/^v/, "");
  try {
    if (!expectTag)
      lockReason = `rules schema "${rules.schema}" has no @version - set "schema": "containers/kubernetes-mcp-server@vX.Y.Z" to the pinned upstream tag, then restart`;
    else {
      const res = await fetch(TARGET, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
          params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "kubernetes-mcp-proxy", version: "0" } },
        }),
        signal: AbortSignal.timeout(5000),
      });
      const raw = await res.text();
      const line = raw.split("\n").find((l) => l.startsWith("data: "));
      const got = JSON.parse(line ? line.slice(6) : raw)?.result?.serverInfo?.version ?? null;
      if (!got) lockReason = `upstream did not report serverInfo.version - cannot verify rules schema ${rules.schema}`;
      else if (norm(got) !== norm(expectTag))
        lockReason = `schema drift: upstream reports ${got}, rules pin ${expectTag} - capture tools/list, refresh snapshot+rules (AGENTS.md), run tests/validate.sh, restart`;
    }
  } catch (e) {
    lockReason = `schema check failed: upstream unreachable at startup (${e.message}) - restart the proxy once upstream is up`;
  }
}
log(lockReason ? `schema LOCKED: ${lockReason}` : `schema ok: upstream matches rules ${expectTag}`);

// --- request-side policy ---
function sniffManifest(s) {
  // returns [{kind, namespace}] (one entry per YAML document) | null when
  // unparseable (fail closed at caller).
  if (s.trim().startsWith("{")) {
    try {
      const o = JSON.parse(s);
      return [{ kind: o?.kind, namespace: o?.metadata?.namespace }];
    } catch {
      return null;
    }
  }
  // YAML: the upstream splits on \r?\n---\r?\n and applies EVERY document -
  // each one is sniffed, never just the first (multi-doc evasion, audit
  // 2026-10-11 #3).
  const docs = s.split(/\r?\n---\r?\n/);
  const out = [];
  for (const doc of docs) {
    // An undecorated top-level `kind:` line only; comment/anchor/tag
    // decoration leaves kind undefined and the caller refuses the manifest
    // (undeterminable kind must never be forwarded, audit #2).
    const kind = /^kind:\s*["']?([^"'#\s]+)["']?\s*$/m.exec(doc)?.[1];
    // Namespace only as a DIRECT child of the top-level metadata block:
    // dedented lines (subjects[].namespace in a RoleBinding) and deeper
    // keys (a label literally named "namespace") must not count (audit #4).
    let namespace;
    const meta = /^metadata:[^\n]*\n((?:[ \t]+[^\n]*\n?)*)/m.exec(doc)?.[1] ?? "";
    const metaLines = meta.split("\n").filter((l) => l.trim() !== "");
    if (metaLines.length) {
      const childIndent = /^[ \t]*/.exec(metaLines[0])[0].length;
      const nsLine = metaLines.find((l) => {
        const m = /^([ \t]+)namespace:/.exec(l);
        return m && m[1].length === childIndent;
      });
      if (nsLine) namespace = /^[ \t]+namespace:\s*["']?([^"'#\s]+)["']?\s*$/m.exec(nsLine)?.[1];
    }
    out.push({ kind, namespace });
  }
  return out;
}

function blockedRequest(msg) {
  const name = msg.params?.name;
  if (typeof name !== "string") return "tools/call without params.name";
  if (denyTools.has(name)) return `${name} is denied by policy`;
  const args = msg.params.arguments || {};
  for (const rule of rules.deny_calls) {
    if (rule.tool !== name) continue;
    const pairs = Object.entries(rule.if || {});
    if (pairs.every(([k, v]) => args[k] === v))
      return rule.reason || `${name} call denied by policy`;
  }
  if (args.kind !== undefined && denyKinds.has(String(args.kind)))
    return `kind ${args.kind} is denied by policy`;
  if (typeof args.resource === "string") {
    // resources_create_or_update: the full manifest is the payload - sniff kind
    // and namespace out of every document (JSON parsed exactly, YAML
    // line-based). Anything undeterminable is refused, never forwarded.
    const docs = sniffManifest(args.resource);
    if (!docs) return "resource manifest is not parseable; refusing to forward";
    for (const d of docs) {
      if (!d.kind)
        return "resource manifest does not declare a verifiable top-level kind; refusing to forward";
      if (denyKinds.has(d.kind)) return `kind ${d.kind} is denied by policy`;
      if (!d.namespace) return "resource manifest must declare metadata.namespace";
      if (allowedNs && !allowedNs.has(d.namespace))
        return `namespace ${d.namespace} is not allowed`;
    }
  }
  if (args.namespace !== undefined && allowedNs && !allowedNs.has(String(args.namespace)))
    return `namespace ${args.namespace} is not allowed`;
  return null;
}

// --- response-side policy ---
function passKindNs(kind, ns) {
  if (kind && denyKinds.has(kind)) return false;
  if (!ns) return true; // cluster-scoped
  return !allowedNs || allowedNs.has(ns);
}

function passObj(it) {
  if (!it || typeof it !== "object") return true;
  const kind = it.kind != null ? String(it.kind) : null;
  const ns =
    (it.Namespace != null ? String(it.Namespace) : null) ??
    (it.metadata?.namespace != null ? String(it.metadata.namespace) : null) ??
    (kind === "Namespace"
      ? String(it.metadata?.name ?? it.name ?? "") || null
      : null);
  return passKindNs(kind, ns);
}

function describeObj(it) {
  const kind = it?.kind ?? "resource";
  const ns = it?.Namespace ?? it?.metadata?.namespace;
  return ns ? `${kind} in namespace ${ns}` : String(kind);
}

// kind/ns out of one YAML item block (object lists, pods_get-style single docs,
// and the events format with its capitalized `  Namespace:` key).
function blockKindNs(lines) {
  let kind = null;
  let ns;
  let name;
  let inMeta = false;
  for (const l of lines) {
    let m;
    if ((m = /^ {2}kind: ["']?([^"'#\s]+)["']?\s*$/.exec(l))) {
      if (kind === null) kind = m[1];
      continue;
    }
    if (/^ {2}metadata:\s*$/.test(l)) {
      inMeta = true;
      continue;
    }
    if (inMeta) {
      if (/^ {2}\S/.test(l)) inMeta = false;
      else if ((m = /^ {4}namespace: ["']?([^"'#\s]+)["']?\s*$/.exec(l))) ns = m[1];
      else if ((m = /^ {4}name: ["']?([^"'#\s]+)["']?\s*$/.exec(l))) name = m[1];
    }
    if (ns === undefined && (m = /^ {2}Namespace: (\S+)\s*$/.exec(l))) ns = m[1];
  }
  if (kind === "Namespace" && ns === undefined) ns = name;
  return { kind, ns };
}

function filterText(text) {
  const lines = text.split("\n");
  const starts = [];
  lines.forEach((l, i) => {
    if (l.startsWith("- ")) starts.push(i);
  });
  if (starts.length) {
    // YAML item list (events: preamble lines before first "- " are kept).
    let dropped = 0;
    const kept = [];
    for (let i = 0; i < starts.length; i++) {
      const from = starts[i];
      const to = i + 1 < starts.length ? starts[i + 1] : lines.length;
      const block = lines.slice(from, to);
      const { kind, ns } = blockKindNs(block);
      if (passKindNs(kind, ns)) kept.push(...block);
      else dropped++;
    }
    if (!dropped) return { text, dropped: 0 };
    return { text: lines.slice(0, starts[0]).concat(kept).join("\n"), dropped };
  }
  if (/^kind:|^apiVersion:/m.test(text)) {
    // single YAML object (resources_get / pods_get)
    const { kind, ns } = blockKindNs(lines);
    if (!passKindNs(kind, ns))
      return { blocked: `${describeObj({ kind, metadata: ns ? { namespace: ns } : null })} is out of scope` };
    return { text, dropped: 0 };
  }
  // table fallback (pods_top / nodes_top): NAMESPACE/KIND columns when present.
  const hi = lines.findIndex((l) => l.trim());
  if (hi >= 0) {
    const cols = lines[hi].split(/\s{2,}/);
    const nsCol = cols.indexOf("NAMESPACE");
    const kindCol = cols.indexOf("KIND");
    if (nsCol >= 0 || kindCol >= 0) {
      const kept = [lines[hi]];
      let dropped = 0;
      for (const l of lines.slice(hi + 1)) {
        if (!l.trim()) {
          kept.push(l);
          continue;
        }
        const cells = l.split(/\s{2,}/);
        const kind = kindCol >= 0 ? cells[kindCol] : null;
        const ns = nsCol >= 0 ? cells[nsCol] : null;
        if (passKindNs(kind, ns)) kept.push(l);
        else dropped++;
      }
      if (!dropped) return { text, dropped: 0 };
      const head = lines.slice(0, hi);
      return { text: head.concat(kept).join("\n"), dropped };
    }
  }
  // ponytail: plain status text (scale results, helm notices) carries no
  // resource listing - pass through unfiltered.
  return { text, dropped: 0 };
}

function filterCallResult(obj) {
  const r = obj.result;
  if (!r || r.isError) return { obj, dropped: 0 };
  const sc = r.structuredContent;
  const ti = (r.content || []).findIndex((c) => c && c.type === "text");
  const text = ti >= 0 ? r.content[ti].text : null;
  let dropped = 0;
  let newText = null;
  if (sc && typeof sc === "object") {
    const arr = Array.isArray(sc) ? sc : Array.isArray(sc.items) ? sc.items : null;
    if (arr) {
      const kept = arr.filter((it) => passObj(it));
      dropped = arr.length - kept.length;
      if (dropped) {
        r.structuredContent = Array.isArray(sc) ? kept : { ...sc, items: kept };
        newText = JSON.stringify(kept, null, 2); // text mirrors filtered structured
      }
    } else if (!passObj(sc)) {
      return { blocked: `${describeObj(sc)} is out of scope` };
    }
  }
  if (!sc && text) {
    const f = filterText(text);
    if (f.blocked) return { blocked: f.blocked };
    dropped = f.dropped;
    if (dropped) newText = f.text;
  }
  if (dropped) {
    if (newText != null && ti >= 0) r.content[ti] = { type: "text", text: newText };
    log(`filtered ${obj.id}: dropped ${dropped} out-of-scope item(s)`);
  }
  return { obj, dropped };
}

// The go-sdk echoes numeric ids through int64 truncation (1.5 -> 1); a
// strict === would miss our own response frame and re-emit it unfiltered
// (audit 2026-10-11 #1). Compare truncated; any response-shaped frame that
// is not ours fails the call closed instead of being re-emitted.
function sameId(a, b) {
  if (a === b) return true;
  return typeof a === "number" && typeof b === "number" && Math.trunc(a) === Math.trunc(b);
}
const isRespFrame = (o) => o && typeof o === "object" && (o.result !== undefined || o.error !== undefined);
function idMismatchError(name, gotId, reqId) {
  log(
    `blocked ${name} response: upstream answered with id ${JSON.stringify(gotId)} for request id ${JSON.stringify(reqId)}; refusing to forward unfiltered`
  );
  return JSON.stringify({
    jsonrpc: "2.0",
    id: reqId,
    error: { code: -32000, message: "blocked by kubernetes-mcp-proxy policy: upstream response id mismatch" },
  });
}

function filterResponse(raw, reqId, name) {
  if (raw.includes("\ndata: ") || raw.startsWith("data: ")) {
    // SSE: rewrite only the frame matching our request id, re-emit the rest.
    const parts = raw.split("\n\n");
    const out = [];
    for (const part of parts) {
      const data = part
        .split("\n")
        .filter((l) => l.startsWith("data: "))
        .map((l) => l.slice(6))
        .join("");
      let obj;
      try {
        obj = JSON.parse(data);
      } catch {
        out.push(part);
        continue;
      }
      if (isRespFrame(obj)) {
        if (!sameId(obj.id, reqId)) return idMismatchError(name, obj.id, reqId);
        const f = filterCallResult(obj);
        if (f.blocked) {
          log(`blocked ${name} response: ${f.blocked}`);
          return JSON.stringify({
            jsonrpc: "2.0",
            id: reqId,
            error: { code: -32000, message: `blocked by kubernetes-mcp-proxy policy: ${f.blocked}` },
          });
        }
        out.push(
          part
            .split("\n")
            .map((l) => (l.startsWith("data: ") ? "data: " + JSON.stringify(f.obj) : l))
            .join("\n")
        );
      } else out.push(part);
    }
    return out.join("\n\n");
  }
  try {
    const obj = JSON.parse(raw);
    if (isRespFrame(obj)) {
      if (!sameId(obj.id, reqId)) return idMismatchError(name, obj.id, reqId);
      const f = filterCallResult(obj);
      if (f.blocked)
        return JSON.stringify({
          jsonrpc: "2.0",
          id: reqId,
          error: { code: -32000, message: `blocked by kubernetes-mcp-proxy policy: ${f.blocked}` },
        });
      return JSON.stringify(f.obj);
    }
  } catch {}
  return raw;
}

// --- http plumbing ---
const HOP = new Set([
  "host",
  "authorization",
  "connection",
  "keep-alive",
  "transfer-encoding",
  "upgrade",
  "proxy-authorization",
  "proxy-connection",
]);

function handle(req, res, body) {
  let parsed = null;
  try {
    parsed = JSON.parse(body.toString("utf8"));
  } catch {}
  let reqId = null;
  let toolsName = null;
  let shouldFilter = false;
  let blockReason = null;
  if (body.length && parsed === null)
    blockReason = "unparseable request body";
  else if (Array.isArray(parsed)) {
    const calls = parsed.filter((m) => m && m.method === "tools/call");
    if (calls.length)
      blockReason = `batch containing ${calls.length} tools/call request(s) is not allowed`;
  } else if (parsed && typeof parsed === "object") {
    if (parsed.method === "tools/call") {
      reqId = parsed.id ?? null;
      toolsName = parsed.params?.name;
      if (reqId !== null && typeof reqId === "object")
        blockReason = "unsupported tools/call request id (must be a string or a number)";
      else {
        blockReason = lockReason ?? blockedRequest(parsed);
        shouldFilter = blockReason === null;
      }
    }
  }
  if (blockReason) {
    log(`blocked ${toolsName ?? (Array.isArray(parsed) ? "batch" : "request")}: ${blockReason}`);
    res.writeHead(200, { "content-type": "application/json" });
    res.end(
      JSON.stringify({
        jsonrpc: "2.0",
        id: reqId,
        error: { code: -32000, message: `blocked by kubernetes-mcp-proxy policy: ${blockReason}` },
      })
    );
    return;
  }
  const headers = {};
  for (const [k, v] of Object.entries(req.headers))
    if (!HOP.has(k.toLowerCase()) && v !== undefined) headers[k] = v;
  const up = http.request(
    {
      hostname: TARGET.hostname,
      port: TARGET.port || 80,
      path: TARGET.pathname + (TARGET.search || ""),
      method: req.method,
      headers,
    },
    (ures) => {
      if (!shouldFilter) {
        res.writeHead(ures.statusCode, ures.headers);
        ures.pipe(res);
        return;
      }
      // Buffer tools/call responses to apply response-side policy. The go-sdk
      // stream ends the HTTP response once the result is delivered, so this
      // terminates normally (no confirmation rules => no server requests).
      const rs = [];
      let rsize = 0;
      let over = false;
      ures.on("data", (c) => {
        rsize += c.length;
        if (rsize > MAX_BODY) over = true;
        else rs.push(c);
      });
      ures.on("end", () => {
        if (over) {
          log(`dropped oversized ${toolsName ?? "call"} response (${rsize} bytes)`);
          res.writeHead(200, { "content-type": "application/json" });
          res.end(
            JSON.stringify({
              jsonrpc: "2.0",
              id: reqId,
              error: {
                code: -32000,
                message: "blocked by kubernetes-mcp-proxy policy: response too large to filter",
              },
            })
          );
          return;
        }
        const out = filterResponse(Buffer.concat(rs).toString("utf8"), reqId, toolsName);
        const buf = Buffer.from(out, "utf8");
        const h = { ...ures.headers };
        delete h["content-length"];
        delete h["transfer-encoding"];
        h["content-length"] = String(buf.length);
        res.writeHead(ures.statusCode, h);
        res.end(buf);
      });
    }
  );
  up.on("error", (e) => {
    log(`upstream error: ${e.message}`);
    res.writeHead(502, { "content-type": "text/plain" });
    res.end(`kubernetes-mcp-proxy: upstream unavailable: ${e.message}\n`);
  });
  up.end(body);
}

const srv = http.createServer((req, res) => {
  if (req.headers.origin || req.headers["sec-fetch-site"]) {
    res.writeHead(403, { "content-type": "text/plain" });
    res.end("kubernetes-mcp-proxy: browser requests are not allowed\n");
    return;
  }
  const chunks = [];
  let size = 0;
  let over = false;
  req.on("data", (c) => {
    size += c.length;
    if (size > MAX_BODY) over = true;
    else chunks.push(c);
  });
  req.on("end", () => {
    if (over) {
      res.writeHead(413, { "content-type": "text/plain" });
      res.end("kubernetes-mcp-proxy: payload too large\n");
      return;
    }
    handle(req, res, Buffer.concat(chunks));
  });
});
srv.listen(PORT, "127.0.0.1", () => {
  log(`listening on 127.0.0.1:${PORT} -> ${TARGET.origin}${TARGET.pathname}`);
});
