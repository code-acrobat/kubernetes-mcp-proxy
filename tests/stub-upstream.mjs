#!/usr/bin/env node
// Minimal streamable-HTTP stub of kubernetes-mcp-server for tests/e2e.sh.
// Canned responses cover: text-only YAML list, structured list, single object,
// namespaces list, events list. Records every tools/call name to $STUB_LOG.
import http from "node:http";
import { appendFileSync } from "node:fs";

const LOG = process.env.STUB_LOG || "/tmp/opencode/stub-calls.log";
const SID = "STUBSESSION0123456789ABCDEF";

const PODS_YAML = `apiVersion: v1
items:
- apiVersion: v1
  kind: Pod
  metadata:
    name: app-in-default
    namespace: default
- apiVersion: v1
  kind: Pod
  metadata:
    name: coredns-abc
    namespace: kube-system
kind: PodList
`;
// Real pods_list emits "- apiVersion" at col 0, not items: — match that shape.
const PODS_LIST_YAML = `- apiVersion: v1
  kind: Pod
  metadata:
    name: app-in-default
    namespace: default
  spec:
    nodeName: minikube
- apiVersion: v1
  kind: Pod
  metadata:
    name: coredns-abc
    namespace: kube-system
  spec:
    nodeName: minikube
`;

const EVENTS_YAML = `# The following events (YAML format) were found:
- InvolvedObject:
    Kind: Pod
    Name: app-in-default
    apiVersion: v1
  Message: Started container
  Namespace: default
  Reason: Started
  Timestamp: 2026-10-10 12:00:00 +0000 UTC
  Type: Normal
- InvolvedObject:
    Kind: Pod
    Name: coredns-abc
    apiVersion: v1
  Message: Pulling image
  Namespace: kube-system
  Reason: Pulling
  Timestamp: 2026-10-10 12:00:00 +0000 UTC
  Type: Normal
`;

const text = (id, t, extra = {}) =>
  `event: message\ndata: ${JSON.stringify({
    jsonrpc: "2.0",
    id,
    result: { content: [{ type: "text", text: t }], ...extra },
  })}\n\n`;

const results = {
  pods_list: (id) => text(id, PODS_LIST_YAML),
  namespaces_list: (id) =>
    text(
      id,
      `- apiVersion: v1
  kind: Namespace
  metadata:
    name: default
- apiVersion: v1
  kind: Namespace
  metadata:
    name: kube-system
`
    ),
  events_list: (id) => text(id, EVENTS_YAML),
  resources_list: (id) =>
    text(
      id,
      "TABLE TEXT SHOULD BE REPLACED",
      {
        structuredContent: {
          items: [
            { Name: "app-in-default", Namespace: "default", kind: "Pod" },
            { Name: "coredns-abc", Namespace: "kube-system", kind: "Pod" },
            { Name: "postgres-postgresql", Namespace: "default", kind: "Secret" },
          ],
        },
      }
    ),
  resources_get: (id) =>
    text(
      id,
      "apiVersion: v1\nkind: Pod\nmetadata:\n  name: coredns-abc\n  namespace: kube-system\n",
      {
        structuredContent: {
          apiVersion: "v1",
          kind: "Pod",
          metadata: { name: "coredns-abc", namespace: "kube-system" },
        },
      }
    ),
};

http
  .createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      let msg = null;
      try {
        msg = JSON.parse(body);
      } catch {}
      if (msg?.method === "tools/call") {
        appendFileSync(LOG, `${msg.params?.name}\n`);
        const r = results[msg.params?.name];
        if (r) {
          res.writeHead(200, {
            "content-type": "text/event-stream",
            "mcp-session-id": SID,
          });
          res.end(r(msg.id));
          return;
        }
        res.writeHead(200, { "content-type": "text/event-stream" });
        res.end(
          text(msg.id, `unhandled tool ${msg.params?.name}`, { isError: true })
        );
        return;
      }
      if (msg?.method === "initialize") {
        res.writeHead(200, {
          "content-type": "text/event-stream",
          "mcp-session-id": SID,
        });
        res.end(
          text(msg.id, "", {}).replace(
            /"content":\[\{"type":"text","text":""\}\]/,
            `"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"stub","version":"0"}`
          )
        );
        return;
      }
      if (msg?.method === "tools/list") {
        res.writeHead(200, { "content-type": "text/event-stream" });
        res.end(
          `event: message\ndata: ${JSON.stringify({
            jsonrpc: "2.0",
            id: msg.id,
            result: {
              tools: Object.keys(results).map((name) => ({
                name,
                inputSchema: { type: "object", properties: {} },
              })),
            },
          })}\n\n`
        );
        return;
      }
      res.writeHead(202, {});
      res.end();
    });
  })
  .listen(18081, "127.0.0.1", () => console.error("stub on 18081"));
