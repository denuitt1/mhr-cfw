// Upstream Forwarder — single-file Node 18+ HTTP server.
//
// Purpose: Provide a stable exit IP for the Cloudflare Worker relay so
// CAPTCHA tokens (Turnstile, reCAPTCHA, hCaptcha) bound to the solving
// IP survive verification on the target site.
//
// Run on a VPS with a stable public IP. Expose behind Caddy/nginx with
// TLS — the Worker rejects non-HTTPS forwarder URLs.
//
// Required env:
//   AUTH_KEY  — must match the Worker's UPSTREAM_AUTH_KEY (>= 32 chars)
//
// Optional env:
//   PORT       — listen port (default 8787)
//   HOST       — listen host (default 127.0.0.1, so Caddy/nginx fronts it)
//
// Wire protocol matches main/script/worker.js:
//   POST /fwd  body: { u, m, h, b, ct, r }   →  { s, h, b }  or  { e }

"use strict";

const http = require("http");

const AUTH_KEY = process.env.AUTH_KEY || "";
const PORT = parseInt(process.env.PORT, 10) || 8787;
const HOST = process.env.HOST || "127.0.0.1";

if (!AUTH_KEY || AUTH_KEY.length < 32) {
  console.error("FATAL: AUTH_KEY env var missing or shorter than 32 chars.");
  process.exit(1);
}

// Mirrors SKIP_HEADERS in main/script/Code.gs:6-9.
const SKIP_HEADERS = new Set([
  "host",
  "connection",
  "content-length",
  "transfer-encoding",
  "proxy-connection",
  "proxy-authorization"
]);

const STATUS_PAGE =
  "<!DOCTYPE html><html><head><title>Forwarder Active</title></head>" +
  '<body style="font-family:sans-serif;max-width:600px;margin:40px auto">' +
  '<h1>Forwarder <span style="color:#16a34a;font-weight:700">Active</span></h1>' +
  "<p>Upstream forwarder for the relay Worker.</p>" +
  "</body></html>";

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === "GET" && (req.url === "/" || req.url === "")) {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(STATUS_PAGE);
      return;
    }

    if (req.method !== "POST" || req.url !== "/fwd") {
      sendJson(res, 404, { e: "not found" });
      return;
    }

    if (req.headers["x-upstream-auth"] !== AUTH_KEY) {
      sendJson(res, 401, { e: "unauthorized" });
      return;
    }

    const raw = await readBody(req);
    let body;
    try {
      body = JSON.parse(raw);
    } catch (_) {
      sendJson(res, 400, { e: "invalid json" });
      return;
    }

    if (!body.u || typeof body.u !== "string" || !/^https?:\/\//i.test(body.u)) {
      sendJson(res, 400, { e: "bad url" });
      return;
    }

    const headers = {};
    if (body.h && typeof body.h === "object") {
      for (const [k, v] of Object.entries(body.h)) {
        if (typeof v !== "string") continue;
        if (SKIP_HEADERS.has(k.toLowerCase())) continue;
        headers[k] = v;
      }
    }
    headers["x-fwd-hop"] = "1";

    const fetchOptions = {
      method: (body.m || "GET").toUpperCase(),
      headers,
      redirect: body.r === false ? "manual" : "follow"
    };

    if (body.b) {
      fetchOptions.body = Buffer.from(body.b, "base64");
    }

    let resp;
    try {
      resp = await fetch(body.u, fetchOptions);
    } catch (err) {
      sendJson(res, 502, { e: "fetch failed: " + String(err && err.message || err) });
      return;
    }

    const buf = Buffer.from(await resp.arrayBuffer());
    const responseHeaders = {};
    resp.headers.forEach((v, k) => {
      responseHeaders[k] = v;
    });

    sendJson(res, 200, {
      s: resp.status,
      h: responseHeaders,
      b: buf.toString("base64")
    });
  } catch (err) {
    sendJson(res, 500, { e: String(err && err.message || err) });
  }
});

server.listen(PORT, HOST, () => {
  console.log("upstream_forwarder listening on " + HOST + ":" + PORT);
});

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", c => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { "content-type": "application/json" });
  res.end(body);
}
