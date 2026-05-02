// Cloudflare Worker File

const WORKER_URL = "myworker.workers.dev";

export default {
  async fetch(request) {
    try {
      if (request.headers.get("x-relay-hop") === "1") {
        return json({ e: "loop detected" }, 508);
      }

      if (request.method !== "POST") {
        return new Response(
          "<!DOCTYPE html><html><head><title>Relay Active</title></head>" +
            '<body style="font-family:sans-serif;max-width:600px;margin:40px auto">' +
            '<h1>Relay <span style="color:#16a34a;font-weight:700">Active</span></h1>' +
            "<p>Cloudflare Worker routing enabled.</p>" +
            "</body></html>",
          { status: 200, headers: { "content-type": "text/html; charset=utf-8" } }
        );
      }

      const req = await request.json();

      if (!req.u) {
        return json({ e: "missing url" }, 400);
      }

      const targetUrl = new URL(req.u);

      const BLOCKED_HOSTS = [
        WORKER_URL,
      ];

      if (BLOCKED_HOSTS.some(h => targetUrl.hostname.endsWith(h))) {
        return json({ e: "self-fetch blocked" }, 400);
      }

      const headers = new Headers();
      if (req.h && typeof req.h === "object") {
        for (const [k, v] of Object.entries(req.h)) {
          headers.set(k, v);
        }
      }

      headers.set("x-relay-hop", "1");

      const fetchOptions = {
        method: (req.m || "GET").toUpperCase(),
        headers,
        redirect: req.r === false ? "manual" : "follow"
      };

      if (req.b) {
        const binary = Uint8Array.from(atob(req.b), c => c.charCodeAt(0));
        fetchOptions.body = binary;
      }

      const resp = await fetch(targetUrl.toString(), fetchOptions);

      // Read response safely (no stack overflow)
      const buffer = await resp.arrayBuffer();
      const uint8 = new Uint8Array(buffer);

      let binary = "";
      const chunkSize = 0x8000; // prevent call stack overflow

      for (let i = 0; i < uint8.length; i += chunkSize) {
        binary += String.fromCharCode.apply(
          null,
          uint8.subarray(i, i + chunkSize)
        );
      }

      const base64 = btoa(binary);

      const responseHeaders = {};
      resp.headers.forEach((v, k) => {
        responseHeaders[k] = v;
      });

      return json({
        s: resp.status,
        h: responseHeaders,
        b: base64
      });

    } catch (err) {
      return json({ e: String(err) }, 500);
    }
  }
};

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      "content-type": "application/json"
    }
  });
}
