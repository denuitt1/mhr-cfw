const WORKER_URL = "myworker.workers.dev";

export default {
  async fetch(request) {
    // Accept only POST requests
    if (request.method !== "POST") {
      return json({ e: "Method not allowed. Use POST." }, 405);
    }

    try {
      // Parse JSON request body
      let req;
      try {
        req = await request.json();
      } catch (e) {
        return json({ e: "Invalid JSON in request body" }, 400);
      }

      // Check if URL is present
      if (!req.u) {
        return json({ e: "Missing 'u' (target URL) in request" }, 400);
      }

      // Validate URL format
      let targetUrl;
      try {
        targetUrl = new URL(req.u);
        if (!targetUrl.protocol.startsWith("http")) {
          return json({ e: "Only HTTP/HTTPS URLs are allowed" }, 400);
        }
      } catch (e) {
        return json({ e: "Invalid URL format" }, 400);
      }

      // Prevent self-fetch loops
      const blockedHosts = [
        WORKER_URL,
        "snowy-bonus-c65a.mshamsi502-dev.workers.dev",
        "script.google.com",
        "script.googleusercontent.com"
      ];

      if (blockedHosts.some(h => targetUrl.hostname === h || targetUrl.hostname.endsWith("." + h))) {
        return json({ e: "Self-fetch or relay loop blocked" }, 400);
      }

      // Check for loop detection header
      if (request.headers.get("x-relay-hop") === "1") {
        return json({ e: "Loop detected (x-relay-hop already set)" }, 508);
      }

      // Build new headers
      const headers = new Headers();
      if (req.h && typeof req.h === "object") {
        for (const [k, v] of Object.entries(req.h)) {
          // Filter out dangerous headers
          const lowerKey = k.toLowerCase();
          if (lowerKey !== "host" && lowerKey !== "content-length" && lowerKey !== "transfer-encoding") {
            headers.set(k, v);
          }
        }
      }

      // Add anti-loop header
      headers.set("x-relay-hop", "1");
      
      // Add default User-Agent if not present
      if (!headers.has("user-agent")) {
        headers.set("user-agent", "Mozilla/5.0 (compatible; CloudflareWorker/1.0)");
      }

      // Configure fetch options
      const fetchOptions = {
        method: (req.m || "GET").toUpperCase(),
        headers: headers,
        redirect: req.r === false ? "manual" : "follow"
      };

      // Add body for allowed methods
      if (req.b && ["POST", "PUT", "PATCH", "DELETE"].includes(fetchOptions.method)) {
        try {
          const binary = Uint8Array.from(atob(req.b), c => c.charCodeAt(0));
          fetchOptions.body = binary;
        } catch (e) {
          return json({ e: "Invalid base64 in request body" }, 400);
        }
      }

      // Execute fetch with timeout
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 30000); // 30 second timeout

      let resp;
      try {
        resp = await fetch(targetUrl.toString(), {
          ...fetchOptions,
          signal: controller.signal
        });
        clearTimeout(timeoutId);
      } catch (e) {
        clearTimeout(timeoutId);
        if (e.name === "AbortError") {
          return json({ e: "Request timeout (30s)" }, 504);
        }
        return json({ e: `Fetch failed: ${e.message}` }, 502);
      }

      // Read response safely
      let buffer;
      try {
        buffer = await resp.arrayBuffer();
      } catch (e) {
        return json({ e: `Failed to read response: ${e.message}` }, 502);
      }

      const uint8 = new Uint8Array(buffer);
      
      // Convert to base64
      let base64;
      try {
        let binary = "";
        const chunkSize = 0x8000; // 32KB chunks to prevent stack overflow
        for (let i = 0; i < uint8.length; i += chunkSize) {
          const chunk = uint8.subarray(i, Math.min(i + chunkSize, uint8.length));
          binary += String.fromCharCode.apply(null, chunk);
        }
        base64 = btoa(binary);
      } catch (e) {
        return json({ e: `Base64 encoding failed: ${e.message}` }, 500);
      }

      // Extract response headers
      const responseHeaders = {};
      resp.headers.forEach((v, k) => {
        // Filter out sensitive headers
        const lowerKey = k.toLowerCase();
        if (!["content-encoding", "transfer-encoding"].includes(lowerKey)) {
          responseHeaders[k] = v;
        }
      });

      // Return successful response
      return json({
        s: resp.status,
        h: responseHeaders,
        b: base64
      });

    } catch (err) {
      // Handle unexpected errors
      console.error("Unhandled error:", err);
      return json({ e: `Internal server error: ${err.message}` }, 500);
    }
  }
};

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type"
    }
  });
}

// Handle CORS preflight requests
export async function options() {
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Max-Age": "86400"
    }
  });
}
