/**
 * Cloudflare Pages Worker — Digital Forensics Investigation Platform
 * 
 * This worker:
 * 1. Serves static frontend files (index.html, custom.css)
 * 2. Proxies all /api/* requests to the Render.com Python backend
 * 3. Proxies /reports/* and /recovered/* to the backend as well
 */

// ── Backend URL (Render.com FastAPI server) ─────────────────────────────────
const BACKEND_URL = "https://forensic-platform.onrender.com";

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const pathname = url.pathname;

    // ── Proxy all API, report, and recovered requests to Render backend ──────
    if (
      pathname.startsWith("/api/") ||
      pathname.startsWith("/reports/") ||
      pathname.startsWith("/recovered/") ||
      pathname.startsWith("/static/")
    ) {
      const backendUrl = BACKEND_URL + pathname + url.search;

      // Forward request headers (include Content-Type for multipart uploads)
      const forwardHeaders = new Headers(request.headers);
      forwardHeaders.set("X-Forwarded-For", request.headers.get("CF-Connecting-IP") || "");
      forwardHeaders.set("X-Forwarded-Host", url.hostname);

      try {
        const backendRequest = new Request(backendUrl, {
          method: request.method,
          headers: forwardHeaders,
          body: request.method !== "GET" && request.method !== "HEAD" ? request.body : null,
          redirect: "follow",
        });

        const backendResponse = await fetch(backendRequest);

        // Add CORS headers to all proxied responses
        const responseHeaders = new Headers(backendResponse.headers);
        responseHeaders.set("Access-Control-Allow-Origin", "*");
        responseHeaders.set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
        responseHeaders.set("Access-Control-Allow-Headers", "Content-Type, Authorization");

        return new Response(backendResponse.body, {
          status: backendResponse.status,
          statusText: backendResponse.statusText,
          headers: responseHeaders,
        });
      } catch (error) {
        return new Response(
          JSON.stringify({ error: "Backend unavailable. The server may be sleeping (Render free tier). Please wait 30 seconds and try again.", details: error.message }),
          {
            status: 503,
            headers: {
              "Content-Type": "application/json",
              "Access-Control-Allow-Origin": "*",
            },
          }
        );
      }
    }

    // ── Handle CORS preflight requests ──────────────────────────────────────
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
          "Access-Control-Max-Age": "86400",
        },
      });
    }

    // ── Serve static files via Cloudflare Pages asset binding ───────────────
    // ASSETS env binding is automatically set by Cloudflare Pages
    if (env.ASSETS) {
      try {
        const assetResponse = await env.ASSETS.fetch(request);
        if (assetResponse.status !== 404) {
          return assetResponse;
        }
      } catch (e) {
        // Fall through to index.html
      }
    }

    // ── SPA fallback — serve index.html for all other routes ────────────────
    const indexRequest = new Request(new URL("/index.html", request.url), request);
    if (env.ASSETS) {
      try {
        return await env.ASSETS.fetch(indexRequest);
      } catch (e) {
        // Final fallback
      }
    }

    return new Response("Digital Forensics Platform — Page not found", { status: 404 });
  },
};
