// Lovable Preview Proxy
// Reverse-proxies a domain to a target IP with correct SNI, so you can preview
// a site (incl. HTTPS WordPress on cPanel) before changing DNS.
//
// Usage:
//   GET /preview?domain=example.com&ip=1.2.3.4&scheme=https
//   GET /preview/<rest>?domain=...&ip=...   (sub-paths/assets keep working
//                                            via a cookie-based fallback)
//
// Deploy: Render, Railway, Fly.io, or any $5 VPS. Node 18+.

import express from "express";
import cors from "cors";
import https from "https";
import http from "http";
import tls from "tls";
import { createProxyMiddleware } from "http-proxy-middleware";

const PORT = process.env.PORT || 8080;
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "*")
  .split(",")
  .map((s) => s.trim());

const app = express();
app.use(
  cors({
    origin: ALLOWED_ORIGINS.includes("*") ? true : ALLOWED_ORIGINS,
    credentials: false,
  }),
);

// ---- helpers ---------------------------------------------------------------

const ipv4 = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$/;
const ipv6 = /^[0-9a-fA-F:]+$/;
const domainRe = /^(?=.{1,253}$)(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,}$/;

function parseTarget(req) {
  // Prefer query, fall back to a cookie set on the first /preview hit so that
  // relative asset requests (which arrive without query string) still resolve.
  const q = req.query || {};
  const cookieHeader = req.headers.cookie || "";
  const cookies = Object.fromEntries(
    cookieHeader.split(";").map((c) => {
      const [k, ...v] = c.trim().split("=");
      return [k, decodeURIComponent(v.join("=") || "")];
    }),
  );
  const domain = (q.domain || cookies.lp_domain || "").toLowerCase();
  const ip = q.ip || cookies.lp_ip || "";
  const scheme = (q.scheme || cookies.lp_scheme || "https").toLowerCase();
  return { domain, ip, scheme };
}

function validate({ domain, ip, scheme }) {
  if (!domainRe.test(domain)) return "invalid domain";
  if (!ipv4.test(ip) && !ipv6.test(ip)) return "invalid ip";
  if (scheme !== "http" && scheme !== "https") return "invalid scheme";
  // Block private/loopback ranges
  if (ipv4.test(ip)) {
    const [a, b] = ip.split(".").map(Number);
    if (a === 10) return "private ip not allowed";
    if (a === 127) return "loopback ip not allowed";
    if (a === 169 && b === 254) return "link-local ip not allowed";
    if (a === 172 && b >= 16 && b <= 31) return "private ip not allowed";
    if (a === 192 && b === 168) return "private ip not allowed";
    if (a === 0) return "invalid ip";
  }
  return null;
}

// Custom agents that connect to `ip` but present `domain` as SNI.
function makeAgents(domain, ip) {
  const httpsAgent = new https.Agent({
    keepAlive: true,
    // Don't fail on shared-host certs that don't match the domain yet.
    rejectUnauthorized: false,
    // Force the TCP connection to the IP, override SNI to the real domain.
    createConnection: (options, callback) => {
      const socket = tls.connect(
        {
          host: ip,
          port: options.port || 443,
          servername: domain, // <-- SNI override (the whole point)
          rejectUnauthorized: false,
          ALPNProtocols: ["http/1.1"],
        },
        () => callback(null, socket),
      );
      socket.on("error", (err) => callback(err));
    },
  });

  const httpAgent = new http.Agent({
    keepAlive: true,
    createConnection: (options, callback) => {
      const socket = http
        .request({ host: ip, port: options.port || 80, method: "GET" })
        .on("socket", (s) => callback(null, s));
      socket.on("error", (err) => callback(err));
    },
  });

  return { httpsAgent, httpAgent };
}

// ---- proxy middleware ------------------------------------------------------

app.get("/healthz", (_req, res) => res.json({ ok: true }));

app.use("/preview", (req, res, next) => {
  const target = parseTarget(req);
  const err = validate(target);
  if (err) return res.status(400).json({ error: err });

  // Pin the target for subsequent asset requests via cookie.
  res.cookie?.("lp_domain", target.domain, { httpOnly: false, sameSite: "lax" });
  res.cookie?.("lp_ip", target.ip, { httpOnly: false, sameSite: "lax" });
  res.cookie?.("lp_scheme", target.scheme, { httpOnly: false, sameSite: "lax" });

  const { domain, ip, scheme } = target;
  const { httpsAgent, httpAgent } = makeAgents(domain, ip);

  const proxy = createProxyMiddleware({
    target: `${scheme}://${ip}`,
    changeOrigin: true,
    secure: false,
    agent: scheme === "https" ? httpsAgent : httpAgent,
    pathRewrite: (path) => path.replace(/^\/preview/, "") || "/",
    headers: { Host: domain },
    selfHandleResponse: false,
    on: {
      proxyReq: (proxyReq) => {
        proxyReq.setHeader("Host", domain);
        proxyReq.setHeader(
          "User-Agent",
          "Mozilla/5.0 (compatible; LovablePreviewProxy/1.0)",
        );
        // Strip cookies meant for our proxy (lp_*) before forwarding.
        const cookie = proxyReq.getHeader("cookie");
        if (typeof cookie === "string") {
          const cleaned = cookie
            .split(";")
            .map((c) => c.trim())
            .filter((c) => !c.startsWith("lp_"))
            .join("; ");
          if (cleaned) proxyReq.setHeader("cookie", cleaned);
          else proxyReq.removeHeader("cookie");
        }
      },
      proxyRes: (proxyRes) => {
        // Drop frame-blocking headers so the iframe in your Lovable app renders.
        delete proxyRes.headers["x-frame-options"];
        delete proxyRes.headers["content-security-policy"];
        delete proxyRes.headers["content-security-policy-report-only"];
        // Rewrite redirects from the origin domain back to /preview/* so the
        // user stays inside the proxy.
        const loc = proxyRes.headers["location"];
        if (typeof loc === "string") {
          try {
            const u = new URL(loc, `${scheme}://${domain}`);
            if (u.hostname === domain || u.hostname === ip) {
              proxyRes.headers["location"] = `/preview${u.pathname}${u.search}`;
            }
          } catch {
            /* ignore */
          }
        }
      },
      error: (err, _req, res) => {
        console.error("[proxy error]", err.message);
        if (!res.headersSent) {
          res.writeHead(502, { "content-type": "application/json" });
        }
        res.end(JSON.stringify({ error: "upstream failed", detail: err.message }));
      },
    },
  });

  return proxy(req, res, next);
});

app.get("/", (_req, res) => {
  res
    .type("text/plain")
    .send(
      "Lovable Preview Proxy\n\n" +
        "GET /preview?domain=example.com&ip=1.2.3.4&scheme=https\n" +
        "GET /healthz\n",
    );
});

app.listen(PORT, () => {
  console.log(`preview-proxy listening on :${PORT}`);
});
