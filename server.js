// Lovable Preview Proxy — full reverse proxy for previewing a domain on a target IP
// before changing DNS. Supports navigation, POST/PUT (admin edits), cookies, redirects,
// and HTML/CSS URL rewriting so the entire site stays inside the proxy.
//
// Deploy on Render (Node service):
//   Build:  npm install
//   Start:  node server.js
//
// Routes:
//   GET  /                       -> health check
//   GET  /start?domain=...&ip=...&scheme=...&path=/  -> sets a session cookie and
//                                                       redirects to /p<path>. Use this URL
//                                                       as the shareable preview link.
//   ANY  /p/*                    -> proxies the request to the target server using the
//                                   session cookie set by /start. All sub-paths, form
//                                   submissions, AJAX, and admin actions go through here.

const express = require("express");
const cookieParser = require("cookie-parser");
const cookie = require("cookie");
const { request: undiciRequest, Agent } = require("undici");

// Custom dispatcher: don't validate TLS certs because we're hitting the
// upstream by raw IP (the cert is issued for the domain, not the IP, so it
// will never validate). This is a preview tool, not a security boundary.
const insecureDispatcher = new Agent({ connect: { rejectUnauthorized: false } });
const zlib = require("zlib");
const { promisify } = require("util");
const crypto = require("crypto");

const gunzip = promisify(zlib.gunzip);
const inflate = promisify(zlib.inflate);
const brotli = promisify(zlib.brotliDecompress);

const app = express();
app.disable("x-powered-by");
app.use(cookieParser());

const SESSION_COOKIE = "lp_target";
const ipv4 = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$/;
const ipv6 = /^[0-9a-fA-F:]+$/;
const domainRe = /^(?=.{1,253}$)(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,}$/;

function setCors(req, res) {
  const origin = req.headers.origin || "*";
  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS,HEAD");
  res.setHeader("Access-Control-Allow-Headers", "*");
}

app.use((req, res, next) => {
  setCors(req, res);
  if (req.method === "OPTIONS") return res.status(204).end();
  next();
});

app.get("/", (_req, res) => {
  res.type("text/plain").send("Lovable Preview Proxy: OK\nUse /start?domain=...&ip=...&scheme=...");
});

function encodeTarget(t) {
  return Buffer.from(JSON.stringify(t)).toString("base64url");
}
function decodeTarget(c) {
  try {
    return JSON.parse(Buffer.from(c, "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

// /start sets the session cookie that pins this browser to a target server.
app.get("/start", (req, res) => {
  const domain = String(req.query.domain || "").trim().toLowerCase();
  const ip = String(req.query.ip || "").trim();
  const scheme = String(req.query.scheme || "http").trim() === "https" ? "https" : "http";
  const path = String(req.query.path || "/") || "/";

  if (!domainRe.test(domain)) return res.status(400).send("Invalid domain");
  if (!ipv4.test(ip) && !ipv6.test(ip)) return res.status(400).send("Invalid IP");

  const token = encodeTarget({ domain, ip, scheme });
  res.cookie(SESSION_COOKIE, token, {
    httpOnly: true,
    sameSite: "none",
    secure: true,
    path: "/",
    maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
  });
  const dest = "/p" + (path.startsWith("/") ? path : "/" + path);
  res.redirect(302, dest);
});

// Decompress upstream body when we need to rewrite it.
async function decompress(buffer, encoding) {
  if (!buffer || !buffer.length) return Buffer.alloc(0);
  try {
    if (encoding === "gzip") return await gunzip(buffer);
    if (encoding === "deflate") return await inflate(buffer);
    if (encoding === "br") return await brotli(buffer);
  } catch (e) {
    console.warn("decompress failed", encoding, e.message);
  }
  return buffer;
}

// Build an upstream URL for the target IP, with the original Host header.
function buildUpstream(target, reqUrl) {
  const host = target.ip.includes(":") && !target.ip.startsWith("[") ? `[${target.ip}]` : target.ip;
  return `${target.scheme}://${host}${reqUrl}`;
}

// Strip headers that should not be forwarded upstream.
const HOP_BY_HOP_REQ = new Set([
  "host", "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
  "te", "trailers", "transfer-encoding", "upgrade", "content-length",
  "x-forwarded-host", "x-forwarded-proto", "x-forwarded-for", "cf-connecting-ip",
  "cf-ipcountry", "cf-ray", "cf-visitor", "render-proxy-ttl", "x-real-ip",
]);
const HOP_BY_HOP_RES = new Set([
  "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
  "te", "trailers", "transfer-encoding", "upgrade",
  "content-encoding", "content-length",
  "content-security-policy", "content-security-policy-report-only",
  "strict-transport-security", "x-frame-options",
  "cross-origin-opener-policy", "cross-origin-embedder-policy", "cross-origin-resource-policy",
]);

function buildRequestHeaders(req, target) {
  const out = {};
  for (const [k, v] of Object.entries(req.headers)) {
    const key = k.toLowerCase();
    if (HOP_BY_HOP_REQ.has(key)) continue;
    if (key === "cookie") continue; // we'll re-attach below, filtered
    if (key === "referer" || key === "origin") continue; // rewrite below
    out[k] = v;
  }
  out["host"] = target.domain;
  out["accept-encoding"] = "gzip, deflate, br";

  // Forward cookies but strip our session cookie.
  const rawCookie = req.headers.cookie || "";
  if (rawCookie) {
    const filtered = rawCookie
      .split(/;\s*/)
      .filter((c) => !c.toLowerCase().startsWith(SESSION_COOKIE.toLowerCase() + "="))
      .join("; ");
    if (filtered) out["cookie"] = filtered;
  }

  // Rewrite Origin/Referer to look like the real site.
  if (req.headers.referer) {
    try {
      const u = new URL(req.headers.referer);
      const idx = u.pathname.indexOf("/p");
      const upstreamPath = idx === 0 ? u.pathname.slice(2) || "/" : u.pathname;
      out["referer"] = `${target.scheme}://${target.domain}${upstreamPath}${u.search}`;
    } catch {}
  }
  if (req.headers.origin) out["origin"] = `${target.scheme}://${target.domain}`;
  return out;
}

// Rewrite Set-Cookie so the browser actually stores them under the proxy domain.
function rewriteSetCookie(values) {
  if (!values) return [];
  const arr = Array.isArray(values) ? values : [values];
  return arr.map((raw) => {
    // Drop Domain= (so the cookie is scoped to the proxy host) and force SameSite=None; Secure
    // so it works inside an iframe.
    const parts = raw.split(/;\s*/);
    const out = [];
    let hasSameSite = false;
    let hasSecure = false;
    for (const p of parts) {
      const lower = p.toLowerCase();
      if (lower.startsWith("domain=")) continue;
      if (lower.startsWith("path=")) {
        out.push("Path=/");
        continue;
      }
      if (lower.startsWith("samesite=")) { out.push("SameSite=None"); hasSameSite = true; continue; }
      if (lower === "secure") { out.push("Secure"); hasSecure = true; continue; }
      out.push(p);
    }
    if (!hasSameSite) out.push("SameSite=None");
    if (!hasSecure) out.push("Secure");
    return out.join("; ");
  });
}

// Rewrite a Location header (handles absolute URLs to the target domain and root-relative paths).
function rewriteLocation(loc, target) {
  if (!loc) return loc;
  try {
    if (/^https?:\/\//i.test(loc)) {
      const u = new URL(loc);
      // If the upstream redirects to the same domain (or the IP), keep it inside the proxy.
      if (u.hostname === target.domain || u.hostname === target.ip || u.hostname === `[${target.ip}]`) {
        return "/p" + u.pathname + u.search + u.hash;
      }
      // External redirect — leave as-is.
      return loc;
    }
    if (loc.startsWith("/")) return "/p" + loc;
    return loc;
  } catch {
    return loc;
  }
}

// Rewrite HTML so all links/forms/assets pointing at the original domain stay in the proxy.
function rewriteHtml(html, target) {
  let out = html;
  const absRe = new RegExp(`(https?:)?\/\/${target.domain.replace(/\./g, "\\.")}`, "gi");
  out = out.replace(absRe, "");
  // Inject <base href="/p/"> so relative URLs resolve via the proxy.
  if (/<head[^>]*>/i.test(out)) {
    out = out.replace(/<head([^>]*)>/i, `<head$1><base href="/p/">`);
  }
  // Tiny banner at the top.
  const banner = `<div style="position:fixed;bottom:8px;right:8px;z-index:2147483647;background:#0f172a;color:#f8fafc;font:500 11px/1.3 -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:6px 10px;border-radius:6px;box-shadow:0 4px 12px rgba(0,0,0,.3);opacity:.85">Preview: ${target.domain} → ${target.ip}</div>`;
  if (/<\/body>/i.test(out)) out = out.replace(/<\/body>/i, `${banner}</body>`);
  return out;
}

// Rewrite CSS url(...) references targeting the original domain.
function rewriteCss(css, target) {
  const absRe = new RegExp(`(https?:)?\/\/${target.domain.replace(/\./g, "\\.")}`, "gi");
  return css.replace(absRe, "");
}

// Main proxy handler. Mounted at /p/* — everything after /p is the upstream path.
app.use("/p", express.raw({ type: "*/*", limit: "50mb" }), async (req, res) => {
  const cookieVal = req.cookies[SESSION_COOKIE];
  const target = cookieVal ? decodeTarget(cookieVal) : null;
  if (!target) {
    return res.status(400).type("text/html").send(
      `<h1>No preview session</h1><p>Open the preview via <code>/start?domain=...&ip=...&scheme=...</code></p>`
    );
  }

  const upstreamPath = req.originalUrl.replace(/^\/p/, "") || "/";
  const upstreamUrl = buildUpstream(target, upstreamPath);
  const headers = buildRequestHeaders(req, target);

  const hasBody = !["GET", "HEAD"].includes(req.method);
  const body = hasBody && req.body && req.body.length ? req.body : undefined;

  let upstream;
  try {
    upstream = await undiciRequest(upstreamUrl, {
      method: req.method,
      headers,
      body,
      maxRedirections: 0,
      bodyTimeout: 30000,
      headersTimeout: 30000,
      dispatcher: insecureDispatcher,
    });
  } catch (err) {
    console.error("upstream error", upstreamUrl, err.message);
    return res.status(502).type("text/html").send(
      `<h1>Upstream unreachable</h1><pre>${(err.message || "").replace(/[<>&]/g, "")}</pre><p>Target: ${upstreamUrl}</p>`
    );
  }

  // Auto-upgrade scheme: if upstream redirects to https on the same domain while we're on http,
  // upgrade the session cookie so future requests use https (avoids infinite http→https loops on
  // sites like WordPress /wp-admin that force HTTPS).
  let updatedTarget = target;
  const rawLoc = upstream.headers["location"];
  if (rawLoc && target.scheme === "http") {
    const locStr = Array.isArray(rawLoc) ? rawLoc[0] : rawLoc;
    try {
      const lu = new URL(locStr);
      if (lu.protocol === "https:" && (lu.hostname === target.domain || lu.hostname === target.ip)) {
        updatedTarget = { ...target, scheme: "https" };
        res.cookie(SESSION_COOKIE, encodeTarget(updatedTarget), {
          httpOnly: true, sameSite: "none", secure: true, path: "/",
          maxAge: 1000 * 60 * 60 * 24 * 7,
        });
      }
    } catch {}
  }

  // Copy headers (filtered).
  const resHeaders = {};
  for (const [k, v] of Object.entries(upstream.headers)) {
    const key = k.toLowerCase();
    if (HOP_BY_HOP_RES.has(key)) continue;
    if (key === "set-cookie") continue;
    if (key === "location") { resHeaders["location"] = rewriteLocation(Array.isArray(v) ? v[0] : v, updatedTarget); continue; }
    resHeaders[k] = v;
  }
  const setCookie = upstream.headers["set-cookie"];
  if (setCookie) resHeaders["set-cookie"] = rewriteSetCookie(setCookie);

  const ct = String(upstream.headers["content-type"] || "");
  const enc = String(upstream.headers["content-encoding"] || "").toLowerCase();
  const shouldRewrite = ct.includes("text/html") || ct.includes("text/css") || ct.includes("application/xhtml");

  res.status(upstream.statusCode);
  for (const [k, v] of Object.entries(resHeaders)) res.setHeader(k, v);

  if (!shouldRewrite) {
    // Stream binary / opaque content through unchanged (still compressed).
    if (enc) res.setHeader("content-encoding", enc);
    upstream.body.pipe(res);
    return;
  }

  // Buffer + decompress + rewrite text content.
  const chunks = [];
  for await (const chunk of upstream.body) chunks.push(chunk);
  const raw = Buffer.concat(chunks);
  const decoded = await decompress(raw, enc);
  const text = decoded.toString("utf8");
  const rewritten = ct.includes("text/css") ? rewriteCss(text, target) : rewriteHtml(text, target);
  const buf = Buffer.from(rewritten, "utf8");
  res.setHeader("content-length", String(buf.length));
  res.end(buf);
});

const port = process.env.PORT || 10000;
app.listen(port, () => console.log(`Lovable preview proxy listening on :${port}`));
