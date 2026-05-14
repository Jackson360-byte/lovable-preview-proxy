# Lovable Preview Proxy

Full reverse proxy that lets you preview a website on a new server (by IP)
before changing DNS — including navigation, form submissions, logins, and
admin edits. Sessions/cookies are preserved per browser via a 7-day cookie.

## Deploy on Render

1. Push this folder to your existing Render service repo (replace the old `server.js`).
2. Render settings:
   - Build Command: `npm install`
   - Start Command: `node server.js`
3. After deploy, the shareable preview URL is:
   ```
   https://lovable-preview-proxy.onrender.com/start?domain=YOURDOMAIN.com&ip=1.2.3.4&scheme=http
   ```
   Open it in a browser — you'll be redirected to `/p/` and can navigate the site
   normally, log into `/wp-admin`, save edits, etc. The link is shareable.

## Notes

- Render free tier sleeps after ~15 min of inactivity; the first request after
  sleep takes ~30s. Upgrade to a paid instance for always-on previews.
- The proxy strips `X-Frame-Options` / CSP so the site can be iframed by Lovable.
- Set-Cookie headers from the target are rewritten with `SameSite=None; Secure`
  and the `Domain=` attribute is removed, so admin sessions persist correctly.
