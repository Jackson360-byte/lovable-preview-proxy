# Lovable Preview Proxy

A tiny Node reverse proxy that lets you preview a website on a new server's IP
**before** changing DNS — including HTTPS WordPress sites on cPanel shared hosting,
which a serverless `fetch` cannot reach (because the TLS SNI must be the domain,
not the IP).

## How it works

1. Browser hits `https://your-proxy.example.com/preview?domain=site.com&ip=1.2.3.4&scheme=https`
2. Proxy opens a TCP socket to `1.2.3.4:443`
3. During TLS handshake it sends `servername: site.com` (SNI override)
4. It forwards the request with `Host: site.com`
5. cPanel/Apache routes to the right vhost → real WordPress HTML comes back
6. Frame-blocking headers are stripped so the page renders inside an iframe
7. Sub-paths/assets keep working via cookie-pinned target

## Run locally

```bash
npm install
npm start
# open http://localhost:8080/preview?domain=example.com&ip=1.2.3.4&scheme=https
```

## Deploy

### Render (free tier works)
- New → Web Service → connect repo / upload
- Build: `npm install`
- Start: `npm start`
- Env: `ALLOWED_ORIGINS=https://prox-pal.lovable.app,https://id-preview--*.lovable.app`

### Railway
- New project → Deploy from repo
- Auto-detects Node, runs `npm start`

### $5 VPS (Hetzner / DigitalOcean / Vultr)
```bash
# install Node 20
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo bash -
sudo apt install -y nodejs
# copy files, then:
npm install
sudo npm i -g pm2
pm2 start server.js --name preview-proxy
pm2 save && pm2 startup
# put nginx or Caddy in front for HTTPS
```

### Caddyfile (one-line HTTPS)
```
proxy.yourdomain.com {
    reverse_proxy localhost:8080
}
```

## Environment variables

| Var | Default | Purpose |
|-----|---------|---------|
| `PORT` | `8080` | Listen port |
| `ALLOWED_ORIGINS` | `*` | Comma-separated CORS origins |

## Wire it into your Lovable app

Set `VITE_PREVIEW_PROXY_URL=https://your-proxy.example.com` in the Lovable
project, then the preview page will iframe `${PROXY}/preview?...` directly.

## Security

- Private/loopback IP ranges (10/8, 127/8, 169.254/16, 172.16/12, 192.168/16) are blocked
- TLS cert verification is **disabled** by design — that's the whole point: the
  cert at the new server typically isn't valid for the domain yet. Only run this
  proxy for previewing sites you control.
