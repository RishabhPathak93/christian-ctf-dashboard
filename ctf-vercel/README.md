# Overlord CTF — Flag Submission Portal (Vercel + Upstash)

Public, fast, serverless flag-submission portal with a live scoreboard and an
admin dashboard. Players need nothing installed — just the URL.

- **Player page:** `/`
- **Admin dashboard:** `/admin`
- Only the three Overlord flags score (100 / 200 / 300 pts), checked server-side.
- One account per IP. Username derived from the registration email.
- Live scoreboard, presence ("online now"), and canvas charts (top players, solves per stage).

## 1. Create an Upstash Redis database

The portal is stateless (serverless) and keeps all state in Redis.

- Easiest: in the Vercel dashboard → your project → **Integrations / Storage** →
  add **Upstash Redis** from the Marketplace. Vercel then injects `KV_REST_API_URL`
  and `KV_REST_API_TOKEN` automatically.
- Or manually: create a database at https://upstash.com, copy its **REST URL** and
  **REST token**, and set `UPSTASH_REDIS_REST_URL` / `UPSTASH_REDIS_REST_TOKEN`.

## 2. Set environment variables (Vercel → Settings → Environment Variables)

| Variable | What |
|---|---|
| `CTF_ADMIN_PASSWORD` | password for `/admin` |
| `CTF_SECRET_KEY` | long random string; signs session cookies |
| `UPSTASH_REDIS_REST_URL` / `UPSTASH_REDIS_REST_TOKEN` | if set manually (skip if using the Vercel integration, which sets `KV_*`) |

## 3. Deploy

```bash
npm i -g vercel        # once
vercel                 # from this folder: preview deploy
vercel --prod          # production URL
```

Or push this folder to a GitHub repo and "Import Project" in the Vercel dashboard.
Give players the production URL; open `/admin` yourself.

## Local dev (optional)

```bash
npm install
cp .env.example .env    # fill in the four values
vercel dev              # http://localhost:3000
```

## Notes

- **Per-IP** uses Vercel's `x-real-ip` / `x-forwarded-for`. It's best-effort —
  a VPN, phone hotspot, or a spoofed `X-Forwarded-For` can get around it. For a
  trusted classroom event it's fine; don't treat it as hard security.
- **Cost:** reads are lean (the scoreboard is a cached blob + one presence query),
  but Upstash's free tier is ~10k commands/day. A busy multi-hour event may exceed
  that; overage is pennies on pay-as-you-go. Poll intervals are set to 8s to be gentle.
- **Resetting between runs:** flush the Redis database from the Upstash console to
  clear all users/scores.
