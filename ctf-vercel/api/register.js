import { redis } from "../lib/redis.js";
import { setCookie } from "../lib/auth.js";
import { clientIp, now, readJson } from "../lib/util.js";
import { rebuildBoard } from "../lib/store.js";

const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).json({ ok: false, error: "method not allowed" });

  const body = await readJson(req);
  const email = String(body.email || "").trim().toLowerCase();
  if (!EMAIL_RE.test(email)) return res.status(400).json({ ok: false, error: "Please enter a valid email address." });

  const ip = clientIp(req);

  // Existing email -> just log them back in.
  const existingId = await redis.get(`email:${email}`);
  if (existingId) {
    const u = await redis.hgetall(`user:${existingId}`);
    setCookie(req, res, "sid", `${existingId}|${u.username}`);
    return res.json({ ok: true, resumed: true, username: u.username });
  }

  // One account per IP.
  if (await redis.get(`ip:${ip}`)) {
    return res.status(403).json({ ok: false,
      error: "An account has already been registered from this network/IP. Only one account per IP is allowed." });
  }

  // Username from the email's local part; de-duplicate with a numeric suffix.
  let base = (email.split("@")[0] || "player").replace(/[^a-zA-Z0-9_.-]/g, "") || "player";
  let username = base, i = 1;
  while (await redis.get(`username:${username}`)) { i++; username = base + i; }

  const id = String(await redis.incr("uid:counter"));
  const t = now();
  await redis.hset(`user:${id}`, { email, username, ip, score: "0", created_at: String(t), solves_count: "0" });
  await redis.set(`email:${email}`, id);
  await redis.set(`ip:${ip}`, id);
  await redis.set(`username:${username}`, id);
  await redis.sadd("users", id);
  await rebuildBoard();

  setCookie(req, res, "sid", `${id}|${username}`);
  return res.json({ ok: true, resumed: false, username });
}
