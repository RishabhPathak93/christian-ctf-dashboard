import { redis } from "../lib/redis.js";
import { setCookie } from "../lib/auth.js";
import { readJson } from "../lib/util.js";

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).json({ ok: false, error: "method not allowed" });
  const body = await readJson(req);
  const email = String(body.email || "").trim().toLowerCase();
  const id = await redis.get(`email:${email}`);
  if (!id) return res.status(404).json({ ok: false, error: "No account with that email. Register first." });
  const u = await redis.hgetall(`user:${id}`);
  setCookie(req, res, "sid", `${id}|${u.username}`);
  return res.json({ ok: true, username: u.username });
}
