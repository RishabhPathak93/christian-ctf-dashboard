import crypto from "crypto";
import { ADMIN_PASSWORD } from "../../lib/config.js";
import { setCookie } from "../../lib/auth.js";
import { readJson } from "../../lib/util.js";

function safeEq(a, b) {
  const A = Buffer.from(a), B = Buffer.from(b);
  return A.length === B.length && crypto.timingSafeEqual(A, B);
}

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).json({ ok: false, error: "method not allowed" });
  const body = await readJson(req);
  if (safeEq(String(body.password || ""), ADMIN_PASSWORD)) {
    setCookie(req, res, "adm", "1");
    return res.json({ ok: true });
  }
  return res.status(403).json({ ok: false, error: "Wrong password." });
}
