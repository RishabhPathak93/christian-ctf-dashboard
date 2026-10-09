import crypto from "crypto";
import { SECRET_KEY } from "./config.js";

// HMAC-signed cookie values (tamper-proof; no server-side session store needed).
function sign(value) {
  const mac = crypto.createHmac("sha256", SECRET_KEY).update(value).digest("base64url");
  return `${value}.${mac}`;
}
function unsign(signed) {
  if (!signed || !signed.includes(".")) return null;
  const idx = signed.lastIndexOf(".");
  const value = signed.slice(0, idx);
  const mac = signed.slice(idx + 1);
  const expect = crypto.createHmac("sha256", SECRET_KEY).update(value).digest("base64url");
  const a = Buffer.from(mac), b = Buffer.from(expect);
  if (a.length !== b.length) return null;
  return crypto.timingSafeEqual(a, b) ? value : null;
}

export function parseCookies(req) {
  const out = {};
  (req.headers.cookie || "").split(";").forEach((p) => {
    const i = p.indexOf("=");
    if (i < 0) return;
    out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}

export function setCookie(req, res, name, value, maxAge = 60 * 60 * 24) {
  const secure = req.headers["x-forwarded-proto"] === "https" ? "; Secure" : "";
  const cookie = `${name}=${encodeURIComponent(sign(value))}; Path=/; HttpOnly; SameSite=Lax${secure}; Max-Age=${maxAge}`;
  const prev = res.getHeader("Set-Cookie");
  res.setHeader("Set-Cookie", prev ? [].concat(prev, cookie) : cookie);
}

export function clearCookie(req, res, name) {
  const secure = req.headers["x-forwarded-proto"] === "https" ? "; Secure" : "";
  const cookie = `${name}=; Path=/; HttpOnly; SameSite=Lax${secure}; Max-Age=0`;
  const prev = res.getHeader("Set-Cookie");
  res.setHeader("Set-Cookie", prev ? [].concat(prev, cookie) : cookie);
}

export function getSignedCookie(req, name) {
  return unsign(parseCookies(req)[name]);
}

// Player session cookie holds "id|username" so we can mark presence without a DB read.
export function getSid(req) {
  const v = getSignedCookie(req, "sid");
  if (!v) return null;
  const i = v.indexOf("|");
  return i < 0 ? { id: v, username: null } : { id: v.slice(0, i), username: v.slice(i + 1) };
}
