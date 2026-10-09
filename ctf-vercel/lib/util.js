export function now() { return Date.now() / 1000; }               // seconds
export function iso(ts) { return new Date(ts * 1000).toISOString(); }

// Real client IP. On Vercel, x-real-ip is set by the platform; x-forwarded-for
// is the fallback (leftmost entry is the client). Best-effort by nature.
export function clientIp(req) {
  const xr = req.headers["x-real-ip"];
  if (xr) return String(xr).trim();
  const xff = req.headers["x-forwarded-for"];
  if (xff) return String(xff).split(",")[0].trim();
  return (req.socket && req.socket.remoteAddress) || "0.0.0.0";
}

// Vercel usually parses JSON bodies for us; handle object, string, and raw stream.
export async function readJson(req) {
  if (req.body && typeof req.body === "object") return req.body;
  if (typeof req.body === "string") { try { return JSON.parse(req.body); } catch { return {}; } }
  return await new Promise((resolve) => {
    let d = "";
    req.on("data", (c) => (d += c));
    req.on("end", () => { try { resolve(JSON.parse(d || "{}")); } catch { resolve({}); } });
    req.on("error", () => resolve({}));
  });
}
