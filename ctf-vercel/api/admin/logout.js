import { clearCookie } from "../../lib/auth.js";

export default async function handler(req, res) {
  clearCookie(req, res, "adm");
  return res.json({ ok: true });
}
