import { redis } from "../lib/redis.js";
import { getSid } from "../lib/auth.js";
import { FLAGS, TOTAL_POINTS } from "../lib/config.js";
import { touch } from "../lib/store.js";
import { iso } from "../lib/util.js";

export default async function handler(req, res) {
  const sid = getSid(req);
  if (!sid) return res.json({ ok: true, authed: false });

  const u = await redis.hgetall(`user:${sid.id}`);
  if (!u || !u.username) return res.json({ ok: true, authed: false });
  await touch(u.username);

  const solves = (await redis.hgetall(`solves:${sid.id}`)) || {}; // flagkey -> ts
  const stages = Object.entries(FLAGS).map(([k, v]) => ({
    key: k, name: v.name, points: v.points,
    solved: Object.prototype.hasOwnProperty.call(solves, k),
  }));
  const solved = Object.entries(solves)
    .map(([k, ts]) => ({ name: FLAGS[k]?.name || k, points: FLAGS[k]?.points || 0, ts: iso(Number(ts)) }))
    .sort((a, b) => new Date(a.ts) - new Date(b.ts));

  return res.json({ ok: true, authed: true, username: u.username,
    score: Number(u.score || 0), total_points: TOTAL_POINTS, stages, solved });
}
