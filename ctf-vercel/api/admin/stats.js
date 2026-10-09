import { redis } from "../../lib/redis.js";
import { getSignedCookie } from "../../lib/auth.js";
import { FLAGS, TOTAL_POINTS, ONLINE_WINDOW } from "../../lib/config.js";
import { allUsers, presenceMap } from "../../lib/store.js";
import { now, iso } from "../../lib/util.js";

export default async function handler(req, res) {
  if (getSignedCookie(req, "adm") !== "1") return res.status(401).json({ ok: false, error: "unauthorized" });

  const users = await allUsers();
  const p = redis.pipeline();
  users.forEach((u) => p.hgetall(`solves:${u.id}`));
  const solvesArr = users.length ? await p.exec() : [];
  const pres = await presenceMap();

  const t = now();
  let online = 0, totalSolves = 0, awarded = 0;
  const userOut = users.map((u, i) => {
    const s = solvesArr[i] || {};
    const keys = Object.keys(s);
    totalSolves += keys.length;
    awarded += u.score;
    const ls = pres.get(u.username) || null;
    const isOn = !!(ls && t - ls <= ONLINE_WINDOW);
    if (isOn) online++;
    return { username: u.username, email: u.email, ip: u.ip, score: u.score,
      created_at: iso(u.created_at), online: isOn, last_seen: ls ? iso(ls) : null,
      solved: keys.map((k) => FLAGS[k]?.name || k) };
  }).sort((a, b) => b.score - a.score);

  const per_flag = [];
  for (const [k, v] of Object.entries(FLAGS)) {
    const n = Number((await redis.get(`flagcount:${k}`)) || 0);
    per_flag.push({ name: v.name, solves: n, points: v.points });
  }

  const times = ((await redis.lrange("solvetimes", 0, -1)) || []).map(Number).sort((a, b) => a - b);
  let cum = 0;
  const timeline = times.map((ts) => ({ ts: iso(ts), cumulative: ++cum }));

  const recentRaw = (await redis.lrange("attempts", 0, 24)) || [];
  const recent = recentRaw.map((x) => {
    try { const o = typeof x === "string" ? JSON.parse(x) : x;
      return { username: o.username, submitted: o.submitted, correct: !!o.correct, ts: iso(o.ts) };
    } catch { return null; }
  }).filter(Boolean);

  return res.json({ ok: true,
    totals: { players: users.length, solves: totalSolves, awarded, possible: TOTAL_POINTS, online },
    per_flag, users: userOut, timeline, recent });
}
