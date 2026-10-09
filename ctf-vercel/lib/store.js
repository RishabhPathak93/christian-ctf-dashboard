import { redis } from "./redis.js";
import { FLAGS, TOTAL_POINTS } from "./config.js";
import { now } from "./util.js";

// ---- presence (sorted set: member=username, score=last_seen seconds) ----
export async function touch(username) {
  if (username) await redis.zadd("presence", { score: now(), member: username });
}
export async function onlineSet(windowSec) {
  const arr = await redis.zrange("presence", now() - windowSec, "+inf", { byScore: true });
  return new Set(arr || []);
}
export async function presenceMap() {
  const arr = (await redis.zrange("presence", 0, -1, { withScores: true })) || [];
  const m = new Map();
  for (let i = 0; i < arr.length; i += 2) m.set(arr[i], Number(arr[i + 1]));
  return m;
}

// ---- users ----
export async function allUsers() {
  const ids = await redis.smembers("users");
  if (!ids || !ids.length) return [];
  const p = redis.pipeline();
  ids.forEach((id) => p.hgetall(`user:${id}`));
  const res = await p.exec();
  const out = [];
  ids.forEach((id, i) => {
    const u = res[i];
    if (u && u.username) {
      out.push({ id, email: u.email, username: u.username, ip: u.ip,
                 score: Number(u.score || 0), created_at: Number(u.created_at || 0) });
    }
  });
  return out;
}

// ---- leaderboard cache (rebuilt only on writes; reads are a single GET) ----
export async function rebuildBoard() {
  const ids = await redis.smembers("users");
  let rows = [];
  if (ids && ids.length) {
    const p = redis.pipeline();
    ids.forEach((id) => p.hgetall(`user:${id}`));
    const res = await p.exec();
    ids.forEach((id, i) => {
      const u = res[i];
      if (u && u.username) {
        rows.push({ username: u.username, score: Number(u.score || 0),
                    solves: Number(u.solves_count || 0),
                    last_solve: u.last_solve ? Number(u.last_solve) : Infinity });
      }
    });
    rows.sort((a, b) => b.score - a.score || a.last_solve - b.last_solve);
  }
  const board = rows.map((r, i) => ({ rank: i + 1, username: r.username, score: r.score, solves: r.solves }));
  const stages = [];
  let si = 0;
  for (const [k, v] of Object.entries(FLAGS)) {
    si++;
    const n = Number((await redis.get(`flagcount:${k}`)) || 0);
    stages.push({ idx: si, points: v.points, solves: n });
  }
  const cache = { board, stages, total_points: TOTAL_POINTS, updated: now() };
  await redis.set("board:cache", JSON.stringify(cache));
  return cache;
}

export async function getBoardCache() {
  const raw = await redis.get("board:cache");
  if (!raw) return await rebuildBoard();
  try { return JSON.parse(raw); } catch { return await rebuildBoard(); }
}
