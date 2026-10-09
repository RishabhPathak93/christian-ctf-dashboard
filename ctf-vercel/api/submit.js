import { redis } from "../lib/redis.js";
import { getSid } from "../lib/auth.js";
import { FLAGS } from "../lib/config.js";
import { touch, rebuildBoard } from "../lib/store.js";
import { now, readJson } from "../lib/util.js";

function normalize(raw) { return String(raw || "").trim().replace(/^⚑+/, "").trim(); }

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).json({ ok: false, error: "method not allowed" });

  const sid = getSid(req);
  if (!sid) return res.status(401).json({ ok: false, error: "You must register before submitting." });
  const u = await redis.hgetall(`user:${sid.id}`);
  if (!u || !u.username) return res.status(401).json({ ok: false, error: "You must register before submitting." });
  await touch(u.username);

  const body = await readJson(req);
  const raw = normalize(body.flag);
  if (!raw) return res.status(400).json({ ok: false, error: "Empty submission." });

  // Light anti-bruteforce: cap rapid wrong tries (counter with a 10s TTL).
  const wrongKey = `wrong:${sid.id}`;
  if (Number((await redis.get(wrongKey)) || 0) >= 8) {
    return res.status(429).json({ ok: false, error: "Too many attempts. Wait a few seconds." });
  }

  const logAttempt = async (correct) => {
    await redis.lpush("attempts", JSON.stringify({ username: u.username, submitted: raw.slice(0, 120), correct, ts: now() }));
    await redis.ltrim("attempts", 0, 199);
  };

  const match = FLAGS[raw];
  if (!match) {
    await redis.incr(wrongKey);
    await redis.expire(wrongKey, 10);
    await logAttempt(false);
    return res.json({ ok: false, correct: false, error: "Incorrect flag." });
  }

  await logAttempt(true);
  if (await redis.hexists(`solves:${sid.id}`, raw)) {
    return res.json({ ok: true, correct: true, duplicate: true, message: "Correct — but you already solved this one." });
  }

  const t = now();
  await redis.hset(`solves:${sid.id}`, { [raw]: String(t) });
  await redis.hincrby(`user:${sid.id}`, "solves_count", 1);
  await redis.hset(`user:${sid.id}`, { last_solve: String(t) });
  const newScore = await redis.hincrby(`user:${sid.id}`, "score", match.points);
  await redis.incr(`flagcount:${raw}`);
  await redis.rpush("solvetimes", String(t));
  await rebuildBoard();

  return res.json({ ok: true, correct: true, duplicate: false, points: match.points,
    stage: match.name, score: Number(newScore),
    message: `Correct! +${match.points} points — ${match.name}` });
}
