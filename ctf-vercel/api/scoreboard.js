import { getSid } from "../lib/auth.js";
import { ONLINE_WINDOW } from "../lib/config.js";
import { getBoardCache, onlineSet, touch } from "../lib/store.js";

export default async function handler(req, res) {
  const sid = getSid(req);
  if (sid && sid.username) await touch(sid.username);

  const cache = await getBoardCache();           // 1 read (cached JSON)
  const online = await onlineSet(ONLINE_WINDOW); // 1 read (presence sorted set)

  const board = cache.board.map((r) => ({ ...r, online: online.has(r.username) }));
  const totalSolves = cache.board.reduce((a, r) => a + r.solves, 0);

  return res.json({ ok: true, board, stages: cache.stages, total_points: cache.total_points,
    presence: { players: cache.board.length, online: board.filter((r) => r.online).length, solves: totalSolves } });
}
