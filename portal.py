#!/usr/bin/env python3
"""
Overlord CTF — Flag Submission Portal & Admin Dashboard
Single-file Flask app. Secure by design (this is NOT the vulnerable target).

Run (recommended — directly on the host so real client IPs are seen):
    pip install flask
    set CTF_ADMIN_PASSWORD=your-strong-password   (Windows)   # or export on Linux/mac
    python portal.py
Then players open   http://<server-ip>:7777/        (LAN or Tailscale IP)
Admin opens         http://<server-ip>:7777/admin
"""

import os
import re
import json
import time
import sqlite3
import secrets
import io
import threading
from datetime import datetime, timezone

from flask import Flask, request, session, jsonify, Response

# Matplotlib for server-rendered chart PNGs. Guarded so a missing install
# doesn't crash the whole portal — chart endpoints just return 503 instead.
# Use the Agg (headless) backend and the object-oriented Figure API, which is
# thread-safe, unlike the global pyplot interface.
try:
    import matplotlib
    matplotlib.use("Agg")
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_agg import FigureCanvasAgg
    from matplotlib.ticker import MaxNLocator
    HAVE_MPL = True
except Exception:
    HAVE_MPL = False

# ----------------------------------------------------------------------------
# CONFIG
# ----------------------------------------------------------------------------
DB_PATH        = os.environ.get("PORTAL_DB", "portal.db")
ADMIN_PASSWORD = os.environ.get("CTF_ADMIN_PASSWORD", "change-me-admin-2026")
# Set CTF_SECRET_KEY in the env so sessions survive a restart. Otherwise a random
# key is generated each start (everyone gets logged out when you restart).
SECRET_KEY     = os.environ.get("CTF_SECRET_KEY", secrets.token_hex(32))
PORT           = int(os.environ.get("PORTAL_PORT", "7777"))
# Which interface/IP to bind to. Default 0.0.0.0 = all interfaces.
# Set PORTAL_HOST to your Tailscale IP (e.g. 100.90.67.72) to serve ONLY over
# Tailscale, so the portal is not reachable on the LAN or any other interface.
HOST           = os.environ.get("PORTAL_HOST", "0.0.0.0")
ONLINE_WINDOW  = 120  # seconds; a player counts as "online" if active within this window

# The ONLY accepted flags and their points. Nothing else scores.
FLAGS = {
    "FLAG1{sqli_extracted_corporate_vault_data}":      {"name": "Stage 1 \u2014 SQL Injection",                 "points": 100},
    "FLAG2{cve_2021_43798_telemetry_config_leaked}":   {"name": "Stage 2 \u2014 Grafana LFI (CVE-2021-43798)",  "points": 200},
    "FLAG3{enterprise_rce_via_template_webhook_2026}": {"name": "Stage 3 \u2014 SSTI \u2192 RCE",                "points": 300},
}
TOTAL_POINTS = sum(f["points"] for f in FLAGS.values())

app = Flask(__name__)
app.config.update(SECRET_KEY=SECRET_KEY, JSON_SORT_KEYS=False)

# ----------------------------------------------------------------------------
# DB helpers (parameterized queries everywhere)
# ----------------------------------------------------------------------------
def db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn

def init_db():
    conn = db()
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        username TEXT UNIQUE NOT NULL,
        ip TEXT NOT NULL,
        score INTEGER NOT NULL DEFAULT 0,
        created_at REAL NOT NULL
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS solves (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        flag_key TEXT NOT NULL,
        flag_name TEXT NOT NULL,
        points INTEGER NOT NULL,
        ts REAL NOT NULL,
        UNIQUE(user_id, flag_key)
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        submitted TEXT,
        correct INTEGER NOT NULL,
        ip TEXT,
        ts REAL NOT NULL
    )""")
    # Presence column — added via migration so existing portal.db files upgrade cleanly.
    try:
        c.execute("ALTER TABLE users ADD COLUMN last_seen REAL")
    except sqlite3.OperationalError:
        pass  # column already exists
    conn.commit()
    conn.close()

def now():
    return time.time()

def iso(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

# ----------------------------------------------------------------------------
# Utilities
# ----------------------------------------------------------------------------
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def client_ip():
    # If a trusted reverse proxy sits in front, it should set X-Forwarded-For.
    # When run directly on the host (recommended), remote_addr is the real client.
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"

def username_from_email(conn, email):
    base = re.sub(r"[^a-zA-Z0-9_.-]", "", email.split("@")[0]) or "player"
    candidate = base
    i = 1
    while conn.execute("SELECT 1 FROM users WHERE username=?", (candidate,)).fetchone():
        i += 1
        candidate = f"{base}{i}"
    return candidate

def current_user(conn):
    uid = session.get("uid")
    if not uid:
        return None
    return conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()

def normalize_flag(raw):
    # Strip whitespace and a leading flag emoji/marker if someone pastes it.
    return raw.strip().lstrip("\u2691").strip()

def touch(conn, uid):
    # Record activity for presence ("online now"). Caller commits.
    if uid:
        conn.execute("UPDATE users SET last_seen=? WHERE id=?", (now(), uid))

# ----------------------------------------------------------------------------
# API — player
# ----------------------------------------------------------------------------
@app.route("/api/register", methods=["POST"])
def api_register():
    data  = request.get_json(silent=True) or request.form
    email = (data.get("email") or "").strip().lower()
    if not EMAIL_RE.match(email):
        return jsonify(ok=False, error="Please enter a valid email address."), 400

    ip = client_ip()
    conn = db()
    try:
        if conn.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
            # Existing email -> just log them back in.
            u = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
            session["uid"] = u["id"]
            return jsonify(ok=True, resumed=True, username=u["username"])

        # One account per IP.
        if conn.execute("SELECT 1 FROM users WHERE ip=?", (ip,)).fetchone():
            return jsonify(ok=False,
                           error="An account has already been registered from this network/IP. "
                                 "Only one account per IP is allowed."), 403

        username = username_from_email(conn, email)
        conn.execute("INSERT INTO users (email, username, ip, score, created_at) VALUES (?,?,?,?,?)",
                     (email, username, ip, 0, now()))
        conn.commit()
        u = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        session["uid"] = u["id"]
        return jsonify(ok=True, resumed=False, username=username)
    finally:
        conn.close()

@app.route("/api/login", methods=["POST"])
def api_login():
    data  = request.get_json(silent=True) or request.form
    email = (data.get("email") or "").strip().lower()
    conn = db()
    try:
        u = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if not u:
            return jsonify(ok=False, error="No account with that email. Register first."), 404
        session["uid"] = u["id"]
        return jsonify(ok=True, username=u["username"])
    finally:
        conn.close()

@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.pop("uid", None)
    return jsonify(ok=True)

@app.route("/api/me")
def api_me():
    conn = db()
    try:
        u = current_user(conn)
        if not u:
            return jsonify(ok=True, authed=False)
        touch(conn, u["id"]); conn.commit()
        solved = conn.execute("SELECT flag_key, flag_name, points, ts FROM solves WHERE user_id=? ORDER BY ts",
                              (u["id"],)).fetchall()
        return jsonify(ok=True, authed=True, username=u["username"], score=u["score"],
                       total_points=TOTAL_POINTS,
                       stages=[{"key": k, "name": v["name"], "points": v["points"],
                                "solved": any(s["flag_key"] == k for s in solved)}
                               for k, v in FLAGS.items()],
                       solved=[{"name": s["flag_name"], "points": s["points"], "ts": iso(s["ts"])} for s in solved])
    finally:
        conn.close()

@app.route("/api/submit", methods=["POST"])
def api_submit():
    conn = db()
    try:
        u = current_user(conn)
        if not u:
            return jsonify(ok=False, error="You must register before submitting."), 401

        touch(conn, u["id"]); conn.commit()
        data = request.get_json(silent=True) or request.form
        raw  = normalize_flag(data.get("flag") or "")
        if not raw:
            return jsonify(ok=False, error="Empty submission."), 400

        # Light anti-bruteforce: cap very rapid repeated wrong tries.
        recent = conn.execute(
            "SELECT COUNT(*) AS n FROM attempts WHERE user_id=? AND correct=0 AND ts > ?",
            (u["id"], now() - 10)).fetchone()["n"]
        if recent >= 8:
            return jsonify(ok=False, error="Too many attempts. Wait a few seconds."), 429

        match = FLAGS.get(raw)
        if not match:
            conn.execute("INSERT INTO attempts (user_id, username, submitted, correct, ip, ts) VALUES (?,?,?,?,?,?)",
                         (u["id"], u["username"], raw[:120], 0, client_ip(), now()))
            conn.commit()
            return jsonify(ok=False, correct=False, error="Incorrect flag."), 200

        already = conn.execute("SELECT 1 FROM solves WHERE user_id=? AND flag_key=?", (u["id"], raw)).fetchone()
        conn.execute("INSERT INTO attempts (user_id, username, submitted, correct, ip, ts) VALUES (?,?,?,?,?,?)",
                     (u["id"], u["username"], raw[:120], 1, client_ip(), now()))
        if already:
            conn.commit()
            return jsonify(ok=True, correct=True, duplicate=True,
                           message="Correct \u2014 but you already solved this one.")

        conn.execute("INSERT INTO solves (user_id, flag_key, flag_name, points, ts) VALUES (?,?,?,?,?)",
                     (u["id"], raw, match["name"], match["points"], now()))
        conn.execute("UPDATE users SET score = score + ? WHERE id=?", (match["points"], u["id"]))
        conn.commit()
        newscore = conn.execute("SELECT score FROM users WHERE id=?", (u["id"],)).fetchone()["score"]
        return jsonify(ok=True, correct=True, duplicate=False, points=match["points"],
                       stage=match["name"], score=newscore,
                       message=f"Correct! +{match['points']} points \u2014 {match['name']}")
    finally:
        conn.close()

@app.route("/api/scoreboard")
def api_scoreboard():
    uid = session.get("uid")
    conn = db()
    try:
        if uid:
            touch(conn, uid); conn.commit()  # polling the board keeps presence fresh
        rows = conn.execute("""
            SELECT u.username, u.score, u.last_seen,
                   (SELECT COUNT(*) FROM solves s WHERE s.user_id=u.id) AS solves,
                   (SELECT MAX(ts) FROM solves s WHERE s.user_id=u.id)  AS last_ts
            FROM users u
            ORDER BY u.score DESC, last_ts ASC
        """).fetchall()
        t = now()
        board, online = [], 0
        for i, r in enumerate(rows):
            is_on = bool(r["last_seen"] and (t - r["last_seen"] <= ONLINE_WINDOW))
            if is_on:
                online += 1
            board.append({"rank": i + 1, "username": r["username"], "score": r["score"],
                          "solves": r["solves"], "online": is_on,
                          "last_ts": iso(r["last_ts"]) if r["last_ts"] else None})
        total_solves = conn.execute("SELECT COUNT(*) AS n FROM solves").fetchone()["n"]
        return jsonify(ok=True, board=board, total_points=TOTAL_POINTS,
                       presence={"players": len(rows), "online": online, "solves": total_solves})
    finally:
        conn.close()

# ----------------------------------------------------------------------------
# API — admin
# ----------------------------------------------------------------------------
def admin_required():
    return bool(session.get("admin"))

@app.route("/api/admin/login", methods=["POST"])
def api_admin_login():
    data = request.get_json(silent=True) or request.form
    pw   = data.get("password") or ""
    if secrets.compare_digest(pw, ADMIN_PASSWORD):
        session["admin"] = True
        return jsonify(ok=True)
    return jsonify(ok=False, error="Wrong password."), 403

@app.route("/api/admin/logout", methods=["POST"])
def api_admin_logout():
    session.pop("admin", None)
    return jsonify(ok=True)

@app.route("/api/admin/stats")
def api_admin_stats():
    if not admin_required():
        return jsonify(ok=False, error="unauthorized"), 401
    conn = db()
    try:
        players = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
        solves  = conn.execute("SELECT COUNT(*) AS n FROM solves").fetchone()["n"]
        awarded = conn.execute("SELECT COALESCE(SUM(points),0) AS n FROM solves").fetchone()["n"]

        per_flag = []
        for k, v in FLAGS.items():
            n = conn.execute("SELECT COUNT(*) AS n FROM solves WHERE flag_key=?", (k,)).fetchone()["n"]
            per_flag.append({"name": v["name"], "solves": n, "points": v["points"]})

        urows = conn.execute("SELECT * FROM users ORDER BY score DESC, created_at ASC").fetchall()
        users = []
        t = now(); online = 0
        for u in urows:
            sc = conn.execute("SELECT flag_name FROM solves WHERE user_id=? ORDER BY ts", (u["id"],)).fetchall()
            is_on = bool(u["last_seen"] and (t - u["last_seen"] <= ONLINE_WINDOW))
            if is_on:
                online += 1
            users.append({"username": u["username"], "email": u["email"], "ip": u["ip"],
                          "score": u["score"], "created_at": iso(u["created_at"]),
                          "online": is_on,
                          "last_seen": iso(u["last_seen"]) if u["last_seen"] else None,
                          "solved": [s["flag_name"] for s in sc]})

        # Cumulative solves over time.
        srows = conn.execute("SELECT ts FROM solves ORDER BY ts").fetchall()
        timeline, cum = [], 0
        for s in srows:
            cum += 1
            timeline.append({"ts": iso(s["ts"]), "cumulative": cum})

        recent = conn.execute("""SELECT username, submitted, correct, ts FROM attempts
                                 ORDER BY ts DESC LIMIT 25""").fetchall()
        recent = [{"username": r["username"], "submitted": r["submitted"],
                   "correct": bool(r["correct"]), "ts": iso(r["ts"])} for r in recent]

        return jsonify(ok=True,
                       totals={"players": players, "solves": solves, "awarded": awarded,
                               "possible": TOTAL_POINTS, "online": online},
                       per_flag=per_flag, users=users, timeline=timeline, recent=recent)
    finally:
        conn.close()

# ----------------------------------------------------------------------------
# Matplotlib charts (server-rendered PNGs, thread-safe OO Figure API)
# ----------------------------------------------------------------------------
_chart_lock  = threading.Lock()
_chart_cache = {}       # name -> (generated_at, png_bytes)
CHART_TTL    = 3.0      # seconds; avoid regenerating on every poll
BAR_COLORS   = ["#38bdf8", "#818cf8", "#a855f7", "#22c55e", "#f472b6",
                "#fbbf24", "#fb7185", "#34d399", "#60a5fa", "#c084fc"]

def _style(fig, ax):
    fig.patch.set_alpha(0)                 # transparent -> blends with dark card
    ax.set_facecolor("none")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color("#27354f")
    ax.spines["bottom"].set_color("#27354f")
    ax.tick_params(colors="#8da2c0", labelsize=9)
    ax.xaxis.label.set_color("#8da2c0")
    ax.yaxis.label.set_color("#8da2c0")

def _to_png(fig):
    buf = io.BytesIO()
    FigureCanvasAgg(fig).print_png(buf)
    return buf.getvalue()

def chart_scoreboard():
    conn = db()
    try:
        rows = conn.execute("SELECT username, score FROM users "
                            "ORDER BY score DESC, created_at ASC LIMIT 10").fetchall()
    finally:
        conn.close()
    fig = Figure(figsize=(6, 3.6)); ax = fig.add_subplot(111); _style(fig, ax)
    if not rows or all(r["score"] == 0 for r in rows):
        ax.text(0.5, 0.5, "No scores yet", ha="center", va="center",
                color="#8da2c0", transform=ax.transAxes); ax.axis("off")
    else:
        names  = [r["username"] for r in rows][::-1]   # top at the top
        scores = [r["score"] for r in rows][::-1]
        bars = ax.barh(names, scores, height=0.62,
                       color=[BAR_COLORS[i % len(BAR_COLORS)] for i in range(len(names))])
        ax.set_xlabel("Points"); ax.bar_label(bars, padding=3, color="#e2e8f0", fontsize=8)
        ax.margins(x=0.14)
    fig.tight_layout()
    return _to_png(fig)

def chart_stages():
    conn = db()
    try:
        labels, counts = [], []
        for i, (k, v) in enumerate(FLAGS.items(), start=1):
            n = conn.execute("SELECT COUNT(*) AS n FROM solves WHERE flag_key=?", (k,)).fetchone()["n"]
            labels.append(f"Stage {i}\n{v['points']} pts"); counts.append(n)
    finally:
        conn.close()
    fig = Figure(figsize=(6, 3.6)); ax = fig.add_subplot(111); _style(fig, ax)
    bars = ax.bar(labels, counts, width=0.6, color=BAR_COLORS[:len(labels)])
    ax.set_ylabel("Solves"); ax.bar_label(bars, padding=3, color="#e2e8f0", fontsize=9)
    ax.margins(y=0.18); ax.yaxis.set_major_locator(MaxNLocator(integer=True))
    fig.tight_layout()
    return _to_png(fig)

CHART_FUNCS = {"scoreboard": chart_scoreboard, "stages": chart_stages}

@app.route("/api/chart/<name>.png")
def api_chart(name):
    fn = CHART_FUNCS.get(name)
    if not fn:
        return Response("not found", status=404)
    if not HAVE_MPL:
        return Response("matplotlib not installed on server", status=503)
    with _chart_lock:
        cached = _chart_cache.get(name)
        if cached and (now() - cached[0] < CHART_TTL):
            png = cached[1]
        else:
            png = fn()
            _chart_cache[name] = (now(), png)
    resp = Response(png, mimetype="image/png")
    resp.headers["Cache-Control"] = "no-store"
    return resp

# ----------------------------------------------------------------------------
# Pages (static shells; all user data rendered client-side via textContent)
# ----------------------------------------------------------------------------
@app.route("/")
def page_player():
    return Response(PLAYER_HTML, mimetype="text/html")

@app.route("/admin")
def page_admin():
    return Response(ADMIN_HTML, mimetype="text/html")

# ----------------------------------------------------------------------------
# Frontend
# ----------------------------------------------------------------------------
BASE_CSS = """
:root{--bg:#070b16;--bg2:#0f172a;--panel:#131d33;--panel2:#1b2742;--accent:#38bdf8;
--accent2:#a855f7;--good:#22c55e;--bad:#ef4444;--text:#f8fafc;--muted:#8da2c0;--border:#27354f;}
*{box-sizing:border-box}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
background:radial-gradient(1200px 600px at 80% -10%,rgba(168,85,247,.12),transparent),
radial-gradient(900px 500px at -10% 10%,rgba(56,189,248,.12),transparent),var(--bg);
color:var(--text);min-height:100vh}
a{color:var(--accent);text-decoration:none}
header{display:flex;justify-content:space-between;align-items:center;padding:16px 28px;
border-bottom:1px solid var(--border);background:rgba(2,6,23,.6);backdrop-filter:blur(8px);
position:sticky;top:0;z-index:10}
.logo{font-weight:800;letter-spacing:-.5px;font-size:1.15rem;
background:linear-gradient(90deg,var(--accent),var(--accent2));-webkit-background-clip:text;
background-clip:text;color:transparent}
.wrap{max-width:1080px;margin:0 auto;padding:28px}
.grid{display:grid;gap:20px}
.card{background:linear-gradient(180deg,var(--panel),var(--panel2));border:1px solid var(--border);
border-radius:14px;padding:22px;box-shadow:0 10px 30px -12px rgba(0,0,0,.5)}
.card h2{margin:0 0 6px;font-size:1.05rem;color:var(--accent)}
.muted{color:var(--muted);font-size:.88rem}
input{width:100%;padding:12px;background:#0a1120;border:1px solid var(--border);color:#fff;
border-radius:10px;font-size:.95rem;margin-top:8px}
input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(56,189,248,.15)}
button{cursor:pointer;border:none;border-radius:10px;padding:12px 16px;font-weight:700;font-size:.95rem;
margin-top:12px;background:linear-gradient(90deg,var(--accent),#0ea5e9);color:#06121f;width:100%;
transition:transform .08s,box-shadow .2s}
button:hover{box-shadow:0 8px 24px -8px var(--accent)}
button:active{transform:translateY(1px)}
button.ghost{background:transparent;border:1px solid var(--border);color:var(--muted);width:auto;padding:8px 14px}
.stat{font-size:2.1rem;font-weight:800}
.row{display:flex;align-items:center;gap:12px}
table{width:100%;border-collapse:collapse;font-size:.9rem}
th,td{text-align:left;padding:10px;border-bottom:1px solid var(--border)}
th{color:var(--muted);font-weight:600;font-size:.78rem;text-transform:uppercase;letter-spacing:.5px}
.badge{display:inline-block;padding:3px 9px;border-radius:999px;font-size:.72rem;font-weight:700}
.b-good{background:rgba(34,197,94,.15);color:var(--good);border:1px solid rgba(34,197,94,.3)}
.b-bad{background:rgba(239,68,68,.15);color:var(--bad);border:1px solid rgba(239,68,68,.3)}
.b-mut{background:rgba(141,162,192,.12);color:var(--muted);border:1px solid var(--border)}
.bar{height:10px;background:#0a1120;border-radius:999px;overflow:hidden;border:1px solid var(--border)}
.bar>i{display:block;height:100%;background:linear-gradient(90deg,var(--accent),var(--accent2));
width:0;transition:width 1s cubic-bezier(.2,.8,.2,1)}
.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%) translateY(120px);
background:var(--panel2);border:1px solid var(--border);padding:14px 20px;border-radius:12px;
box-shadow:0 20px 50px -15px rgba(0,0,0,.7);transition:transform .35s cubic-bezier(.2,.9,.2,1);z-index:50;font-weight:600}
.toast.show{transform:translateX(-50%) translateY(0)}
.toast.good{border-color:rgba(34,197,94,.5)} .toast.bad{border-color:rgba(239,68,68,.5)}
.stage{display:flex;justify-content:space-between;align-items:center;padding:12px 14px;border-radius:10px;
border:1px solid var(--border);margin-top:10px;background:#0a1120}
.stage.done{border-color:rgba(34,197,94,.4);background:rgba(34,197,94,.06)}
.pulse{animation:pulse 2s infinite} @keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
#cf{position:fixed;inset:0;pointer-events:none;z-index:40}
.rank1{color:#fde047} .rank2{color:#e2e8f0} .rank3{color:#fdba74}
canvas{width:100%;height:auto;display:block}
.chartimg{width:100%;border-radius:10px;background:#0a1120;border:1px solid var(--border);min-height:60px;display:block}
.dot{font-size:.7rem;margin-right:6px}
"""

PLAYER_HTML = """<!DOCTYPE html><html lang=en><head><meta charset=UTF-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Overlord CTF \u2014 Submit Flags</title><style>""" + BASE_CSS + """</style></head><body>
<canvas id=cf></canvas>
<header><div class=logo>\u2691 OVERLORD CTF</div>
<div class=row><span id=whoami class=muted></span>
<button class=ghost id=logoutBtn style=display:none onclick=logout()>Log out</button></div></header>
<div class=wrap>

<div id=authView>
  <div class=card style="max-width:460px;margin:40px auto">
    <h2>Join the CTF</h2>
    <p class=muted>Register with your email. Your username is taken from your email.
    One account per network/IP.</p>
    <input id=email type=email placeholder="you@example.com" autocomplete=email>
    <button onclick=register()>Register / Enter</button>
    <p class=muted style=margin-top:14px>Already registered on another device?
    <a href=# onclick="login();return false">Log in with the same email</a>.</p>
    <p id=authErr class=muted style=color:var(--bad)></p>
  </div>
</div>

<div id=appView style=display:none>
  <div class=grid style=grid-template-columns:1fr>
    <div class=card>
      <div class=row style=justify-content:space-between>
        <div><h2 style=margin:0>Your score</h2><span class=muted>Points earned</span></div>
        <div style=text-align:right><div class=stat id=score>0</div>
          <span class=muted>of <span id=possible></span></span></div>
      </div>
      <div class=bar style=margin-top:14px><i id=scoreBar></i></div>
    </div>

    <div class=card>
      <h2>Event stats</h2>
      <div class=row style="justify-content:space-around;text-align:center;flex-wrap:wrap;gap:18px">
        <div><div class=stat id=pPlayers>0</div><span class=muted>Players</span></div>
        <div><div class=stat id=pOnline style=color:var(--good)>0</div><span class=muted>Online now</span></div>
        <div><div class=stat id=pSolves>0</div><span class=muted>Total solves</span></div>
      </div>
      <div class=grid style="grid-template-columns:1fr 1fr;margin-top:18px">
        <div><div class=muted style=margin-bottom:6px>Top players</div>
          <img id=chartScore class=chartimg alt="Top players chart"></div>
        <div><div class=muted style=margin-bottom:6px>Solves per stage</div>
          <img id=chartStages class=chartimg alt="Solves per stage chart"></div>
      </div>
    </div>

    <div class=card>
      <h2>Submit a flag</h2>
      <p class=muted>Paste a flag in the form <code>FLAGn{...}</code>.</p>
      <input id=flag placeholder="FLAG1{...}" onkeydown="if(event.key==='Enter')submit()">
      <button onclick=submit()>Submit flag</button>
    </div>

    <div class=card>
      <h2>Stages</h2>
      <div id=stages></div>
    </div>

    <div class=card>
      <h2>Live scoreboard</h2>
      <table><thead><tr><th>#</th><th>Player</th><th>Solves</th><th>Score</th></tr></thead>
      <tbody id=board></tbody></table>
    </div>
  </div>
</div>
</div>

<div id=toast class=toast></div>
<script>
const $=s=>document.querySelector(s);
async function api(p,b){const o={headers:{'Content-Type':'application/json'}};
 if(b){o.method='POST';o.body=JSON.stringify(b)}return (await fetch(p,o)).json()}
function toast(msg,kind){const t=$('#toast');t.textContent=msg;t.className='toast show '+(kind||'');
 setTimeout(()=>t.className='toast',2600)}

async function register(){const email=$('#email').value.trim();$('#authErr').textContent='';
 const r=await api('/api/register',{email});
 if(!r.ok){$('#authErr').textContent=r.error;return}await load()}
async function login(){const email=$('#email').value.trim();$('#authErr').textContent='';
 const r=await api('/api/login',{email});
 if(!r.ok){$('#authErr').textContent=r.error;return}await load()}
async function logout(){await api('/api/logout',{});location.reload()}

async function submit(){const flag=$('#flag').value.trim();if(!flag)return;
 const r=await api('/api/submit',{flag});
 if(r.ok&&r.correct&&!r.duplicate){toast(r.message,'good');confetti();$('#flag').value=''}
 else if(r.ok&&r.duplicate){toast(r.message,'')}
 else{toast(r.error||'Incorrect flag.','bad')}
 await load()}

async function load(){const me=await api('/api/me');
 if(!me.authed){$('#authView').style.display='';$('#appView').style.display='none';return}
 $('#authView').style.display='none';$('#appView').style.display='';
 $('#logoutBtn').style.display='';$('#whoami').textContent='Logged in as '+me.username;
 $('#possible').textContent=me.total_points;
 animateNum($('#score'),me.score);
 $('#scoreBar').style.width=Math.round(me.score/me.total_points*100)+'%';
 const st=$('#stages');st.innerHTML='';
 me.stages.forEach(s=>{const d=document.createElement('div');d.className='stage'+(s.solved?' done':'');
  const l=document.createElement('div');l.textContent=s.name;
  const r=document.createElement('div');
  r.innerHTML=s.solved?'<span class="badge b-good">SOLVED</span>':
   '<span class="badge b-mut">'+s.points+' pts</span>';
  d.appendChild(l);d.appendChild(r);st.appendChild(d)});
 const sb=await api('/api/scoreboard');renderBoard(sb);refreshCharts()}

function animateNum(el,to){let from=parseInt(el.textContent)||0,t0=performance.now();
 (function step(t){let k=Math.min(1,(t-t0)/600);el.textContent=Math.round(from+(to-from)*k);
  if(k<1)requestAnimationFrame(step)})(t0)}

// tiny dependency-free confetti
function confetti(){const c=$('#cf'),x=c.getContext('2d');c.width=innerWidth;c.height=innerHeight;
 const P=[],col=['#38bdf8','#a855f7','#22c55e','#fde047','#f472b6'];
 for(let i=0;i<140;i++)P.push({x:innerWidth/2,y:innerHeight/3,
  vx:(Math.random()-.5)*12,vy:Math.random()*-14-4,g:.4+Math.random()*.3,
  s:4+Math.random()*5,c:col[i%col.length],r:Math.random()*6});
 let n=0;(function f(){x.clearRect(0,0,c.width,c.height);n++;
  P.forEach(p=>{p.vy+=p.g;p.x+=p.vx;p.y+=p.vy;p.r+=.2;
   x.save();x.translate(p.x,p.y);x.rotate(p.r);x.fillStyle=p.c;
   x.fillRect(-p.s/2,-p.s/2,p.s,p.s*1.6);x.restore()});
  if(n<120)requestAnimationFrame(f);else x.clearRect(0,0,c.width,c.height)})()}

function renderBoard(sb){const tb=$('#board');tb.innerHTML='';
 sb.board.forEach(p=>{const tr=document.createElement('tr');const rc=p.rank<=3?'rank'+p.rank:'';
  const col=p.online?'var(--good)':'#475569';
  tr.innerHTML='<td class="'+rc+'">'+p.rank+'</td><td><span class=dot style="color:'+col+'">●</span></td>'+
   '<td>'+p.solves+'</td><td><b>'+p.score+'</b></td>';
  tr.children[1].appendChild(document.createTextNode(p.username));tb.appendChild(tr)});
 if(sb.presence){$('#pPlayers').textContent=sb.presence.players;
  $('#pOnline').textContent=sb.presence.online;$('#pSolves').textContent=sb.presence.solves}}
function refreshCharts(){const t=Date.now();const a=$('#chartScore'),b=$('#chartStages');
 if(a){a.onerror=()=>{a.style.opacity=.25};a.src='/api/chart/scoreboard.png?t='+t}
 if(b){b.onerror=()=>{b.style.opacity=.25};b.src='/api/chart/stages.png?t='+t}}
load();setInterval(async()=>{if($('#appView').style.display!=='none'){
 const sb=await api('/api/scoreboard');renderBoard(sb);refreshCharts()}},5000);
</script></body></html>"""

ADMIN_HTML = """<!DOCTYPE html><html lang=en><head><meta charset=UTF-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Overlord CTF \u2014 Admin</title><style>""" + BASE_CSS + """</style></head><body>
<header><div class=logo>\u2691 OVERLORD CTF \u00b7 ADMIN</div>
<div class=row><span id=live class="muted pulse" style=display:none>\u25cf live</span>
<button class=ghost id=aout style=display:none onclick=alogout()>Log out</button></div></header>
<div class=wrap>

<div id=loginView>
  <div class=card style="max-width:420px;margin:40px auto">
    <h2>Admin login</h2>
    <input id=pw type=password placeholder="Admin password" onkeydown="if(event.key==='Enter')alogin()">
    <button onclick=alogin()>Enter dashboard</button>
    <p id=aerr class=muted style=color:var(--bad)></p>
  </div>
</div>

<div id=dash style=display:none>
  <div class=grid style="grid-template-columns:repeat(auto-fit,minmax(150px,1fr))">
    <div class=card><span class=muted>Players</span><div class=stat id=tPlayers>0</div></div>
    <div class=card><span class=muted>Online now</span><div class=stat id=tOnline style=color:var(--good)>0</div></div>
    <div class=card><span class=muted>Total solves</span><div class=stat id=tSolves>0</div></div>
    <div class=card><span class=muted>Points awarded</span><div class=stat id=tAwarded>0</div></div>
    <div class=card><span class=muted>Max possible</span><div class=stat id=tPossible>0</div></div>
  </div>

  <div class=grid style="grid-template-columns:1fr 1fr;margin-top:20px">
    <div class=card><h2>Solves per stage</h2><canvas id=barChart height=220></canvas></div>
    <div class=card><h2>Solves over time</h2><canvas id=lineChart height=220></canvas></div>
  </div>

  <div class=card style=margin-top:20px>
    <h2>Players</h2>
    <table><thead><tr><th>Player</th><th>Email</th><th>IP</th><th>Solved</th><th>Score</th><th>Status</th></tr></thead>
    <tbody id=users></tbody></table>
  </div>

  <div class=card style=margin-top:20px>
    <h2>Recent submissions</h2>
    <table><thead><tr><th>When</th><th>Player</th><th>Submitted</th><th>Result</th></tr></thead>
    <tbody id=recent></tbody></table>
  </div>
</div>
</div>

<script>
const $=s=>document.querySelector(s);
async function api(p,b){const o={headers:{'Content-Type':'application/json'}};
 if(b){o.method='POST';o.body=JSON.stringify(b)}return (await fetch(p,o)).json()}

async function alogin(){const r=await api('/api/admin/login',{password:$('#pw').value});
 if(!r.ok){$('#aerr').textContent=r.error;return}start()}
async function alogout(){await api('/api/admin/logout',{});location.reload()}

function animateNum(el,to){let from=parseInt(el.textContent)||0,t0=performance.now();
 (function step(t){let k=Math.min(1,(t-t0)/600);el.textContent=Math.round(from+(to-from)*k);
  if(k<1)requestAnimationFrame(step)})(t0)}

function drawBars(cv,labels,vals){const x=cv.getContext('2d'),W=cv.width=cv.clientWidth,H=cv.height;
 x.clearRect(0,0,W,H);const pad=30,max=Math.max(1,...vals),bw=(W-pad*2)/vals.length*.6,
 gap=(W-pad*2)/vals.length;x.font='11px sans-serif';
 vals.forEach((v,i)=>{const h=(H-50)*(v/max),bx=pad+gap*i+(gap-bw)/2,by=H-30-h;
  const g=x.createLinearGradient(0,by,0,H-30);g.addColorStop(0,'#38bdf8');g.addColorStop(1,'#a855f7');
  x.fillStyle=g;x.beginPath();x.roundRect(bx,by,bw,h,6);x.fill();
  x.fillStyle='#f8fafc';x.textAlign='center';x.fillText(v,bx+bw/2,by-6);
  x.fillStyle='#8da2c0';x.fillText(labels[i],bx+bw/2,H-12)})}

function drawLine(cv,pts){const x=cv.getContext('2d'),W=cv.width=cv.clientWidth,H=cv.height;
 x.clearRect(0,0,W,H);const pad=30,max=Math.max(1,...pts.map(p=>p.v));
 if(pts.length===0){x.fillStyle='#8da2c0';x.textAlign='center';x.fillText('No solves yet',W/2,H/2);return}
 const X=i=>pad+(W-pad*2)*(pts.length===1?0:i/(pts.length-1)),Y=v=>H-30-(H-50)*(v/max);
 const g=x.createLinearGradient(0,0,0,H);g.addColorStop(0,'rgba(56,189,248,.35)');g.addColorStop(1,'rgba(56,189,248,0)');
 x.beginPath();x.moveTo(X(0),H-30);pts.forEach((p,i)=>x.lineTo(X(i),Y(p.v)));
 x.lineTo(X(pts.length-1),H-30);x.closePath();x.fillStyle=g;x.fill();
 x.beginPath();pts.forEach((p,i)=>i?x.lineTo(X(i),Y(p.v)):x.moveTo(X(i),Y(p.v)));
 x.strokeStyle='#38bdf8';x.lineWidth=2.5;x.stroke();
 pts.forEach((p,i)=>{x.beginPath();x.arc(X(i),Y(p.v),3,0,7);x.fillStyle='#a855f7';x.fill()})}

async function refresh(){const d=await api('/api/admin/stats');if(!d.ok)return;
 animateNum($('#tPlayers'),d.totals.players);animateNum($('#tSolves'),d.totals.solves);
 animateNum($('#tAwarded'),d.totals.awarded);$('#tPossible').textContent=d.totals.possible;
 if(d.totals.online!==undefined)animateNum($('#tOnline'),d.totals.online);
 drawBars($('#barChart'),d.per_flag.map(f=>'S'+(d.per_flag.indexOf(f)+1)),d.per_flag.map(f=>f.solves));
 drawLine($('#lineChart'),d.timeline.map((t,i)=>({v:t.cumulative})));
 const ut=$('#users');ut.innerHTML='';
 d.users.forEach(u=>{const tr=document.createElement('tr');
  const st=u.online?'<span class="badge b-good">online</span>':'<span class="badge b-mut">offline</span>';
  tr.innerHTML='<td></td><td></td><td></td><td>'+u.solved.length+'/3</td><td><b>'+u.score+'</b></td><td>'+st+'</td>';
  tr.children[0].textContent=u.username;tr.children[1].textContent=u.email;tr.children[2].textContent=u.ip;
  ut.appendChild(tr)});
 const rt=$('#recent');rt.innerHTML='';
 d.recent.forEach(r=>{const tr=document.createElement('tr');
  const t=new Date(r.ts).toLocaleTimeString();
  tr.innerHTML='<td>'+t+'</td><td></td><td></td><td>'+
   (r.correct?'<span class="badge b-good">correct</span>':'<span class="badge b-bad">wrong</span>')+'</td>';
  tr.children[1].textContent=r.username||'-';tr.children[2].textContent=r.submitted||'';
  rt.appendChild(tr)})}

function start(){$('#loginView').style.display='none';$('#dash').style.display='';
 $('#aout').style.display='';$('#live').style.display='';refresh();setInterval(refresh,4000)}

// auto-resume if already authed
api('/api/admin/stats').then(d=>{if(d.ok)start()});
</script></body></html>"""

# ----------------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    if ADMIN_PASSWORD == "change-me-admin-2026":
        print("[!] WARNING: default admin password in use. Set CTF_ADMIN_PASSWORD.")
    print(f"[+] Portal binding on {HOST}:{PORT}  ->  http://{HOST}:{PORT}/   (admin: /admin)")
    if HOST not in ("0.0.0.0", "127.0.0.1", "localhost"):
        print(f"[+] Tailscale-only mode: players reach it at http://{HOST}:{PORT}/")
    # debug=False on purpose — this portal must NOT leak tracebacks like the target app.
    app.run(host=HOST, port=PORT, debug=False, threaded=True)