import sqlite3
import traceback
import sys
from flask import Flask, request, render_template_string, jsonify

app = Flask(__name__)
app.config['DEBUG'] = True

def init_db():
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        # Public Trackable Shipments
        cursor.execute('''CREATE TABLE IF NOT EXISTS shipments (tracking_id TEXT, destination TEXT, status TEXT)''')
        cursor.execute("DELETE FROM shipments")
        cursor.execute("INSERT INTO shipments VALUES ('TRK-1001', 'New York Hub, USA', 'In Transit')")
        cursor.execute("INSERT INTO shipments VALUES ('TRK-1002', 'London Depot, UK', 'Delivered')")
        cursor.execute("INSERT INTO shipments VALUES ('TRK-1003', 'Tokyo Gateway, JP', 'Customs Hold')")

        # Internal Corporate System Table (Target for SQLi)
        cursor.execute('''CREATE TABLE IF NOT EXISTS sys_vault (id INTEGER, service_key TEXT, secret_data TEXT)''')
        cursor.execute("DELETE FROM sys_vault")
        cursor.execute("INSERT INTO sys_vault VALUES (1, 'grafana_metrics_relay', 'FLAG1{sqli_extracted_corporate_vault_data}')")
        cursor.execute("INSERT INTO sys_vault VALUES (2, 'aws_s3_backup_bucket', 's3://overlord-internal-backups-prod-2026')")

        conn.commit()
        conn.close()
        print("[+] SQLite Database initialized successfully.", file=sys.stdout)
    except Exception as e:
        print(f"[-] Database initialization error: {e}", file=sys.stderr)

init_db()

MAIN_UI = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Overlord Supply Chain & Logistics Suite</title>
    <style>
        :root { --bg: #0f172a; --panel: #1e293b; --accent: #38bdf8; --text: #f8fafc; --muted: #94a3b8; --border: #334155; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 0; }
        header { background: #020617; border-bottom: 1px solid var(--border); padding: 16px 32px; display: flex; justify-content: space-between; align-items: center; }
        .logo { font-size: 1.25rem; font-weight: 700; color: var(--accent); letter-spacing: -0.5px; }
        nav a { color: var(--muted); text-decoration: none; margin-left: 20px; font-size: 0.9rem; transition: color 0.2s; }
        nav a:hover { color: var(--accent); }
        .hero { padding: 40px 32px; text-align: center; max-width: 800px; margin: 0 auto; }
        .hero h1 { font-size: 2.2rem; margin-bottom: 10px; }
        .hero p { color: var(--muted); font-size: 1.1rem; }
        .container { max-width: 1100px; margin: 0 auto; padding: 20px; display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        .card { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 24px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); }
        .card h2 { font-size: 1.1rem; margin-top: 0; color: var(--accent); display: flex; align-items: center; gap: 8px; }
        input, select, button { width: 100%; padding: 10px; margin-top: 8px; background: #0f172a; border: 1px solid var(--border); color: #fff; border-radius: 6px; box-sizing: border-box; font-size: 0.9rem; }
        button { background: var(--accent); color: #0f172a; font-weight: 600; cursor: pointer; border: none; margin-top: 16px; transition: opacity 0.2s; }
        button:hover { opacity: 0.9; }
        footer { border-top: 1px solid var(--border); text-align: center; padding: 20px; color: var(--muted); font-size: 0.8rem; margin-top: 40px; }
    </style>
</head>
<body>
    <header>
        <div class="logo">📦 OVERLORD LOGISTICS</div>
        <nav>
            <a href="/">Dashboard</a>
            <a href="/portal/tracking">Global Tracker</a>
            <a href="#" onclick="window.open('http://' + window.location.hostname + ':3333', '_blank'); return false;">Driver Telemetry Dashboard</a>
            <a href="/portal/login">Partner Login</a>
        </nav>
    </header>

    <div class="hero">
        <h1>Autonomous Fleet & Global Supply Chain Management</h1>
        <p>Real-time telemetry, automated dispatching, and high-security parcel routing.</p>
    </div>

    <div class="container">
        <!-- FEATURE 1: Shipment Tracking (Vulnerable to SQLi) -->
        <div class="card">
            <h2>🔍 Live Package Tracker</h2>
            <p style="color: var(--muted); font-size:0.85rem;">Track real-time location and customs clearance status.</p>
            <form action="/portal/tracking" method="GET">
                <label style="font-size: 0.8rem; color: var(--muted);">Tracking ID or Internal Ref Code</label>
                <input type="text" name="id" placeholder="e.g., TRK-1001" value="TRK-1001" required>
                <button type="submit">Track Package</button>
            </form>
        </div>

        <!-- FEATURE 2: Partner Login (Decoy Authentication) -->
        <div class="card">
            <h2>🔑 Enterprise SSO Portal</h2>
            <p style="color: var(--muted); font-size:0.85rem;">Restricted to verified logistics partners and dispatch personnel.</p>
            <form action="/portal/login" method="POST">
                <input type="text" name="username" placeholder="Partner ID / Email">
                <input type="password" name="password" placeholder="Access Token">
                <button type="submit" style="background:#475569; color:#fff;">Authenticate</button>
            </form>
        </div>

        <!-- FEATURE 3: Webhook Alert Builder (Vulnerable to Filtered SSTI) -->
        <div class="card" style="grid-column: span 2;">
            <h2>⚡ Automated Email Notification Webhook Customizer</h2>
            <p style="color: var(--muted); font-size:0.85rem;">Dispatch managers can customize dynamic notification templates. Requires authorized <code>WEBHOOK_DIAG_SECRET.</p>
            <form action="/api/v2/webhooks/test" method="POST">
                <div style="display:grid; grid-template-columns: 1fr 2fr; gap: 10px;">
                    <input type="password" name="auth_secret" placeholder="Webhook Secret Key">
                    <input type="text" name="template_payload" placeholder="Dynamic Notification Tag">
                </div>
                <button type="submit">Send Test Trigger</button>
            </form>
        </div>
    </div>

    RESULTS_PLACEHOLDER

    <footer>
        &copy; 2026 Overlord Logistics SaaS Solutions Inc. | ISO/IEC 27001 Certified Enterprise Portal
    </footer>
</body>
</html>
"""

# Global Error Handler: Catches 500 errors and displays full Python traceback on screen
@app.errorhandler(Exception)
def handle_exception(e):
    tb = traceback.format_exc()
    print(f"[CRITICAL ERROR]:\n{tb}", file=sys.stderr)
    err_display = f"""
    <div style="max-width:1100px; margin: 20px auto; padding:20px; background:#450a0a; border-radius:8px; border:2px solid #ef4444; color:#fca5a5; font-family:monospace;">
        <h2 style="color:#f87171; margin-top:0;">⚠️ 500 Internal Server Error Caught</h2>
        <p><strong>Exception:</strong> {str(e)}</p>
        <pre style="background:#020617; padding:15px; border-radius:6px; overflow-x:auto;">{tb}</pre>
    </div>
    """
    return MAIN_UI.replace("RESULTS_PLACEHOLDER", err_display), 500

@app.route('/')
def index():
    return MAIN_UI.replace("RESULTS_PLACEHOLDER", "")

# STAGE 1: SQL Injection
@app.route('/portal/tracking', methods=['GET'])
def tracking():
    tracking_id = request.args.get('id', '')
    if not tracking_id:
        return MAIN_UI.replace("RESULTS_PLACEHOLDER", "")

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    query = f"SELECT tracking_id, destination, status FROM shipments WHERE tracking_id = '{tracking_id}'"
    try:
        cursor.execute(query)
        results = cursor.fetchall()

        table_html = f"""
        <div style="max-width:1100px; margin: 20px auto; padding:20px; background:#1e293b; border-radius:8px; border:1px solid #334155;">
            <h3 style="color:#38bdf8; margin-top:0;">Search Results for: {tracking_id}</h3>
            <table style="width:100%; text-align:left; color:#f8fafc; border-collapse:collapse;">
                <tr style="border-bottom: 1px solid #334155;">
                    <th style="padding:8px;">ID / Record</th><th style="padding:8px;">Location / Metadata</th><th style="padding:8px;">Status</th>
                </tr>
        """
        for r in results:
            table_html += f"<tr style='border-bottom: 1px solid #334155;'><td style='padding:8px;'>{r[0]}</td><td style='padding:8px;'>{r[1]}</td><td style='padding:8px;'>{r[2]}</td></tr>"
        table_html += "</table></div>"

        return MAIN_UI.replace("RESULTS_PLACEHOLDER", table_html)
    except Exception as e:
        err_html = f"""
        <div style="max-width:1100px; margin: 20px auto; padding:20px; background:#450a0a; border-radius:8px; border:1px solid #f87171; color:#fca5a5;">
            <h3>SQL Query Error</h3>
            <p><strong>Query executed:</strong> <code>{query}</code></p>
            <p><strong>Database Exception:</strong> {str(e)}</p>
        </div>
        """
        return MAIN_UI.replace("RESULTS_PLACEHOLDER", err_html), 200

# DECOY: Realistic Auth Handler
@app.route('/portal/login', methods=['POST'])
def login():
    return MAIN_UI.replace("RESULTS_PLACEHOLDER", """
    <script>alert("Authentication Failed: Partner OAuth server unreachable. IP address logged.");</script>
    """)

# STAGE 3: Template Injection in Webhook Feature
@app.route('/api/v2/webhooks/test', methods=['POST'])
def webhook_test():
    secret = request.form.get('auth_secret', '')
    payload = request.form.get('template_payload', '')

    REAL_SECRET = "Ov3rl0rd_S3cr3t_Diag_T0k3n_2026!"
    if secret != REAL_SECRET:
        return jsonify({"status": "UNAUTHORIZED", "message": "Invalid Webhook Secret Key provided."}), 403

    if "'" in payload or '"' in payload:
        return jsonify({"status": "SECURITY_BLOCK", "reason": "Quotes (' or \") forbidden in dynamic template strings."}), 400

    template = f"""
    <div style="font-family:sans-serif; background:#020617; color:#38bdf8; padding:15px; border-radius:6px; border:1px solid #38bdf8;">
        <h4>Webhook Test Trigger Output:</h4>
        <div>{payload}</div>
    </div>
    """

    # Isolated Jinja rendering only on user-supplied template string
    rendered_output = render_template_string(template)
    return MAIN_UI.replace("RESULTS_PLACEHOLDER", rendered_output)

if __name__ == '__main__':
    # Force output flushing so logs appear instantly
    app.run(host='0.0.0.0', port=8080, debug=True)