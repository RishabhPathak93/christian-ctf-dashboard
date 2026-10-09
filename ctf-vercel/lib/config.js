// Server-side only. Flags never reach the client — they are compared here.
export const FLAGS = {
  "FLAG1{sqli_extracted_corporate_vault_data}":      { name: "Stage 1 — SQL Injection",                 points: 100 },
  "FLAG2{cve_2021_43798_telemetry_config_leaked}":   { name: "Stage 2 — Grafana LFI (CVE-2021-43798)",  points: 200 },
  "FLAG3{enterprise_rce_via_template_webhook_2026}": { name: "Stage 3 — SSTI → RCE",                points: 300 },
};

export const TOTAL_POINTS  = Object.values(FLAGS).reduce((a, f) => a + f.points, 0);
export const ONLINE_WINDOW = 120; // seconds; "online" = active within this window

// Secrets come from environment variables (set these in the Vercel dashboard).
export const ADMIN_PASSWORD = process.env.CTF_ADMIN_PASSWORD || "change-me-admin-2026";
export const SECRET_KEY     = process.env.CTF_SECRET_KEY     || "dev-insecure-change-me";
