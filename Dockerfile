FROM python:3.10-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    curl \
    sqlite3 \
    supervisor \
    ca-certificates \
    libfontconfig1 \
    ucf \
    && rm -rf /var/lib/apt/lists/*

# Download & Install Grafana 8.0.0 (Vulnerable Telemetry Backend)
RUN wget --no-check-certificate https://dl.grafana.com/oss/release/grafana_8.0.0_amd64.deb \
    && dpkg -i grafana_8.0.0_amd64.deb || apt-get install -f -y \
    && rm grafana_8.0.0_amd64.deb

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Setup System Artifacts & Company Files
RUN mkdir -p /etc/app_config /var/backups

# Decoy Credentials
RUN echo "admin:$2a$12$e8392d81029af38d1aFAKEHASHDO_NOT_CRACK" > /var/backups/shadow_passwords.bak

# Flag 2 Location (Target of CVE-2021-43798)
RUN echo "FLAG2{cve_2021_43798_telemetry_config_leaked}" > /etc/app_config/secret.env
RUN echo "WEBHOOK_DIAG_SECRET=Ov3rl0rd_S3cr3t_Diag_T0k3n_2026!" >> /etc/app_config/secret.env

# Flag 3 Location
RUN echo "FLAG3{enterprise_rce_via_template_webhook_2026}" > /root/flag3.txt && chmod 400 /root/flag3.txt

EXPOSE 8080 3000

CMD ["/usr/bin/supervisord"]