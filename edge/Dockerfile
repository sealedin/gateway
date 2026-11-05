# The TLS edge with the measured routing table: the pinned caddy base the compose used to run raw, plus the
# Caddyfile the stock entrypoint already loads (the measured compose cannot bind-mount config).
FROM caddy@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648
COPY Caddyfile /etc/caddy/Caddyfile
