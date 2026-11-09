# The TLS edge with the measured routing table: the pinned caddy base the compose used to run raw, plus the
# Caddyfile the stock entrypoint already loads (the measured compose cannot bind-mount config).
FROM caddy@sha256:0c2243efcf437ab7f7a978f1027fcf0d4f9be8a75df27b1b3fbc5dbe0ffa8cf0
COPY Caddyfile /etc/caddy/Caddyfile
