# Minimal DHCP-only dnsmasq for the panel's managed private networks.
# DNS is disabled (port=0) — AdGuard Home owns :53. Per-network configs are written by the
# panel into /etc/dnsmasq.d (a shared volume) and the panel restarts this container to reload.
FROM alpine:3.24

RUN apk add --no-cache dnsmasq

COPY dnsmasq.base.conf /etc/dnsmasq.base.conf

# --keep-in-foreground so Docker supervises it; log to stderr. The base config disables DNS and
# includes /etc/dnsmasq.d/*.conf. With no networks configured yet it idles harmlessly.
ENTRYPOINT ["dnsmasq", "--keep-in-foreground", "--log-facility=-", "--conf-file=/etc/dnsmasq.base.conf"]
