# SovereignVPN — immagine di Unbound (FR-DNS-003) [H22]. Base pin-nata per digest (ANC-0319: mai tag mobili), solo il
# pacchetto Debian: niente immagini di terzi. La configurazione la genera `sovereignctl dns plan` e si monta in sola
# lettura su /etc/unbound/unbound.conf.
FROM debian:12-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
RUN apt-get update \
 && apt-get install -y --no-install-recommends unbound dns-root-data \
 && rm -rf /var/lib/apt/lists/*
CMD ["unbound", "-d", "-c", "/etc/unbound/unbound.conf"]
