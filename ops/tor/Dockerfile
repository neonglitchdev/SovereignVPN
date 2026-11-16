# SovereignVPN — immagine di Tor come uscita [H52, in costruzione]. Stessa base pin-nata per digest di Unbound (ANC-0319:
# mai tag mobili), solo il pacchetto Debian: niente immagini di terzi. Il torrc lo genera `sovereignctl` (tor.torrc) e si
# monta in sola lettura; Tor gira come utente debian-tor, mai root. tor-geoipdb serve a ExitNodes {xx}: senza, Tor non sa in
# che paese sta un relay e resta fermo al 50% (misurato il 16/11 nella VM: «Failed to open GEOIP file»).
FROM debian:12-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
RUN apt-get update \
 && apt-get install -y --no-install-recommends tor tor-geoipdb \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/tor && chown debian-tor:debian-tor /run/tor && chmod 0700 /run/tor
USER debian-tor
CMD ["tor", "-f", "/etc/tor/torrc"]
