"""`sovereignctl audit run` (ANC-0254, ANC-0307, ANC-0398; T-016, T-030) [H42].

Il security audit (32 controlli): solo letture, non invasivo, senza cronologie. Ogni controllo ha un ID stabile, la severita' del
requisito che verifica (P0, P1, P2), lo stato PASS | WARN | FAIL | SKIPPED, un'evidenza non sensibile (mai chiavi,
nomi, indirizzi o query dei peer: conteggi e nomi di file), il rimedio e il timestamp. SKIPPED non vale PASS e porta
il suo motivo (una feature opzionale spenta, il DNS non applicato su questo host). I controlli di `status` entrano col
loro ID; gli altri guardano permessi, configurazione, regole chiave della tabella viva, porte, scadenze, registro,
export, backup, immagini, opzionali, porte Docker, file di Unbound e Pi-hole.
Codici: 0 nessun FAIL; 1 almeno un FAIL fuori da P0; 3 almeno un FAIL P0 (ANC-0307). Stesso stato, stesso esito.
"""
import ipaddress, json, os, sqlite3, stat, sys

from . import VERSIONE, backup, bootstrap, dns, peer, preflight, profilo, registro, runtime, stato
from .configurazione import OPZIONALI

ETC, VAR = "/etc/sovereignvpn", "/var/lib/sovereignvpn"
STATI = ("PASS", "WARN", "FAIL", "SKIPPED")
DA_STATUS = {  # nome del controllo di status -> (ID, severita', requisito, rimedio)
    "release": ("AUD-01", "P1", "FR-OPS-004", "sovereignctl init --apply"),
    "chiave del server": ("AUD-02", "P0", "NFR-SEC-004", "chmod 0600 /etc/sovereignvpn/wg-server.key; se esposta, nuova chiave e profili"),
    "wg0": ("AUD-03", "P0", "FR-WG-001", "sovereignctl reconcile --config /etc/sovereignvpn/server.toml"),
    "peer": ("AUD-04", "P0", "FR-PEER-004", "sovereignctl reconcile --config /etc/sovereignvpn/server.toml"),
    "firewall": ("AUD-05", "P0", "FR-NET-001", "sovereignctl firewall apply --config /etc/sovereignvpn/server.toml"),
    "sysctl": ("AUD-06", "P0", "FR-NET-006", "sovereignctl host apply"),
    "avvio": ("AUD-07", "P1", "FR-NET-007", "systemctl enable sovereignvpn-reconcile.service sovereignvpn-expire.timer"),
    "unbound": ("AUD-08", "P1", "FR-DNS-003", "systemctl restart sovereignvpn-unbound.service"),
    "pihole": ("AUD-09", "P1", "FR-DNS-001", "systemctl restart sovereignvpn-pihole.service"),
    "porte": ("AUD-10", "P0", "FR-NET-004", "fermare il servizio che ascolta fuori inventario; rifare sovereignctl dns apply"),
}
REGOLE_CHIAVE = (  # ID, severita', requisito, testo nella tabella viva (`nft list`), che cosa garantisce
    ("AUD-13", "P0", "T-013", 'iifname "wg0" reject with icmpv6 admin-prohibited', "IPv6 dei peer rifiutato in modo esplicito [H38]"),
    ("AUD-14", "P0", "FR-NET-002", 'iifname "wg0" oifname "wg0" drop', "peer isolati fra loro"),
    ("AUD-15", "P0", "FR-DNS-005", 'iifname "wg0" meta l4proto { tcp, udp } th dport 53 drop', "DNS esterno dei peer bloccato"),
)


def _modo(p):
    return stat.S_IMODE(os.stat(p).st_mode)


def _permessi():
    """Cartelle 0700 e nessun file leggibile da altri (il manifest e' pubblico per scelta, 0644)."""
    male, esaminati = [], 0
    for d in (ETC, VAR):
        if not os.path.isdir(d):
            continue
        if _modo(d) & 0o077:
            male.append(f"{d} {oct(_modo(d))}")
        for radice, _, file in os.walk(d):
            for f in file:
                esaminati += 1
                p = os.path.join(radice, f)
                if os.path.basename(p) != "manifest.json" and not os.path.islink(p) and _modo(p) & 0o077:
                    male.append(f"{os.path.relpath(p, '/')} {oct(_modo(p))}")
    if not os.path.isdir(ETC) and not os.path.isdir(VAR):
        return "SKIPPED", "prodotto non installato su questo host", "sudo ops/install.sh"
    if male:
        return "FAIL", f"{len(male)} su {esaminati} file o cartelle leggibili da altri: " + ", ".join(sorted(male)[:5]), "chmod 0700 alle cartelle e 0600 ai file"
    return "PASS", f"{esaminati} file esaminati, cartelle 0700, nessun file leggibile da altri", ""


def _sorgenti_ssh(cfg):
    larghe = [s for s in cfg.get("admin_ssh_sources", []) if ipaddress.ip_network(s).prefixlen == 0]
    if larghe:
        return "WARN", f"SSH ammesso da {', '.join(larghe)}: tutta internet", "restringere admin_ssh_sources alle reti dell'amministratore (ANC-0182)"
    return "PASS", f"{len(cfg.get('admin_ssh_sources', []))} sorgenti SSH dichiarate, nessuna /0", ""


def _registro_e_scadenze(db):
    """(controllo del registro, controllo delle scadenze): leggibile, schema giusto, nessun peer scaduto ancora attivo."""
    if not os.path.exists(db):
        n = ("SKIPPED", "registro dei peer assente: nessun peer ancora", "")
        return n, n
    try:
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        try:
            controllo = con.execute("PRAGMA quick_check").fetchone()[0]
            versione = con.execute("SELECT versione FROM schema").fetchone()[0]
            scaduti = con.execute("SELECT count(*) FROM peer WHERE scade IS NOT NULL AND scade < ? AND stato IN ('PENDING','ACTIVE','SUSPENDED')",
                                  (peer.ora(),)).fetchone()[0]
        finally:
            con.close()
    except sqlite3.Error as e:
        guasto = ("FAIL", f"registro illeggibile ({type(e).__name__})", "sovereignctl backup restore <file> --identity <chiave> --conferma (T-026)")
        return guasto, ("SKIPPED", "registro illeggibile: scadenze non verificabili", "")
    if controllo != "ok":
        reg = ("FAIL", f"PRAGMA quick_check: {controllo[:80]}", "sovereignctl backup restore <file> --identity <chiave> --conferma (T-026)")
    elif versione != peer.VERSIONE_SCHEMA_DB:
        reg = ("WARN", f"schema {versione}, il codice conosce il {peer.VERSIONE_SCHEMA_DB}", "un comando peer qualunque migra il registro (H31)")
    else:
        reg = ("PASS", f"quick_check ok, schema {versione}", "")
    sca = ("FAIL", f"{scaduti} peer col TTL passato ancora attivi", "sovereignctl peer expire-sweep, poi reconcile") if scaduti \
        else ("PASS", "nessun peer scaduto ancora attivo", "")
    return reg, sca


def _export():
    d = profilo.CARTELLA
    if not os.path.isdir(d):
        return "SKIPPED", "nessun profilo esportato", ""
    aperti = [f for f in os.listdir(d) if _modo(os.path.join(d, f)) & 0o077]
    if _modo(d) & 0o077 or aperti:
        return "FAIL", f"cartella {oct(_modo(d))}, {len(aperti)} profili leggibili da altri", f"chmod 0700 {d}; chmod 0600 ai profili"
    return "PASS", f"cartella 0700, {len(os.listdir(d))} profili 0600", ""


def _backup(cfg):
    if not cfg.get("backup_recipient"):
        return "WARN", "nessun backup_recipient nella configurazione", "dichiarare la chiave pubblica age in backup_recipient (H20)"
    n = len([f for f in os.listdir(backup.CARTELLA) if f.endswith(".age")]) if os.path.isdir(backup.CARTELLA) else 0
    if n == 0:
        return "WARN", "destinatario dichiarato, nessun backup ancora", "sovereignctl backup create"
    return "PASS", f"{n} backup cifrati in {backup.CARTELLA}", ""


def _immagini():
    try:
        with open(bootstrap.MANIFEST, encoding="utf-8") as f:
            imm = json.load(f).get("immagini", [])
    except (OSError, ValueError):
        return "SKIPPED", "manifest assente: init --apply non eseguito", "sovereignctl init --apply"
    senza = [i.get("nome", "?") for i in imm if not str(i.get("digest", "")).startswith("sha256:")]
    if senza or not imm:
        return "FAIL", f"{len(senza)} immagini su {len(imm)} senza digest", "reinstallare la release (FR-OPS-004)"
    return "PASS", f"{len(imm)} immagini pin-nate per digest", ""


def _ascolti_amministrazione(cfg, server):
    """ADR-006 [H37]: sulla porta di amministrazione nessun ascolto fuori da loopback e VPN."""
    codice, uscita = stato._leggi("ss", "-H", "-lnt")
    if codice != 0:
        return "FAIL", "ss non risponde: gli ascolti non si possono verificare", "installare iproute2"
    porta, fuori = int(cfg.get("admin_port", 8443)), []
    for riga in uscita.splitlines():
        campi = riga.split()
        if len(campi) >= 4:
            indirizzo, _, p = campi[3].rpartition(":")
            if p.isdigit() and int(p) == porta and indirizzo.strip("[]").split("%")[0] not in ("127.0.0.1", "::1", server):
                fuori.append(campi[3])
    if fuori:
        return "FAIL", f"in ascolto sulla porta di amministrazione fuori da loopback e VPN: {', '.join(sorted(fuori))}", "chiudere il servizio o legarlo a 127.0.0.1 (ADR-006)"
    return "PASS", f"porta {porta}: nessun ascolto fuori da loopback e VPN", ""


def _ula(cfg, server, wg_if):
    atteso = str(runtime.indirizzo6(cfg["subnet6"], server))
    codice, uscita = stato._leggi("ip", "-j", "addr", "show", "dev", wg_if)
    trovati = [a.get("local") for i in (json.loads(uscita) if codice == 0 and uscita else []) for a in i.get("addr_info", []) if a.get("family") == "inet6"]
    if atteso in trovati:
        return "PASS", f"{wg_if} ha l'IPv6 ULA del server", ""
    return "FAIL", f"{wg_if} senza l'IPv6 ULA del server: l'IPv6 dei peer cadrebbe in silenzio", "sovereignctl reconcile --config /etc/sovereignvpn/server.toml"


def _porte_docker():
    codice, uscita = stato._leggi("docker", "ps", "--format", "{{.Names}}\t{{.Ports}}")
    if codice != 0:
        return "SKIPPED", "Docker assente o non raggiungibile", ""
    pubblicate = [r.split("\t")[0] for r in uscita.splitlines() if r.startswith("sovereignvpn-") and "->" in r]
    if pubblicate:
        return "FAIL", f"container della release con porte pubblicate: {', '.join(pubblicate)}", "i container della release usano la rete host senza -p (H36)"
    return "PASS", "nessun container della release pubblica porte", ""


def _file_dns(nome, vietati, voluti):
    p = os.path.join(dns.CARTELLA_DNS, nome)
    if not os.path.exists(p):
        return "SKIPPED", "DNS interno non applicato su questo host", ""
    with open(p, encoding="utf-8") as f:
        testo = f.read()
    male = [v for v in vietati if v in testo] + [v for v in voluti if v not in testo]
    if male:
        return "FAIL", f"{nome}: {', '.join(male)}", "sovereignctl dns apply (rigenera il file)"
    return "PASS", f"{nome}: nessuna traccia delle query", ""


def vincoli_mancanti(nome, attesi):
    """[H44] Che cosa manca al container acceso rispetto ai vincoli dichiarati (o che cosa ha in piu': una capability
    aggiunta non dichiarata). None se il container non c'e'."""
    codice, uscita = stato._leggi("docker", "inspect", "--format", "{{json .HostConfig}}", nome)
    if codice != 0 or not uscita.strip():
        return None
    hc = json.loads(uscita)
    cap = lambda xs: {str(x).upper().removeprefix("CAP_") for x in (xs or [])}
    voluti = {"cap-drop": set(), "cap-add": set(), "security-opt": set(), "tmpfs": set()}
    for i, x in enumerate(attesi):
        if x.startswith("--") and x[2:] in voluti:
            voluti[x[2:]].add(attesi[i + 1])
    mancano = (["read-only"] if "--read-only" in attesi and not hc.get("ReadonlyRootfs") else [])
    mancano += [f"cap-drop {c}" for c in sorted(cap(voluti["cap-drop"]) - cap(hc.get("CapDrop")))]
    mancano += [f"cap-add {c} in piu'" for c in sorted(cap(hc.get("CapAdd")) - cap(voluti["cap-add"]))]
    mancano += [f"security-opt {s}" for s in sorted(voluti["security-opt"] - set(hc.get("SecurityOpt") or []))]
    mancano += [f"tmpfs {t}" for t in sorted(voluti["tmpfs"] - set((hc.get("Tmpfs") or {}).keys()))]
    return mancano


def _vincoli():
    accesi, male = 0, []
    for nome, attesi in (("sovereignvpn-unbound", dns.VINCOLI_UNBOUND), ("sovereignvpn-pihole", dns.VINCOLI_PIHOLE)):
        m = vincoli_mancanti(nome, attesi)
        if m is not None:
            accesi += 1
            male += [f"{nome}: {x}" for x in m]
    if not accesi:
        return "SKIPPED", "nessun container del DNS acceso (o Docker assente)", ""
    if male:
        return "FAIL", f"vincoli mancanti: {', '.join(male)}", "riavviare il servizio dall'unita' installata (systemctl restart sovereignvpn-unbound)"
    return "PASS", f"{accesi} container coi vincoli dichiarati (capability minime; sola lettura e nessun nuovo privilegio dove compatibili)", ""


def esegui_controlli(cfg, db=None, wg_if=runtime.INTERFACCIA):
    """La lista dei controlli, in ordine di ID: ognuno {id, severita, requisito, nome, stato, evidenza, rimedio, timestamp}."""
    db = db or peer.DB_PREDEFINITO
    adesso, c = peer.ora(), []

    def metti(ident, sev, req, nome, esito):
        st, evidenza, rimedio = esito
        assert st in STATI, st
        c.append({"id": ident, "severita": sev, "requisito": req, "nome": nome, "stato": st,
                  "evidenza": registro.redigi(evidenza), "rimedio": rimedio, "timestamp": adesso})

    controlli, _ = stato.controlla(cfg, db, wg_if)
    visti = {x["nome"] if x["nome"] != wg_if else "wg0": x for x in controlli}
    for nome, (ident, sev, req, rimedio) in DA_STATUS.items():
        x = visti.get(nome)
        if x is None:
            metti(ident, sev, req, nome, ("SKIPPED", "DNS interno non applicato su questo host", "sovereignctl dns apply"))
        else:
            metti(ident, sev, req, nome, ("PASS", x["dettaglio"], "") if x["esito"] == "OK" else ("FAIL", x["dettaglio"], rimedio))
    server = str(next(ipaddress.ip_network(cfg.get("subnet") or "10.66.0.0/24").hosts()))
    metti("AUD-11", "P0", "NFR-SEC-004", "permessi", _permessi())
    metti("AUD-12", "P1", "ANC-0182", "sorgenti SSH", _sorgenti_ssh(cfg))
    codice, tabella = stato._leggi("nft", "list", "table", "inet", "sovereignvpn")
    for ident, sev, req, regola, garanzia in REGOLE_CHIAVE:
        metti(ident, sev, req, garanzia, ("PASS", f"regola presente: {garanzia}", "") if codice == 0 and regola in tabella
              else ("FAIL", f"regola assente nella tabella viva: {garanzia}", "sovereignctl firewall apply --config /etc/sovereignvpn/server.toml"))
    if not cfg.get("dns_block_dot", True):
        metti("AUD-16", "P1", "FR-DNS-006", "blocco DoT", ("WARN", "blocco DoT spento dalla configurazione (dns_block_dot = false)", "dns_block_dot = true (H25)"))
    else:
        metti("AUD-16", "P1", "FR-DNS-006", "blocco DoT", ("PASS", "TCP 853 dei peer verso fuori rifiutato", "") if codice == 0 and "tcp dport 853 reject" in tabella
              else ("FAIL", "regola DoT assente nella tabella viva", "sovereignctl firewall apply --config /etc/sovereignvpn/server.toml"))
    if codice != 0:
        recupero = ("SKIPPED", "tabella del firewall non leggibile: il recupero non si puo' verificare (vedi AUD-05)", "")
    elif f'iifname "{wg_if}" drop' in tabella:
        recupero = ("FAIL", "firewall in recupero: registro dei peer illeggibile, nessun traffico dei peer",
                    "sovereignctl backup restore <file> --identity <chiave> --conferma")
    else:
        recupero = ("PASS", "firewall nel modo normale", "")
    metti("AUD-17", "P0", "T-026", "firewall non in recupero", recupero)
    metti("AUD-18", "P0", "T-013", "IPv6 ULA di wg0", _ula(cfg, server, wg_if))
    metti("AUD-19", "P0", "ADR-006", "porta di amministrazione", _ascolti_amministrazione(cfg, server))
    reg, sca = _registro_e_scadenze(db)
    metti("AUD-20", "P0", "FR-PEER-005", "scadenze dei peer", sca)
    metti("AUD-21", "P0", "T-026", "registro dei peer", reg)
    metti("AUD-22", "P0", "FR-PEER-007", "profili esportati", _export())
    metti("AUD-23", "P1", "FR-OPS-001", "backup", _backup(cfg))
    metti("AUD-24", "P1", "FR-OPS-004", "immagini col digest", _immagini())
    for n, opz in enumerate(OPZIONALI):
        metti(f"AUD-{25 + n}", "P2", "ANC-0110", f"opzionale {opz}", ("SKIPPED", f"{opz}: opzionale fuori dalla 1.0 e spento (ANC-0110)", ""))
    metti("AUD-29", "P0", "FR-NET-005", "porte Docker", _porte_docker())
    metti("AUD-30", "P0", "FR-DNS-004", "log di Pi-hole", _file_dns("pihole.env", ("FTLCONF_dns_queryLogging=true",),
                                                                    ("FTLCONF_dns_queryLogging=false", "FTLCONF_database_maxDBdays=0")))
    metti("AUD-31", "P0", "FR-DNS-004", "log di Unbound", _file_dns("unbound.conf", ("forward-zone:", "log-queries: yes"), ("log-queries: no", "verbosity: 0")))
    metti("AUD-32", "P1", "NFR-SEC-003", "vincoli dei container", _vincoli())
    return sorted(c, key=lambda x: int(x["id"][4:]))


def codice_di_uscita(controlli):
    falliti = [x for x in controlli if x["stato"] == "FAIL"]
    return 3 if any(x["severita"] == "P0" for x in falliti) else (1 if falliti else 0)


def esegui(a):
    from . import configurazione
    try:
        cfg = configurazione.leggi(a.config)
    except preflight.InputNonValido as e:
        print(f"sovereignctl: input non valido: {registro.redigi(e)}", file=sys.stderr)
        return 2
    controlli = esegui_controlli(cfg, a.db)
    conta = {s: sum(1 for x in controlli if x["stato"] == s) for s in STATI}
    if a.json:
        print(json.dumps({"versione": VERSIONE, "comando": "audit run", "controlli_eseguiti": len(controlli), **conta,
                          "controlli": controlli}, ensure_ascii=False, indent=1))
    else:
        print(f"SovereignVPN {VERSIONE} — security audit: {len(controlli)} controlli; " + ", ".join(f"{conta[s]} {s}" for s in STATI))
        for x in controlli:
            print(f"  [{x['stato']:7}] {x['id']} {x['severita']} {x['nome']}: {x['evidenza']}" + (f" — rimedio: {x['rimedio']}" if x["rimedio"] else ""))
    return codice_di_uscita(controlli)
