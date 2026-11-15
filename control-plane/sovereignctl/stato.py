"""`sovereignctl status` (ANC-0254, NFR-AVL-002): release e salute del server, solo letture e sanitizzato.

Un processo vivo non basta, si guarda che il servizio funzioni davvero: wg0 accesa, in ascolto sulla porta della
configurazione e con la chiave del file; i peer nel runtime uguali al registro; la tabella del firewall con le policy
drop e tutte le regole dichiarate; i sysctl; le unita' systemd abilitate. Mai la chiave privata del server o una PSK
(cap. 8), mai nomi, chiavi o indirizzi dei peer: solo conteggi. Il registro si apre in sola lettura.
Ogni controllo e' OK o GUASTO; cio' che la release non ha ancora (il DNS interno) si elenca a parte e non conta.
Codici (ANC-0255): 0 tutto OK; 1 almeno un GUASTO; 3 se la chiave del server e' leggibile da altri (security gate).
"""
import ipaddress, json, os, pathlib, socket, sqlite3, subprocess, sys

from . import VERSIONE, bootstrap, dns, firewall, host, peer, preflight, registro, runtime

UNITA = ("sovereignvpn-reconcile.service", "sovereignvpn-expire.timer")


def dns_applicato():
    return os.path.exists(os.path.join(dns.CARTELLA_DNS, "unbound.conf"))


def non_applicati():
    """Cio' che su questo host non e' ancora stato messo in opera: si elenca e non conta ne' come OK ne' come GUASTO."""
    return [] if dns_applicato() else ["DNS interno (Unbound + Pi-hole): `sovereignctl dns apply` non eseguito qui"]


def inventario(server, server6):
    """FR-NET-004 [H26]: le porte dei container del DNS, dichiarate. Sono in rete host e non pubblicano porte: si
    verifica chi ascolta, e dove. Unbound solo su 127.0.0.1:5335; Pi-hole solo sull'indirizzo del server in VPN, porta
    53, il loopback sulla 53 (BIND lo apre sempre, dalla rete non si raggiunge) e il pannello su 127.0.0.1:8081 (ADR-006).
    [H38] BIND apre la 53 anche sull'ULA del server, che sta su wg0: irraggiungibile, perche' tutto l'IPv6 da wg0 lo
    rifiuta il PREROUTING e l'INPUT accetta il DNS solo in IPv4 dalla VPN."""
    return {"unbound": {("127.0.0.1", dns.PORTA_UNBOUND)},
            "pihole-FTL": {(server, 53), (server6, 53), ("127.0.0.1", 53), ("::1", 53), ("127.0.0.1", 8081)}}  # loopback: mai dalla rete


def porte_fuori_inventario(server, server6):
    """Gli ascolti di unbound e pihole-FTL che l'inventario non dichiara, da `ss -H -lntup`: «processo indirizzo:porta»."""
    codice, uscita = _leggi("ss", "-H", "-lntup")
    if codice != 0:
        raise RuntimeError("ss non risponde: le porte in ascolto non si possono verificare")
    ammessi, fuori = inventario(server, server6), []
    for riga in uscita.splitlines():
        campi = riga.split()
        if len(campi) < 7 or "users:((" not in riga:
            continue
        locale, processo = campi[4], riga.split('users:(("', 1)[1].split('"', 1)[0]
        indirizzo, _, porta = locale.rpartition(":")
        indirizzo = indirizzo.strip("[]").split("%", 1)[0]
        if processo in ammessi and (indirizzo, int(porta)) not in ammessi[processo]:
            fuori.append(f"{processo} {locale}")
    return sorted(set(fuori))


def _dns_risponde(indirizzo, porta, attesa=2):
    """Una domanda vera («.» NS, ricorsiva), in libreria standard: vale se torna una risposta con lo stesso id e rcode 0."""
    ident = os.urandom(2)
    domanda = ident + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"\x00\x00\x02\x00\x01"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(attesa)
    try:
        s.sendto(domanda, (indirizzo, porta))
        r, _ = s.recvfrom(4096)
    except OSError:
        return False
    finally:
        s.close()
    return len(r) >= 12 and r[:2] == ident and bool(r[2] & 0x80) and (r[3] & 0x0F) == 0


def _leggi(*argomenti, ingresso=None):
    try:
        p = subprocess.run(list(argomenti), input=ingresso, capture_output=True, text=True, timeout=15,
                           env={"PATH": os.environ.get("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"), "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired):
        return 127, ""
    return p.returncode, p.stdout


def _registro(db):
    """Righe (chiave_pubblica, indirizzo, stato), in sola lettura: lo status non crea ne' blocca il registro."""
    if not os.path.exists(db):
        raise RuntimeError(f"registro dei peer assente in {db}")
    con = sqlite3.connect(pathlib.Path(db).resolve().as_uri() + "?mode=ro", uri=True)
    try:
        return con.execute("SELECT chiave_pubblica, indirizzo, stato FROM peer").fetchall()
    finally:
        con.close()


def controlla(cfg, db=None, wg_if=runtime.INTERFACCIA):
    """Restituisce (controlli, chiave_esposta). Ogni controllo: {nome, esito OK|GUASTO, dettaglio}."""
    db = db or peer.DB_PREDEFINITO
    c, esposta = [], False

    def esito(nome, ok, dettaglio):
        c.append({"nome": nome, "esito": "OK" if ok else "GUASTO", "dettaglio": dettaglio})

    try:
        with open(bootstrap.MANIFEST, encoding="utf-8") as f:
            m = json.load(f)
        esito("release", m.get("sovereignvpn") == VERSIONE,
              f"installata {m.get('sovereignvpn')}, control plane {VERSIONE}, installazione {m.get('id_installazione')}")
    except (OSError, ValueError):
        esito("release", False, f"manifest assente o illeggibile in {bootstrap.MANIFEST}: init --apply non eseguito")

    chiave = None
    try:
        chiave = runtime.leggi_chiave_server(runtime.CHIAVE_SERVER)
        esito("chiave del server", True, f"{runtime.CHIAVE_SERVER}, 0600 (il contenuto non si mostra)")
    except runtime.ChiaveEsposta as e:
        esposta = True
        esito("chiave del server", False, registro.redigi(e))
    except RuntimeError as e:
        esito("chiave del server", False, registro.redigi(e))

    porta = str(cfg.get("wg_port", 51820))
    codice, link = _leggi("ip", "-j", "link", "show", wg_if)
    accesa = codice == 0 and "UP" in (json.loads(link or "[{}]")[0].get("flags") or [])
    ascolto = _leggi("wg", "show", wg_if, "listen-port")[1].strip()
    pubblica = _leggi("wg", "show", wg_if, "public-key")[1].strip()
    attesa = _leggi("wg", "pubkey", ingresso=chiave)[1].strip() if chiave else None
    if not accesa:
        esito(wg_if, False, f"{wg_if} assente o spenta: la rifa' `sovereignctl reconcile`")
    elif ascolto != porta:
        esito(wg_if, False, f"{wg_if} in ascolto su {ascolto or 'nessuna porta'}, la configurazione dice {porta}")
    elif not attesa or pubblica != attesa:
        esito(wg_if, False, f"{wg_if} non usa la chiave di {runtime.CHIAVE_SERVER}")
    else:
        esito(wg_if, True, f"{wg_if} accesa, in ascolto su {porta}, con la chiave del file")

    try:
        attesi = runtime.nel_runtime(_registro(db), cfg["subnet6"])
        vivi = runtime.leggi_runtime(wg_if)
        diverse = len(set(vivi.items()) ^ set(attesi.items()))
        esito("peer", diverse == 0, f"{len(vivi)} nel runtime, {len(attesi)} attesi dal registro, differenze {diverse}")
    except (RuntimeError, sqlite3.Error) as e:
        esito("peer", False, registro.redigi(e))

    try:
        t = firewall.leggi()
        dichiarate = None
        if cfg.get("wan_interface") and cfg.get("admin_ssh_sources"):
            dichiarate = firewall.regole_dichiarate(firewall.componi(
                cfg.get("subnet") or "10.66.0.0/24", wg_if, cfg.get("wg_port", 51820), cfg["wan_interface"],
                cfg.get("admin_port", 8443), cfg.get("ssh_port", 22), cfg["admin_ssh_sources"], cfg.get("mtu", 1420), cfg.get("dns_block_dot", True),
                peer.limiti_rotte(db), peer.dns_liberi(db), peer.quote(db, firewall.quote_usate)))
        ok = t["verificato"] and dichiarate in (None, t["regole"])
        esito("firewall", ok, f"tabella {t['tabella']}, policy " + " ".join(f"{k}={v}" for k, v in t["catene"].items())
              + f", {t['regole']} regole" + ("" if dichiarate is None else f" su {dichiarate} dichiarate"))
    except (RuntimeError, ValueError, KeyError, sqlite3.Error, OSError) as e:  # [H41] registro illeggibile o nft assente: GUASTO, non un crash
        esito("firewall", False, registro.redigi(e))

    letti = host.leggi()
    diversi = sorted(k for k, v in host.VALORI.items() if letti.get(k) != v)
    esito("sysctl", not diversi, "ip_forward 1, inoltro IPv6 0" if not diversi else "diversi dal dichiarato: " + ", ".join(diversi))

    codice, uscita = _leggi("systemctl", "is-enabled", *UNITA)
    stati = uscita.split()
    ok = codice == 0 and stati == ["enabled"] * len(UNITA)
    esito("avvio", ok, ", ".join(f"{u} {s}" for u, s in zip(UNITA, stati)) if stati else
          "systemd non risponde: niente ripristino al riavvio ne' scadenze")
    if dns_applicato():  # NFR-AVL-002: il servizio che risponde, non il container acceso
        esito("unbound", _dns_risponde("127.0.0.1", dns.PORTA_UNBOUND), f"127.0.0.1:{dns.PORTA_UNBOUND}, ricorsivo con DNSSEC")
        server = str(next(ipaddress.ip_network(cfg.get("subnet") or "10.66.0.0/24").hosts()))
        esito("pihole", _dns_risponde(server, 53), f"{server}:53 su {wg_if}, il resolver dei profili")
        try:
            fuori = porte_fuori_inventario(server, str(runtime.indirizzo6(cfg["subnet6"], server)))
            esito("porte", not fuori, "unbound e pihole-FTL ascoltano solo dove dichiarato" if not fuori
                  else "in ascolto fuori dall'inventario: " + ", ".join(fuori))
        except RuntimeError as e:
            esito("porte", False, registro.redigi(e))
    return c, esposta


def esegui(a):
    from . import configurazione
    try:
        cfg = configurazione.leggi(a.config)
    except preflight.InputNonValido as e:
        print(f"sovereignctl: input non valido: {registro.redigi(e)}", file=sys.stderr)
        return 2
    controlli, esposta = controlla(cfg, a.db)
    superati = sum(1 for x in controlli if x["esito"] == "OK")
    r = {"versione": VERSIONE, "comando": "status", "controlli_eseguiti": len(controlli), "superati": superati,
         "controlli": controlli, "non_consegnati": non_applicati()}
    if a.json:
        print(json.dumps(r, ensure_ascii=False, indent=1))
    else:
        print(f"SovereignVPN {VERSIONE} — status: {superati} controlli superati su {len(controlli)}")
        for x in controlli:
            print(f"  [{x['esito']:6}] {x['nome']}: {x['dettaglio']}")
        for n in r["non_consegnati"]:
            print(f"  [ASSENTE] {n}")
    if esposta:
        return 3
    return 0 if superati == len(controlli) else 1
