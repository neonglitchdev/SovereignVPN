"""Uscite per paese (FR-NET-008, richiesta di Francesco del 15/11) [H48].

Un'uscita e' un file WireGuard del provider scelto (o di un VPS) con il suo paese (ISO 3166-1 alpha-2, da cui la
bandierina dell'app). Si accettano solo i campi WireGuard che servono a un'uscita; gli script (PreUp, PostUp, PreDown,
PostDown) si RIFIUTANO: un file di terzi eseguirebbe comandi come root sul server. L'Endpoint deve essere un IPv4
letterale: al riavvio la rete non c'e' ancora e la scelta del paese non deve passare da un DNS. Il pool sta in
/var/lib/sovereignvpn/uscite (0700), un file 0600 per uscita; la chiave privata dell'uscita resta li', mai a schermo.

Instradamento (FR-NET-008: tabella dedicata, mark riservato, regole di ritorno, nessun ripiego sulla WAN):
- il traffico che entra da wg0 cerca la rotta nella tabella TABELLA_ROTTE: default su wgx0, la subnet VPN di ritorno su
  wg0 e un «unreachable default» che resta quando wgx0 cade, cosi' la ricerca non scivola mai nella tabella main;
- i pacchetti cifrati di wgx0 portano il mark MARK e cercano sempre nella main: escono dalla WAN verso il provider;
- kill switch in nftables, tabella sua (un drop in qualunque tabella e' definitivo): da wg0 si inoltra solo verso
  wgx0. Si applica per primo e resta finche' l'uscita e' scelta, anche con wgx0 giu'.
La tabella principale accetta e maschera sempre anche wgx0 (firewall.componi): senza uscita wgx0 non esiste.
Rotazione: statica (0) o ogni N minuti fra le uscite dello stesso paese; failover: se l'uscita non fa handshake da
HANDSHAKE_MASSIMO secondi si passa alla successiva dello stesso paese. Lo fa `exit tick`, dal timer ogni minuto.
Il DNS dei peer resta Pi-hole e Unbound sul server: i nomi si risolvono dall'IP del server, i siti vedono l'uscita.
"""
import contextlib, fcntl, ipaddress, json, os, re, subprocess, sys, time

from . import firewall, peer, profilo, registro
from .preflight import InputNonValido

CARTELLA = "/var/lib/sovereignvpn/uscite"
INTERFACCIA = firewall.INTERFACCIA_USCITA
TABELLA_ROTTE = 51888
MARK = 0x5E48
PRIO_MARK, PRIO_PEER = 5198, 5199
TABELLA_NFT = "sovereignvpn_uscita"
HANDSHAKE_MASSIMO = 180  # con PersistentKeepalive 25 un'uscita viva rifa' l'handshake ogni 2 minuti
KEEPALIVE = 25
ROTAZIONE_MASSIMA = 1440
PAESE = re.compile(r"^[A-Z]{2}$")
NOME = re.compile(r"^[\w .()-]{1,40}$")
AMMESSI = {"Interface": {"PrivateKey", "Address", "DNS", "MTU"},
           "Peer": {"PublicKey", "PresharedKey", "Endpoint", "AllowedIPs", "PersistentKeepalive"}}
VIETATI = {"PreUp", "PostUp", "PreDown", "PostDown", "SaveConfig", "Table", "FwMark"}


class UscitaNonValida(ValueError):
    """Un file d'uscita o una scelta rifiutati, col motivo (il valore di una chiave non si ripete mai)."""


def bandierina(paese):
    """«IT» -> la bandierina emoji (due simboli regionali): la mostra l'app accanto al nome del paese."""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in paese)


def _analizza(testo):
    """Il file WireGuard -> {sezione: {campo: valore}}, rifiutando script, campi estranei e sezioni in piu'."""
    sezione, campi = None, {"Interface": {}, "Peer": {}}
    for n, riga in enumerate(testo.splitlines(), 1):
        riga = riga.split("#", 1)[0].strip()
        if not riga:
            continue
        if riga.startswith("[") and riga.endswith("]"):
            sezione = riga[1:-1]
            if sezione not in campi or (sezione == "Peer" and campi["Peer"]):
                raise UscitaNonValida(f"riga {n}: sezione «{sezione}» non ammessa (un'Interface e un solo Peer)")
            continue
        chiave = riga.split("=", 1)[0].strip()
        if chiave in VIETATI:
            raise UscitaNonValida(f"riga {n}: «{chiave}» rifiutato: un'uscita non esegue comandi ne' cambia tabelle sul server")
        if sezione is None or chiave not in AMMESSI[sezione] or "=" not in riga:
            raise UscitaNonValida(f"riga {n}: campo «{chiave}» non ammesso in [{sezione}]")
        campi[sezione][chiave] = riga.split("=", 1)[1].strip()
    return campi


def _ipv4(campi):
    return [str(ipaddress.ip_interface(a.strip())) for a in campi["Interface"]["Address"].split(",")
            if ipaddress.ip_interface(a.strip()).version == 4]


def leggi(testo, paese):
    """Il file WireGuard di un'uscita -> {paese, bandierina, endpoint, indirizzi, chiave_pubblica}. Solleva UscitaNonValida."""
    if not PAESE.match(paese or ""):
        raise UscitaNonValida("paese: codice ISO di due lettere maiuscole (IT, DE, JP...)")
    campi = _analizza(testo)
    for s, k in (("Interface", "PrivateKey"), ("Interface", "Address"), ("Peer", "PublicKey"), ("Peer", "Endpoint")):
        if k not in campi[s]:
            raise UscitaNonValida(f"manca {k} in [{s}]")
    for s, k in (("Interface", "PrivateKey"), ("Peer", "PublicKey")):  # una chiave sbagliata cadrebbe solo all'accensione
        try:
            peer.valida_chiave(campi[s][k])
        except InputNonValido:
            raise UscitaNonValida(f"{k} in [{s}] non e' una chiave WireGuard (32 byte in base64)" + (
                ": e' ancora il segnaposto del profilo" if campi[s][k] == profilo.SEGNAPOSTO else ""))
    if "0.0.0.0/0" not in [x.strip() for x in campi["Peer"].get("AllowedIPs", "").split(",")]:
        raise UscitaNonValida("AllowedIPs del Peer deve contenere 0.0.0.0/0: e' l'uscita di tutto il traffico dei peer")
    host, _, porta = campi["Peer"]["Endpoint"].rpartition(":")
    try:
        if ipaddress.ip_address(host).version != 4 or not 1 <= int(porta) <= 65535:
            raise ValueError
    except ValueError:
        raise UscitaNonValida("Endpoint: un IPv4 letterale con la porta (al riavvio non c'e' DNS, e la scelta del paese non passa da un DNS)")
    try:
        indirizzi = _ipv4(campi)
        if "MTU" in campi["Interface"] and not 1280 <= int(campi["Interface"]["MTU"]) <= 1500:
            raise ValueError
    except ValueError:
        raise UscitaNonValida("Address o MTU non validi (MTU da 1280 a 1500)")
    if not indirizzi:
        raise UscitaNonValida("Address: serve un indirizzo IPv4 del tunnel d'uscita (l'IPv6 dei peer e' bloccato nella 1.0)")
    return {"paese": paese, "bandierina": bandierina(paese), "endpoint": campi["Peer"]["Endpoint"],
            "indirizzi": indirizzi, "chiave_pubblica": campi["Peer"]["PublicKey"]}


# --- pool e stato su disco ------------------------------------------------------------------------------------------

def _scrivi_json(percorso, dati):
    tmp = percorso + ".nuovo"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(dati, f, ensure_ascii=False, indent=1)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, percorso)


def _leggi_json(percorso, predefinito):
    try:
        with open(percorso, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, PermissionError):  # come il manifest in status: da utente normale /var/lib/sovereignvpn
        return predefinito                          # (0700 di root) non si legge, e status non deve cadere per questo


def pool(cartella=None):
    return _leggi_json(os.path.join(cartella or CARTELLA, "pool.json"), [])


def stato(cartella=None):
    return {"scelta": None, "attiva": None, "rotazione_minuti": 0, "ultimo_cambio": 0,
            **_leggi_json(os.path.join(cartella or CARTELLA, "stato.json"), {})}


def _salva_stato(st, cartella):
    _scrivi_json(os.path.join(cartella, "stato.json"), st)


@contextlib.contextmanager
def lucchetto(cartella=None):
    """Un solo scrittore alla volta: `exit set` dalla CLI e `exit tick` dal timer leggono, cambiano e applicano lo
    stesso stato; senza lucchetto uno sovrascriverebbe la scelta dell'altro."""
    cartella = cartella or CARTELLA
    os.makedirs(cartella, mode=0o700, exist_ok=True)
    fd = os.open(os.path.join(cartella, ".lucchetto"), os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def importa(testo, paese, nome=None, cartella=None, subnet=None):
    """Aggiunge un'uscita al pool: file 0600 col testo originale, scheda pubblica in pool.json. Restituisce la scheda.

    `subnet` e' la rete dei peer di questo server: un'uscita col suo indirizzo li' dentro si rifiuta (route overlap,
    ANC-0273). Succede col profilo di un altro server SovereignVPN che usa la stessa rete [H50]."""
    cartella = cartella or CARTELLA
    testo = _con_la_chiave(testo, cartella)  # il file salvato porta la chiave vera, non il segnaposto
    u = leggi(testo, paese)
    if subnet:
        rete = ipaddress.ip_network(subnet)
        for ind in u["indirizzi"]:
            if ipaddress.ip_interface(ind).network.overlaps(rete):
                raise UscitaNonValida(f"l'indirizzo dell'uscita {ind} sta nella rete dei peer di questo server ({rete}): "
                                      "i due server usano la stessa rete. Uno dei due va installato con un'altra subnet")
    if nome is not None and not NOME.match(nome):
        raise UscitaNonValida("--nome: da 1 a 40 fra lettere, cifre, spazi e . - ( )")
    os.makedirs(cartella, mode=0o700, exist_ok=True)
    os.chmod(cartella, 0o700)
    schede = pool(cartella)
    doppia = [s["id"] for s in schede if s["chiave_pubblica"] == u["chiave_pubblica"] and s["endpoint"] == u["endpoint"]]
    if doppia:
        raise UscitaNonValida(f"uscita gia' nel pool come {doppia[0]}")
    ids, n = {s["id"] for s in schede}, 1
    while f"{paese.lower()}-{n}" in ids:
        n += 1
    ident = f"{paese.lower()}-{n}"
    fd = os.open(os.path.join(cartella, ident + ".conf"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(testo)
    scheda = {"id": ident, "nome": nome or ident, **{k: u[k] for k in ("paese", "endpoint", "indirizzi", "chiave_pubblica")}}
    _scrivi_json(os.path.join(cartella, "pool.json"), schede + [scheda])
    return {**scheda, "bandierina": u["bandierina"]}


CHIAVE_USCITA = "chiave-uscita.key"  # [H50] la privata di questo server verso le uscite federate: nasce qui, mai stampata


def chiave_uscita(cartella=None):
    """La chiave pubblica di questo server per le uscite federate; la privata si crea qui se manca (wg genkey, 0600)."""
    cartella = cartella or CARTELLA
    os.makedirs(cartella, mode=0o700, exist_ok=True)
    os.chmod(cartella, 0o700)
    percorso = os.path.join(cartella, CHIAVE_USCITA)
    if not os.path.exists(percorso):
        privata = _cmd("wg", "genkey")[1].strip()
        fd = os.open(percorso, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)  # in esclusiva: mai sopra una chiave esistente
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(privata + "\n")
    with open(percorso, encoding="ascii") as f:
        return _cmd("wg", "pubkey", ingresso=f.read().strip() + "\n")[1].strip()


def _con_la_chiave(testo, cartella):
    """Il profilo di un altro server SovereignVPN porta il segnaposto al posto della privata: ci va quella di `exit key`."""
    riga = re.compile(r"^(\s*PrivateKey\s*=\s*)" + re.escape(profilo.SEGNAPOSTO) + r"\s*$", re.M)
    if not riga.search(testo):
        return testo
    percorso = os.path.join(cartella, CHIAVE_USCITA)
    if not os.path.exists(percorso):
        raise UscitaNonValida("il profilo ha il segnaposto della chiave privata: crea la chiave di questo server con "
                              "`sovereignctl exit key` e dai la pubblica al server che ti fa da uscita")
    with open(percorso, encoding="ascii") as f:
        privata = f.read().strip()
    return riga.sub(lambda m: m.group(1) + privata, testo)


def togli(ident, cartella=None):
    cartella = cartella or CARTELLA
    schede = pool(cartella)
    if ident not in {s["id"] for s in schede}:
        raise UscitaNonValida(f"nessuna uscita «{ident}» nel pool")
    st = stato(cartella)
    if ident in (st["attiva"], st["scelta"]):
        raise UscitaNonValida(f"{ident} e' l'uscita in uso: prima `exit set` un'altra o `exit set off`")
    _scrivi_json(os.path.join(cartella, "pool.json"), [s for s in schede if s["id"] != ident])
    os.remove(os.path.join(cartella, ident + ".conf"))


def _candidate(st, schede):
    """Le uscite fra cui ruotare: quelle del paese scelto, in ordine di id; una sola se la scelta e' un'uscita."""
    if st["scelta"] and PAESE.match(st["scelta"]):
        return sorted((s["id"] for s in schede if s["paese"] == st["scelta"]), key=lambda i: (len(i), i))
    return [st["scelta"]] if st["scelta"] else []


def scegli(chi, cartella=None, adesso=None):
    """`exit set`: un paese (IT), un'uscita (it-2) o off. Restituisce lo stato nuovo, gia' salvato."""
    cartella, adesso = cartella or CARTELLA, int(adesso if adesso is not None else time.time())
    st, schede = stato(cartella), pool(cartella)
    if chi == "off":
        st.update(scelta=None, attiva=None, ultimo_cambio=adesso)
    elif PAESE.match(chi) or chi in {s["id"] for s in schede}:
        prima = st["attiva"]
        st["scelta"] = chi
        candidate = _candidate(st, schede)
        if not candidate:
            raise UscitaNonValida(f"nessuna uscita per {chi} nel pool: prima `exit import <file> --paese {chi}`")
        st["attiva"] = prima if prima in candidate else candidate[0]
        if st["attiva"] != prima:
            st["ultimo_cambio"] = adesso
    else:
        raise UscitaNonValida("exit set: un paese (IT), un'uscita del pool (it-2) o off")
    os.makedirs(cartella, mode=0o700, exist_ok=True)
    _salva_stato(st, cartella)
    return st


def imposta_rotazione(minuti, cartella=None):
    cartella = cartella or CARTELLA
    if not 0 <= minuti <= ROTAZIONE_MASSIMA:
        raise UscitaNonValida(f"rotazione: minuti da 0 (statica) a {ROTAZIONE_MASSIMA}")
    st = stato(cartella)
    st["rotazione_minuti"] = minuti
    os.makedirs(cartella, mode=0o700, exist_ok=True)
    _salva_stato(st, cartella)
    return st


def da_cambiare(st, schede, adesso, eta_handshake):
    """(uscita nuova, motivo) o (None, None). Rotazione allo scadere; failover se l'uscita non fa handshake."""
    candidate = _candidate(st, schede)
    if not st["attiva"] or len(candidate) < 2:
        return None, None
    i = candidate.index(st["attiva"]) if st["attiva"] in candidate else -1
    prossima = candidate[(i + 1) % len(candidate)]
    attiva_da = adesso - st["ultimo_cambio"]
    if st["rotazione_minuti"] and attiva_da >= st["rotazione_minuti"] * 60:
        return prossima, f"rotazione ogni {st['rotazione_minuti']} minuti"
    if attiva_da >= HANDSHAKE_MASSIMO and (eta_handshake is None or eta_handshake >= HANDSHAKE_MASSIMO):
        return prossima, "failover: " + ("nessun handshake" if eta_handshake is None else f"ultimo handshake {eta_handshake} s fa")
    return None, None


# --- l'host --------------------------------------------------------------------------------------------------------

def _cmd(*argomenti, ingresso=None, tollera=False):
    p = subprocess.run(list(argomenti), input=ingresso, capture_output=True, text=True, timeout=30,
                       env={"PATH": os.environ.get("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"), "LC_ALL": "C"})
    if p.returncode != 0 and not tollera:
        raise RuntimeError(f"{argomenti[0]} {argomenti[1] if len(argomenti) > 1 else ''} non riuscito ({registro.redigi(p.stderr.strip())[:160]})")
    return p.returncode, p.stdout


def kill_switch(wg_if="wg0"):
    """La tabella nft del kill switch: da wg0 si inoltra solo verso wgx0 (priorita' prima della tabella principale)."""
    return (f"table inet {TABELLA_NFT}\ndelete table inet {TABELLA_NFT}\ntable inet {TABELLA_NFT} {{\n"
            "  chain forward {\n    type filter hook forward priority filter - 1; policy accept;\n"
            f'    iifname "{wg_if}" oifname != "{INTERFACCIA}" drop\n  }}\n}}\n')


def conf_wg(campi):
    """Il testo per `wg setconf`: chiavi ed endpoint del provider; AllowedIPs solo IPv4, mark e keepalive nostri."""
    righe = ["[Interface]", f"PrivateKey = {campi['Interface']['PrivateKey']}", f"FwMark = {MARK:#x}",
             "[Peer]", f"PublicKey = {campi['Peer']['PublicKey']}"]
    if "PresharedKey" in campi["Peer"]:
        righe.append(f"PresharedKey = {campi['Peer']['PresharedKey']}")
    righe += [f"Endpoint = {campi['Peer']['Endpoint']}", "AllowedIPs = 0.0.0.0/0", f"PersistentKeepalive = {KEEPALIVE}"]
    return "\n".join(righe) + "\n"


def _regole(wg_if):
    """Le due regole dell'uscita con la firma completa: si tolgono solo queste, mai un'altra alla stessa priorita'."""
    return (("fwmark", f"{MARK:#x}", "lookup", "main", "priority", str(PRIO_MARK)),
            ("iif", wg_if, "lookup", str(TABELLA_ROTTE), "priority", str(PRIO_PEER)))


def _togli_regole(wg_if):
    for regola in _regole(wg_if):
        for _ in range(10):  # piu' copie della stessa regola possono esserci: si tolgono tutte
            if _cmd("ip", "rule", "del", *regola, tollera=True)[0] != 0:
                break


def spegni(wg_if="wg0"):
    """Nessuna uscita: i peer tornano a uscire dal server (scelta esplicita di chi amministra)."""
    _togli_regole(wg_if)
    _cmd("ip", "route", "flush", "table", str(TABELLA_ROTTE), tollera=True)
    _cmd("ip", "link", "del", INTERFACCIA, tollera=True)
    _cmd("nft", "delete", "table", "inet", TABELLA_NFT, tollera=True)


def applica(cfg, wg_if="wg0", cartella=None):
    """Porta l'host allo stato salvato. {attiva, salita, dettaglio}: il kill switch e le rotte DEVONO riuscire
    (altrimenti RuntimeError); se cade solo wgx0, il kill switch tiene e i peer restano senza uscita, mai sulla WAN."""
    cartella = cartella or CARTELLA
    st = stato(cartella)
    if not st["attiva"]:
        spegni(wg_if)
        return {"attiva": None, "salita": True, "dettaglio": "nessuna uscita: i peer escono dal server"}
    with open(os.path.join(cartella, st["attiva"] + ".conf"), encoding="utf-8") as f:
        campi = _analizza(f.read())
    rete = str(ipaddress.ip_network(cfg.get("subnet") or "10.66.0.0/24"))
    firewall.applica_tabella(kill_switch(wg_if))  # per primo: da qui in poi niente esce dalla WAN
    t = str(TABELLA_ROTTE)
    _cmd("ip", "route", "replace", "unreachable", "default", "metric", "4294967295", "table", t)
    _cmd("ip", "route", "replace", rete, "dev", wg_if, "table", t)  # ritorno: la subnet VPN resta su wg0
    _togli_regole(wg_if)
    for regola in _regole(wg_if):  # prima il mark (i pacchetti cifrati di wgx0 nella main), poi i peer nella tabella
        _cmd("ip", "rule", "add", *regola)
    try:
        if _cmd("ip", "link", "show", INTERFACCIA, tollera=True)[0] != 0:
            _cmd("ip", "link", "add", INTERFACCIA, "type", "wireguard")
        # le risposte dei siti tornano da wgx0 mentre la rotta main verso di loro e' la WAN: con rp_filter stretto
        # (1) cadrebbero; 2 (lasco) e' il minimo che vale, il kernel usa il massimo fra all e l'interfaccia
        _cmd("sysctl", "-qw", f"net/ipv4/conf/{INTERFACCIA}/rp_filter=2")
        _cmd("wg", "setconf", INTERFACCIA, "/dev/stdin", ingresso=conf_wg(campi))
        _cmd("ip", "address", "flush", "dev", INTERFACCIA)
        for a in _ipv4(campi):
            _cmd("ip", "address", "add", a, "dev", INTERFACCIA)
        _cmd("ip", "link", "set", INTERFACCIA, "mtu", campi["Interface"].get("MTU", "1420"), "up")
        _cmd("ip", "route", "replace", "default", "dev", INTERFACCIA, "table", t)
    except RuntimeError as e:
        return {"attiva": st["attiva"], "salita": False,
                "dettaglio": f"{st['attiva']} non salita ({registro.redigi(e)}); kill switch attivo: nessuna uscita dalla WAN"}
    return {"attiva": st["attiva"], "salita": True, "dettaglio": f"{st['attiva']} su {INTERFACCIA}, kill switch attivo"}


def eta_handshake(adesso=None):
    """Secondi dall'ultimo handshake di wgx0, None se mai o se wgx0 non c'e'."""
    codice, uscita = _cmd("wg", "show", INTERFACCIA, "latest-handshakes", tollera=True)
    try:
        epoca = int(uscita.split()[1]) if codice == 0 else 0
    except (IndexError, ValueError):
        epoca = 0
    return int((adesso or time.time()) - epoca) if epoca else None


def viva():
    """Le tre parti dell'uscita ci sono: kill switch, regola dei peer, wgx0."""
    return (_cmd("nft", "list", "table", "inet", TABELLA_NFT, tollera=True)[0] == 0
            and f"lookup {TABELLA_ROTTE}" in _cmd("ip", "rule", "show", "priority", str(PRIO_PEER), tollera=True)[1]
            and _cmd("ip", "link", "show", INTERFACCIA, tollera=True)[0] == 0)


def tick(cfg, wg_if="wg0", cartella=None, adesso=None):
    """Dal timer, ogni minuto: rotazione, failover e riparazione. {cambio, motivo, applicato}."""
    cartella, adesso = cartella or CARTELLA, int(adesso if adesso is not None else time.time())
    st = stato(cartella)
    if not st["attiva"]:
        return {"cambio": None, "motivo": None, "applicato": None}
    nuova, motivo = da_cambiare(st, pool(cartella), adesso, eta_handshake(adesso))
    if nuova:
        st.update(attiva=nuova, ultimo_cambio=adesso)
        _salva_stato(st, cartella)
    elif viva():
        return {"cambio": None, "motivo": None, "applicato": None}
    else:
        motivo = "riparazione: una parte dell'uscita mancava"
    return {"cambio": nuova, "motivo": motivo, "applicato": applica(cfg, wg_if, cartella)}


def ripristina(cfg, wg_if="wg0", cartella=None):
    """Il passo «uscita» di reconcile: senza uscita scelta non tocca niente; con l'uscita il kill switch va su
    prima dei peer, e wgx0 che non sale non ferma il ripristino (riprova il timer)."""
    cartella = cartella or CARTELLA
    if not stato(cartella)["attiva"]:
        return "nessuna uscita scelta"
    with lucchetto(cartella):
        return applica(cfg, wg_if, cartella)["dettaglio"]


def rapporto(cartella=None, adesso=None):
    """Per `exit list` e per l'app: pool, paesi con bandierina e stato (mai chiavi private)."""
    cartella, adesso = cartella or CARTELLA, int(adesso if adesso is not None else time.time())
    st, schede = stato(cartella), pool(cartella)
    paesi = {}
    for s in schede:
        paesi.setdefault(s["paese"], 0)
        paesi[s["paese"]] += 1
    attiva = next((s for s in schede if s["id"] == st["attiva"]), None)
    prossimo = (st["ultimo_cambio"] + st["rotazione_minuti"] * 60 - adesso) if st["rotazione_minuti"] and attiva else None
    return {"scelta": st["scelta"], "attiva": st["attiva"], "rotazione_minuti": st["rotazione_minuti"],
            "prossimo_cambio_secondi": max(prossimo, 0) if prossimo is not None else None,
            "endpoint_attivo": attiva["endpoint"] if attiva else None,
            "paesi": [{"paese": p, "bandierina": bandierina(p), "uscite": n} for p, n in sorted(paesi.items())],
            "uscite": [{**s, "bandierina": bandierina(s["paese"]), "attiva": s["id"] == st["attiva"]} for s in schede]}


# --- CLI ------------------------------------------------------------------------------------------------------------

def aggiungi_parser(sotto, classe):
    ex = sotto.add_parser("exit", help="uscite per paese: pool, scelta, rotazione, kill switch (FR-NET-008)")
    az = ex.add_subparsers(dest="azione", required=True, parser_class=classe)
    im = az.add_parser("import", help="aggiunge al pool un file WireGuard del provider, col suo paese")
    im.add_argument("file", help="il file .conf del provider, o - per leggerlo da stdin"); im.add_argument("--paese", required=True, help="ISO 3166-1 alpha-2: IT, DE, JP...")
    im.add_argument("--nome", help="nome mostrato nell'app (di base l'id, es. de-1)")
    rm = az.add_parser("remove", help="toglie un'uscita non in uso dal pool"); rm.add_argument("id")
    az.add_parser("list", help="pool, paesi con bandierina, uscita attiva e rotazione")
    se = az.add_parser("set", help="paese (IT), uscita (it-2) o off; applica subito"); se.add_argument("scelta")
    ro = az.add_parser("rotation", help="minuti fra un cambio e l'altro nel paese scelto; 0 = statica"); ro.add_argument("minuti", type=int)
    az.add_parser("tick", help="rotazione, failover e riparazione: lo lancia il timer ogni minuto")
    az.add_parser("key", help="chiave pubblica di questo server per usare un altro server SovereignVPN come uscita [H50]")
    for p in az.choices.values():
        p.add_argument("--cartella", help=f"di base {CARTELLA} (0700)")
        p.add_argument("--config", default="/etc/sovereignvpn/server.toml")
        p.add_argument("--json", action="store_true")


def esegui(a):
    from . import configurazione, preflight
    try:
        if a.azione == "list":
            esito = rapporto(a.cartella)
            esito["handshake_secondi"] = eta_handshake() if esito["attiva"] else None  # per l'app: collegata o no
            print(json.dumps(esito, ensure_ascii=False, indent=1) if a.json else
                  "\n".join([f"scelta: {esito['scelta'] or 'nessuna (i peer escono dal server)'}; rotazione: "
                             + (f"ogni {esito['rotazione_minuti']} minuti" if esito['rotazione_minuti'] else "statica")]
                            + [f"  {u['bandierina']} {u['id']:8} {u['nome']:20} {u['endpoint']}" + ("  <- attiva" if u["attiva"] else "")
                               for u in esito["uscite"]]))
            return 0
        with lucchetto(a.cartella):
            return _scrivi(a, configurazione)
    except (UscitaNonValida, preflight.InputNonValido) as e:
        print(f"sovereignctl: input non valido: {registro.redigi(e)}", file=sys.stderr)
        return 2
    except (OSError, RuntimeError, ValueError) as e:
        print(f"sovereignctl: exit {a.azione}: {registro.redigi(e)}", file=sys.stderr)
        return 1


def _scrivi(a, configurazione):
    """Le azioni che cambiano il pool, lo stato o l'host: girano col lucchetto preso. Codice d'uscita."""
    if a.azione == "import":
        if a.file == "-":  # dall'app: il file del provider passa da stdin e non resta copiato nella VM
            testo = sys.stdin.read(65536)
        else:
            with open(a.file, encoding="utf-8") as f:
                testo = f.read(65536)
        cfg = configurazione.leggi(a.config)  # la rete dei peer, per rifiutare un'uscita che ci si sovrappone [H50]
        esito = importa(testo, a.paese, a.nome, a.cartella, subnet=cfg.get("subnet") or "10.66.0.0/24")
        umano = f"{esito['bandierina']} {esito['id']} ({esito['paese']}) aggiunta: {esito['endpoint']}"
    elif a.azione == "key":
        esito = {"chiave_pubblica": chiave_uscita(a.cartella)}
        umano = (f"{esito['chiave_pubblica']}\nDalla al server che ti fa da uscita: sovereignctl peer add --public-key ..., "
                 "poi importa qui il suo profilo con exit import")
    elif a.azione == "remove":
        togli(a.id, a.cartella)
        esito, umano = {"tolta": a.id}, f"{a.id} tolta dal pool"
    elif a.azione == "rotation":
        esito = imposta_rotazione(a.minuti, a.cartella)
        umano = "rotazione " + (f"ogni {a.minuti} minuti" if a.minuti else "statica")
    elif a.azione == "set":
        cfg = configurazione.leggi(a.config)  # prima di salvare la scelta: una configurazione rotta non cambia niente
        scegli(a.scelta, a.cartella)
        esito = applica(cfg, cartella=a.cartella)
        umano = esito["dettaglio"]
    else:
        esito = tick(configurazione.leggi(a.config), cartella=a.cartella)
        umano = json.dumps(esito, ensure_ascii=False)
    print(json.dumps(esito, ensure_ascii=False, indent=1) if a.json else umano)
    return 1 if a.azione == "set" and not esito["salita"] else 0
