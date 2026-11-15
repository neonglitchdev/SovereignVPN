"""Schema della configurazione del server, versione 1 (ServerConfig, ANC-0230; validazione ANC-0236-0242; FR-BOOT-003).

Il file e' TOML [H8] (tomllib e' nella libreria standard dalla 3.11, ANC-0334). Schema stretto: una chiave sconosciuta
e' un errore. Ogni errore nomina il campo e NON ripete mai il valore di un campo che puo' contenere un segreto (ANC-0241).
Esempio completo: config/examples/server.toml.
"""
import ipaddress, re, tomllib

from .preflight import InputNonValido

VERSIONE_SCHEMA = 1
NOME_HOST = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*$", re.I)
INTERFACCIA = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")       # IFNAMSIZ di Linux: 15 caratteri
HASH_TOKEN = re.compile(r"^(scrypt|pbkdf2_sha256|argon2id)\$\S{20,}$")
DESTINATARIO_AGE = re.compile(r"^age1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58}$")
OPZIONALI = ("tor", "multihop", "wstunnel", "udp2raw")      # fuori dalla 1.0 finche' non hanno un gate (ANC-0110)
SEGRETI = re.compile(r"token|password|secret|private|psk", re.I)
SUBNET6 = "fdd3:5205:9303::/64"  # [H38] ULA con l'ID globale casuale (RFC 4193); chi ne vuole un'altra scrive subnet6
CAMPI = {"schema_version", "endpoint", "wg_port", "admin_port", "subnet", "subnet6", "dns", "mtu", "wan_interface",
         "tls_domain", "firewall_profile", "admin_token_hash", "flags", "admin_ssh_sources", "ssh_port", "dns_block_dot",
         "backup_recipient"}


def _errore(campo, motivo):
    return InputNonValido(f"config.{campo}: {motivo}")


def _ip_o_host(campo, v):
    if not isinstance(v, str):
        raise _errore(campo, "deve essere un testo")
    try:
        ipaddress.ip_address(v)
        return v
    except ValueError:
        if NOME_HOST.match(v):
            return v.lower()
    raise _errore(campo, f"«{v}» non e' ne' un indirizzo IP ne' un nome host valido")


def valida(dati):
    """Dizionario TOML gia' letto -> impostazioni normalizzate. Solleva InputNonValido col nome del campo."""
    sconosciuti = sorted(set(dati) - CAMPI)
    for k in sconosciuti:  # un segreto in chiaro si nomina senza mostrarlo
        if SEGRETI.search(k):
            raise _errore(k, "un segreto in chiaro non si scrive nella configurazione: usare admin_token_hash (ANC-0230, ANC-0247)")
        raise _errore(k, "campo sconosciuto allo schema v1")
    if dati.get("schema_version") != VERSIONE_SCHEMA:
        raise _errore("schema_version", f"obbligatorio e uguale a {VERSIONE_SCHEMA}")
    if "endpoint" not in dati:
        raise _errore("endpoint", "obbligatorio: indirizzo IP o nome host pubblico del server")
    imp = {"endpoint": _ip_o_host("endpoint", dati["endpoint"])}
    for campo in ("wg_port", "admin_port", "subnet"):
        if campo in dati:
            imp[campo] = dati[campo]
    try:  # [H38] l'IPv6 dentro il tunnel esiste solo per essere rifiutato in modo esplicito
        r6 = ipaddress.ip_network(dati.get("subnet6", SUBNET6), strict=True)
    except (TypeError, ValueError):
        raise _errore("subnet6", f"«{dati['subnet6']}» non e' un CIDR IPv6 canonico")
    if r6.version != 6 or not r6.subnet_of(ipaddress.ip_network("fc00::/7")) or r6.prefixlen > 96:
        raise _errore("subnet6", "deve essere una rete IPv6 ULA (fc00::/7) grande almeno /96: ci stanno i 32 bit dell'IPv4 del peer")
    imp["subnet6"] = str(r6)
    dns = dati.get("dns", [])
    if not isinstance(dns, list):
        raise _errore("dns", "deve essere un elenco di indirizzi IP")
    for i, x in enumerate(dns):
        try:
            ipaddress.ip_address(x)
        except (TypeError, ValueError):
            raise _errore(f"dns[{i}]", f"«{x}» non e' un indirizzo IP")
    imp["dns"] = list(dns)
    mtu = dati.get("mtu", 1420)  # [H9] 1420, il valore abituale di WireGuard
    if not isinstance(mtu, int) or isinstance(mtu, bool) or not 1280 <= mtu <= 1500:
        raise _errore("mtu", "deve essere un intero fra 1280 (minimo IPv6) e 1500")
    imp["mtu"] = mtu
    if "wan_interface" in dati:
        if not isinstance(dati["wan_interface"], str) or not INTERFACCIA.match(dati["wan_interface"]):
            raise _errore("wan_interface", "nome di interfaccia Linux di 1-15 caratteri (ANC-0174: mai presumere eth0)")
        imp["wan_interface"] = dati["wan_interface"]
    if "tls_domain" in dati:
        if not isinstance(dati["tls_domain"], str) or not NOME_HOST.match(dati["tls_domain"]):
            raise _errore("tls_domain", "deve essere un nome host valido")
        imp["tls_domain"] = dati["tls_domain"].lower()
    if "backup_recipient" in dati:  # [H20] una chiave PUBBLICA age: decifrare si fa altrove, mai sul server
        if not isinstance(dati["backup_recipient"], str) or not DESTINATARIO_AGE.match(dati["backup_recipient"]):
            raise _errore("backup_recipient", "deve essere una chiave pubblica age (age1 seguito da 58 caratteri bech32)")
        imp["backup_recipient"] = dati["backup_recipient"]
    profilo = dati.get("firewall_profile", "nftables")
    if profilo != "nftables":
        raise _errore("firewall_profile", "nella 1.0 vale solo «nftables» (ADR-005, ANC-0372)")
    imp["firewall_profile"] = profilo
    if "admin_token_hash" in dati:
        if not isinstance(dati["admin_token_hash"], str) or not HASH_TOKEN.match(dati["admin_token_hash"]):
            raise _errore("admin_token_hash", "deve essere un hash scrypt$, pbkdf2_sha256$ o argon2id$ (ANC-0247); il valore non si mostra")
        imp["admin_token_hash"] = dati["admin_token_hash"]
    sorgenti = dati.get("admin_ssh_sources", [])
    if not isinstance(sorgenti, list):
        raise _errore("admin_ssh_sources", "deve essere un elenco di CIDR (sorgenti autorizzate per SSH, ANC-0182)")
    for i, s in enumerate(sorgenti):
        try:
            ipaddress.ip_network(s, strict=True)
        except (TypeError, ValueError):
            raise _errore(f"admin_ssh_sources[{i}]", f"«{s}» non e' un CIDR canonico")
    imp["admin_ssh_sources"] = list(sorgenti)
    if "dns_block_dot" in dati:  # [H25] FR-DNS-006: di base acceso
        if not isinstance(dati["dns_block_dot"], bool):
            raise _errore("dns_block_dot", "deve essere true o false")
        imp["dns_block_dot"] = dati["dns_block_dot"]
    porta_ssh = dati.get("ssh_port", 22)
    if not isinstance(porta_ssh, int) or isinstance(porta_ssh, bool) or not 1 <= porta_ssh <= 65535:
        raise _errore("ssh_port", "deve essere un intero fra 1 e 65535")
    imp["ssh_port"] = porta_ssh
    flags = dati.get("flags", {})
    if not isinstance(flags, dict):
        raise _errore("flags", "deve essere una tabella [flags]")
    for k, v in flags.items():
        if k not in OPZIONALI:
            raise _errore(f"flags.{k}", f"flag sconosciuto; quelli previsti sono {', '.join(OPZIONALI)}")
        if not isinstance(v, bool):
            raise _errore(f"flags.{k}", "deve essere true o false")
        if v:
            raise _errore(f"flags.{k}", "servizio opzionale fuori dalla 1.0 finche' non ha il suo gate (ANC-0110)")
    return imp


def leggi(percorso):
    try:
        with open(percorso, "rb") as f:
            return valida(tomllib.load(f))
    except FileNotFoundError:
        raise InputNonValido(f"--config: il file «{percorso}» non esiste")
    except tomllib.TOMLDecodeError as e:
        raise InputNonValido(f"--config: TOML non valido ({e})")
