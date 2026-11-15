"""Preflight del bootstrap (FR-BOOT-001, FR-BOOT-003, FR-BOOT-004; ANC-0114, ANC-0263-0265).

Due tempi separati: `raccogli()` legge l'host senza scrivere niente, `valuta()` decide sui fatti raccolti.
Cosi' le prove girano con fatti finti su qualunque macchina, e il dry-run non ha un punto dove potrebbe mutare.
Le soglie che il documento non fissa sono ipotesi [H] dichiarate nel rapporto: docs/decisions/ipotesi.md.
"""
import ipaddress, json, os, platform, shutil, socket, subprocess

SISTEMI = {("debian", "12"), ("ubuntu", "24.04")}        # ANC-0086
KERNEL_MINIMO = (5, 6)                                     # [H4] WireGuard e' nel kernel dalla 5.6
DISCO_MINIMO = 10 * 1024 ** 3                              # [H5] 10 GiB liberi
PORTA_WG = 51820                                           # ANC-0173, UDP
PORTA_ADMIN = 8443                                         # [H7] TCP, solo su indirizzo locale (ADR-006)
CANDIDATE_VPN = [f"10.{n}.0.0/24" for n in range(66, 100)]  # [H6] IPAM: la prima /24 che non collide


class InputNonValido(ValueError):
    """Input o schema non valido: codice di uscita 2, nessuna raccolta e nessuna mutazione (FR-BOOT-003)."""


def leggi_impostazioni(wg_port=None, admin_port=None, subnet=None, nomi=None):
    """Valida porte e subnet; `nomi` dice da dove viene ogni valore (--wg-port o config.wg_port) per l'errore."""
    nomi = {"wg_port": "--wg-port", "admin_port": "--admin-port", "subnet": "--subnet", **(nomi or {})}

    def porta(nome, v, base):
        if v is None:
            return base
        try:
            n = int(v)
        except (TypeError, ValueError):
            raise InputNonValido(f"{nome}: «{v}» non e' un numero di porta")
        if not 1 <= n <= 65535:
            raise InputNonValido(f"{nome}: {n} fuori dall'intervallo 1-65535")
        return n
    imp = {"wg_port": porta(nomi["wg_port"], wg_port, PORTA_WG),
           "admin_port": porta(nomi["admin_port"], admin_port, PORTA_ADMIN), "subnet": None}
    if subnet is not None:
        try:
            rete = ipaddress.ip_network(subnet, strict=True)
        except (TypeError, ValueError) as e:
            raise InputNonValido(f"{nomi['subnet']}: «{subnet}» non e' un CIDR canonico ({e})")
        if rete.version != 4 or not rete.is_private or rete.prefixlen > 29:
            raise InputNonValido(f"{nomi['subnet']}: {rete} deve essere una rete IPv4 privata grande almeno /29")
        imp["subnet"] = str(rete)
    if imp["wg_port"] == imp["admin_port"]:
        raise InputNonValido(f"{nomi['admin_port']}: {imp['admin_port']} coincide con {nomi['wg_port']}")
    return imp


def _comando(*args, timeout=10):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or "").strip()
    except (OSError, subprocess.TimeoutExpired):
        return None, ""


def _porta_libera(proto, porta):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if proto == "udp" else socket.SOCK_STREAM)
    try:
        s.bind(("0.0.0.0", porta))
        return True
    except OSError:
        return False
    finally:
        s.close()


def _reti_host():
    reti = []
    codice, uscita = _comando("ip", "-j", "addr")
    if codice == 0 and uscita:
        for itf in json.loads(uscita):
            for a in itf.get("addr_info", []):
                if a.get("family") == "inet":
                    reti.append(str(ipaddress.ip_interface(f"{a['local']}/{a['prefixlen']}").network))
    codice, uscita = _comando("docker", "network", "inspect", "--format", "{{range .IPAM.Config}}{{.Subnet}} {{end}}",
                              *(_comando("docker", "network", "ls", "-q")[1].split() or ["-"]))
    if codice == 0:
        reti += [x for x in uscita.split() if "." in x]
    return sorted(set(reti))


def raccogli(imp):
    """Fatti dell'host. Solo letture e un bind di prova che si chiude subito: niente file, firewall o servizi."""
    os_rel = {}
    try:
        for riga in open("/etc/os-release", encoding="utf-8"):
            k, _, v = riga.strip().partition("=")
            os_rel[k] = v.strip('"')
    except OSError:
        pass
    docker = _comando("docker", "version", "--format", "{{.Server.Version}}")
    compose = _comando("docker", "compose", "version", "--short")
    ntp = _comando("timedatectl", "show", "-p", "NTPSynchronized", "--value")
    wg = os.path.isdir("/sys/module/wireguard") or _comando("modinfo", "wireguard")[0] == 0
    return {
        "os": (os_rel.get("ID", platform.system().lower()), os_rel.get("VERSION_ID", "")),
        "architettura": platform.machine(),
        "kernel": platform.release(),
        "docker": docker[1] if docker[0] == 0 else None,
        "compose": compose[1] if compose[0] == 0 else None,
        "wireguard": wg,
        "disco_libero": shutil.disk_usage("/").free,
        "ntp": {"yes": True, "no": False}.get(ntp[1]) if ntp[0] == 0 else None,
        "porte_libere": {f"udp/{imp['wg_port']}": _porta_libera("udp", imp["wg_port"]),
                         f"tcp/{imp['admin_port']}": _porta_libera("tcp", imp["admin_port"])},
        "reti_host": _reti_host(),
    }


def _versione(testo):
    parti = []
    for p in testo.split("-")[0].split(".")[:2]:
        if not p.isdigit():
            break
        parti.append(int(p))
    return tuple(parti)


def scegli_subnet(imp, reti_host):
    """La subnet VPN: quella data, se non collide; altrimenti la prima candidata libera. (rete, collisioni)."""
    occupate = [ipaddress.ip_network(r) for r in reti_host]
    if imp["subnet"]:
        rete = ipaddress.ip_network(imp["subnet"])
        return str(rete), [str(o) for o in occupate if o.overlaps(rete)]
    for c in CANDIDATE_VPN:
        rete = ipaddress.ip_network(c)
        if not any(o.overlaps(rete) for o in occupate):
            return c, []
    return None, ["nessuna /24 libera fra 10.66.0.0 e 10.99.0.0"]


def valuta(fatti, imp):
    """Controlli in ordine fisso: (id, nome, esito OK|FALLITO, dettaglio, rimedio)."""
    c = []

    def esito(id_, nome, ok, dettaglio, rimedio):
        c.append({"id": id_, "nome": nome, "esito": "OK" if ok else "FALLITO", "dettaglio": dettaglio,
                  "rimedio": "" if ok else rimedio})

    sist, ver = fatti["os"]
    esito("os", "Sistema operativo", (sist, ver) in SISTEMI, f"{sist} {ver}".strip(),
          "Installare su Debian 12 o Ubuntu 24.04 LTS (ANC-0086).")
    esito("arch", "Architettura", fatti["architettura"] in ("x86_64", "amd64"), fatti["architettura"],
          "Serve amd64; ARM64 e' da validare a parte (ANC-0086).")
    k = _versione(fatti["kernel"])
    esito("kernel", "Kernel", k >= KERNEL_MINIMO, fatti["kernel"],
          f"Serve un kernel {KERNEL_MINIMO[0]}.{KERNEL_MINIMO[1]} o successivo [H4].")
    esito("docker", "Docker Engine", bool(fatti["docker"]), fatti["docker"] or "assente o demone non raggiungibile",
          "Installare Docker Engine e avviare il demone (ANC-0160).")
    esito("compose", "Docker Compose", bool(fatti["compose"]), fatti["compose"] or "plugin assente",
          "Installare il plugin docker compose v2 (ANC-0160).")
    esito("wireguard", "WireGuard nel kernel", fatti["wireguard"], "modulo disponibile" if fatti["wireguard"] else "modulo assente",
          "Caricare il modulo wireguard o installare un kernel che lo contenga (FR-WG-001).")
    gib = fatti["disco_libero"] / 1024 ** 3
    esito("disco", "Spazio disco", fatti["disco_libero"] >= DISCO_MINIMO, f"{gib:.1f} GiB liberi su /",
          f"Liberare spazio: servono almeno {DISCO_MINIMO // 1024 ** 3} GiB [H5].")
    ntp = fatti["ntp"]
    esito("ora", "Sincronizzazione oraria", ntp is True, {True: "sincronizzata", False: "NON sincronizzata", None: "stato sconosciuto"}[ntp],
          "Attivare NTP/chrony: timestamp e TTL dipendono dall'ora (ANC-0325).")
    for chiave, libera in fatti["porte_libere"].items():
        proto, porta = chiave.split("/")
        esito(f"porta-{proto}-{porta}", f"Porta {proto.upper()} {porta}", libera, "libera" if libera else "gia' in uso",
              f"Liberare la porta {porta}/{proto} o sceglierne un'altra con --{'wg' if proto == 'udp' else 'admin'}-port (T-004).")
    rete, collisioni = scegli_subnet(imp, fatti["reti_host"])
    if not fatti["reti_host"]:  # zero reti lette non vuol dire zero collisioni: vuol dire che non si e' guardato
        collisioni = ["nessuna rete dell'host letta (serve `ip` di iproute2)"]
    esito("subnet", "Subnet VPN", bool(rete) and not collisioni,
          f"{rete} (reti dell'host esaminate: {len(fatti['reti_host'])})" + (f"; collide con {', '.join(collisioni)}" if collisioni else ""),
          "Scegliere con --subnet una rete privata che non collida con LAN, VPC o reti Docker (T-003, ANC-0178).")
    return c, rete


def piano(imp, rete):
    """Che cosa farebbe `init` senza --check (ANC-0266-0270). Solo descrizione: niente viene eseguito."""
    return [
        "Attendere l'approvazione dell'operatore su questo piano (ANC-0266).",
        "Salvare backup e manifest iniziali, senza chiavi ne' token (ANC-0267, FR-BOOT-002).",
        f"Applicare a fasi atomiche container, firewall nftables (ADR-005), sysctl e WireGuard su udp/{imp['wg_port']}, rete {rete} (ANC-0268).",
        f"Esporre l'amministrazione solo su 127.0.0.1:{imp['admin_port']} o sulla VPN (ADR-006) [H7].",
        "Eseguire health check e test di leak (ANC-0269), poi stampare il riepilogo e le sole azioni successive (ANC-0270).",
    ]
