"""Firewall di base (Slice B; ANC-0181-0187, FR-NET-001/002/003/006, FR-DNS-005, ADR-005, ADR-006).

Una tabella nftables propria, `inet sovereignvpn`, che si sostituisce in UN batch atomico: prima `nft -c -f -` (solo
controllo), poi `nft -f -`; se il controllo fallisce non si applica niente e la tabella di prima resta (ANC-0187).
- INPUT drop: loopback, connessioni gia' stabilite, ICMP essenziale, la porta UDP di WireGuard, SSH SOLO dalle sorgenti
  della configurazione (ANC-0182: mai un drop senza la via dell'amministratore), amministrazione e DNS solo dalla VPN.
- FORWARD drop: niente fra peer (FR-NET-002); il DNS dei peer verso l'esterno bloccato (FR-DNS-005, va ai resolver
  interni); IPv6 dei peer respinto in modo esplicito, la 1.0 e' IPv4 (T-013, ANC-0186); i peer escono solo dalla WAN.
- NAT: masquerade della subnet VPN verso la WAN.
"""
import ipaddress, json, os, re, subprocess

from . import registro
from .preflight import InputNonValido

TABELLA = "sovereignvpn"
INTERFACCIA = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")


def _rete(nome, v, versione=None):
    try:
        r = ipaddress.ip_network(v, strict=True)
    except (TypeError, ValueError):
        raise InputNonValido(f"{nome}: «{v}» non e' un CIDR canonico")
    if versione and r.version != versione:
        raise InputNonValido(f"{nome}: serve una rete IPv{versione}")
    return r


def componi(subnet, wg_if="wg0", wg_port=51820, wan_if=None, admin_port=8443, ssh_port=22, ssh_sorgenti=None):
    for nome, v in (("--wg-interface", wg_if), ("--wan-interface", wan_if)):
        if not isinstance(v, str) or not INTERFACCIA.match(v):
            raise InputNonValido(f"{nome}: nome di interfaccia Linux di 1-15 caratteri (ANC-0174: la WAN si dichiara, mai eth0 presunta)")
    vpn = _rete("subnet", subnet, 4)
    if not vpn.is_private:
        raise InputNonValido("subnet: la subnet VPN deve essere privata")
    if not ssh_sorgenti:
        raise InputNonValido("admin_ssh_sources: servono le sorgenti autorizzate per SSH, o un drop su INPUT chiude fuori l'amministratore (ANC-0182)")
    sorgenti = [_rete(f"admin_ssh_sources[{i}]", s) for i, s in enumerate(ssh_sorgenti)]
    v4 = ", ".join(str(s) for s in sorgenti if s.version == 4)
    v6 = ", ".join(str(s) for s in sorgenti if s.version == 6)
    r = [f"table inet {TABELLA}", f"delete table inet {TABELLA}", f"table inet {TABELLA} {{",
         "  chain input {",
         "    type filter hook input priority filter; policy drop;",
         '    iif "lo" accept',
         "    ct state established,related accept",
         "    ct state invalid drop",
         "    icmp type { echo-request, destination-unreachable, time-exceeded } limit rate 10/second accept",
         "    icmpv6 type { echo-request, destination-unreachable, packet-too-big, time-exceeded, parameter-problem, "
         "nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept",
         f"    udp dport {int(wg_port)} accept"]
    if v4:
        r.append(f"    ip saddr {{ {v4} }} tcp dport {int(ssh_port)} accept")
    if v6:
        r.append(f"    ip6 saddr {{ {v6} }} tcp dport {int(ssh_port)} accept")
    r += [f'    iifname "{wg_if}" ip saddr {vpn} tcp dport {int(admin_port)} accept',
          f'    iifname "{wg_if}" ip saddr {vpn} meta l4proto {{ tcp, udp }} th dport 53 accept',
          "  }",
          "  chain forward {",
          "    type filter hook forward priority filter; policy drop;",
          "    ct state established,related accept",
          "    ct state invalid drop",
          f'    iifname "{wg_if}" oifname "{wg_if}" drop',
          f'    iifname "{wg_if}" meta l4proto {{ tcp, udp }} th dport 53 drop',
          f'    iifname "{wg_if}" meta nfproto ipv6 reject with icmpv6 type admin-prohibited',
          f'    iifname "{wg_if}" ip saddr {vpn} oifname "{wan_if}" accept',
          "  }",
          "  chain postrouting {",
          "    type nat hook postrouting priority srcnat; policy accept;",
          f'    ip saddr {vpn} oifname "{wan_if}" masquerade',
          "  }",
          "}"]
    return "\n".join(r) + "\n"


def _nft(*argomenti, ingresso=None):
    p = subprocess.run(["nft", *argomenti], input=ingresso, capture_output=True, text=True, timeout=30,
                       env={"PATH": os.environ.get("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"), "LC_ALL": "C"})
    return p.returncode, p.stdout, p.stderr


def applica(ruleset):
    """Controllo, applicazione atomica, verifica: le due catene filtro esistono con policy drop."""
    codice, _, errore = _nft("-c", "-f", "-", ingresso=ruleset)
    if codice != 0:
        raise RuntimeError(f"nft -c ha rifiutato il ruleset, niente applicato ({registro.redigi(errore.strip())[:200]})")
    codice, _, errore = _nft("-f", "-", ingresso=ruleset)
    if codice != 0:
        raise RuntimeError(f"nft -f non riuscito, il batch e' atomico: vale la tabella di prima ({registro.redigi(errore.strip())[:200]})")
    return leggi()


def leggi():
    """La tabella com'e' nel kernel: catene con le policy, numero di regole, e se INPUT e FORWARD sono in drop."""
    codice, uscita, errore = _nft("-j", "list", "table", "inet", TABELLA)
    if codice != 0:
        raise RuntimeError(f"tabella {TABELLA} non leggibile ({registro.redigi(errore.strip())[:200]})")
    oggetti = json.loads(uscita)["nftables"]
    catene = {o["chain"]["name"]: o["chain"].get("policy") for o in oggetti if "chain" in o}
    ok = catene.get("input") == "drop" and catene.get("forward") == "drop"
    return {"tabella": f"inet {TABELLA}", "catene": catene, "regole": sum(1 for o in oggetti if "rule" in o), "verificato": ok}


def regole_dichiarate(ruleset):
    """Quante regole dichiara un ruleset di `componi`: le righe dentro le catene, tolte quelle `type ... hook`."""
    return sum(1 for r in ruleset.splitlines() if r.startswith("    ") and not r.lstrip().startswith("type "))
