"""Firewall di base (Slice B; ANC-0181-0187, FR-NET-001/002/003/006, FR-DNS-005, ADR-005, ADR-006).

Una tabella nftables propria, `inet sovereignvpn`, che si sostituisce in UN batch atomico: prima `nft -c -f -` (solo
controllo), poi `nft -f -`; se il controllo fallisce non si applica niente e la tabella di prima resta (ANC-0187).
- INPUT drop: loopback, connessioni gia' stabilite, ICMP essenziale, la porta UDP di WireGuard, SSH SOLO dalle sorgenti
  della configurazione (ANC-0182: mai un drop senza la via dell'amministratore), amministrazione e DNS solo dalla VPN.
- PREROUTING: l'IPv6 dei peer rifiutato con ICMPv6 admin-prohibited, prima dell'instradamento: con l'inoltro IPv6
  spento non arriverebbe mai al FORWARD, e cadrebbe in silenzio; cosi' fallisce subito e in modo esplicito (T-013, H38).
- FORWARD drop: niente fra peer (FR-NET-002); il DNS dei peer verso l'esterno bloccato (FR-DNS-005, va ai resolver
  interni); i peer escono solo dalla WAN, e solo in IPv4 (ANC-0045, ANC-0186), o dall'uscita wgx0 quando c'e'
  (FR-NET-008 [H48]: il kill switch e le rotte dell'uscita stanno in uscite.py, in una tabella nft loro).
- NAT: masquerade della subnet VPN verso la WAN e verso wgx0.
"""
import ipaddress, json, os, re, subprocess

from . import registro
from .preflight import InputNonValido

TABELLA = "sovereignvpn"
INTERFACCIA_USCITA = "wgx0"  # [H48] l'uscita per paese; senza uscita scelta non esiste, e le sue regole non toccano niente
INTERFACCIA = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")


def _rete(nome, v, versione=None):
    try:
        r = ipaddress.ip_network(v, strict=True)
    except (TypeError, ValueError):
        raise InputNonValido(f"{nome}: «{v}» non e' un CIDR canonico")
    if versione and r.version != versione:
        raise InputNonValido(f"{nome}: serve una rete IPv{versione}")
    return r


def componi(subnet, wg_if="wg0", wg_port=51820, wan_if=None, admin_port=8443, ssh_port=22, ssh_sorgenti=None, mtu=1420, blocca_dot=True, limiti=(), dns_liberi=(), quote=(), recupero=False):
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
    # FR-PEER-008 [H35]: un oggetto quota per peer, coi byte gia' usati (il reconcile sostituisce la tabella ogni minuto)
    oggetti = [f"  quota {_nome_quota(ind)} {{ over {int(tot)} bytes used {int(usati or 0)} bytes }}" for ind, tot, usati in quote]
    r = [f"table inet {TABELLA}", f"delete table inet {TABELLA}", f"table inet {TABELLA} {{", *oggetti,
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
          "  chain prerouting {",
          "    type filter hook prerouting priority filter; policy accept;",
          f'    iifname "{wg_if}" meta nfproto ipv6 reject with icmpv6 type admin-prohibited',
          "  }",
          "  chain forward {",
          "    type filter hook forward priority filter; policy drop;",
          # T-026 [H41]: registro illeggibile = nessuno sa chi e' revocato o limitato: niente traffico dei peer
          *([f'    iifname "{wg_if}" drop', f'    oifname "{wg_if}" drop'] if recupero else []),
          # FR-WG-006, solo dove serve: i SYN fra wg0 e la WAN, prima di ct established (il SYN-ACK e' gia' «established»).
          # Verso la WAN la MSS annunciata dal peer scende a MTU del tunnel - 40, e solo se e' piu' alta: rt mtu qui
          # direbbe 1500, la MTU di ens3, mentre la strozzatura e' wg0. Verso il peer basta rt mtu, che e' quella di wg0.
          f'    iifname "{wg_if}" oifname "{wan_if}" tcp flags syn / syn,rst tcp option maxseg size > {int(mtu) - 40} '
          f"tcp option maxseg size set {int(mtu) - 40}",
          f'    iifname "{wan_if}" oifname "{wg_if}" tcp flags syn / syn,rst tcp option maxseg size set rt mtu',
          # [H48] verso l'uscita la strozzatura e' wgx0 stessa (la MTU del provider): basta rt mtu nei due versi
          f'    iifname "{wg_if}" oifname "{INTERFACCIA_USCITA}" tcp flags syn / syn,rst tcp option maxseg size set rt mtu',
          f'    iifname "{INTERFACCIA_USCITA}" oifname "{wg_if}" tcp flags syn / syn,rst tcp option maxseg size set rt mtu',
          # la quota conta i due versi e sta prima di ct established: dopo, i pacchetti delle connessioni aperte non passano di qui
          *[x for ind, _, _ in quote for x in (f'    iifname "{wg_if}" ip saddr {ipaddress.ip_address(ind)} quota name "{_nome_quota(ind)}" drop',
                                               f'    oifname "{wg_if}" ip daddr {ipaddress.ip_address(ind)} quota name "{_nome_quota(ind)}" drop')],
          "    ct state established,related accept",
          "    ct state invalid drop",
          f'    iifname "{wg_if}" oifname "{wg_if}" drop',
          # FR-PEER-008 [H34]: i peer con DNS libero passano prima del blocco del DNS esterno
          *[f'    iifname "{wg_if}" ip saddr {ipaddress.ip_address(ind)} meta l4proto {{ tcp, udp }} th dport 53 accept' for ind in dns_liberi],
          f'    iifname "{wg_if}" meta l4proto {{ tcp, udp }} th dport 53 drop',
          # FR-DNS-006 [H25]: DoT verso fuori aggira il resolver interno. Il reject su 853 NON ferma ogni DNS cifrato:
          # DoH viaggia su 443 come il resto del web, DoQ su UDP 853 o altre porte. Si dichiara, non si promette.
          *([f'    iifname "{wg_if}" tcp dport 853 reject with tcp reset'] if blocca_dot else []),
          # FR-PEER-008 [H33]: un peer con rotte esce solo verso le sue rotte (e la VPN): il limite e' nel firewall
          *[f'    iifname "{wg_if}" ip saddr {ipaddress.ip_address(ind)} ip daddr != {{ {vpn}, '
            + ", ".join(str(ipaddress.ip_network(r)) for r in rotte) + " } drop" for ind, rotte in limiti],
          f'    iifname "{wg_if}" ip saddr {vpn} oifname "{wan_if}" accept',
          f'    iifname "{wg_if}" ip saddr {vpn} oifname "{INTERFACCIA_USCITA}" accept',
          "  }",
          "  chain postrouting {",
          "    type nat hook postrouting priority srcnat; policy accept;",
          f'    ip saddr {vpn} oifname "{wan_if}" masquerade',
          f'    ip saddr {vpn} oifname "{INTERFACCIA_USCITA}" masquerade',
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


def applica_tabella(ruleset):
    """Una tabella nft d'appoggio (il kill switch dell'uscita): controllo, poi batch atomico, come la principale."""
    for argomenti in (("-c", "-f", "-"), ("-f", "-")):
        codice, _, errore = _nft(*argomenti, ingresso=ruleset)
        if codice != 0:
            raise RuntimeError(f"nft {' '.join(argomenti)} ha rifiutato la tabella, niente applicato ({registro.redigi(errore.strip())[:200]})")


def _nome_quota(ind):
    return "q_" + str(ipaddress.ip_address(ind)).replace(".", "_")


def quote_usate():
    """{indirizzo: byte usati} dalle quote della tabella viva, prima di sostituirla; tabella assente = {}."""
    try:
        codice, uscita, _ = _nft("-j", "list", "table", "inet", TABELLA)
    except OSError:
        return {}  # nft assente: nessuna tabella viva
    if codice != 0:
        return {}
    usate = {}
    for o in json.loads(uscita)["nftables"]:
        q = o.get("quota")
        if q and str(q.get("name", "")).startswith("q_"):
            usate[q["name"][2:].replace("_", ".")] = int(q.get("used", 0))
    return usate


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
