"""sovereignctl — CLI del control plane. Per ora: `init --check` (Slice A, ANC-0346).

Codici di uscita (ANC-0255): 0 successo; 1 errore runtime/sistema (anche un prerequisito mancante [H3]);
2 input o schema non valido; 3 security gate fallito; 4 applicato in parte, serve recovery.
Uso: python3 -m sovereignctl init --check [--config server.toml] [--wg-port N] [--admin-port N] [--subnet CIDR] [--json]
     python3 -m sovereignctl init --apply --config server.toml --wan-interface IF [--json]
     python3 -m sovereignctl reconcile --config server.toml [--wan-interface IF] [--json]   (a ogni avvio, FR-NET-007)
     python3 -m sovereignctl status [--config server.toml] [--db FILE] [--json]           (solo letture)
"""
import argparse, json, sys

from . import VERSIONE, configurazione, manifest, peer, preflight, registro, runtime


class _Parser(argparse.ArgumentParser):
    def error(self, message):  # argparse esce con 2 di suo: qui si tiene il codice e si nomina la voce
        self.print_usage(sys.stderr)
        print(f"sovereignctl: input non valido: {message}", file=sys.stderr)
        sys.exit(2)


def _esito_passi(rapporto, comando, passi, errore, come_json):
    """Rapporto di `init --apply` e `reconcile`. Codice (ANC-0255): 3 se la chiave del server e' esposta (come
    `peer reconcile`), 4 se il guasto arriva dopo almeno un passo (applicato in parte), 1 se prima."""
    rapporto.update({"comando": comando, "passi": [{"passo": p, "esito": e} for p, e in passi],
                     "errore": registro.redigi(errore) if errore else None})
    print(json.dumps(rapporto, ensure_ascii=False, indent=1) if come_json else
          "\n".join([f"SovereignVPN {VERSIONE} — {comando}"] + [f"  [OK] {p}: {e}" for p, e in passi]
                    + ([f"  [FERMO] {registro.redigi(errore)}"] if errore else [])))
    if errore is None:
        return 0
    return 3 if isinstance(errore, runtime.ChiaveEsposta) else (4 if passi else 1)


def _ripristina(a):
    from . import bootstrap
    try:
        cfg = configurazione.leggi(a.config)
        wan = a.wan_interface or cfg.get("wan_interface")
        if not wan:
            raise preflight.InputNonValido("reconcile vuole --wan-interface o wan_interface nella configurazione: "
                                           "al riavvio la WAN si legge da li' (ANC-0174: mai presunta)")
        passi, errore = bootstrap.ripristina(cfg, wan)
    except preflight.InputNonValido as e:
        print(f"sovereignctl: input non valido: {registro.redigi(e)}", file=sys.stderr)
        return 2
    return _esito_passi({"versione": VERSIONE}, "reconcile", passi, errore, a.json)


def main(argv=None):
    p = _Parser(prog="sovereignctl", description=f"SovereignVPN {VERSIONE} — control plane")
    sotto = p.add_subparsers(dest="comando", required=True, parser_class=_Parser)
    init = sotto.add_parser("init", help="preflight e bootstrap")
    modo = init.add_mutually_exclusive_group(required=True)
    modo.add_argument("--check", action="store_true", help="solo preflight e piano, nessuna mutazione")
    modo.add_argument("--apply", action="store_true", help="bootstrap vero, dopo aver visto il piano di --check (ANC-0266)")
    init.add_argument("--wan-interface", help="interfaccia verso Internet (ANC-0174: mai presunta)")
    init.add_argument("--wg-port"); init.add_argument("--admin-port"); init.add_argument("--subnet")
    init.add_argument("--config", help="file TOML della configurazione, schema v1 (config/examples/server.toml)")
    init.add_argument("--json", action="store_true", help="rapporto in JSON")
    rec = sotto.add_parser("reconcile", help="riporta l'host allo stato dichiarato: firewall, sysctl, wg0, peer (FR-NET-007)")
    rec.add_argument("--config", required=True, help="file TOML della configurazione (al riavvio /etc/sovereignvpn/server.toml)")
    rec.add_argument("--wan-interface", help="interfaccia verso Internet; altrimenti wan_interface della configurazione")
    rec.add_argument("--json", action="store_true", help="rapporto in JSON")
    pr = sotto.add_parser("profile", help="profili dei client (FR-PEER-007)")
    pa = pr.add_subparsers(dest="azione", required=True, parser_class=_Parser)
    ex = pa.add_parser("export", help="scrive il profilo full-tunnel del peer in un file 0600; stampa percorso e checksum")
    ex.add_argument("id", help="UUID del peer")
    ex.add_argument("--conferma", action="store_true", help="autorizzazione esplicita all'export (FR-PEER-007)")
    ex.add_argument("--keepalive", type=int, help="PersistentKeepalive in secondi; senza, spento (FR-WG-005)")
    ex.add_argument("--config", default="/etc/sovereignvpn/server.toml")
    ex.add_argument("--db", default=peer.DB_PREDEFINITO)
    ex.add_argument("--server-key", default="/etc/sovereignvpn/wg-server.key")
    ex.add_argument("--out", help="cartella di destinazione (0700); di base /var/lib/sovereignvpn/export")
    ex.add_argument("--json", action="store_true")
    st = sotto.add_parser("status", help="release e salute, solo letture e sanitizzato (NFR-AVL-002)")
    st.add_argument("--config", default="/etc/sovereignvpn/server.toml", help="configurazione (porta, subnet, WAN)")
    st.add_argument("--db", default=peer.DB_PREDEFINITO)
    st.add_argument("--json", action="store_true", help="rapporto in JSON")
    bk = sotto.add_parser("backup", help="backup cifrato con age (FR-OPS-001)")
    ba = bk.add_subparsers(dest="azione", required=True, parser_class=_Parser)
    bc = ba.add_parser("create", help="archivio cifrato con manifest e checksum; a schermo percorso e checksum")
    bc.add_argument("--config", default="/etc/sovereignvpn/server.toml")
    bc.add_argument("--recipient", help="chiave pubblica age; altrimenti backup_recipient della configurazione [H20]")
    bc.add_argument("--out", help="cartella di destinazione (0700); di base /var/lib/sovereignvpn/backup")
    bc.add_argument("--db", default=peer.DB_PREDEFINITO)
    bc.add_argument("--json", action="store_true")
    br = ba.add_parser("restore", help="restore transazionale: preflight, stato di prima salvato, verifica, ritorno indietro")
    br.add_argument("file", help="il backup .tar.age")
    br.add_argument("--identity", required=True, help="chiave privata age (tenuta fuori dal server)")
    br.add_argument("--conferma", action="store_true", help="il restore sovrascrive lo stato del server (FR-OPS-003)")
    br.add_argument("--config", default="/etc/sovereignvpn/server.toml")
    br.add_argument("--wan-interface", help="altrimenti wan_interface della configurazione ripristinata")
    br.add_argument("--out", help="dove salvare lo stato di prima; di base /var/lib/sovereignvpn/backup")
    br.add_argument("--db", default=peer.DB_PREDEFINITO)
    br.add_argument("--json", action="store_true")
    from . import dns
    dns.aggiungi_parser(sotto, _Parser)
    peer.aggiungi_parser(sotto, _Parser)
    peer.aggiungi_parser_firewall(sotto, _Parser)
    peer.aggiungi_parser_host(sotto, _Parser)
    a = p.parse_args(argv)
    if a.comando == "peer":
        return peer.esegui(a)
    if a.comando == "firewall":
        return peer.esegui_firewall(a)
    if a.comando == "host":
        return peer.esegui_host(a)
    if a.comando == "reconcile":
        return _ripristina(a)
    if a.comando == "dns":
        return dns.esegui(a)
    if a.comando == "profile":
        from . import profilo
        return profilo.esegui(a)
    if a.comando == "backup":
        from . import backup, ripristino
        return ripristino.esegui(a) if a.azione == "restore" else backup.esegui(a)
    if a.comando == "status":
        from . import stato
        return stato.esegui(a)
    try:
        cfg = configurazione.leggi(a.config) if a.config else {}
        valori, nomi = {}, {}
        for campo, da_cli in (("wg_port", a.wg_port), ("admin_port", a.admin_port), ("subnet", a.subnet)):
            if da_cli is None and campo in cfg:  # il file da' il valore, la riga di comando lo sovrascrive
                valori[campo], nomi[campo] = cfg[campo], f"config.{campo}"
            else:
                valori[campo] = da_cli
        imp = preflight.leggi_impostazioni(**valori, nomi=nomi)
    except preflight.InputNonValido as e:
        print(f"sovereignctl: input non valido: {registro.redigi(e)}", file=sys.stderr)  # ANC-0059: mai un segreto in uscita
        return 2
    try:
        fatti = preflight.raccogli(imp)
        controlli, rete = preflight.valuta(fatti, imp)
    except Exception as e:  # errore di sistema: si dice quale, senza dettagli interni sfruttabili
        print(f"sovereignctl: errore durante il preflight ({type(e).__name__})", file=sys.stderr)
        return 1
    falliti = [c for c in controlli if c["esito"] != "OK"]
    rapporto = {"versione": VERSIONE, "comando": "init --check", "mutazioni_eseguite": 0,
                "controlli_eseguiti": len(controlli), "superati": len(controlli) - len(falliti),
                "controlli": controlli, "piano": preflight.piano(imp, rete) if not falliti else []}
    if not falliti:  # FR-BOOT-002: il manifest si mostra in anteprima; lo scrive solo `init` vero
        try:
            from . import dns
            rapporto["manifest_anteprima"] = manifest.componi(fatti, a.config, immagini=dns.immagini())
        except manifest.ManifestNonValido as e:
            print(f"sovereignctl: security gate: {registro.redigi(e)}", file=sys.stderr)
            return 3  # ANC-0255: security gate fallito
    if a.config:  # il rapporto dice che cosa ha letto, senza l'hash del token
        rapporto["configurazione"] = {"file": a.config, "schema": configurazione.VERSIONE_SCHEMA,
                                      **{k: ("impostato" if k == "admin_token_hash" else v) for k, v in cfg.items()}}
    if a.apply:
        if falliti:
            print(f"sovereignctl: init --apply rifiutato: {len(falliti)} controlli FALLITO, niente toccato (vedi init --check)", file=sys.stderr)
            return 1
        wan = a.wan_interface or cfg.get("wan_interface")
        if not a.config or not wan:
            print("sovereignctl: input non valido: init --apply vuole --config e --wan-interface (o wan_interface nella config)", file=sys.stderr)
            return 2
        from . import bootstrap
        try:
            passi, errore = bootstrap.esegui(fatti, cfg, a.config, wan)
        except preflight.InputNonValido as e:  # WAN o sorgenti SSH sbagliate: rifiutate prima di toccare l'host
            print(f"sovereignctl: input non valido: {registro.redigi(e)}", file=sys.stderr)
            return 2
        rapporto.pop("mutazioni_eseguite", None)
        return _esito_passi(rapporto, "init --apply", passi, errore, a.json)
    if a.json:
        print(json.dumps(rapporto, ensure_ascii=False, indent=1))
    else:
        print(f"SovereignVPN {VERSIONE} — init --check (dry-run: nessuna mutazione)")
        if a.config:
            print(f"Configurazione: {a.config} (schema v{configurazione.VERSIONE_SCHEMA}, endpoint {cfg['endpoint']}, MTU {cfg['mtu']})")
        print(f"Controlli eseguiti: {len(controlli)} su {len(controlli)}; superati: {rapporto['superati']}; falliti: {len(falliti)}")
        for c in controlli:
            print(f"  [{c['esito']:7}] {c['nome']}: {c['dettaglio']}" + (f"\n            -> {c['rimedio']}" if c["rimedio"] else ""))
        if falliti:
            print("Piano non generato: prima vanno risolti i controlli FALLITO.")
        else:
            print("Piano (da approvare, niente e' stato eseguito):")
            for i, passo in enumerate(rapporto["piano"], 1):
                print(f"  {i}. {passo}")
            m = rapporto["manifest_anteprima"]
            print(f"Manifest (anteprima, non scritto): SovereignVPN {m['sovereignvpn']}, {m['os']}, kernel {m['kernel']}, "
                  f"schema v{m['schema_configurazione']}, configurazione {m['checksum_configurazione'] or 'non indicata'}")
    return 1 if falliti else 0


if __name__ == "__main__":
    sys.exit(main())
