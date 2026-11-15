"""sovereignctl — CLI del control plane. Per ora: `init --check` (Slice A, ANC-0346).

Codici di uscita (ANC-0255): 0 successo; 1 errore runtime/sistema (anche un prerequisito mancante [H3]);
2 input o schema non valido; 3 security gate fallito; 4 applicato in parte, serve recovery.
Uso: python3 -m sovereignctl init --check [--config server.toml] [--wg-port N] [--admin-port N] [--subnet CIDR] [--json]
"""
import argparse, json, sys

from . import VERSIONE, configurazione, preflight


class _Parser(argparse.ArgumentParser):
    def error(self, message):  # argparse esce con 2 di suo: qui si tiene il codice e si nomina la voce
        self.print_usage(sys.stderr)
        print(f"sovereignctl: input non valido: {message}", file=sys.stderr)
        sys.exit(2)


def main(argv=None):
    p = _Parser(prog="sovereignctl", description=f"SovereignVPN {VERSIONE} — control plane")
    sotto = p.add_subparsers(dest="comando", required=True, parser_class=_Parser)
    init = sotto.add_parser("init", help="preflight e bootstrap")
    init.add_argument("--check", action="store_true", required=True, help="solo preflight e piano, nessuna mutazione")
    init.add_argument("--wg-port"); init.add_argument("--admin-port"); init.add_argument("--subnet")
    init.add_argument("--config", help="file TOML della configurazione, schema v1 (config/examples/server.toml)")
    init.add_argument("--json", action="store_true", help="rapporto in JSON")
    a = p.parse_args(argv)
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
        print(f"sovereignctl: input non valido: {e}", file=sys.stderr)
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
    if a.config:  # il rapporto dice che cosa ha letto, senza l'hash del token
        rapporto["configurazione"] = {"file": a.config, "schema": configurazione.VERSIONE_SCHEMA,
                                      **{k: ("impostato" if k == "admin_token_hash" else v) for k, v in cfg.items()}}
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
    return 1 if falliti else 0


if __name__ == "__main__":
    sys.exit(main())
