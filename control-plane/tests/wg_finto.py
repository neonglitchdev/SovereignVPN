#!/usr/bin/env python3
"""Un `wg` finto per le prove sul Mac (sul runner Linux gira quello vero). Tiene lo stato in WG_FINTO_STATO (JSON),
annota argomenti in WG_FINTO_REGISTRO, e simula i guasti scritti nel file WG_FINTO_MODO_FILE. Le variabili le mette il
lanciatore `wg`: sovereignctl passa ai sottoprocessi un ambiente controllato (ANC-0344) e non le farebbe arrivare.
  syncconf-fallisce   syncconf esce con 1, niente applicato
  perde-un-peer       syncconf applica tutti i peer tranne il primo in ordine di chiave
  interfaccia-assente show esce con 1
"""
import json, os, sys

stato, registro = os.environ["WG_FINTO_STATO"], os.environ["WG_FINTO_REGISTRO"]
modo = open(os.environ["WG_FINTO_MODO_FILE"]).read().strip() if os.path.exists(os.environ["WG_FINTO_MODO_FILE"]) else ""
a = sys.argv[1:]
with open(registro, "a") as f:
    f.write(json.dumps(a) + "\n")
if a[:1] == ["syncconf"]:
    if modo == "syncconf-fallisce":
        print("Unable to modify interface: Operation not permitted", file=sys.stderr); sys.exit(1)
    conf, peer, chiave = sys.stdin.read(), {}, None
    for riga in conf.splitlines():
        k, _, v = (x.strip() for x in riga.partition("="))  # la chiave base64 finisce con «=»: si prende tutto dopo il primo
        if k == "PublicKey": chiave = v
        if k == "AllowedIPs": peer[chiave] = v
    if modo == "perde-un-peer" and peer:
        peer.pop(sorted(peer)[0])
    with open(stato, "w") as f:
        json.dump({"peer": peer, "chiave_privata_da_stdin": "PrivateKey = " in conf, "argomenti": a}, f)
elif a[:1] == ["show"] and a[2:3] == ["dump"]:
    if modo == "interfaccia-assente":
        print(f"Unable to access interface: No such device", file=sys.stderr); sys.exit(1)
    peer = json.load(open(stato))["peer"] if os.path.exists(stato) else {}
    print("(chiave privata nascosta)\tPUBBLICA\t51820\toff")
    for k, ips in peer.items():
        print(f"{k}\t(none)\t(none)\t{ips}\t0\t0\t0\toff")
else:
    print(f"wg finto: comando non previsto {a}", file=sys.stderr); sys.exit(2)
