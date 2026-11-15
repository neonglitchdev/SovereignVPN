#!/usr/bin/env python3
"""Banco dei mutanti del control plane: le prove valgono solo se un guasto vero le fa diventare rosse
e un cambiamento innocuo le lascia verdi.
Uso, da control-plane/: python3 tests/mutanti.py      (esce 0 solo se tutti i guasti sono presi e tutti gli innocui sopravvivono)

Ogni mutante gira su una copia in una cartella temporanea propria, tolta alla fine. Il codice di uscita di unittest
si controlla: 0 = verde, 1 = prove rosse; qualunque altro valore e' un guasto dello strumento e ferma il banco.
"""
import pathlib, shutil, subprocess, sys, tempfile

QUI = pathlib.Path(__file__).resolve().parents[1]  # control-plane/
GUASTI = {  # devono essere PRESI: almeno una prova rossa
    "il controllo del sistema dice sempre OK": ("preflight.py", "(sist, ver) in SISTEMI, f\"{sist} {ver}\"", "True, f\"{sist} {ver}\""),
    "nessun controllo dell'intervallo della porta": ("preflight.py", "if not 1 <= n <= 65535:", "if False:"),
    "IPAM che ignora le collisioni": ("preflight.py", "return str(rete), [str(o) for o in occupate if o.overlaps(rete)]", "return str(rete), []"),
    "il preflight scrive un file": ("preflight.py", "    os_rel = {}\n", "    os_rel = {}\n    open('/tmp/sovereign-mutante', 'w').close()\n"),
    "zero reti lette passa come nessuna collisione": ("preflight.py", "    if not fatti[\"reti_host\"]:", "    if False:"),
    "chiavi sconosciute accettate": ("configurazione.py", "sconosciuti = sorted(set(dati) - CAMPI)", "sconosciuti = []"),
    "il segreto finisce nell'errore": ("configurazione.py", "raise _errore(k, \"un segreto in chiaro", "raise _errore(k, f\"{dati[k]} un segreto in chiaro"),
    "MTU senza limiti": ("configurazione.py", "not 1280 <= mtu <= 1500", "False"),
    "la CLI ignora il file di configurazione": ("__main__.py", "if da_cli is None and campo in cfg:", "if False:"),
    "le chiavi WireGuard non vengono redatte": ("registro.py", "    t = _CHIAVE_WG.sub(\"[CHIAVE REDATTA]\", t)\n", ""),
    "il filtro lascia passare gli argomenti": ("registro.py", "        record.msg = redigi(record.getMessage())\n        record.args = ()\n", ""),
    "il manifest accetta segreti e URL": ("manifest.py", "    if redigi(testo) != testo:", "    if False:"),
    "il manifest accetta il tag latest": ("manifest.py", "        if nome.endswith(\":latest\"):", "        if False:"),
    "scrittura diretta sul file vero, non atomica": ("manifest.py", "fd, tmp = tempfile.mkstemp(prefix=\".manifest-\", dir=cartella)", "fd, tmp = os.open(percorso, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644), percorso"),
    "il dry-run dell'installer muta": ("ops/install.sh", 'if [ "$DRY" -eq 1 ]; then\n  echo "install.sh --dry-run:', 'if false; then\n  echo "install.sh --dry-run:'),
    "il dry-run dell'uninstall muta": ("ops/install.sh", 'if [ "$DRY" -eq 1 ]; then\n    echo "install.sh --uninstall --dry-run:', 'if false; then\n    echo "install.sh --uninstall --dry-run:'),
    "l'installer ignora il lucchetto": ("ops/install.sh", '\nmkdir "$LUCCHETTO" 2>/dev/null ||', '\nmkdir -p "$LUCCHETTO" 2>/dev/null ||'),
    "l'uninstall ignora il lucchetto": ("ops/install.sh", '\n  mkdir "$LUCCHETTO" 2>/dev/null ||', '\n  mkdir -p "$LUCCHETTO" 2>/dev/null ||'),
    "configurazione leggibile da tutti": ("ops/install.sh", 'chmod 0700 "$ETC" "$VAR"', 'chmod 0755 "$ETC" "$VAR"'),
    "unita' systemd scrivibili da tutti": ("ops/install.sh", 'install -m 0644 "$SORGENTE_UNITA/$u"', 'install -m 0666 "$SORGENTE_UNITA/$u"'),
    "input non valido dell'installer esce con 1": ("ops/install.sh", 'echo "install.sh: input non valido: $1" >&2; exit 2; }', 'echo "install.sh: input non valido: $1" >&2; exit 1; }'),
    "un peer scaduto si riattiva": ("peer.py", '("SUSPENDED", "resume"): "ACTIVE",', '("SUSPENDED", "resume"): "ACTIVE", ("EXPIRED", "resume"): "ACTIVE",'),
    "la scadenza ignora l'ora": ("peer.py", "adesso = adesso or ora()", 'adesso = "9999-12-31T23:59:59Z"'),
    "la scadenza tocca anche i revocati": ("peer.py", 'nuovo = TRANSIZIONI.get((s, "expire"))', 'nuovo = TRANSIZIONI.get((s, "expire"), "EXPIRED")'),
    "scadenza senza audit": ("peer.py", '                    self.audit(c, "peer.expire", "success", i)\n', ""),
    "la revoca torna indietro": ("peer.py", '    ("ERROR", "revoke"): "REVOKED",\n', '    ("ERROR", "revoke"): "REVOKED", ("REVOKED", "resume"): "ACTIVE",\n'),
    "nomi confrontati con le maiuscole": ("peer.py", "return n, n.casefold()", "return n, n"),
    "chiave di lunghezza qualunque": ("peer.py", "if len(grezza) != 32 or ", "if False or "),
    "il server perde il suo indirizzo": ("peer.py", "host = list(rete.hosts())[1:]", "host = list(rete.hosts())"),
    "il rinomina rimette il peer in riconciliazione": ("peer.py", '"UPDATE peer SET nome = ?, nome_chiave = ? WHERE id = ?"', '"UPDATE peer SET nome = ?, nome_chiave = ?, saga = \'PENDING_APPLY\' WHERE id = ?"'),
    "il rinomina non guarda i nomi degli altri": ("peer.py", '"SELECT 1 FROM peer WHERE nome_chiave = ? AND id != ?"', '"SELECT 1 FROM peer WHERE 0 AND nome_chiave = ? AND id != ?"'),
    "il rinomina si scontra con se' stesso": ("peer.py", 'nome_chiave = ? AND id != ?", (nome_chiave, p["id"])', 'nome_chiave = ?", (nome_chiave,)'),
    "rinomina senza audit": ("peer.py", '                self.audit(c, "peer.rename", "success", p["id"])\n', "                pass\n"),
    "l'uninstall cancella i dati senza scelta": ("ops/install.sh", '  if [ "$ELIMINA" -eq 1 ]; then\n    rm -rf "$ETC" "$VAR"', '  rm -rf "$ETC" "$VAR"\n  if [ "$ELIMINA" -eq 1 ]; then'),
    "l'uninstall cancella i dati senza conferma": ("ops/install.sh", 'if [ "$ELIMINA" -eq 1 ] && [ "$CONFERMA" -eq 0 ]; then', "if false; then"),
    "l'uninstall toglie le unita' di altri": ("ops/install.sh", 'for u in "${UNITA_NOMI[@]}"; do rm -f "$UNITA/$u"; done', 'rm -f "$UNITA"/*'),
    "l'uninstall lascia il control plane": ("ops/install.sh", '  rm -f "$BIN/sovereignctl"\n  rm -rf "$OPT"\n', '  rm -f "$BIN/sovereignctl"\n'),
    "registro illeggibile senza recupero": ("bootstrap.py", "    except sqlite3.Error:\n        per_peer, recupero = ((), (), ()), True", "    except sqlite3.Error:\n        per_peer, recupero = ((), (), ()), False"),
    "recupero senza fermare il traffico dei peer": ("firewall.py", """*([f'    iifname "{wg_if}" drop', f'    oifname "{wg_if}" drop'] if recupero else []),""", "*([] if recupero else []),"),
    "recupero che riconcilia lo stesso": ("bootstrap.py", "        if recupero:  # mai un peer", "        if False:  # mai un peer"),
    "un registro bloccato passa per schema vecchio": ("peer.py", 'return getattr(e, "sqlite_errorname", "") == "SQLITE_ERROR"', "return True"),
    "status cade col registro illeggibile": ("stato.py", "    except (RuntimeError, ValueError, KeyError, sqlite3.Error, OSError) as e:  # [H41]", "    except (RuntimeError, ValueError, KeyError) as e:  # [H41]"),
    "audit: un FAIL P0 esce con 1": ("audit.py", 'return 3 if any(x["severita"] == "P0" for x in falliti)', 'return 1 if any(x["severita"] == "P0" for x in falliti)'),
    "audit: SKIPPED contato come PASS": ("audit.py", 'metti(ident, sev, req, nome, ("SKIPPED", "DNS interno non applicato su questo host", "sovereignctl dns apply"))', 'metti(ident, sev, req, nome, ("PASS", "DNS interno non applicato su questo host", "sovereignctl dns apply"))'),
    "audit: porta DNS esposta declassata (T-016)": ("audit.py", '"porte": ("AUD-10", "P0"', '"porte": ("AUD-10", "P1"'),
    "audit: recupero del firewall non visto": ("audit.py", """    elif f'iifname "{wg_if}" drop' in tabella:""", "    elif False:"),
    "audit: amministrazione ammessa ovunque": ("audit.py", 'not in ("127.0.0.1", "::1", server)', 'not in ("127.0.0.1", "::1", server, "0.0.0.0")'),
    "audit: peer scaduti non contati": ("audit.py", "WHERE scade IS NOT NULL AND scade < ?", "WHERE scade IS NOT NULL AND scade > ?"),
    "audit: file leggibili da altri non visti": ("audit.py", 'and not os.path.islink(p) and _modo(p) & 0o077:', 'and not os.path.islink(p) and False:'),
    "status cade senza nft": ("stato.py", "sqlite3.Error, OSError) as e:  # [H41]", "sqlite3.Error) as e:  # [H41]"),
    "diagnostica: endpoint non redatto": ("diagnostica.py", 'REDATTI = ("endpoint", "admin_ssh_sources",', 'REDATTI = ("admin_ssh_sources",'),
    "diagnostica: estesa senza conferma": ("diagnostica.py", "    if a.extended and not a.conferma:", "    if False:"),
    "diagnostica: scan dei segreti spento": ("diagnostica.py", "    if colpevoli:\n        raise SegretoNelBundle", "    if False:\n        raise SegretoNelBundle"),
    "diagnostica: indirizzi della VPN nei log": ("diagnostica.py", "    return registro._IP.sub(sostituisci, testo)", "    return testo"),
    "diagnostica: una raccolta sopra l'altra": ("diagnostica.py", "    while os.path.exists(percorso):", "    while False:"),
    "diagnostica: i log redatti a meta'": ("diagnostica.py", "    return {n: redigi_vpn(registro.redigi(t), cfg).encode", "    return {n: redigi_vpn(t, cfg).encode"),
    "Unbound senza sola lettura": ("dns.py", 'VINCOLI_UNBOUND = ("--read-only", "--cap-drop", "ALL",', 'VINCOLI_UNBOUND = ("--cap-drop", "ALL",'),
    "Unbound col pidfile": ("dns.py", """'  chroot: ""', '  pidfile: ""',""", """'  chroot: ""',"""),
    "vincoli: sola lettura non controllata": ("audit.py", 'mancano = (["read-only"] if "--read-only" in attesi and not hc.get("ReadonlyRootfs") else [])', "mancano = []"),
    "vincoli: capability in piu' non viste": ("audit.py", """    mancano += [f"cap-add {c} in piu'" for c in sorted(cap(hc.get("CapAdd")) - cap(voluti["cap-add"]))]\n""", ""),
    "Pi-hole con no-new-privileges": ("dns.py", '"--cap-add", "SETFCAP")', '"--cap-add", "SETFCAP", "--security-opt", "no-new-privileges")'),
    "Pi-hole con tutte le capability": ("dns.py", 'VINCOLI_PIHOLE = ("--cap-drop", "ALL", ', 'VINCOLI_PIHOLE = ('),
    "transizione respinta senza audit": ("peer.py", 'self.audit(c, f"peer.{azione}", "denied", p["id"], f"transizione non valida da {stato}")', "pass"),
    "il sospeso resta nel runtime": ("runtime.py", 'NEL_RUNTIME = ("PENDING", "ACTIVE")', 'NEL_RUNTIME = ("PENDING", "ACTIVE", "SUSPENDED")'),
    "chiave del server leggibile accettata": ("runtime.py", "    if modo & 0o077:", "    if False:"),
    "nessuna verifica del runtime": ("runtime.py", "coincide = vivi == attesi", "coincide = True"),
    "un cambio nel frattempo sovrascritto": ("runtime.py", "AND stato = ? AND saga = 'PENDING_APPLY'", "AND ? IS NOT NULL"),
    "forward aperto": ("firewall.py", "type filter hook forward priority filter; policy drop;", "type filter hook forward priority filter; policy accept;"),
    "peer non isolati": ("firewall.py", '          f\'    iifname "{wg_if}" oifname "{wg_if}" drop\',\n', ""),
    "SSH aperto a tutti": ("firewall.py", 'r.append(f"    ip saddr {{ {v4} }} tcp dport {int(ssh_port)} accept")', 'r.append(f"    ip saddr {{ 0.0.0.0/0 }} tcp dport {int(ssh_port)} accept")'),
    "IPv6 dei peer non respinto": ("firewall.py", "meta nfproto ipv6 reject with icmpv6 type admin-prohibited", "meta nfproto ipv6 accept"),
    "DNS esterno dei peer non bloccato": ("firewall.py", 'meta l4proto {{ tcp, udp }} th dport 53 drop', 'meta l4proto {{ tcp, udp }} th dport 53 accept'),
    "rp_filter imposto globalmente": ("host.py", '"net.ipv6.conf.default.forwarding": "0"}', '"net.ipv6.conf.default.forwarding": "0", "net.ipv4.conf.all.rp_filter": "1"}'),
    "inoltro IPv6 acceso": ("host.py", '"net.ipv6.conf.all.forwarding": "0"', '"net.ipv6.conf.all.forwarding": "1"'),
    "verifica dei sysctl che dice sempre si'": ("host.py", '"verificato": letti == VALORI}', '"verificato": True}'),
    "id dell'installazione rigenerato": ("bootstrap.py", "id_installazione=vecchio or str(uuid.uuid4())", "id_installazione=str(uuid.uuid4())"),
    "chiave del server rigenerata sopra quella esistente": ("bootstrap.py", "    if os.path.exists(percorso):\n        return False\n    os.makedirs(os.path.dirname(percorso), mode=0o700", "    os.makedirs(os.path.dirname(percorso), mode=0o700"),
    "la WAN si valida dopo aver toccato l'host": ("bootstrap.py", '    regole = firewall.componi(rete, wg_if, porta, wan_if, cfg.get("admin_port", 8443), cfg.get("ssh_port", 22), cfg.get("admin_ssh_sources"), cfg.get("mtu", 1420), cfg.get("dns_block_dot", True), *per_peer,\n                              recupero=recupero)\n\n    def _firewall():\n        ok = _verificato("firewall", firewall.applica(regole)["verificato"])', '    def _firewall():\n        ok = _verificato("firewall", firewall.applica(firewall.componi(rete, wg_if, porta, wan_if, cfg.get("admin_port", 8443), cfg.get("ssh_port", 22), cfg.get("admin_ssh_sources"), cfg.get("mtu", 1420), cfg.get("dns_block_dot", True), *per_peer,\n                              recupero=recupero))["verificato"])'),
    "al riavvio il firewall dopo l'interfaccia": ("bootstrap.py", 'AL_RIAVVIO = ("firewall", "sysctl", "interfaccia", "riconciliazione")', 'AL_RIAVVIO = ("sysctl", "interfaccia", "firewall", "riconciliazione")'),
    "al riavvio si rigenera la chiave": ("bootstrap.py", "return _sequenza([(n, rete[n]) for n in AL_RIAVVIO])", "return _sequenza([(\"chiave\", chiave_server), *((n, rete[n]) for n in AL_RIAVVIO)])"),
    "al riavvio gira il preflight": ("__main__.py", "        passi, errore = bootstrap.ripristina(cfg, wan)\n", "        preflight.raccogli({})\n        passi, errore = bootstrap.ripristina(cfg, wan)\n"),
    "chiave esposta trattata come un guasto qualunque": ("__main__.py", "return 3 if isinstance(errore, runtime.ChiaveEsposta) else", "return 4 if isinstance(errore, runtime.ChiaveEsposta) else"),
    "init --apply ignora le verifiche": ("bootstrap.py", "    if ok is not True:", "    if False:"),
    "profilo con l'IPv6 fuori dal tunnel": ("profilo.py", 'else "0.0.0.0/0, ::/0")]', 'else "0.0.0.0/0")]'),
    "profilo esportato senza conferma": ("profilo.py", "    if not a.conferma:", "    if False:"),
    "profilo di un peer revocato": ("profilo.py", 'if p["stato"] in ("REVOKED", "EXPIRED"):', "if False:"),
    "profilo leggibile da altri": ("profilo.py", "manifest.scrivi_testo(percorso, testo, 0o600)", "manifest.scrivi_testo(percorso, testo, 0o644)"),
    "keepalive sempre acceso": ("profilo.py", "    if keepalive:\n", "    if True:\n"),
    "la porta di un'altra wg0 passa per nostra": ("preflight.py", 'not libera and bool(fatti.get("installato")) and', "not libera and"),
    "la rete di wg0 sempre esclusa": ("preflight.py", '            if itf.get("ifname") == escludi:', '            if itf.get("ifname") in (escludi, "wg0"):'),
    "status dice sempre OK": ("stato.py", "    return 0 if superati == len(controlli) else 1", "    return 0"),
    "status non confronta i peer": ("stato.py", 'esito("peer", diverse == 0,', 'esito("peer", True,'),
    "status non conta le regole del firewall": ("stato.py", 'ok = t["verificato"] and dichiarate in (None, t["regole"])', 'ok = t["verificato"]'),
    "status senza security gate sulla chiave": ("stato.py", "    if esposta:\n        return 3\n", ""),
    "status non guarda la porta": ("stato.py", "    elif ascolto != porta:", "    elif False:"),
    "MSS non abbassata verso la WAN": ("firewall.py", "tcp option maxseg size set {int(mtu) - 40}", "tcp option maxseg size set rt mtu"),
    "MSS verso il peer tolta": ("firewall.py", """          f'    iifname "{wan_if}" oifname "{wg_if}" tcp flags syn / syn,rst tcp option maxseg size set rt mtu',\n""", ""),
    "il backup tralascia la chiave del server": ("backup.py", '                           ("etc/sovereignvpn/wg-server.key", runtime.CHIAVE_SERVER),\n', ""),
    "backup leggibile da altri": ("backup.py", "        os.chmod(tmp, 0o600)", "        os.chmod(tmp, 0o644)"),
    "manifest del backup senza checksum": ("backup.py", '"sha256": hashlib.sha256(b).hexdigest()', '"sha256": ""'),
    "backup verso un destinatario qualunque": ("backup.py", 'if not configurazione.DESTINATARIO_AGE.match(destinatario or ""):', "if not destinatario:"),
    "registro nel backup col flag WAL": ("backup.py", "    dati[18] = dati[19] = 1", "    pass"),
    "restore senza controllo dei checksum": ("ripristino.py", "    if diversi:\n", "    if False:\n"),
    "restore che accetta voci estranee": ("ripristino.py", "            if estranei:\n", "            if False:\n"),
    "restore senza tornare indietro": ("ripristino.py", "        if prima:  # si torna indietro", "        if False:  # si torna indietro"),
    "restore senza salvare lo stato di prima": ("ripristino.py", "    if prima:  # lo stato corrente", "    if False:  # lo stato corrente"),
    "WAL vecchio lasciato sul registro nuovo": ("ripristino.py", '            for coda in ("-wal", "-shm"):', "            for coda in ():"),
    "restore senza conferma": ("ripristino.py", "    if not a.conferma:\n", "    if False:\n"),
    "Unbound con un forwarder pubblico": ("dns.py", '             "  # ricorsione dalle radici, nessuna forward-zone (cap. 6); DNSSEC validato",', '             "forward-zone:", \'  name: "."\', "  forward-addr: 1.1.1.1",'),
    "Unbound che registra le query": ("dns.py", '"  log-queries: no"', '"  log-queries: yes"'),
    "Unbound in ascolto ovunque": ("dns.py", 'f"  interface: 127.0.0.1@{porta}"', 'f"  interface: 0.0.0.0@{porta}"'),
    "immagine con un tag mobile": ("ops/dns/unbound/Dockerfile", "FROM debian:12-slim@sha256:", "FROM debian:latest\n# era debian:12-slim@sha256:"),
    "Pi-hole in ascolto su tutte le interfacce": ("dns.py", '"FTLCONF_dns_listeningMode": "BIND"', '"FTLCONF_dns_listeningMode": "ALL"'),
    "Pi-hole che registra le query": ("dns.py", '"FTLCONF_dns_queryLogging": "false"', '"FTLCONF_dns_queryLogging": "true"'),
    "Pi-hole con un upstream pubblico": ("dns.py", 'f"127.0.0.1#{porta_unbound}"', 'f"127.0.0.1#{porta_unbound};1.1.1.1"'),
    "password del pannello rigenerata": ("dns.py", "    if not os.path.exists(segreto):\n        fd = os.open(segreto, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)", "    if True:\n        fd = os.open(segreto, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)"),
    "ambiente di Pi-hole leggibile da altri": ("dns.py", 'for k, v in pihole_env(wg_if).items()), 0o600)', 'for k, v in pihole_env(wg_if).items()), 0o644)'),
    "unita' di Pi-hole con un'altra immagine": ("ops/systemd/sovereignvpn-pihole.service", "@sha256:30f803ad", "@sha256:00f803ad"),
    "status non guarda il DNS applicato": ("stato.py", "    if dns_applicato():  # NFR-AVL-002", "    if False:  # NFR-AVL-002"),
    "domanda DNS che accetta un errore": ("stato.py", "and (r[3] & 0x0F) == 0", "and True"),
    "DoT dei peer non bloccato": ("firewall.py", "    iifname \"{wg_if}\" tcp dport 853 reject with tcp reset", "    iifname \"{wg_if}\" tcp dport 853 accept"),
    "blocco DoT ignorato dalla configurazione": ("firewall.py", "] if blocca_dot else []),", "] if True else []),"),
    "ascolto fuori inventario ignorato": ("stato.py", "        if processo in ammessi and (indirizzo, int(porta)) not in ammessi[processo]:", "        if False:"),
    "lista invalida attivata lo stesso": ("liste.py", "    if errori or not domini:", "    if not domini:"),
    "indirizzi IP accettati come domini": ("liste.py", "            ipaddress.ip_address(r)\n", "            raise ValueError\n"),
    "rollback che non torna indietro": ("liste.py", 'return _attiva(cartella, vecchio["attiva"],', 'return _attiva(cartella, prima["attiva"],'),
    "Pi-hole con il server NTP acceso": ("dns.py", '"FTLCONF_ntp_ipv4_active": "false"', '"FTLCONF_ntp_ipv4_active": "true"'),
    "permessi registrati come blocco": ("liste.py", '"allowlist": 1}  # colonna `type`', '"allowlist": 0}  # colonna `type`'),
    "conflitti fra permessi e blocchi non segnalati": ("liste.py", '"conflitti": comuni[:50],', '"conflitti": [],'),
    "manifest senza immagini": ("bootstrap.py", ", immagini=dns.immagini())", ")"),
    "base di Unbound diversa dal Dockerfile": ("dns.py", 'BASE_UNBOUND = "debian:12-slim@sha256:734a', 'BASE_UNBOUND = "debian:12-slim@sha256:004a'),
    "il rollback non rimette la release precedente": ("ops/install.sh", '  mv "$OPT/sovereignctl.precedente" "$OPT/sovereignctl"\n', '  cp -R "$OPT/sovereignctl.scambio" "$OPT/sovereignctl"\n'),
    "la release precedente si butta": ("ops/install.sh", '  mv "$OPT/sovereignctl" "$OPT/sovereignctl.precedente"\n', '  rm -rf "$OPT/sovereignctl"\n'),
    "migrazione senza copia prima": ("peer.py", "                self.db.backup(dest)  # copia coerente", "                pass  # copia coerente"),
    "migrazione che non aggiorna la versione": ("peer.py", '            c.execute("UPDATE schema SET versione = ?", (VERSIONE_SCHEMA_DB,))', "            pass"),
    "rotte sovrapposte alla VPN accettate": ("peer.py", " or r.overlaps(ipaddress.ip_network(rete)):", ":"),
    "profilo full-tunnel anche con le rotte": ("profilo.py", 'if p.get("rotte") else "0.0.0.0/0, ::/0")]', 'if False else "0.0.0.0/0, ::/0")]'),
    "rotte del peer non applicate al firewall": ("firewall.py", ' } drop" for ind, rotte in limiti],', ' } drop" for ind, rotte in ()],'),
    "DNS libero ignorato dal firewall": ("firewall.py", "th dport 53 accept' for ind in dns_liberi],", "th dport 53 accept' for ind in ()],"),
    "politica DNS qualunque accettata": ("peer.py", '        if politica_dns not in (None, "interno", "libero"):', "        if False:"),
    "quota che riparte da zero a ogni reconcile": ("firewall.py", "bytes used {int(usati or 0)} bytes }}", "bytes used 0 bytes }}"),
    "byte usati della quota non salvati": ("peer.py", "    if salva and esito:", "    if False:"),
    "quota contata in un verso solo": ("firewall.py", """,
                                               f'    oifname "{wg_if}" ip daddr {ipaddress.ip_address(ind)} quota name "{_nome_quota(ind)}" drop')],""", ",)],"),
    "IPv6 del peer fuori dal runtime": ("runtime.py", 'return ",".join(sorted((f"{ipv4}/32", f"{indirizzo6(subnet6, ipv4)}/128")))', 'return f"{ipv4}/32"'),
    "ordine degli AllowedIPs del kernel confrontato": ("runtime.py", 'vivi[campi[0]] = ",".join(sorted(x.strip() for x in campi[3].split(",")))', "vivi[campi[0]] = campi[3]"),
    "peer reconcile ignora la subnet6 della configurazione": ("peer.py", 'subnet6 = configurazione.leggi(a.config)["subnet6"]', "subnet6 = configurazione.SUBNET6"),
    "subnet6 dove l'IPv4 non ci sta": ("configurazione.py", "r6.prefixlen > 96:", "r6.prefixlen > 120:"),
    "wg0 senza IPv6 ULA": ("bootstrap.py", '    _cmd("ip", "address", "replace", server6, "dev", nome)\n', ""),
    "IPv6 di wg0 lasciato spento": ("bootstrap.py", '    _cmd("sysctl", "-qw", f"net/ipv6/conf/{nome}/disable_ipv6=0")', "    pass"),
    "profilo senza IPv6 nel tunnel": ("profilo.py", "/32, {runtime.indirizzo6(cfg['subnet6'], p['indirizzo'])}/128\"", "/32\""),
    "rifiuto IPv6 dopo l'instradamento": ("firewall.py", '"    type filter hook prerouting priority filter; policy accept;",', '"    type filter hook forward priority filter; policy accept;",'),
    "ULA del server fuori dall'inventario": ("stato.py", "(server, 53), (server6, 53),", "(server, 53),"),
    "status con l'ULA di un altro prefisso": ("stato.py", 'runtime.indirizzo6(cfg["subnet6"], server)', 'runtime.indirizzo6("fd00::/64", server)'),
    "init --apply ignora il preflight":("__main__.py", "        if falliti:\n            print(f\"sovereignctl: init --apply rifiutato", "        if False:\n            print(f\"sovereignctl: init --apply rifiutato"),
    "redazione per eccesso: anche gli IP privati": ("registro.py", "if ipaddress.ip_address(m.group(0)).is_global else", "if True else"),
}
INNOCUI = {  # devono SOPRAVVIVERE: stesso comportamento, prove verdi
    "un rimedio detto con altre parole": ("preflight.py", "\"Liberare spazio: servono almeno", "\"Fare spazio: servono almeno"),
    "un segnaposto detto con altre parole": ("registro.py", "\"[URL REDATTO]\"", "\"[INDIRIZZO WEB REDATTO]\""),
    "un messaggio dell'installer detto con altre parole": ("ops/install.sh", "Prossimo passo:", "Passo successivo:"),
    "un messaggio del registro detto con altre parole": ("peer.py", "riprovare (CONFLICT)", "ritentare (CONFLICT)"),
    "un messaggio della riconciliazione detto con altre parole": ("runtime.py", "va creata da `init`", "la crea `init`"),
    "un messaggio del firewall detto con altre parole": ("firewall.py", "niente applicato (", "nulla applicato ("),
    "un commento del profilo detto con altre parole": ("profilo.py", "dove il server lo rifiuta subito", "dove il server lo respinge subito"),
    "una variabile locale rinominata": ("preflight.py", "    gib = fatti[\"disco_libero\"] / 1024 ** 3\n", "    giga = fatti[\"disco_libero\"] / 1024 ** 3\n    gib = giga\n"),
}


def prova(file, da, a):
    with tempfile.TemporaryDirectory(prefix="mutante-") as t:
        repo = pathlib.Path(t) / "repo"  # tutta la repo senza .git: i mutanti possono toccare anche ops/ e config/
        shutil.copytree(QUI.parent, repo, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        copia = repo / "control-plane"
        f = repo / file if "/" in file else copia / "sovereignctl" / file
        testo = f.read_text(encoding="utf-8")
        if testo.count(da) != 1:
            sys.exit(f"GUASTO DEL BANCO: punto di mutazione non univoco in {file}: {da[:60]!r}")
        f.write_text(testo.replace(da, a), encoding="utf-8")
        r = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests"], cwd=copia, capture_output=True, text=True)
        if r.returncode not in (0, 1):
            sys.exit(f"GUASTO DEL BANCO: unittest e' uscito con {r.returncode}\n{r.stderr[-800:]}")
        rosse = [l.split("(")[0].split(": ", 1)[-1].strip() for l in r.stderr.splitlines() if l.startswith(("FAIL:", "ERROR:"))]
        return r.returncode, rosse


if __name__ == "__main__":
    base, rosse = prova("__init__.py", "VERSIONE", "VERSIONE")  # nessun cambiamento: la suite di partenza dev'essere verde
    if base != 0:
        sys.exit(f"GUASTO DEL BANCO: la suite senza mutazioni e' rossa ({', '.join(rosse)})")
    presi = 0
    for nome, (file, da, a) in GUASTI.items():
        codice, rosse = prova(file, da, a)
        presi += codice == 1
        print(f"{'PRESO      ' if codice == 1 else 'SFUGGITO   '} {nome}: {len(rosse)} prove rosse — {', '.join(rosse)[:150]}")
    vivi = 0
    for nome, (file, da, a) in INNOCUI.items():
        codice, rosse = prova(file, da, a)
        vivi += codice == 0
        print(f"{'SOPRAVVIVE ' if codice == 0 else 'UCCISO     '} {nome} (innocuo){': ' + ', '.join(rosse) if rosse else ''}")
    print(f"guasti presi: {presi} su {len(GUASTI)}; innocui sopravvissuti: {vivi} su {len(INNOCUI)}")
    sys.exit(0 if presi == len(GUASTI) and vivi == len(INNOCUI) else 1)
