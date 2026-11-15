#!/usr/bin/env python3
"""Attrezzi di rete per prova_traffico_vero.sh, solo libreria standard.
  ascolta tcp|udp INDIRIZZO PORTA FILE [BYTE]   crea FILE quando e' in ascolto, poi vi scrive una riga per
                                         connessione o datagramma: «sorgente» (tcp) o «sorgente testo» (udp); in tcp,
                                         dopo «ok» manda BYTE byte (una risposta grande, per le prove di MTU)
  scarica INDIRIZZO PORTA BYTE           esce 0 se riceve «ok» e poi BYTE byte entro 5 s, 1 altrimenti
  tcp INDIRIZZO PORTA [SORGENTE]         esce 0 se la connessione riesce e la risposta arriva, 1 altrimenti (2 s)
  udp INDIRIZZO PORTA TESTO              manda un datagramma: UDP non ha esito, lo dice il file dell'ascoltatore
"""
import socket, sys


def ascolta(proto, indirizzo, porta, file, grande=0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((indirizzo, porta))
    if proto == "tcp":
        s.listen()
    open(file, "a").close()  # pronto
    while True:
        if proto == "tcp":
            c, (sorgente, _) = s.accept()
            with c:
                with open(file, "a") as f:  # prima la riga, poi la risposta: chi riceve «ok» trova gia' la riga
                    f.write(sorgente + "\n")
                c.sendall(b"ok\n" + b"x" * grande)
        else:
            dati, (sorgente, _) = s.recvfrom(512)
            with open(file, "a") as f:
                f.write(f"{sorgente} {dati.decode(errors='replace')}\n")


def tcp(indirizzo, porta, sorgente=None):
    try:
        with socket.create_connection((indirizzo, porta), timeout=2,
                                      source_address=(sorgente, 0) if sorgente else None) as c:
            return 0 if c.recv(3) == b"ok\n" else 1
    except OSError:
        return 1


def scarica(indirizzo, porta, attesi):
    ricevuti = b""
    try:
        with socket.create_connection((indirizzo, porta), timeout=5) as c:
            while len(ricevuti) < attesi + 3:
                pezzo = c.recv(65536)
                if not pezzo:
                    break
                ricevuti += pezzo
    except OSError:
        pass
    return 0 if ricevuti == b"ok\n" + b"x" * attesi else 1


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["ascolta"] and len(a) in (5, 6) and a[1] in ("tcp", "udp"):
        ascolta(a[1], a[2], int(a[3]), a[4], *(int(x) for x in a[5:]))
    elif a[:1] == ["scarica"] and len(a) == 4:
        sys.exit(scarica(a[1], int(a[2]), int(a[3])))
    elif a[:1] == ["tcp"] and len(a) in (3, 4):
        sys.exit(tcp(a[1], int(a[2]), *a[3:]))
    elif a[:1] == ["udp"] and len(a) == 4:
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(a[3].encode(), (a[1], int(a[2])))
    else:
        sys.exit(__doc__)
