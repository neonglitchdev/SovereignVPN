"""Logging sanitizzato (Slice A, ANC-0346): niente chiavi, token, URL o IP pubblici nei log e nell'output (ANC-0059,
FR-OPS-002, NFR-SEC-004), ed eventi di audit coi soli campi ammessi (AuditEvent ANC-0232, NFR-SEC-005, ora UTC ANC-0239).

redigi(testo)      sostituisce i segreti e i dati vietati con un segnaposto che dice che cosa c'era
FiltroSanitizza    filtro per il logging della libreria standard: redige messaggio e argomenti prima dell'uscita
evento_audit(...)  un evento coi soli campi di ANC-0232, motivo redatto, JSON su una riga
"""
import datetime, ipaddress, json, logging, re, uuid

_PEM = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----", re.S)
_CHIAVE_WG = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=(?![A-Za-z0-9+/=])")  # 32 byte in base64
_PORTATORE = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")
_CAMPO_SEGRETO = re.compile(r"""(?ix)
    (["']?\b[\w-]*(?:token|password|passwd|secret|private[_-]?key|privatekey|presharedkey|psk|api[_-]?key)[\w-]*\b["']?
     \s*[:=]\s*)
    ("[^"]*"|'[^']*'|[^\s,;}&]+)""")
_HASH = re.compile(r"\b(?:scrypt|pbkdf2_sha256|argon2id)\$\S+")
_URL = re.compile(r"(?i)\b(?:https?|wss?|ftp)://[^\s\"'<>]+")
_IP = re.compile(r"(?<![\w.:])(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7})(?![\w.:])", re.I)


def _ip(m):
    try:
        return "[IP PUBBLICO REDATTO]" if ipaddress.ip_address(m.group(0)).is_global else m.group(0)
    except ValueError:
        return m.group(0)


def redigi(testo):
    """Il testo con segreti, URL e IP pubblici sostituiti. Gli indirizzi privati della VPN e della LAN restano."""
    t = _PEM.sub("[CHIAVE PRIVATA REDATTA]", str(testo))
    t = _CAMPO_SEGRETO.sub(lambda m: m.group(1) + "[REDATTO]", t)
    t = _PORTATORE.sub(lambda m: m.group(1) + " [REDATTO]", t)
    t = _HASH.sub("[HASH REDATTO]", t)
    t = _CHIAVE_WG.sub("[CHIAVE REDATTA]", t)
    t = _URL.sub("[URL REDATTO]", t)
    return _IP.sub(_ip, t)


class FiltroSanitizza(logging.Filter):
    """Si aggancia a un handler: il messaggio esce gia' composto e redatto, gli argomenti non arrivano piu' all'uscita."""

    def filter(self, record):
        record.msg = redigi(record.getMessage())
        record.args = ()
        if record.exc_info:  # una traccia puo' contenere segreti: si tiene solo il tipo dell'eccezione
            record.msg += f" [{record.exc_info[0].__name__}]"
            record.exc_info = record.exc_text = None
        return True


ESITI = {"success", "failure", "denied"}


def evento_audit(*, actor, action, target=None, outcome, request_id=None, reason=""):
    """AuditEvent di ANC-0232. Solo argomenti con nome: un campo in piu' (url, query, ip, payload...) e' un TypeError."""
    if outcome not in ESITI:
        raise ValueError(f"outcome deve essere uno di {sorted(ESITI)}")
    if target is not None:
        target = str(uuid.UUID(str(target)))  # il bersaglio e' un UUID, mai un nome o un percorso (ANC-0238)
    return json.dumps({
        "id": str(uuid.uuid4()),
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "actor": redigi(actor), "action": redigi(action), "target": target, "outcome": outcome,
        "request_id": redigi(request_id) if request_id else None, "reason": redigi(reason),
    }, ensure_ascii=False)
