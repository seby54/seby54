#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bloc-notes Pro — éditeur de texte façon Notepad++, pour le Mac du travail
(fonctionne aussi sous Windows).

* Même environnement que l'explorateur : PySide6-Essentials + bibliothèque standard.
* Aucun accès réseau : un verrou (« audit hook » Python, impossible à retirer une fois
  posé) bloque sockets, HTTP et modules réseau, interdit de lancer des commandes
  (sauf ton explorateur maison pour « Ouvrir le dossier ») et refuse toute
  bibliothèque native chargée à la main.
* Session et copies de sécurité restent dans un dossier privé de ton compte.

Lancement :  ~/mac/explorer/venv/bin/python ~/mac/explorer/blocnotes.py [fichiers…]
"""

import base64
import codecs
import datetime
import difflib
import fnmatch
import hashlib
import json
import os
import re
import sys
import threading
import time
import unicodedata

APP_NAME = "Bloc-notes Pro"
VERSION = "1.1"          # à augmenter à chaque modification
VERSION_DATE = "26/11/2026"
ORG_NAME = "explorateur-maison"
IS_MAC = sys.platform == "darwin"
IS_WIN = sys.platform.startswith("win")
HERE = os.path.dirname(os.path.abspath(__file__))
BIG_FILE = 16 * 1024 * 1024        # au-delà : mode allégé (sans coloration ni repli)
HUGE_FILE = 200 * 1024 * 1024      # au-delà : on n'ouvre pas
sys.setrecursionlimit(max(sys.getrecursionlimit(), 6000))


def version_details():
    """Version du script, de Python et de PySide6 (pour comparer avec un collègue)."""
    try:
        import PySide6
        qt = PySide6.__version__
    except ImportError:
        qt = "absent"
    return f"{APP_NAME} {VERSION} du {VERSION_DATE} — Python {sys.version.split()[0]}, PySide6 {qt}"


def explorer_script():
    for name in ("explor.py", "explorateur.py"):
        path = os.path.join(HERE, name)
        if os.path.isfile(path):
            return path
    return ""


# ======================================================================================
# Verrou anti-exfiltration
# ======================================================================================

_NET_MODULES = frozenset({
    "socket", "_socket", "ssl", "_ssl", "http", "urllib3", "ftplib", "smtplib",
    "imaplib", "poplib", "nntplib", "telnetlib", "xmlrpc", "socketserver", "asyncio",
    "webbrowser", "requests", "httpx", "aiohttp", "paramiko", "multiprocessing", "mailbox",
})
# urllib : seule la partie qui télécharge est interdite. urllib.parse ne fait que découper du texte
# (Python 3.9 et 3.10 le chargent d'office avec PySide6).
_NET_SUBMODULES = frozenset({"urllib.request", "urllib.robotparser", "urllib.response"})
_QT_NET = frozenset({
    "QtNetwork", "QtNetworkAuth", "QtWebEngineCore", "QtWebEngineWidgets", "QtWebEngineQuick",
    "QtWebSockets", "QtWebChannel", "QtWebView", "QtHttpServer", "QtRemoteObjects",
    "QtBluetooth", "QtNfc", "QtMqtt", "QtCoap", "QtSerialBus", "QtPdf", "QtPdfWidgets",
})
_EVENTS_FORBIDDEN = frozenset({
    "os.system", "os.exec", "os.spawn", "os.startfile", "os.forkpty", "pty.spawn",
    "webbrowser.open", "urllib.Request", "http.client.connect", "http.client.send",
    "ftplib.connect", "ftplib.sendcmd", "smtplib.connect", "smtplib.send", "imaplib.open",
    "imaplib.send", "poplib.connect", "poplib.putline", "nntplib.connect", "nntplib.putline",
    "telnetlib.Telnet.open", "telnetlib.Telnet.write",
})
_LIBS_FORBIDDEN = ("QtNetwork", "Qt6Network", "qpdf", "QtPdf", "Qt6Pdf", "QtWebEngine", "Qt6WebEngine",
                   "QtWebSockets", "Qt6WebSockets", "QtHttpServer", "_ssl.", "_socket.")
_VERROU = {"actif": False}


def module_reseau(name):
    if not isinstance(name, str):
        return False
    parts = name.split(".")
    if parts[0] in _NET_MODULES or ".".join(parts[:2]) in _NET_SUBMODULES:
        return True
    return parts[0] == "PySide6" and len(parts) > 1 and parts[1] in _QT_NET


def commande_autorisee(argv):
    """Une seule commande permise : ouvrir un dossier dans ton explorateur maison."""
    if isinstance(argv, (str, bytes)) or not argv:
        return False
    try:
        argv = [os.fsdecode(a) for a in argv]
    except TypeError:
        return False
    script = explorer_script()
    return (len(argv) == 3 and bool(script) and argv[0] == sys.executable
            and os.path.realpath(argv[1]) == os.path.realpath(script)
            and os.path.isabs(argv[2]) and "\x00" not in argv[2])


def installer_verrou():
    """Pose le verrou. Python ne permet pas de le retirer ensuite."""
    if _VERROU["actif"]:
        return
    already = sorted(m for m in list(sys.modules) if module_reseau(m))
    if already:
        raise SystemExit("[verrou] modules réseau déjà chargés : " + ", ".join(already))

    def hook(event, args):
        if event == "import":
            if module_reseau(args[0]):
                raise ImportError(f"[verrou] module réseau interdit : {args[0]}")
        elif event.startswith("socket.") or event in _EVENTS_FORBIDDEN:
            raise PermissionError(f"[verrou] interdit : {event}")
        elif event == "subprocess.Popen":
            exe, argv = args[0], args[1]
            if (not commande_autorisee(argv) or not isinstance(exe, (str, bytes, os.PathLike))
                    or os.fsdecode(exe) != os.fsdecode(argv[0])):
                raise PermissionError(f"[verrou] commande refusée : {argv!r}"[:300])
        elif event in ("os.posix_spawn", "os.posix_spawnp"):
            if not commande_autorisee(args[1]):
                raise PermissionError("[verrou] commande refusée")
        elif event == "ctypes.dlopen":
            if args[0] is not None:
                raise PermissionError(f"[verrou] bibliothèque refusée : {args[0]!r}")

    sys.addaudithook(hook)
    _VERROU["actif"] = True


def bibliotheques_chargees():
    if sys.platform.startswith("linux"):
        try:
            with open("/proc/self/maps", "r", encoding="utf-8", errors="replace") as fh:
                return sorted({line.split()[-1] for line in fh if "/" in line})
        except OSError:
            return []
    return []


def controle_reseau():
    """Auto-contrôle : rien de ce qui sait parler au réseau ne doit être chargé."""
    problems = [m for m in list(sys.modules) if module_reseau(m)]
    for lib in bibliotheques_chargees():
        base = os.path.basename(lib)
        if any(bad in base for bad in _LIBS_FORBIDDEN):
            problems.append(lib)
    return problems


# ======================================================================================
# Encodages et fins de ligne
# ======================================================================================

ENCODINGS = {
    "utf-8": "UTF-8", "utf-8-bom": "UTF-8-BOM", "ansi": "ANSI", "latin-1": "ISO-8859-1",
    "utf-16-le": "UTF-16 LE BOM", "utf-16-be": "UTF-16 BE BOM",
}
_CODECS = {"utf-8": "utf-8", "utf-8-bom": "utf-8", "ansi": "cp1252", "latin-1": "latin-1",
           "utf-16-le": "utf-16-le", "utf-16-be": "utf-16-be"}
_BOMS = {"utf-8-bom": codecs.BOM_UTF8, "utf-16-le": codecs.BOM_UTF16_LE, "utf-16-be": codecs.BOM_UTF16_BE}
EOL_LABELS = {"\r\n": "Windows (CR LF)", "\n": "Unix (LF)", "\r": "Mac (CR)"}
_EOL_RE = re.compile(r"\r\n|\n|\r")


def decode_bytes(data, forced=None):
    """Octets → (texte, encodage). BOM, puis UTF-8 strict, sinon ANSI (Windows-1252)."""
    if forced:
        bom = _BOMS.get(forced)
        body = data[len(bom):] if bom and data.startswith(bom) else data
        return body.decode(_CODECS[forced], errors="replace"), forced
    for enc, bom in (("utf-8-bom", codecs.BOM_UTF8), ("utf-16-le", codecs.BOM_UTF16_LE),
                     ("utf-16-be", codecs.BOM_UTF16_BE)):
        if data.startswith(bom):
            return data[len(bom):].decode(_CODECS[enc], errors="replace"), enc
    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        pass
    try:
        return data.decode("cp1252"), "ansi"
    except UnicodeDecodeError:
        return data.decode("latin-1"), "latin-1"


def encode_text(text, enc):
    """Texte → octets dans l'encodage voulu (UnicodeEncodeError si impossible)."""
    return _BOMS.get(enc, b"") + text.encode(_CODECS[enc])


def unencodable(text, enc):
    """Caractères qui ne passent pas dans cet encodage (pour prévenir avant d'enregistrer)."""
    codec = _CODECS[enc]
    bad = []
    for ch in set(text):
        try:
            ch.encode(codec)
        except UnicodeEncodeError:
            bad.append(ch)
    return sorted(bad)


def looks_binary(data):
    head = data[:8192]
    if head.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return False
    return b"\x00" in head


def split_eols(text):
    """« a\\r\\nb\\nc » → (['a', 'b', 'c'], ['\\r\\n', '\\n'])."""
    lines, eols, pos = [], [], 0
    for m in _EOL_RE.finditer(text):
        lines.append(text[pos:m.start()])
        eols.append(m.group())
        pos = m.end()
    lines.append(text[pos:])
    return lines, eols


def main_eol(eols, default):
    if not eols:
        return default
    counts = {}
    for e in eols:
        counts[e] = counts.get(e, 0) + 1
    return max(counts, key=lambda e: (counts[e], e == default))


# ======================================================================================
# JSON : formater sans réécrire les valeurs
# ======================================================================================

class JsonError(ValueError):
    def __init__(self, message, pos):
        super().__init__(message)
        self.pos = pos


_JSON_RE = re.compile(
    r'(?P<ws>[ \t\r\n]+)'
    r'|(?P<str>"(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*")'
    r'|(?P<num>-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)'
    r'|(?P<lit>true|false|null)'
    r'|(?P<p>[{}\[\]:,])')


def _json_tokens(s):
    toks, pos, n = [], 0, len(s)
    if s.startswith("\ufeff"):
        pos = 1
    while pos < n:
        m = _JSON_RE.match(s, pos)
        if not m:
            ch = s[pos]
            if ch == '"':
                msg = "chaîne mal formée ou non fermée"
            elif ch == "'":
                msg = "les chaînes JSON s'écrivent entre guillemets doubles"
            elif ch == "/":
                msg = "les commentaires ne sont pas permis en JSON"
            else:
                msg = f"caractère inattendu « {ch} »"
            raise JsonError(msg, pos)
        if m.lastgroup != "ws":
            toks.append((m.lastgroup, m.group(), pos))
        pos = m.end()
    return toks


class _JsonParser:
    def __init__(self, toks, end):
        self.t, self.i, self.end = toks, 0, end

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else ("eof", "", self.end)

    def take(self):
        tok = self.peek()
        self.i += 1
        return tok

    def value(self):
        kind, text, pos = self.take()
        if kind in ("str", "num", "lit"):
            return ("val", text, pos)
        if text == "{":
            items = []
            if self.peek()[1] == "}":
                return ("obj", items, pos, self.take()[2])
            while True:
                key = self.take()
                if key[0] != "str":
                    raise JsonError("nom de clé attendu (entre guillemets doubles)", key[2])
                colon = self.take()
                if colon[1] != ":":
                    raise JsonError("« : » attendu après la clé", colon[2])
                items.append((key[1], key[2], self.value()))
                sep = self.take()
                if sep[1] == "}":
                    return ("obj", items, pos, sep[2])
                if sep[1] != ",":
                    raise JsonError("« , » ou « } » attendu", sep[2])
                if self.peek()[1] == "}":
                    raise JsonError("virgule en trop avant « } »", self.peek()[2])
        if text == "[":
            items = []
            if self.peek()[1] == "]":
                return ("arr", items, pos, self.take()[2])
            while True:
                items.append(self.value())
                sep = self.take()
                if sep[1] == "]":
                    return ("arr", items, pos, sep[2])
                if sep[1] != ",":
                    raise JsonError("« , » ou « ] » attendu", sep[2])
                if self.peek()[1] == "]":
                    raise JsonError("virgule en trop avant « ] »", self.peek()[2])
        if kind == "eof":
            raise JsonError("le texte s'arrête trop tôt : une valeur est attendue", pos)
        raise JsonError(f"valeur attendue, « {text} » trouvé", pos)


def json_parse(s):
    """Arbre qui garde le texte exact des valeurs et la position de chaque élément."""
    try:
        parser = _JsonParser(_json_tokens(s), len(s))
        if not parser.t:
            raise JsonError("document vide", 0)
        node = parser.value()
        if parser.i < len(parser.t):
            raise JsonError("contenu en trop après la fin du JSON", parser.t[parser.i][2])
        return node
    except RecursionError:
        raise JsonError("imbrication trop profonde", 0) from None


def _json_dump(node, indent, sort, level, out):
    kind = node[0]
    if kind == "val":
        out.append(node[1])
        return
    opening, closing = ("{", "}") if kind == "obj" else ("[", "]")
    items = node[1]
    if not items:
        out.append(opening + closing)
        return
    if kind == "obj" and sort:
        items = sorted(items, key=lambda it: json.loads(it[0]))
    out.append(opening)
    pad = None if indent is None else "\n" + indent * (level + 1)
    for j, item in enumerate(items):
        if j:
            out.append(",")
        if pad:
            out.append(pad)
        if kind == "obj":
            out.append(item[0] + (": " if pad else ":"))
            _json_dump(item[2], indent, sort, level + 1, out)
        else:
            _json_dump(item, indent, sort, level + 1, out)
    if pad:
        out.append("\n" + indent * level)
    out.append(closing)


def json_format(s, indent="    ", sort=False):
    out = []
    try:
        _json_dump(json_parse(s), indent, sort, 0, out)
    except RecursionError:
        raise JsonError("imbrication trop profonde", 0) from None
    return "".join(out)


def json_minify(s):
    return json_format(s, indent=None)


def line_col(s, pos):
    """Position → (ligne, colonne), à partir de 1."""
    line = s.count("\n", 0, pos) + 1
    return line, pos - (s.rfind("\n", 0, pos) + 1) + 1


# ======================================================================================
# Outils MIME : Base64, URL, hexadécimal, JWT, empreintes
# ======================================================================================

def b64_encode(text, padding=True, url=False):
    raw = text.encode("utf-8") if isinstance(text, str) else text
    out = (base64.urlsafe_b64encode if url else base64.b64encode)(raw).decode("ascii")
    return out if padding else out.rstrip("=")


def b64_decode(text):
    """Décodage tolérant : avec ou sans « = », espaces et retours ignorés, variante URL reconnue."""
    s = re.sub(r"\s+", "", text)
    body = s.rstrip("=")
    if not body:
        raise ValueError("rien à décoder")
    url = "-" in body or "_" in body
    bad = re.search(r"[^A-Za-z0-9\-_]" if url else r"[^A-Za-z0-9+/]", body)
    if bad:
        hint = " (mélange des variantes standard et URL)" if bad.group() in "+/-_" else ""
        raise ValueError(f"caractère « {bad.group()} » invalide en position {bad.start() + 1}{hint}")
    if len(body) % 4 == 1:
        raise ValueError("longueur impossible pour du Base64 : il manque ou il y a un caractère de trop")
    padded = body + "=" * (-len(body) % 4)
    return base64.b64decode(padded, altchars=b"-_" if url else None, validate=True)


_UNRESERVED = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")


def url_encode(text):
    return "".join(chr(b) if b in _UNRESERVED else f"%{b:02X}" for b in text.encode("utf-8"))


def url_decode(text):
    data, out, i = text.encode("utf-8"), bytearray(), 0
    while i < len(data):
        chunk = data[i + 1:i + 3]
        if data[i] == 0x25 and len(chunk) == 2 and all(c in b"0123456789abcdefABCDEF" for c in chunk):
            out.append(int(chunk, 16))
            i += 3
        else:
            out.append(data[i])
            i += 1
    try:
        return out.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("le résultat n'est pas du texte UTF-8") from None


def to_hex(text):
    return " ".join(f"{b:02X}" for b in text.encode("utf-8"))


def from_hex(text):
    s = re.sub(r"0x|\\x|[\s:,\-]", "", text, flags=re.IGNORECASE)
    if not s or len(s) % 2 or re.search(r"[^0-9A-Fa-f]", s):
        raise ValueError("ce n'est pas de l'hexadécimal valide")
    return bytes.fromhex(s)


def bytes_to_text(data):
    """Octets décodés → texte si c'est du vrai texte UTF-8, sinon None."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if any(unicodedata.category(c) == "Cc" and c not in "\t\n\r" for c in text):
        return None
    return text


def _human_time(value):
    try:
        when = datetime.datetime.fromtimestamp(float(value))
    except (TypeError, ValueError, OverflowError, OSError):
        return None
    text = when.strftime("%d/%m/%Y %H:%M:%S") + " (heure locale)"
    return text


def jwt_decode(token):
    """En-tête et contenu d'un jeton JWT, avec les dates en clair."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("un JWT a trois parties séparées par des points")
    try:
        header = json.loads(b64_decode(parts[0]).decode("utf-8"))
        payload = json.loads(b64_decode(parts[1]).decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError(f"JWT illisible : {exc}") from None
    result = {"header": header, "payload": payload, "signature": parts[2]}
    if isinstance(payload, dict):
        dates = {}
        now = time.time()
        for key in ("iat", "nbf", "exp", "auth_time"):
            if key in payload:
                human = _human_time(payload[key])
                if human:
                    if key == "exp":
                        human += " — expiré" if float(payload[key]) < now else " — encore valide"
                    dates[key] = human
        if dates:
            result["dates_lisibles"] = dates
    return json.dumps(result, indent=4, ensure_ascii=False)


HASHES = ("MD5", "SHA-1", "SHA-256", "SHA-512")


def digest(data, algo):
    name = {"MD5": "md5", "SHA-1": "sha1", "SHA-256": "sha256", "SHA-512": "sha512"}[algo]
    return hashlib.new(name, data).hexdigest()


# ======================================================================================
# Lignes, casse, blancs, commentaires
# ======================================================================================

def fold(text):
    """Minuscules sans accents."""
    norm = unicodedata.normalize("NFKD", text or "")
    return "".join(c for c in norm if not unicodedata.combining(c)).casefold()


def _num_key(line):
    m = re.match(r"\s*([-+]?\d+(?:[.,]\d+)?)", line)
    return (0, float(m.group(1).replace(",", ".")), line) if m else (1, 0.0, line)


def sort_lines(lines, reverse=False, ci=False, numeric=False):
    if numeric:
        return sorted(lines, key=_num_key, reverse=reverse)
    if ci:
        return sorted(lines, key=lambda l: (fold(l), l), reverse=reverse)
    return sorted(lines, reverse=reverse)


def unique_lines(lines, consecutive=False):
    out, seen = [], set()
    for line in lines:
        if consecutive:
            if out and out[-1] == line:
                continue
        elif line in seen:
            continue
        seen.add(line)
        out.append(line)
    return out


def remove_empty(lines, blank_too=False):
    return [l for l in lines if (l.strip() if blank_too else l)]


def title_case(text):
    return re.sub(r"\w+", lambda m: m.group()[0].upper() + m.group()[1:].lower(), text)


def leading_to_tabs(line, width):
    m = re.match(r"[ \t]*", line)
    n = len(m.group().expandtabs(width))
    return "\t" * (n // width) + " " * (n % width) + line[m.end():]


SPECIAL_CHARS = {
    "\u00a0": "NBSP", "\u202f": "NNBSP", "\u2007": "FIGSP", "\u200b": "ZWSP", "\u200c": "ZWNJ",
    "\u200d": "ZWJ", "\u2060": "WJ", "\ufeff": "BOM", "\u00ad": "SHY",
}
SPECIAL_RE = re.compile("[" + "".join(SPECIAL_CHARS) + "]")


def clean_special(text):
    """Espaces insécables → espaces ; caractères invisibles → supprimés."""
    count = len(SPECIAL_RE.findall(text))
    text = re.sub("[\u00a0\u202f\u2007]", " ", text)
    text = re.sub("[\u200b\u200c\u200d\u2060\ufeff\u00ad]", "", text)
    return text, count


COMMENTS = {
    "yaml": "#", "bash": "#", "python": "#", "dockerfile": "#", "ini": ";", "sql": "--",
    "javascript": "//", "groovy": "//", "css": ("/*", "*/"), "xml": ("<!--", "-->"),
    "html": ("<!--", "-->"), "markdown": ("<!--", "-->"),
}


def comment_lines(lines, lang, mode="toggle"):
    """Commenter / décommenter des lignes selon le langage (None si le langage n'a pas de commentaire)."""
    spec = COMMENTS.get(lang)
    if spec is None:
        return None
    pair = isinstance(spec, tuple)
    opening, closing = spec if pair else (spec, "")
    nonblank = [l for l in lines if l.strip()]

    def commented(line):
        s = line.strip()
        return s.startswith(opening) and (not pair or s.endswith(closing))

    if mode == "toggle":
        mode = "remove" if nonblank and all(commented(l) for l in nonblank) else "add"
    out = []
    if mode == "add":
        indent = min((len(l) - len(l.lstrip()) for l in nonblank), default=0)
        for line in lines:
            if not line.strip():
                out.append(line)
            elif pair:
                out.append(line[:indent] + opening + " " + line[indent:] + " " + closing)
            else:
                out.append(line[:indent] + opening + " " + line[indent:])
        return out
    for line in lines:
        s = line.lstrip()
        lead = line[:len(line) - len(s)]
        if s.startswith(opening):
            s = s[len(opening):]
            if s.startswith(" "):
                s = s[1:]
            if pair:
                body = s.rstrip()
                if body.endswith(closing):
                    body = body[:-len(closing)]
                    s = body[:-1] if body.endswith(" ") else body
        out.append(lead + s)
    return out


def vcol_of(text, idx, tab):
    """Colonne visuelle (tabulations développées) de l'index idx."""
    col = 0
    for ch in text[:idx]:
        col = (col // tab + 1) * tab if ch == "\t" else col + 1
    return col


def index_at_vcol(text, vcol, tab):
    """Index du caractère à la colonne visuelle vcol, et espaces à ajouter si la ligne est trop courte."""
    col = 0
    for i, ch in enumerate(text):
        if col >= vcol:
            return i, 0
        nxt = (col // tab + 1) * tab if ch == "\t" else col + 1
        if nxt > vcol:
            return i, 0
        col = nxt
    return len(text), max(0, vcol - col)


# ======================================================================================
# Recherche
# ======================================================================================

def unescape_extended(s):
    """Mode « étendu » : \\n, \\r, \\t, \\0, \\\\, \\xHH, \\uHHHH."""
    mapping = {"n": "\n", "r": "\r", "t": "\t", "0": "\0", "\\": "\\"}
    out, i = [], 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            n = s[i + 1]
            if n in mapping:
                out.append(mapping[n])
                i += 2
                continue
            if n == "x" and re.fullmatch(r"[0-9a-fA-F]{2}", s[i + 2:i + 4]):
                out.append(chr(int(s[i + 2:i + 4], 16)))
                i += 4
                continue
            if n == "u" and re.fullmatch(r"[0-9a-fA-F]{4}", s[i + 2:i + 6]):
                out.append(chr(int(s[i + 2:i + 6], 16)))
                i += 6
                continue
        out.append(c)
        i += 1
    return "".join(out)


# Caractères qui ressemblent à un tiret, une espace, une apostrophe ou un guillemet ordinaires.
# Fréquents dans un texte copié depuis Outlook, Teams, Word, un PDF ou une page web.
DASH_LIKE = "-\u2010\u2011\u2012\u2013\u2014\u2015\u2212\ufe58\ufe63\uff0d"
SPACE_LIKE = " \u00a0\u202f\u2007\u2009\u200a\u2002\u2003\u2004\u2005\u2006\u2008\u3000"
APOS_LIKE = "'\u2018\u2019\u201a\u201b\u2032\u02bc"
QUOTE_LIKE = '"\u201c\u201d\u201e\u201f\u2033'
INVISIBLE = "\u200b\u200c\u200d\u2060\ufeff\u00ad"
LOOKALIKE_GROUPS = (DASH_LIKE, SPACE_LIKE, APOS_LIKE, QUOTE_LIKE)
LOOKALIKE_NAMES = {
    "\u2010": "trait d'union typographique", "\u2011": "trait d'union insécable", "\u2012": "tiret numérique",
    "\u2013": "tiret moyen", "\u2014": "tiret long", "\u2015": "barre horizontale", "\u2212": "signe moins",
    "\ufe58": "petit tiret", "\ufe63": "petit trait d'union", "\uff0d": "tiret pleine largeur",
    "\u00a0": "espace insécable", "\u202f": "espace fine insécable", "\u2007": "espace de chiffre",
    "\u2009": "espace fine", "\u200a": "espace ultra-fine", "\u3000": "espace idéographique",
    "\u2018": "apostrophe ouvrante", "\u2019": "apostrophe typographique", "\u201a": "apostrophe basse",
    "\u2032": "prime", "\u02bc": "apostrophe modificative", "\u201c": "guillemet anglais ouvrant",
    "\u201d": "guillemet anglais fermant", "\u201e": "guillemet bas", "\u2033": "double prime",
    "\u200b": "espace invisible", "\u200c": "antiliant invisible", "\u200d": "liant invisible",
    "\u2060": "gluon invisible", "\ufeff": "BOM invisible", "\u00ad": "trait d'union conditionnel invisible",
}
ASCII_OF = {c: g[0] for g in LOOKALIKE_GROUPS for c in g[1:]}


def describe_special(c):
    """« ‑ » trait d'union insécable (U+2011)"""
    name = LOOKALIKE_NAMES.get(c) or unicodedata.name(c, "caractère spécial").lower()
    shown = "" if c in INVISIBLE or c in SPACE_LIKE else f"« {c} » "
    return f"{shown}{name} (U+{ord(c):04X})"


def lookalike_source(literal):
    """Motif qui trouve le texte même écrit avec des tirets/espaces/apostrophes « qui ressemblent »
    et des caractères invisibles glissés au milieu."""
    inv = "[" + INVISIBLE + "]*"
    parts = []
    for c in literal:
        if c in INVISIBLE:
            continue
        group = next((g for g in LOOKALIKE_GROUPS if c in g), None)
        parts.append("[" + re.escape(group) + "]" if group else re.escape(c))
    return inv.join(parts)


def to_plain_typo(text):
    """Tirets, espaces, apostrophes et guillemets typographiques → leur version clavier ; invisibles supprimés."""
    count = sum(1 for c in text if c in ASCII_OF or c in INVISIBLE)
    out = "".join(ASCII_OF.get(c, c) for c in text if c not in INVISIBLE)
    return out, count


def lookalike_hint(texts, find, mode, case=False, word=False, dotall=False, limit=100000):
    """Une recherche ne trouve rien : la trouverait-on avec des caractères « qui ressemblent » ?
    → (nombre d'occurrences, [caractères différents rencontrés]) ou None."""
    if mode == "regex" or not find:
        return None
    try:
        pat = build_pattern(find, mode, case, word, dotall, lookalike=True)
    except ValueError:
        return None
    literal = unescape_extended(find) if mode == "extended" else find
    n, odd = 0, []
    for text in texts:
        for m in pat.finditer(text):
            n += 1
            for c in m.group():
                if c not in literal and c not in odd and (c in INVISIBLE or c in ASCII_OF):
                    odd.append(c)
            if n >= limit:
                break
    return (n, odd) if n and odd else None


def build_pattern(find, mode="normal", case=False, word=False, dotall=False, lookalike=False):
    if not find:
        raise ValueError("rien à rechercher")
    lead, exact = "", False
    if mode == "regex":
        converted = pcre_to_python(find)
        lead, src = split_global_flags(converted)
        exact = converted == find           # positions d'erreur fiables dans le texte tapé
    else:
        literal = unescape_extended(find) if mode == "extended" else find
        src = (lookalike_source(literal) if lookalike else "") or re.escape(literal)
    prefix = f"(?{lead})" if lead else ""
    body_at = len(prefix)
    if word:
        src = r"(?<!\w)(?:" + src + ("\n" if "x" in lead else "") + r")(?!\w)"
        body_at += len(r"(?<!\w)(?:")
    flags = re.MULTILINE | (0 if case else re.IGNORECASE) | (re.DOTALL if dotall else 0)
    try:
        return re.compile(prefix + src, flags)
    except re.error as exc:
        typed_lead = len(find) - len(split_global_flags(find)[1]) if mode == "regex" else 0
        shift = body_at - typed_lead
        msg, pos = french_re_error(exc, shift if exact else 10 ** 9)
        err = ValueError(f"expression régulière invalide : {msg}")
        err.pos = pos
        raise err from None


def make_replacer(repl, mode):
    """Remplacement façon Notepad++ : $1, ${1}, ${nom}, $& ou \\1 pour les groupes en mode regex."""
    if mode == "normal":
        return lambda m: repl
    if mode == "extended":
        literal = unescape_extended(repl)
        return lambda m: literal
    tpl = npp_repl_template(repl)
    return lambda m: m.expand(tpl)


def iter_files(root, patterns="*", recursive=True, hidden=False):
    pats = [p for p in re.split(r"[;,\s]+", (patterns or "").strip()) if p]
    include = [p for p in pats if not p.startswith("!")] or ["*"]
    exclude = [p[1:] for p in pats if p.startswith("!")]
    for dirpath, dirnames, filenames in os.walk(root):
        if not hidden:
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        dirnames.sort()
        if not recursive:
            dirnames[:] = []
        for name in sorted(filenames):
            if not hidden and name.startswith("."):
                continue
            low = name.lower()
            if any(fnmatch.fnmatch(low, p.lower()) for p in include) and \
                    not any(fnmatch.fnmatch(low, p.lower()) for p in exclude):
                yield os.path.join(dirpath, name)


def read_text_file(path, max_size=20 * 1024 * 1024):
    """(texte, encodage) d'un fichier texte, ou None (binaire, trop gros, illisible)."""
    try:
        if os.path.getsize(path) > max_size:
            return None
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    if looks_binary(data):
        return None
    return decode_bytes(data)


def find_in_text(text, pattern, limit=100000):
    """[(n° de ligne, colonne, longueur, texte de la ligne)] pour chaque occurrence."""
    out, line_no, line_start, scan = [], 1, 0, 0
    for m in pattern.finditer(text):
        if m.start() == m.end() and m.start() == len(text):
            break
        nl = text.count("\n", scan, m.start())
        if nl:
            line_no += nl
            line_start = text.rfind("\n", scan, m.start()) + 1
        scan = m.start()
        end = text.find("\n", m.start())
        line_text = text[line_start:end if end >= 0 else len(text)].rstrip("\r")
        out.append((line_no, m.start() - line_start, m.end() - m.start(), line_text))
        if len(out) >= limit:
            break
    return out


# ======================================================================================
# Expressions régulières : compatibilité, explication, générateur, exemples d'utilisation
# ======================================================================================

try:                                    # analyseur d'expressions de Python (pur Python, hors réseau)
    from re import _parser as _sre_parse          # Python 3.11 et plus
except ImportError:                     # pragma: no cover - anciens Python
    import sre_parse as _sre_parse

_GLOBAL_FLAGS = re.compile(r"\(\?([aiLmsux]+)\)")
_NAME = re.compile(r"[A-Za-z_]\w*")


def split_global_flags(src):
    """« (?i)(?m)abc » -> ("im", "abc") : options globales placées en tête."""
    letters = ""
    while True:
        m = _GLOBAL_FLAGS.match(src)
        if not m:
            return letters, src
        letters += "".join(c for c in m.group(1) if c not in letters)
        src = src[m.end():]


def pcre_to_python(src):
    """Accepte aussi les écritures PCRE / Notepad++ : (?<nom>…), (?'nom'…), \\k<nom>, \\z."""
    out, i, n, in_class = [], 0, len(src), False
    while i < n:
        c = src[i]
        if c == "\\" and i + 1 < n:
            nxt = src[i + 1]
            if not in_class and nxt == "k" and i + 2 < n and src[i + 2] in "<{'":
                close = {"<": ">", "{": "}", "'": "'"}[src[i + 2]]
                j = src.find(close, i + 3)
                if j > 0 and _NAME.fullmatch(src[i + 3:j]):
                    out.append(f"(?P={src[i + 3:j]})")
                    i = j + 1
                    continue
            if nxt == "z" and not in_class:
                out.append(r"\Z")
            else:
                out.append(src[i:i + 2])
            i += 2
            continue
        if in_class:
            if c == "]":
                in_class = False
            out.append(c)
            i += 1
            continue
        if c == "[":
            in_class = True
            out.append(c)
            i += 1
            if i < n and src[i] == "^":
                out.append("^")
                i += 1
            if i < n and src[i] == "]":
                out.append("]")
                i += 1
            continue
        if src.startswith("(?<", i) and i + 3 < n and (src[i + 3].isalpha() or src[i + 3] == "_"):
            out.append("(?P<")
            i += 3
            continue
        if src.startswith("(?'", i):
            j = src.find("'", i + 3)
            if j > 0 and _NAME.fullmatch(src[i + 3:j]):
                out.append(f"(?P<{src[i + 3:j]}>")
                i = j + 1
                continue
        out.append(c)
        i += 1
    return "".join(out)


_RE_ERRORS = (
    ("missing ), unterminated subpattern", "parenthèse « ) » manquante"),
    ("unbalanced parenthesis", "parenthèse « ) » en trop"),
    ("unterminated character set", "crochet « ] » manquant"),
    ("nothing to repeat", "rien à répéter avant ce quantificateur"),
    ("multiple repeat", "deux quantificateurs à la suite (par ex. « ** »)"),
    ("bad escape", "séquence avec antislash inconnue"),
    ("bad character range", "intervalle invalide entre crochets (par ex. « z-a »)"),
    ("look-behind requires fixed-width pattern", "un « précédé de » (?<=…) doit avoir une longueur fixe"),
    ("unknown group name", "nom de groupe inconnu"),
    ("invalid group reference", "référence à un groupe qui n'existe pas"),
    ("cannot refer to an open group", "référence à un groupe pas encore fermé"),
    ("missing group name", "nom de groupe manquant"),
    ("bad character in group name", "caractère interdit dans le nom de groupe"),
    ("redefinition of group name", "nom de groupe utilisé deux fois"),
    ("global flags not at the start", "les options comme (?i) doivent être au tout début"),
    ("unknown extension", "construction « (?… » inconnue"),
    ("unknown flag", "option inconnue dans « (?…) »"),
    ("missing ), unterminated name", "« > » manquant après le nom du groupe"),
    ("missing >, unterminated name", "« > » manquant après le nom du groupe"),
    ("min repeat greater than max repeat", "dans {n,m}, n est plus grand que m"),
    ("the repetition number is too large", "nombre de répétitions trop grand"),
    ("missing ), unterminated comment", "commentaire (?#…) non fermé"),
    ("unterminated", "élément non fermé"),
)


def french_re_error(exc, offset=0):
    """Message d'erreur de `re` traduit, avec la position dans le texte tapé."""
    msg = str(getattr(exc, "msg", "") or exc)
    for en, fr in _RE_ERRORS:
        if msg.startswith(en):
            detail = msg[len(en):].strip(" :")
            msg = fr + (f" ({detail})" if detail and en == "bad escape" else "")
            break
    pos = getattr(exc, "pos", None)
    if isinstance(pos, int) and pos - offset >= 0:
        return f"{msg} — position {pos - offset + 1}", pos - offset
    return msg, None


def npp_repl_template(repl):
    """Remplacement Notepad++ ($1, ${1}, ${nom}, $+{nom}, $&, \\1, \\$) -> modèle Python (\\g<1>)."""
    def conv(m):
        t = m.group(0)
        if t == "\\\\":
            return t
        if t == "\\$":
            return "$"
        if t == "$&":
            return r"\g<0>"
        return "\\g<" + next(g for g in m.groups() if g is not None) + ">"
    return re.sub(r"\\\\|\\\$|\$\{(\w+)\}|\$\+\{(\w+)\}|\$(\d+)|\$&|\\(\d+)", conv, repl)


# ---- explication en français ------------------------------------------------------------

_CATEGORIES = {
    "CATEGORY_DIGIT": ("un chiffre (\\d)", "chiffre"),
    "CATEGORY_NOT_DIGIT": ("un caractère qui n'est pas un chiffre (\\D)", "non-chiffre"),
    "CATEGORY_SPACE": ("un blanc : espace, tabulation, retour à la ligne… (\\s)", "blanc"),
    "CATEGORY_NOT_SPACE": ("un caractère qui n'est pas un blanc (\\S)", "non-blanc"),
    "CATEGORY_WORD": ("une lettre, un chiffre ou « _ » (\\w)", "lettre, chiffre ou _"),
    "CATEGORY_NOT_WORD": ("un caractère qui n'est ni lettre, ni chiffre, ni « _ » (\\W)", "hors lettre/chiffre/_"),
}
_CHAR_NAMES = {" ": "espace", "\t": "tabulation (\\t)", "\n": "retour à la ligne (\\n)",
               "\r": "retour chariot (\\r)", "\x00": "caractère nul (\\0)"}


def _char_name(code):
    ch = chr(code)
    if ch in _CHAR_NAMES:
        return _CHAR_NAMES[ch]
    return f"« {ch} »" if ch.isprintable() else f"U+{code:04X}"


def _visible(text):
    return text.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")


def _quantity(lo, hi, kind):
    inf = hi == _sre_parse.MAXREPEAT
    if (lo, hi) == (0, 1):
        s = "facultatif (0 ou 1 fois)"
    elif lo == 0 and inf:
        s = "0 fois ou plus"
    elif lo == 1 and inf:
        s = "1 fois ou plus"
    elif inf:
        s = f"au moins {lo} fois"
    elif lo == hi:
        s = f"exactement {lo} fois"
    else:
        s = f"de {lo} à {hi} fois"
    if kind == "MIN_REPEAT":
        s += ", le moins possible"
    elif kind == "POSSESSIVE_REPEAT":
        s += ", sans retour en arrière"
    return s


def explain_regex(pattern):
    """Explication pas à pas d'un motif compilé -> (texte, alertes)."""
    flags = pattern.flags
    names = {v: k for k, v in pattern.groupindex.items()}
    multiline, dotall = bool(flags & re.MULTILINE), bool(flags & re.DOTALL)
    warnings = []
    try:
        tree = _sre_parse.parse(pattern.pattern, flags)
    except Exception:  # noqa: BLE001 - l'explication est un bonus, jamais bloquante
        return "", []

    def unbounded(items):
        for op, av in items:
            name = str(op)
            if name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
                if av[1] == _sre_parse.MAXREPEAT or unbounded(av[2]):
                    return True
            elif name == "SUBPATTERN" and unbounded(av[-1]):
                return True
            elif name == "BRANCH" and any(unbounded(alt) for alt in av[1]):
                return True
            elif name in ("ASSERT", "ASSERT_NOT") and unbounded(av[1]):
                return True
            elif name == "ATOMIC_GROUP" and unbounded(av):
                return True
        return False

    def in_set(av):
        neg, parts = False, []
        for op, a in av:
            name = str(op)
            if name == "NEGATE":
                neg = True
            elif name == "LITERAL":
                parts.append(_char_name(a))
            elif name == "RANGE":
                parts.append(f"{_visible(chr(a[0]))} à {_visible(chr(a[1]))}")
            elif name == "CATEGORY":
                parts.append(_CATEGORIES.get(str(a), (str(a), str(a)))[1])
            else:
                parts.append(name.lower())
        if len(parts) == 1 and not neg and len(av) == 1 and str(av[0][0]) == "CATEGORY":
            return _CATEGORIES.get(str(av[0][1]), (parts[0],))[0]
        return ("un caractère sauf : " if neg else "un caractère parmi : ") + ", ".join(parts)

    def atom(op, av):
        name = str(op)
        if name == "LITERAL":
            return "le caractère " + _char_name(av)
        if name == "NOT_LITERAL":
            return "n'importe quel caractère sauf " + _char_name(av)
        if name == "ANY":
            return "n'importe quel caractère" + (" (retours à la ligne compris)" if dotall
                                                 else " sauf un retour à la ligne")
        if name == "IN":
            return in_set(av)
        if name == "AT":
            at = str(av)
            return {
                "AT_BEGINNING": "début de ligne (^)" if multiline else "début du texte (^)",
                "AT_BEGINNING_LINE": "début de ligne (^)",
                "AT_BEGINNING_STRING": "tout début du texte (\\A)",
                "AT_END": "fin de ligne ($)" if multiline else "fin du texte ($)",
                "AT_END_LINE": "fin de ligne ($)",
                "AT_END_STRING": "toute fin du texte (\\Z)",
                "AT_BOUNDARY": "limite de mot (\\b)",
                "AT_NON_BOUNDARY": "pas en limite de mot (\\B)",
            }.get(at, at.lower())
        if name == "GROUPREF":
            label = f" « {names[av]} »" if av in names else ""
            return f"le même texte que celui trouvé par le groupe {av}{label}"
        return None

    def inline(items):
        items = list(items)
        if not items:
            return "rien"
        if all(str(op) == "LITERAL" for op, _ in items):
            text = "".join(chr(av) for _, av in items)
            return "le caractère " + _char_name(ord(text)) if len(text) == 1 else f"le texte « {_visible(text)} »"
        if len(items) == 1:
            op, av = items[0]
            one = atom(op, av)
            if one:
                return one
            if str(op) in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
                inner = inline(av[2])
                if inner and "\n" not in inner and len(inner) < 90:
                    return f"{inner}, {_quantity(av[0], av[1], str(op))}"
        return None

    lines = []

    def add(depth, text):
        lines.append((depth, text[:1].upper() + text[1:]))

    def walk(items, depth):
        items = list(items)
        i = 0
        while i < len(items):
            op, av = items[i]
            name = str(op)
            if name == "LITERAL":
                j = i
                while j < len(items) and str(items[j][0]) == "LITERAL":
                    j += 1
                add(depth, inline(items[i:j]))
                i = j
                continue
            i += 1
            one = atom(op, av)
            if one:
                add(depth, one)
            elif name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
                lo, hi, sub = av
                if hi == _sre_parse.MAXREPEAT and unbounded(sub) and not warnings:
                    warnings.append("Quantificateur imbriqué (du genre « (a+)+ ») : sur un long texte "
                                    "sans correspondance, la recherche peut tourner très longtemps.")
                text = inline(sub)
                if text and len(text) < 90:
                    add(depth, f"{text}, {_quantity(lo, hi, name)}")
                else:
                    add(depth, (_quantity(lo, hi, name) if (lo, hi) == (0, 1)
                                else "répéter " + _quantity(lo, hi, name)) + " :")
                    walk(sub, depth + 1)
            elif name == "SUBPATTERN":
                group, sub = av[0], av[-1]
                if group is None:
                    head = "groupe non capturé"
                else:
                    head = f"groupe {group}" + (f" « {names[group]} »" if group in names else "") + " (capturé)"
                add_flags = av[1] if len(av) == 4 else 0
                if add_flags & re.IGNORECASE:
                    head += ", majuscules et minuscules confondues"
                text = inline(sub)
                if text and len(text) < 90:
                    add(depth, f"{head} : {text}")
                else:
                    add(depth, head + " :")
                    walk(sub, depth + 1)
            elif name == "BRANCH":
                alts = av[1]
                texts = [inline(alt) for alt in alts]
                if all(texts) and sum(len(t) for t in texts) < 160:
                    texts = [t[len("le texte "):] if t.startswith("le texte « ") else t for t in texts]
                    add(depth, "au choix : " + (", ".join(texts[:-1]) + " ou " + texts[-1]))
                else:
                    add(depth, "au choix, l'une de ces possibilités :")
                    for k, alt in enumerate(alts, 1):
                        add(depth + 1, f"possibilité {k} :")
                        walk(alt, depth + 2)
            elif name in ("ASSERT", "ASSERT_NOT"):
                direction, sub = av
                head = {("ASSERT", 1): "suivi de", ("ASSERT", -1): "précédé de",
                        ("ASSERT_NOT", 1): "non suivi de", ("ASSERT_NOT", -1): "non précédé de"}[
                    (name, 1 if direction >= 0 else -1)]
                head += " (vérifié sans faire partie du résultat)"
                text = inline(sub)
                if text and len(text) < 90:
                    add(depth, f"{head} : {text}")
                else:
                    add(depth, head + " :")
                    walk(sub, depth + 1)
            elif name == "ATOMIC_GROUP":
                add(depth, "groupe atomique (sans retour en arrière) :")
                walk(av, depth + 1)
            elif name == "GROUPREF_EXISTS":
                cond, yes, no = av
                add(depth, f"si le groupe {cond} a trouvé quelque chose :")
                walk(yes, depth + 1)
                if no:
                    add(depth, "sinon :")
                    walk(no, depth + 1)
            else:
                add(depth, name.lower().replace("_", " "))

    walk(tree, 0)
    opts = ["majuscules et minuscules confondues" if flags & re.IGNORECASE else "respecte la casse",
            "^ et $ à chaque ligne" if multiline else "^ et $ au début et à la fin du texte"]
    if dotall:
        opts.append("« . » prend aussi les retours à la ligne")
    if flags & re.VERBOSE:
        opts.append("mode verbeux (espaces et # ignorés)")
    out, num = ["Options : " + ", ".join(opts), ""], 0
    for depth, text in lines:
        if depth == 0:
            num += 1
            out.append(f"{num}. {text}")
        else:
            out.append("    " * depth + "– " + text)
    if pattern.groups:
        out.append("")
        out.append(f"Groupes capturés : {pattern.groups}" + (
            " (" + ", ".join(f"{k} = {v}" for k, v in sorted(names.items())) + ")" if names else ""))
    return "\n".join(out), warnings


# ---- générateur à partir d'exemples -------------------------------------------------------

_SPECIAL = set(".^$*+?{}[]\\|()")


def _esc(text):
    out = []
    for ch in text:
        if ch in _SPECIAL:
            out.append("\\" + ch)
        elif ch == "\t":
            out.append(r"\t")
        elif ch == "\n":
            out.append(r"\n")
        elif ch == "\r":
            out.append(r"\r")
        else:
            out.append(ch)
    return "".join(out)


def _class_of(chars):
    chars = sorted(set(chars))
    dash = "-" in chars
    body = "".join(("\\" + c) if c in "\\]^[" else c for c in chars if c != "-")
    return "[" + body + ("-" if dash else "") + "]"


def _tokenize(sample):
    out = []
    for m in re.finditer(r"\w+|\s+|.", sample, re.S):
        t = m.group(0)
        out.append(("w" if (t[0].isalnum() or t[0] == "_") else "s" if t.isspace() else "p", t))
    return out


def _word_class(values):
    chars = set("".join(values))
    if any(not c.isascii() for c in chars):
        return r"\w", False
    digits = any(c.isdigit() for c in chars)
    lower = any(c.islower() for c in chars)
    upper = any(c.isupper() for c in chars)
    under = "_" in chars
    letters = {c for c in chars if c.isalpha()}
    if digits and not letters and not under:
        return r"\d", False
    if digits and letters and not under:
        if letters <= set("abcdef"):
            return "[0-9a-f]", False
        if letters <= set("ABCDEF"):
            return "[0-9A-F]", False
    if (not digits and not under and all(len(v) > 1 and v[0].isupper() and v[1:].islower() for v in values)):
        return "[A-Z][a-z]", True                     # Mot Capitalisé
    if lower and upper and digits and under:
        return r"\w", False
    return "[" + ("A-Z" if upper else "") + ("a-z" if lower else "") + ("0-9" if digits else "") + \
        ("_" if under else "") + "]", False


def _quant(lengths, flexible):
    lo, hi = min(lengths), max(lengths)
    if flexible:
        return "+" if lo >= 1 else "*"
    if lo == hi:
        return "" if lo == 1 else f"{{{lo}}}"
    return f"{{{lo},{hi}}}"


def regex_from_examples(examples, keep_same=True, keep_words=False, flexible=False, anchors=False,
                        capture=False):
    """Fabrique une expression qui reconnaît tous les exemples (un par ligne) -> (regex, explication)."""
    samples = [s.rstrip("\r") for s in examples if s.strip()]
    if not samples:
        raise ValueError("colle au moins un exemple")
    groups = {}
    for s in samples:
        toks = _tokenize(s)
        groups.setdefault(tuple(k for k, _ in toks), []).append(toks)
    parts = []
    for sig, members in groups.items():
        several = len(members) > 1
        out = []
        for pos, kind in enumerate(sig):
            values = [m[pos][1] for m in members]
            distinct = list(dict.fromkeys(values))
            if kind == "p":
                out.append(_esc(distinct[0]) if len(distinct) == 1 else _class_of(distinct))
                continue
            if kind == "s":
                if len(distinct) == 1 and not flexible:
                    v = distinct[0]
                    piece = _esc(v[0]) + ("" if len(v) == 1 else f"{{{len(v)}}}") if len(set(v)) == 1 \
                        else r"\s" + _quant([len(v)], False)
                else:
                    piece = r"\s" + _quant([len(v) for v in values], flexible)
                out.append(piece)
                continue
            if (keep_same and several and len(distinct) == 1) or \
                    (keep_words and len(distinct) == 1 and distinct[0].isalpha()):
                out.append(_esc(distinct[0]))
                continue
            if keep_words and all(v.isalpha() for v in distinct) and len(distinct) <= 6:
                alt = "|".join(_esc(v) for v in distinct)
                out.append(f"({alt})" if capture else f"(?:{alt})")
                continue
            cls, capitalized = _word_class(values)
            if capitalized:
                piece = cls + _quant([len(v) - 1 for v in values], flexible)
            else:
                piece = cls + _quant([len(v) for v in values], flexible)
            out.append(f"({piece})" if capture else piece)
        parts.append("".join(out))
    body = parts[0] if len(parts) == 1 else "(?:" + "|".join(parts) + ")"
    regex = ("^" + body + "$") if anchors else body
    n = len(samples)
    info = f"{n} exemple{'s' if n > 1 else ''}"
    if len(parts) > 1:
        info += f", {len(parts)} formes différentes : une alternative par forme."
    elif n > 1:
        info += ", tous de la même forme."
    else:
        info += " : ajoute d'autres exemples (un par ligne) pour une expression plus juste."
    return regex, info


# ---- exemples d'utilisation : Python, Ansible, grep -------------------------------------------

def _py_literal(s):
    if "'" not in s and not s.endswith("\\") and "\n" not in s:
        return "r'" + s + "'"
    if '"' not in s and not s.endswith("\\") and "\n" not in s:
        return 'r"' + s + '"'
    return repr(s)


def jinja_literal(s):
    """Chaîne Jinja2 entre apostrophes : Jinja interprète les antislashs, on les double."""
    return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"


def yaml_double(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def shell_quote(s):
    return "'" + s.replace("'", "'\\''") + "'"


def to_posix_ere(src):
    """Conversion au mieux vers grep -E (POSIX) -> (ere, alertes, ok)."""
    out, warn, i, n, ok = [], [], 0, len(src), True

    def note(msg, fatal=False):
        nonlocal ok
        if msg not in warn:
            warn.append(msg)
        if fatal:
            ok = False

    lead, src = split_global_flags(src)
    n = len(src)
    if set(lead) - {"i", "m"}:
        note("options (?s)/(?x)/(?a) ignorées par grep")
    shorthand = {"d": "[0-9]", "D": "[^0-9]", "w": "[[:alnum:]_]", "W": "[^[:alnum:]_]",
                 "s": "[[:space:]]", "S": "[^[:space:]]", "A": "^", "Z": "$", "z": "$"}

    def lazy_after():
        nonlocal i
        if i < n and src[i] in "?+":
            note("quantificateurs « le moins possible » (*? +? ??) ou possessifs : remplacés "
                 "par la version normale")
            i += 1

    while i < n:
        c = src[i]
        if c == "\\" and i + 1 < n:
            e = src[i + 1]
            i += 2
            if e in shorthand:
                out.append(shorthand[e])
            elif e in "bB":
                out.append("\\" + e)
            elif e.isdigit():
                out.append("\\" + e)
                note("références arrière (\\1…) : pas garanties avec grep -E")
            elif e in "nr":
                note("grep travaille ligne par ligne : \\n et \\r ne peuvent pas marcher", True)
            elif e == "t":
                out.append("\t")
                note("\\t remplacé par une vraie tabulation")
            elif e.isalnum():
                note(f"\\{e} n'existe pas en POSIX", True)
            else:
                out.append("\\" + e)
            continue
        if c == "[":
            j, neg = i + 1, False
            if j < n and src[j] == "^":
                neg, j = True, j + 1
            items, has_close, has_dash, has_caret, has_bs, first = [], False, False, False, False, True
            while j < n and not (src[j] == "]" and not first):
                ch = src[j]
                if ch == "\\" and j + 1 < n:
                    e = src[j + 1]
                    j += 2
                    if e in "dws":
                        items.append({"d": "0-9", "w": "[:alnum:]_", "s": "[:space:]"}[e])
                    elif e in "DWS":
                        note(f"\\{e} entre crochets n'existe pas en POSIX", True)
                    elif e == "]":
                        has_close = True
                    elif e == "-":
                        has_dash = True
                    elif e == "^":
                        has_caret = True
                    elif e == "\\":
                        has_bs = True
                    elif e == "t":
                        items.append("\t")
                    elif e.isalnum():
                        note(f"\\{e} entre crochets n'existe pas en POSIX", True)
                    else:
                        items.append(e)
                elif ch == "]" and first:
                    has_close, j = True, j + 1
                elif ch == "-" and (first or (j + 1 < n and src[j + 1] == "]")):
                    has_dash, j = True, j + 1
                else:
                    items.append(ch)
                    j += 1
                first = False
            body = ("]" if has_close else "") + "".join(items) + ("\\" if has_bs else "")
            if has_caret:
                body += "^" if body else ""
            body += "-" if has_dash else ""
            if not body and has_caret:
                out.append("\\^")
            else:
                out.append("[" + ("^" if neg else "") + body + "]")
            i = j + 1
            continue
        if c == "(" and src.startswith("(?", i):
            if src.startswith("(?:", i):
                out.append("(")
                i += 3
            elif src.startswith("(?P<", i):
                j = src.find(">", i)
                out.append("(")
                i = j + 1 if j > 0 else n
                note("noms de groupes retirés (grep ne les connaît pas)")
            elif src.startswith("(?#", i):
                j = src.find(")", i)
                i = j + 1 if j > 0 else n
            else:
                kind = ("« suivi de / précédé de » (?=, ?!, ?<=, ?<!)" if src[i + 2:i + 3] in "=!<"
                        else f"la construction « {src[i:i + 4]}… »")
                note(f"grep -E ne connaît pas {kind}", True)
                out.append("(")
                i += 2
                while i < n and src[i] not in ":=!>)":
                    i += 1
                i += 1 if i < n and src[i] != ")" else 0
            continue
        if c in "*+?":
            out.append(c)
            i += 1
            lazy_after()
            continue
        if c == "{":
            m = re.match(r"\{\d*(?:,\d*)?\}", src[i:])
            if m and m.group(0) not in ("{}", "{,}"):
                out.append(m.group(0))
                i += m.end()
                lazy_after()
            else:
                out.append("\\{")
                i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out), warn, ok


def regex_usage(src, case=False, word=False, dotall=False, repl=None):
    """Morceaux prêts à copier : Python, Ansible (YAML + Jinja2) et grep."""
    pattern = build_pattern(src, "regex", case, word, dotall)
    _lead, body = split_global_flags(pattern.pattern)
    names = [("IGNORECASE", re.IGNORECASE), ("MULTILINE", re.MULTILINE), ("DOTALL", re.DOTALL),
             ("VERBOSE", re.VERBOSE), ("ASCII", re.ASCII)]
    py_flags = " | ".join("re." + n for n, f in names if pattern.flags & f)
    letters = "".join(l for l, f in (("i", re.IGNORECASE), ("m", re.MULTILINE), ("s", re.DOTALL),
                                      ("x", re.VERBOSE), ("a", re.ASCII)) if pattern.flags & f)
    inline = (f"(?{letters})" if letters else "") + body
    tpl = npp_repl_template(repl) if repl is not None else None
    out = ["# ---- Python " + "-" * 60,
           "import re",
           "",
           f"motif = re.compile({_py_literal(body)}{', ' + py_flags if py_flags else ''})",
           "premiere = motif.search(texte)        # 1re correspondance (ou None)",
           "toutes = motif.findall(texte)         # toutes (les groupes, s'il y en a)",
           "for m in motif.finditer(texte):       # une par une, avec m.group(1)…",
           "    print(m.start(), m.group(0))"]
    if tpl is not None:
        out.append(f"nouveau = motif.sub({_py_literal(tpl)}, texte)")
    jl = jinja_literal(inline)
    out += ["",
            "# ---- Ansible (filtres Jinja2) " + "-" * 43,
            "# Forme conseillée : bloc YAML « >- », les antislashs ne sont doublés qu'une fois.",
            "- name: Utiliser l'expression régulière",
            "  ansible.builtin.set_fact:",
            "    trouve: >-",
            f"      {{{{ texte | regex_search({jl}) }}}}",
            "    toutes: >-",
            f"      {{{{ texte | regex_findall({jl}) }}}}"]
    if pattern.groups:
        out += ["    groupe_1: >-",
                f"      {{{{ texte | regex_search({jl}, '\\\\1') }}}}"]
    if tpl is not None:
        out += ["    remplace: >-",
                f"      {{{{ texte | regex_replace({jl}, {jinja_literal(tpl)}) }}}}"]
    out += ["  when: >-",
            f"    texte is search({jl})",
            "",
            "# Même chose sur une seule ligne entre guillemets doubles (antislashs doublés deux fois) :",
            "    trouve: " + yaml_double(f"{{{{ texte | regex_search({jl}) }}}}")]
    if tpl is not None:
        out.append("    remplace: " + yaml_double(f"{{{{ texte | regex_replace({jl}, {jinja_literal(tpl)}) }}}}"))
    lead, raw = split_global_flags(pcre_to_python(src))
    ere, warns, ok = to_posix_ere(raw)
    opts = "E" + ("" if case and "i" not in lead else "i") + ("w" if word else "")
    out += ["", "# ---- grep (Terminal Mac ou Linux) " + "-" * 38]
    if dotall:
        warns.insert(0, "grep travaille ligne par ligne : l'option « . = retour à la ligne » ne s'applique pas")
    for w in warns:
        out.append("# ⚠ " + w)
    if ok:
        out += [f"grep -{opts}n {shell_quote(ere)} fichier.txt      # lignes qui correspondent, avec leur numéro",
                f"grep -{opts}o {shell_quote(ere)} fichier.txt      # seulement les morceaux trouvés",
                f"grep -{opts}rn {shell_quote(ere)} dossier/        # dans tout un dossier"]
    else:
        out.append("# Cette expression n'a pas d'équivalent pour grep -E : utilise plutôt Python ou Ansible.")
    return "\n".join(out)


# ---- bibliothèque d'expressions prêtes à l'emploi -------------------------------------------------

_IPV4_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_H4 = r"[0-9A-Fa-f]{1,4}"

REGEX_LIBRARY = (
    ("Réseau", (
        ("Adresse IPv4", r"\b(?:" + _IPV4_OCTET + r"\.){3}" + _IPV4_OCTET + r"\b",
         "Quatre nombres de 0 à 255 séparés par des points.",
         "Serveur 192.168.1.20 joignable, 10.0.0.1 aussi.\nRefusé : 256.1.1.1 et 1.2.3"),
        ("Adresse IPv4 avec masque (CIDR)",
         r"\b(?:" + _IPV4_OCTET + r"\.){3}" + _IPV4_OCTET + r"/(?:3[0-2]|[12]?\d)\b",
         "Une adresse IPv4 suivie de /0 à /32.",
         "Réseaux autorisés : 10.0.0.0/8, 192.168.10.0/24\nRefusé : 10.0.0.0/33"),
        ("Adresse IPv6",
         r"(?<![\w:])(?:(?:" + _H4 + r":){7}" + _H4 + r"|(?:" + _H4 + r":){1,7}:|(?:" + _H4 + r":){1,6}:"
         + _H4 + r"|(?:" + _H4 + r":){1,5}(?::" + _H4 + r"){1,2}|(?:" + _H4 + r":){1,4}(?::" + _H4
         + r"){1,3}|(?:" + _H4 + r":){1,3}(?::" + _H4 + r"){1,4}|(?:" + _H4 + r":){1,2}(?::" + _H4
         + r"){1,5}|" + _H4 + r":(?::" + _H4 + r"){1,6}|:(?:(?::" + _H4 + r"){1,7}|:))(?![\w:])",
         "Forme complète ou abrégée avec « :: ».",
         "2001:0db8:85a3:0000:0000:8a2e:0370:7334\nfe80::1 et ::1 et 2001:db8::8a2e:370:7334"),
        ("Adresse MAC", r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b|\b(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}\b",
         "Six paires hexadécimales séparées par « : » ou « - ».",
         "eth0 : 00:1A:2b:3C:4d:5E\nwifi : AC-DE-48-00-11-22"),
        ("Numéro de port (1 à 65535)",
         r"\b(?:6553[0-5]|655[0-2]\d|65[0-4]\d{2}|6[0-4]\d{3}|[1-5]\d{4}|[1-9]\d{0,3})\b",
         "Un nombre entre 1 et 65535.", "ports: 22, 443, 8080, 65535\nhors plage : 65536"),
        ("Hôte:port", r"\b([A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?):(\d{1,5})\b",
         "Groupe 1 = hôte, groupe 2 = port.", "db01.prod.local:5432\nlocalhost:8080 et 10.1.2.3:22"),
        ("Nom d'hôte complet (FQDN)",
         r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b",
         "Morceaux séparés par des points, terminés par un domaine en lettres.",
         "srv-web-01.intra.exemple.fr\napi.exemple.com"),
        ("URL http(s)", r"\bhttps?://[^\s\"'<>]+",
         "Commence par http:// ou https:// et s'arrête au premier blanc ou guillemet.",
         "Doc : https://docs.exemple.com/guide?page=2#haut\nhttp://intranet/outil"),
        ("Adresse e-mail", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
         "Forme courante nom@domaine.ext (pas toutes les subtilités de la norme).",
         "Contact : prenom.nom@exemple.fr, support+ops@exemple.com"),
    )),
    ("Dates et heures", (
        ("Date ISO (AAAA-MM-JJ)", r"\b\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])\b",
         "Mois de 01 à 12, jour de 01 à 31.", "Livraison le 2026-11-25, pas le 2026-13-01."),
        ("Date française (JJ/MM/AAAA)", r"\b(?:0[1-9]|[12]\d|3[01])/(?:0[1-9]|1[0-2])/\d{4}\b",
         "Jour/mois/année sur quatre chiffres.", "Réunion le 25/11/2026 (et non 32/01/2026)."),
        ("Heure (HH:MM ou HH:MM:SS)", r"\b(?:[01]\d|2[0-3]):[0-5]\d(?::[0-5]\d)?\b",
         "De 00:00 à 23:59, secondes facultatives.", "Début 08:30, fin 17:45:12, pas 24:00."),
        ("Horodatage ISO 8601",
         r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?(?!\w)",
         "Date, heure, fractions de seconde et fuseau facultatifs.",
         "2026-11-25T14:02:03Z\n2026-11-25 14:02:03.123+01:00"),
        ("Date syslog (« Nov 25 14:02:03 »)",
         r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [ \d]\d \d{2}:\d{2}:\d{2}\b",
         "Format des journaux système Unix.", "Nov 25 14:02:03 srv01 sshd[812]: Accepted publickey"),
    )),
    ("Identifiants et sécurité", (
        ("UUID", r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
         "Identifiant 8-4-4-4-12 en hexadécimal.", "job_id: 550e8400-e29b-41d4-a716-446655440000"),
        ("Empreinte MD5 / SHA-1 / SHA-256", r"\b(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})\b",
         "32, 40 ou 64 caractères hexadécimaux.",
         "md5 d41d8cd98f00b204e9800998ecf8427e\nsha1 da39a3ee5e6b4b0d3255bfef95601890afd80709"),
        ("Jeton JWT", r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*",
         "Trois blocs Base64 URL séparés par des points.",
         "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl"),
        ("Bloc Base64 (16 caractères ou plus)",
         r"(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?(?![A-Za-z0-9+/=])",
         "Suite de groupes de 4 caractères Base64, avec « = » final éventuel.",
         "data: SGVsbG8gdG91dCBsZSBtb25kZSAh\ncourt : abc="),
        ("Clé publique SSH",
         r"\b(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp(?:256|384|521)) [A-Za-z0-9+/]+=*(?: \S+)?",
         "Type de clé, contenu Base64 et commentaire facultatif.",
         "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExempleExempleExemple user@mac"),
        ("Bloc PEM (certificat, clé…)", r"-----BEGIN ([A-Z0-9 ]+)-----[\s\S]*?-----END \1-----",
         "Du BEGIN au END correspondant (sur plusieurs lignes).",
         "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIU\n-----END CERTIFICATE-----"),
        ("Secret en clair (password: …)",
         r"\b(?i:\w*(?:password|passwd|pwd|secret|token|api[_-]?key)\w*)\s*[:=]\s*\S+",
         "Repère les mots de passe ou jetons écrits en clair avant un commit.",
         "db_password: Sup3rS3cret\nAPI_KEY=abcd1234\nvault_password_file: ~/.vault"),
    )),
    ("Ansible, YAML, Jinja2", (
        ("Variable Jinja {{ … }}", r"\{\{\s*(.*?)\s*\}\}", "Groupe 1 = l'expression entre les accolades.",
         "dest: \"{{ app_dir }}/conf/{{ env | default('prod') }}.yml\""),
        ("Bloc Jinja {% … %}", r"\{%-?\s*(\w+)(.*?)-?%\}", "Groupe 1 = mot-clé (if, for, set…).",
         "{% for h in groups['web'] %}{{ h }}{% endfor %}"),
        ("Clé YAML en début de ligne", r"^(\s*)(?:- )?([\w.-]+):(?=\s|$)",
         "Groupe 1 = indentation, groupe 2 = nom de la clé.",
         "- name: Installer nginx\n  ansible.builtin.package:\n    name: nginx\n    state: present"),
        ("Nom de tâche (- name:)", r"^\s*- name:\s*(.*)$", "Groupe 1 = titre de la tâche.",
         "- name: Copier la configuration\n  ansible.builtin.copy:\n    src: app.conf"),
        ("Module FQCN (ansible.builtin.copy…)", r"^\s*(?:- )?([a-z0-9_]+\.[a-z0-9_]+\.[a-z0-9_]+):",
         "Groupe 1 = nom complet du module.",
         "- name: Redémarrer\n  ansible.builtin.service:\n    name: nginx\n  community.general.ufw:"),
        ("Récapitulatif PLAY RECAP",
         r"^(\S+)\s*:\s*ok=(\d+)\s+changed=(\d+)\s+unreachable=(\d+)\s+failed=(\d+)",
         "Groupes : hôte, ok, changed, unreachable, failed.",
         "srv01                      : ok=12   changed=3    unreachable=0    failed=0\n"
         "srv02                      : ok=4    changed=0    unreachable=1    failed=2"),
        ("Variable d'environnement ($VAR, ${VAR})", r"\$(?:\{(\w+)\}|(\w+))",
         "Groupe 1 ou 2 = nom de la variable.", "export PATH=$HOME/bin:${PATH}"),
    )),
    ("Journaux (logs)", (
        ("Ligne contenant ERROR, FATAL ou CRITICAL", r"^.*\b(?:ERROR|FATAL|CRITICAL)\b.*$",
         "La ligne entière (à utiliser avec « Respecter la casse »).",
         "2026-11-25 10:00:01 INFO démarrage\n2026-11-25 10:00:02 ERROR connexion refusée\n"
         "2026-11-25 10:00:03 WARN lent"),
        ("Niveau de log", r"\b(?:TRACE|DEBUG|INFO|NOTICE|WARN(?:ING)?|ERROR|FATAL|CRITICAL)\b",
         "Les niveaux usuels.", "[INFO] ok\n[WARNING] disque à 85 %\n[ERROR] échec"),
        ("Requête HTTP dans un log d'accès",
         r"\"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) (\S+) HTTP/[\d.]+\" (\d{3})",
         "Groupes : méthode, chemin, code de retour.",
         "10.0.0.5 - - [25/Nov/2026:10:00:00 +0100] \"GET /api/health HTTP/1.1\" 200 17\n"
         "10.0.0.6 - - [25/Nov/2026:10:00:01 +0100] \"POST /login HTTP/1.1\" 401 0"),
        ("Pile d'appels Java (« at … »)", r"^\s+at [\w.$<>]+\([^)]*\)$",
         "Lignes d'une stack trace Java.",
         "java.lang.NullPointerException\n    at com.exemple.App.run(App.java:42)\n"
         "    at com.exemple.App.main(App.java:10)"),
        ("Pile d'appels Python (fichier, ligne)", r"^\s*File \"([^\"]+)\", line (\d+)",
         "Groupes : fichier, numéro de ligne.",
         "Traceback (most recent call last):\n  File \"/opt/app/main.py\", line 12, in <module>"),
    )),
    ("Texte et code", (
        ("Ligne vide (ou blancs seuls)", r"^[ \t]*$", "Pratique avec « Remplacer » pour nettoyer.",
         "ligne 1\n\n   \nligne 4"),
        ("Espaces en fin de ligne", r"[ \t]+$", "Remplacer par rien pour les supprimer.",
         "texte avec espaces   \nautre ligne\t"),
        ("Lignes en double qui se suivent", r"^(.*)(?:\r?\n\1)+$",
         "Remplacer par $1 garde un seul exemplaire.", "alpha\nalpha\nbeta\ngamma\ngamma\ngamma"),
        ("Nombre entier ou décimal", r"[-+]?\b\d+(?:[.,]\d+)?\b", "Accepte le point ou la virgule.",
         "Total : 1250, remise -12,5 et taux 0.2"),
        ("Texte entre guillemets doubles", r"\"((?:[^\"\\]|\\.)*)\"",
         "Groupe 1 = contenu, guillemets échappés compris.", "msg = \"Bonjour \\\"toi\\\"\" + \"!\""),
        ("Texte entre apostrophes", r"'((?:[^'\\]|\\.)*)'", "Groupe 1 = contenu.", "when: env == 'prod'"),
        ("Commentaire # (shell, YAML, Python)", r"(?<!\S)#.*$", "Du # jusqu'à la fin de la ligne.",
         "port: 8080   # port HTTP\n# ligne commentée\ncouleur: \"#FF0000\""),
        ("Balise HTML / XML", r"<(/?)([A-Za-z][\w:.-]*)([^>]*)>",
         "Groupes : / de fermeture, nom, attributs.", "<div class=\"note\"><b>Gras</b></div>"),
        ("Chemin Unix / Mac", r"(?<![\w.~/])~?/[\w.@+/-]+", "Chemin absolu ou commençant par ~/.",
         "Voir /etc/hosts et ~/mac/explorer/blocnotes.py"),
        ("Chemin Windows", r"\b[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*",
         "Lettre de lecteur suivie de dossiers.", r"Copie vers C:\Users\moi\Documents\rapport.docx"),
        ("Numéro de version (semver)",
         r"\bv?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?\b",
         "Groupes : majeure, mineure, correctif, pré-version, build.",
         "ansible-core 2.16.3, outil v1.4.0-rc.1+build.7"),
        ("Couleur hexadécimale", r"#(?:[0-9a-fA-F]{3}){1,2}\b", "#RGB ou #RRGGBB.",
         "color: #0067C0; background: #fff;"),
    )),
    ("France", (
        ("Téléphone français", r"(?<!\d)(?:\+33\s?|0)[1-9](?:[\s.-]?\d{2}){4}(?!\d)",
         "06 12 34 56 78, 01.23.45.67.89 ou +33 6 12 34 56 78.",
         "Tél. 06 12 34 56 78 / +33 1 23 45 67 89 / 0123456789"),
        ("Code postal", r"\b(?:0[1-9]|[1-8]\d|9[0-8])\d{3}\b", "Cinq chiffres, département 01 à 98.",
         "75001 Paris, 69002 Lyon, 13008 Marseille"),
    )),
)


# ======================================================================================
# Langages
# ======================================================================================

LANGS = {
    "text": ("Fichier texte", ()),
    "yaml": ("YAML", (".yml", ".yaml")),
    "json": ("JSON", (".json", ".jsonc", ".geojson", ".har", ".ipynb")),
    "bash": ("Bash", (".sh", ".bash", ".zsh", ".ksh", ".bashrc", ".zshrc", ".profile", ".bash_profile",
                      ".bash_aliases", ".zprofile")),
    "python": ("Python", (".py", ".pyw", ".pyi")),
    "ini": ("INI", (".ini", ".cfg", ".conf", ".properties", ".toml", ".editorconfig", ".gitconfig",
                    ".env", ".service", ".desktop")),
    "xml": ("XML", (".xml", ".xsd", ".xsl", ".xslt", ".svg", ".plist", ".pom", ".csproj", ".wsdl")),
    "html": ("HTML", (".html", ".htm", ".xhtml")),
    "markdown": ("Markdown", (".md", ".markdown")),
    "sql": ("SQL", (".sql",)),
    "dockerfile": ("Dockerfile", (".dockerfile",)),
    "groovy": ("Groovy", (".groovy", ".gradle", ".jenkinsfile")),
    "javascript": ("JavaScript", (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx")),
    "css": ("CSS", (".css", ".scss", ".less")),
    "log": ("Log", (".log", ".out")),
}
_NAMES = {"dockerfile": "dockerfile", "containerfile": "dockerfile", "jenkinsfile": "groovy",
          "makefile": "bash", "ansible.cfg": "ini", "hosts": "ini", "inventory": "ini", ".gitignore": "bash"}
_EXT = {ext: code for code, (_label, exts) in LANGS.items() for ext in exts}


def _lang_by_name(name):
    if name in _NAMES:
        return _NAMES[name]
    if name.startswith(("dockerfile.", "containerfile.")):
        return "dockerfile"
    if name.startswith("jenkinsfile"):
        return "groovy"
    ext = os.path.splitext(name)[1]
    if ext in _EXT:
        return _EXT[ext]
    if name in _EXT:              # .bashrc, .env…
        return _EXT[name]
    return None


_LOG_LINE = re.compile(r"\b(ERROR|WARN(?:ING)?|INFO|DEBUG|TRACE|FATAL)\b|\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}")


def detect_language(path, text):
    """(langage, jinja) d'après le nom du fichier, sinon d'après son contenu."""
    name = os.path.basename(path or "").lower()
    jinja = name.endswith(".j2") or name.endswith(".jinja2")
    if jinja:
        name = name.rsplit(".", 1)[0]
    lang = _lang_by_name(name) if name else None
    if lang:
        return lang, jinja
    head = text[:4000]
    first = next((l.strip() for l in head.splitlines() if l.strip()), "")
    if first.startswith("#!"):
        if "python" in first:
            return "python", jinja
        if re.search(r"\b(ba|z|k|da)?sh\b", first):
            return "bash", jinja
    low = first.lower()
    if low.startswith("<?xml"):
        return ("html" if "<html" in head.lower() else "xml"), jinja
    if low.startswith(("<!doctype html", "<html")):
        return "html", jinja
    if first.startswith(("{", "[")) and len(text) < 4 * 1024 * 1024:
        try:
            json_parse(text)
            return "json", jinja
        except JsonError:
            pass
    if first == "---" or re.match(r"^-\s+\w+:\s", first) or re.match(r"^[\w.\-]+:(\s|$)", first) and \
            ":" in head.splitlines()[min(1, len(head.splitlines()) - 1)]:
        return "yaml", True if jinja else ("{{" in head)
    if re.search(r"^(TASK|PLAY|PLAY RECAP) \[", head, re.MULTILINE) or \
            sum(1 for l in head.splitlines()[:30] if _LOG_LINE.search(l)) >= 3:
        return "log", jinja
    if path and name.endswith(".txt"):
        return "text", jinja
    return "text", jinja or ("{{" in head and "}}" in head)


# ======================================================================================
# Qt (uniquement QtCore, QtGui et QtWidgets)
# ======================================================================================

from bisect import bisect_left  # noqa: E402

from PySide6.QtCore import (QByteArray, QFileSystemWatcher, QLockFile, QMimeData,  # noqa: E402
                            QObject, QPoint, QPointF, QRect, QRectF, QSettings, QSize,
                            QStandardPaths, Qt, QTimer, Signal)
from PySide6.QtGui import (QAction, QActionGroup, QBrush, QColor, QFont, QFontDatabase,  # noqa: E402
                           QFontMetricsF, QGuiApplication, QIcon, QKeySequence, QPainter, QPainterPath,
                           QPalette, QPen, QPixmap, QPolygonF, QSyntaxHighlighter, QTextCharFormat, QTextCursor, QTextFormat, QTextOption)
from PySide6.QtWidgets import (QApplication, QCheckBox,  # noqa: E402
                               QComboBox, QDialog, QDialogButtonBox, QDockWidget, QFileDialog,
                               QFontComboBox, QFormLayout, QFrame, QGridLayout, QGroupBox, QHBoxLayout,
                               QInputDialog, QLabel, QLineEdit, QListWidget, QListWidgetItem,
                               QMainWindow, QMenu, QMessageBox, QPlainTextEdit, QPushButton, QRadioButton,
                               QScrollArea, QSpinBox, QSplitter, QStatusBar, QTabBar, QTabWidget, QTextEdit,
                               QToolBar, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)

EOL_PROP = QTextFormat.Property.UserProperty.value + 1
RECT_MIME = "application/x-blocnotes-colonne"
ASTRAL = re.compile("[\U00010000-\U0010FFFF]")


class PosMap:
    """Python compte les caractères, Qt compte en UTF-16 : on convertit (émojis…)."""

    def __init__(self, text):
        self.idx = [m.start() for m in ASTRAL.finditer(text)]

    def to_doc(self, i):
        return i + bisect_left(self.idx, i) if self.idx else i

    def to_py(self, p):
        if not self.idx:
            return p
        lo, hi = 0, p
        while lo < hi:
            mid = (lo + hi) // 2
            if mid + bisect_left(self.idx, mid) < p:
                lo = mid + 1
            else:
                hi = mid
        return lo


def u16(text):
    return len(text) + len(ASTRAL.findall(text)) if ASTRAL.search(text) else len(text)


# ---- thème ---------------------------------------------------------------------------

EDITOR_COLORS = {
    False: dict(bg="#FFFFFF", fg="#000000", line="#E8E8FF", gutter="#E4E4E4", gutter_fg="#808080",
                gutter_cur="#000000", fold_bg="#F3F3F3", fold_fg="#8A8A8A", sel="#ADD6FF", guide="#D0D0D0",
                badge_bg="#3C3C3C", badge_fg="#FFFFFF", special_bg="#E04040", special_fg="#FFFFFF",
                smart="#B6F2B6", mark="#FFC680", brace="#C8F0C8", brace_bad="#FFB4B4", bookmark="#2B7BD8",
                block="#ADD6FF", folded="#808080", added="#DDF7DD", removed="#FBDADA", changed="#FFF4C2",
                blank="#F0F0F0", tabwarn="#FFC8C8"),
    True: dict(bg="#1E1E1E", fg="#D4D4D4", line="#2A2D2E", gutter="#1E1E1E", gutter_fg="#858585",
               gutter_cur="#C6C6C6", fold_bg="#1E1E1E", fold_fg="#7A7A7A", sel="#264F78", guide="#404040",
               badge_bg="#C8C8C8", badge_fg="#1E1E1E", special_bg="#D04848", special_fg="#FFFFFF",
               smart="#3A4F3A", mark="#7A4B12", brace="#3B514D", brace_bad="#6B2020", bookmark="#4CC2FF",
               block="#264F78", folded="#8A8A8A", added="#1F3B26", removed="#4B2224", changed="#4A4320",
               blank="#262626", tabwarn="#5A2A2A"),
}
SYNTAX_COLORS = {
    False: {"keyword": ("#0000FF", True), "builtin": ("#8000FF", False), "string": ("#808080", False),
            "comment": ("#008000", False), "number": ("#FF8000", False), "key": ("#0000A0", False),
            "tag": ("#0000FF", False), "attr": ("#FF0000", False), "constant": ("#0000FF", True),
            "punct": ("#000080", True), "jinja": ("#A000A0", False), "jinja_kw": ("#A000A0", True),
            "heading": ("#0000FF", True), "error": ("#E00000", True), "warning": ("#C86400", True),
            "info": ("#0063B1", False), "debug": ("#909090", False), "date": ("#008080", False),
            "variable": ("#B000B0", False), "decorator": ("#808000", False), "url": ("#0000FF", False),
            "ok": ("#1E8E3E", True)},
    True: {"keyword": ("#569CD6", True), "builtin": ("#C586C0", False), "string": ("#CE9178", False),
           "comment": ("#6A9955", False), "number": ("#B5CEA8", False), "key": ("#9CDCFE", False),
           "tag": ("#569CD6", False), "attr": ("#9CDCFE", False), "constant": ("#569CD6", True),
           "punct": ("#D4D4D4", True), "jinja": ("#D7BA7D", False), "jinja_kw": ("#D7BA7D", True),
           "heading": ("#4FC1FF", True), "error": ("#F44747", True), "warning": ("#D7A64B", True),
           "info": ("#4FC1FF", False), "debug": ("#808080", False), "date": ("#4EC9B0", False),
           "variable": ("#9CDCFE", False), "decorator": ("#DCDCAA", False), "url": ("#3794FF", False),
           "ok": ("#73C991", True)},
}


class Theme:
    dark = False

    @classmethod
    def ed(cls, name):
        return QColor(EDITOR_COLORS[cls.dark][name])


def editor_font(size=None):
    families = ("Menlo", "SF Mono", "Monaco") if IS_MAC else (("Consolas", "Cascadia Mono") if IS_WIN
                                                              else ("DejaVu Sans Mono", "Liberation Mono"))
    available = set(QFontDatabase.families())
    for fam in families:
        if fam in available:
            font = QFont(fam)
            break
    else:
        font = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
    font.setStyleHint(QFont.StyleHint.Monospace)
    font.setFixedPitch(True)
    font.setPointSizeF(size or (12.0 if IS_MAC else 10.0))
    return font


# ---- coloration syntaxique -------------------------------------------------------------

LEX = {
    "yaml": dict(quotes="\"'", line=("#",), need_space=True, yaml=True),
    "bash": dict(quotes="\"'`", line=("#",), need_space=True, sq_raw=True),
    "python": dict(quotes="\"'", line=("#",), triple=True),
    "json": dict(quotes='"'),
    "javascript": dict(quotes="\"'`", line=("//",), block=("/*", "*/")),
    "groovy": dict(quotes="\"'", line=("//",), block=("/*", "*/"), triple=True),
    "css": dict(quotes="\"'", block=("/*", "*/")),
    "sql": dict(quotes="'\"", line=("--",), block=("/*", "*/")),
    "ini": dict(quotes='"', line=(";", "#"), line_start=True),
    "dockerfile": dict(quotes="\"'", line=("#",), line_start=True),
    "xml": dict(block=("<!--", "-->")),
    "html": dict(block=("<!--", "-->")),
}
ST_BLOCK, ST_TRIPLE_DQ, ST_TRIPLE_SQ, ST_FENCE = 1, 2, 3, 4


def _quote_ok(text, i, cfg):
    if cfg.get("yaml"):
        return i == 0 or text[i - 1] in " \t:[{,-"
    return True


def scan_line(text, cfg, state):
    """Chaînes et commentaires d'une ligne : [(début, fin, style)], état pour la ligne suivante."""
    spans, i, n = [], 0, len(text)
    block = cfg.get("block")
    if state == ST_BLOCK and block:
        end = text.find(block[1])
        if end < 0:
            return [(0, n, "comment")], ST_BLOCK
        i = end + len(block[1])
        spans.append((0, i, "comment"))
    elif state in (ST_TRIPLE_DQ, ST_TRIPLE_SQ):
        quote = '"""' if state == ST_TRIPLE_DQ else "'''"
        end = text.find(quote)
        if end < 0:
            return [(0, n, "string")], state
        i = end + 3
        spans.append((0, i, "string"))
    quotes, line_toks = cfg.get("quotes", ""), cfg.get("line", ())
    while i < n:
        c = text[i]
        if block and text.startswith(block[0], i):
            end = text.find(block[1], i + len(block[0]))
            if end < 0:
                spans.append((i, n, "comment"))
                return spans, ST_BLOCK
            spans.append((i, end + len(block[1]), "comment"))
            i = end + len(block[1])
            continue
        hit = False
        for tok in line_toks:
            if text.startswith(tok, i):
                if cfg.get("need_space") and i > 0 and text[i - 1] not in " \t":
                    continue
                if cfg.get("line_start") and text[:i].strip():
                    continue
                hit = True
                break
        if hit:
            spans.append((i, n, "comment"))
            return spans, 0
        if cfg.get("triple") and text.startswith(('"""', "'''"), i):
            quote = text[i:i + 3]
            end = text.find(quote, i + 3)
            if end < 0:
                spans.append((i, n, "string"))
                return spans, ST_TRIPLE_DQ if quote == '"""' else ST_TRIPLE_SQ
            spans.append((i, end + 3, "string"))
            i = end + 3
            continue
        if c in quotes and _quote_ok(text, i, cfg):
            raw = c == "'" and (cfg.get("sq_raw") or cfg.get("yaml"))
            j = i + 1
            while j < n:
                ch = text[j]
                if cfg.get("yaml") and c == "'" and ch == "'" and j + 1 < n and text[j + 1] == "'":
                    j += 2
                    continue
                if ch == "\\" and not raw:
                    j += 2
                    continue
                j += 1
                if ch == c:
                    break
            spans.append((i, min(j, n), "string"))
            i = j
            continue
        i += 1
    return spans, 0


def _kw(words, flags=0):
    return re.compile(r"\b(?:" + "|".join(words.split()) + r")\b", flags)


_NUM = re.compile(r"(?<![\w.])-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b")
_BASH_VARS = re.compile(r"\$\{[^}\n]*\}|\$\(|\$[A-Za-z_][A-Za-z0-9_]*|\$[0-9#?@*$!\-]")
RULES = {
    "yaml": [
        (re.compile(r"^(?:---|\.\.\.)\s*$"), "keyword", 0, False),
        (re.compile(r"^\s*(-)(?=\s|$)"), "punct", 1, False),
        (re.compile(r"(?<![\w&*])[&*][\w\-.]+"), "builtin", 0, False),
        (re.compile(r"(?<!\S)!!?[\w\-./]+"), "decorator", 0, False),
        (re.compile(r"(?:(?<=:\s)|(?<=-\s))\s*(true|false|True|False|TRUE|FALSE|yes|no|null|Null|~)(?=\s*(?:#|$))"),
         "constant", 1, False),
        (re.compile(r"(?:(?<=:\s)|(?<=-\s))\s*([-+]?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?)(?=\s*(?:#|$))"),
         "number", 1, False),
        (re.compile(r":\s+([|>][-+]?\d*)\s*$"), "punct", 1, False),
        (re.compile(r"^(\s*(?:-\s+)*)((?:[^\s#'\"{}\[\],&*!|>%@`][^#]*?)|\"[^\"]*\"|'[^']*')(?=\s*:(?:\s|$))"),
         "key", 2, True),
    ],
    "json": [
        (_NUM, "number", 0, False),
        (re.compile(r"\b(?:true|false|null)\b"), "constant", 0, False),
        (re.compile(r"[{}\[\]]"), "punct", 0, False),
        (re.compile(r'("(?:[^"\\]|\\.)*")(?=\s*:)'), "key", 1, True),
    ],
    "bash": [
        (_kw("if then else elif fi for while until do done case esac in function select time return break "
             "continue local export readonly declare typeset unset shift source trap exit set"), "keyword", 0, False),
        (_kw("echo printf cd pwd test read eval exec alias mkdir rm cp mv ls cat grep sed awk find chmod chown "
             "sudo ssh scp rsync tar kill sleep curl wget sort uniq head tail cut tr xargs tee touch ln"),
         "builtin", 0, False),
        (_NUM, "number", 0, False),
        (_BASH_VARS, "variable", 0, True),
        (re.compile(r"^#!.*"), "decorator", 0, True),
    ],
    "python": [
        (_kw("def class if elif else for while try except finally with as import from return yield lambda "
             "pass break continue raise global nonlocal assert del in is not and or async await match case"),
         "keyword", 0, False),
        (_kw("True False None"), "constant", 0, False),
        (_kw("print len range str int float dict list set tuple open super isinstance enumerate zip map "
             "filter sorted any all min max abs sum type object Exception self cls bytes bool"), "builtin", 0, False),
        (re.compile(r"^\s*@[\w.]+"), "decorator", 0, False),
        (re.compile(r"\b(?:def|class)\s+(\w+)"), "key", 1, False),
        (_NUM, "number", 0, False),
    ],
    "ini": [
        (re.compile(r"^\s*\[[^\]]*\]"), "keyword", 0, False),
        (re.compile(r"^\s*([^=:#;\[\s][^=:]*?)\s*(?=[=:])"), "key", 1, False),
        (re.compile(r"\b([\w.\-]+)(?==)"), "key", 1, False),
        (re.compile(r"(?<==)\s*(true|false|yes|no|on|off)\b", re.IGNORECASE), "constant", 1, False),
        (_NUM, "number", 0, False),
    ],
    "xml": [
        (re.compile(r"<\?.*?\?>|<![A-Z][^>]*>"), "decorator", 0, False),
        (re.compile(r"</?\s*([\w:.\-]+)"), "tag", 1, False),
        (re.compile(r"</?|/?>"), "tag", 0, False),
        (re.compile(r"\s([\w:.\-]+)(?=\s*=)"), "attr", 1, False),
        (re.compile(r"=\s*(\"[^\"]*\"|'[^']*')"), "string", 1, False),
        (re.compile(r"&[#\w]+;"), "constant", 0, False),
    ],
    "markdown": [
        (re.compile(r"^#{1,6}\s.*"), "heading", 0, False),
        (re.compile(r"\*\*[^*]+\*\*|__[^_]+__"), "keyword", 0, False),
        (re.compile(r"`[^`]+`"), "string", 0, False),
        (re.compile(r"\[[^\]]+\]\([^)]+\)"), "url", 0, False),
        (re.compile(r"^\s*([-*+]|\d+\.)\s"), "punct", 1, False),
        (re.compile(r"^\s*>.*"), "comment", 0, False),
    ],
    "sql": [
        (_kw("select from where and or not insert into values update set delete create table drop alter join left "
             "right inner outer full on group by order having limit offset as distinct union all null is like in "
             "between case when then else end begin commit rollback index primary key foreign references default "
             "exists view procedure function returns declare", re.IGNORECASE), "keyword", 0, False),
        (re.compile(r"\b(\w+)(?=\()"), "builtin", 1, False),
        (_NUM, "number", 0, False),
    ],
    "dockerfile": [
        (re.compile(r"^\s*(FROM|RUN|CMD|LABEL|MAINTAINER|EXPOSE|ENV|ADD|COPY|ENTRYPOINT|VOLUME|USER|WORKDIR|ARG|"
                    r"ONBUILD|STOPSIGNAL|HEALTHCHECK|SHELL)\b", re.IGNORECASE), "keyword", 1, False),
        (re.compile(r"\bAS\b"), "keyword", 0, False),
        (_BASH_VARS, "variable", 0, True),
        (_NUM, "number", 0, False),
    ],
    "groovy": [
        (_kw("def if else for while switch case default return try catch finally throw new class import package "
             "static final void boolean int String in as"), "keyword", 0, False),
        (_kw("true false null"), "constant", 0, False),
        (_kw("pipeline agent stages stage steps sh bat echo script environment post always success failure "
             "node withCredentials parallel when options parameters tools input timeout retry dir"), "builtin", 0, False),
        (re.compile(r"\$\{[^}\n]*\}|\$[A-Za-z_]\w*"), "variable", 0, True),
        (_NUM, "number", 0, False),
    ],
    "javascript": [
        (_kw("var let const function return if else for while do switch case default break continue new delete "
             "typeof instanceof in of class extends super this import export from try catch finally throw async "
             "await yield interface type enum"), "keyword", 0, False),
        (_kw("true false null undefined NaN"), "constant", 0, False),
        (_kw("console window document Math JSON Promise Object Array String Number"), "builtin", 0, False),
        (_NUM, "number", 0, False),
    ],
    "css": [
        (re.compile(r"^[^{}\n:;]+(?=\{)"), "tag", 0, False),
        (re.compile(r"([\w-]+)(?=\s*:[^:])"), "attr", 1, False),
        (re.compile(r"#[0-9a-fA-F]{3,8}\b|(?<![\w-])-?\d+(?:\.\d+)?(?:px|em|rem|%|vh|vw|s|ms|pt|deg)?\b"),
         "number", 0, False),
        (re.compile(r"!important"), "keyword", 0, False),
    ],
    "log": [
        (re.compile(r'"[^"\n]*"'), "string", 0, False),
        (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b"), "number", 0, False),
        (re.compile(r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?|"
                    r"\b\d{2}/\d{2}/\d{4}\b|\b\d{2}:\d{2}:\d{2}(?:[.,]\d+)?\b"), "date", 0, False),
        (re.compile(r"\b(?:DEBUG|TRACE)\b"), "debug", 0, False),
        (re.compile(r"\b(?:INFO|NOTICE)\b"), "info", 0, False),
        (re.compile(r"\b(?:WARN|WARNING)\b"), "warning", 0, False),
        (re.compile(r"\b(?:ERROR|ERR|FATAL|CRITICAL|SEVERE|FAILED|FAILURE|Exception|Traceback)\b"), "error", 0, False),
        (re.compile(r"^(?:ok|\s*ok)(?=:)|\bok(?==)"), "ok", 0, False),
        (re.compile(r"\bchanged(?=[:=])"), "warning", 0, False),
        (re.compile(r"\b(?:failed|fatal|unreachable)(?=[:=])"), "error", 0, False),
        (re.compile(r"\b(?:skipping|skipped|rescued|ignored)(?=[:=])"), "info", 0, False),
        (re.compile(r"^(?:PLAY RECAP|PLAY|TASK|RUNNING HANDLER)\b.*"), "heading", 0, False),
    ],
}
RULES["html"] = RULES["xml"]
_JINJA = re.compile(r"\{\{.*?\}\}|\{%.*?%\}|\{#.*?#\}")
_JINJA_KW = re.compile(r"\b(?:if|elif|else|endif|for|endfor|in|not|and|or|is|set|block|endblock|macro|"
                       r"endmacro|include|import|from|with|endwith|raw|endraw|filter|endfilter|true|false|"
                       r"none|default)\b|\|\s*\w+")
URL_RE = re.compile(r"\bhttps?://[^\s\"'<>)\]}]+")
_YAML_TABS = re.compile(r"^[ ]*(\t+)")


def make_formats(font):
    out = {}
    for name, (color, bold) in SYNTAX_COLORS[Theme.dark].items():
        fmt = QTextCharFormat()
        fmt.setForeground(QColor(color))
        if bold:
            fmt.setFontWeight(QFont.Weight.Bold)
        if name == "comment" and not Theme.dark:
            pass
        if name == "url":
            fmt.setFontUnderline(True)
        if name == "jinja":
            fmt.setBackground(QColor("#F6EAF6" if not Theme.dark else "#33283A"))
        out[name] = fmt
    tab = QTextCharFormat()
    tab.setBackground(Theme.ed("tabwarn"))
    out["tabwarn"] = tab
    small = QFont(font)
    small.setPointSizeF(max(6.0, font.pointSizeF() * 0.72))
    fm, normal = QFontMetricsF(small), QFontMetricsF(font)
    for char, label in SPECIAL_CHARS.items():
        fmt = QTextCharFormat()
        width = fm.horizontalAdvance(label) + 8
        fmt.setFontLetterSpacingType(QFont.SpacingType.AbsoluteSpacing)
        fmt.setFontLetterSpacing(max(0.0, width - normal.horizontalAdvance(char)))
        fmt.setForeground(Theme.ed("special_fg"))
        out["special:" + char] = fmt
    return out


class Highlighter(QSyntaxHighlighter):
    def __init__(self, doc, editor):
        super().__init__(doc)
        self.ed = editor
        self.enabled = True
        self.formats = make_formats(editor_font())

    def rebuild(self, font):
        self.formats = make_formats(font)
        self.rehighlight()

    def highlightBlock(self, text):
        n = len(text)
        if not n:
            prev = self.previousBlockState()
            self.setCurrentBlockState(prev if prev in (ST_BLOCK, ST_TRIPLE_DQ, ST_TRIPLE_SQ, ST_FENCE) else 0)
            return
        pm = PosMap(text) if ASTRAL.search(text) else None
        F = self.formats

        def fmt(s, e, style):
            if pm:
                s, e = pm.to_doc(s), pm.to_doc(e)
            self.setFormat(s, e - s, F[style])

        lang = self.ed.lang
        if self.enabled and n <= 20000:
            prev = max(self.previousBlockState(), 0)
            if lang == "markdown":
                if text.lstrip().startswith("```"):
                    fmt(0, n, "string")
                    self.setCurrentBlockState(0 if prev == ST_FENCE else ST_FENCE)
                    self._specials(text, fmt)
                    return
                if prev == ST_FENCE:
                    fmt(0, n, "string")
                    self.setCurrentBlockState(ST_FENCE)
                    self._specials(text, fmt)
                    return
            cfg = LEX.get(lang)
            spans, state = scan_line(text, cfg, prev) if cfg else ([], 0)
            prot = bytearray(n)
            for s, e, style in spans:
                fmt(s, e, style)
                prot[s:e] = b"\x01" * (e - s)
            for rx, style, grp, override in RULES.get(lang, ()):
                for m in rx.finditer(text):
                    s, e = m.span(grp)
                    if s < 0 or s == e or (not override and prot[s]):
                        continue
                    fmt(s, e, style)
            if lang == "yaml" or self.ed.jinja:
                for m in _JINJA.finditer(text):
                    fmt(m.start(), m.end(), "jinja")
                    for k in _JINJA_KW.finditer(text, m.start(), m.end()):
                        fmt(k.start(), k.end(), "jinja_kw")
            if lang == "yaml":
                m = _YAML_TABS.match(text)
                if m:
                    fmt(m.start(1), m.end(1), "tabwarn")
            for m in URL_RE.finditer(text):
                fmt(m.start(), m.end(), "url")
            self.setCurrentBlockState(state)
        else:
            self.setCurrentBlockState(0)
        self._specials(text, fmt)

    def _specials(self, text, fmt):
        for m in SPECIAL_RE.finditer(text):
            fmt(m.start(), m.end(), "special:" + m.group())


# ---- dessin des icônes (aucune image de Notepad++) ---------------------------------------

_GLYPHS = {}


def _glyph(name):
    def register(fn):
        _GLYPHS[name] = fn
        return fn
    return register


def _pen(p, color, width=1.2):
    pen = QPen(QColor(color))
    pen.setWidthF(width)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    p.setPen(pen)
    p.setBrush(Qt.BrushStyle.NoBrush)


def glyph(p, name, rect, color, **kw):
    rect = QRectF(rect)
    p.save()
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.translate(rect.x(), rect.y())
    p.scale(rect.width() / 16.0, rect.height() / 16.0)
    _GLYPHS[name](p, QColor(color), **kw)
    p.restore()


def glyph_icon(name, color=None, **kw):
    color = color or ("#D4D4D4" if Theme.dark else "#303030")
    icon = QIcon()
    for px in (16, 20, 24, 32, 48, 64, 128, 256):
        pm = QPixmap(px, px)
        pm.fill(Qt.GlobalColor.transparent)
        p = QPainter(pm)
        glyph(p, name, QRectF(0, 0, px, px), color, **kw)
        p.end()
        icon.addPixmap(pm)
    return icon


@_glyph("app")
def _(p, c):
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#FFFFFF"))
    page = QPainterPath()
    page.moveTo(2.5, 1.2)
    page.lineTo(10.6, 1.2)
    page.lineTo(13.5, 4.1)
    page.lineTo(13.5, 14.8)
    page.lineTo(2.5, 14.8)
    page.closeSubpath()
    p.drawPath(page)
    _pen(p, "#7A8696", 0.8)
    p.drawPath(page)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#1A9E8F"))
    p.drawRect(QRectF(2.5, 1.2, 8.1, 2.6))
    for y, w in ((6.2, 8.0), (8.3, 6.2), (10.4, 7.2), (12.5, 4.8)):
        p.setBrush(QColor("#5B6B7F"))
        p.drawRoundedRect(QRectF(4.0, y, w, 0.9), 0.4, 0.4)
    _pen(p, "#E8A317", 1.7)
    p.drawLine(QPointF(15.0, 7.0), QPointF(10.2, 13.4))


@_glyph("new")
def _(p, c):
    _pen(p, c)
    p.drawPolyline(QPolygonF([QPointF(9.5, 1.5), QPointF(3, 1.5), QPointF(3, 14.5), QPointF(13, 14.5),
                              QPointF(13, 5), QPointF(9.5, 1.5), QPointF(9.5, 5), QPointF(13, 5)]))


@_glyph("open")
def _(p, c):
    _pen(p, c)
    p.drawPolyline(QPolygonF([QPointF(1.5, 13.5), QPointF(1.5, 3), QPointF(6, 3), QPointF(7.5, 4.5),
                              QPointF(13, 4.5), QPointF(13, 7)]))
    p.drawPolygon(QPolygonF([QPointF(1.5, 13.5), QPointF(4, 7), QPointF(15, 7), QPointF(12.5, 13.5)]))


@_glyph("save")
def _(p, c):
    _pen(p, c)
    p.drawRoundedRect(QRectF(2, 2, 12, 12), 1.2, 1.2)
    p.drawRect(QRectF(5, 2, 6, 4))
    p.drawRect(QRectF(4.5, 9, 7, 5))


@_glyph("saveall")
def _(p, c):
    _pen(p, c)
    p.drawRoundedRect(QRectF(4, 4, 10.5, 10.5), 1.2, 1.2)
    p.drawRect(QRectF(6.5, 4, 5, 3.3))
    p.drawPolyline(QPolygonF([QPointF(2, 12), QPointF(2, 2), QPointF(12, 2)]))


@_glyph("close")
def _(p, c):
    _pen(p, c, 1.4)
    p.drawLine(QPointF(4, 4), QPointF(12, 12))
    p.drawLine(QPointF(12, 4), QPointF(4, 12))


@_glyph("cut")
def _(p, c):
    _pen(p, c)
    p.drawEllipse(QPointF(4.5, 12), 2.2, 2.2)
    p.drawEllipse(QPointF(11.5, 12), 2.2, 2.2)
    p.drawLine(QPointF(6, 10.4), QPointF(12, 2))
    p.drawLine(QPointF(10, 10.4), QPointF(4, 2))


@_glyph("copy")
def _(p, c):
    _pen(p, c)
    p.drawRoundedRect(QRectF(5.5, 5, 8.5, 10), 1, 1)
    p.drawPolyline(QPolygonF([QPointF(3.5, 11), QPointF(2, 11), QPointF(2, 1.5), QPointF(10, 1.5),
                              QPointF(10, 3)]))


@_glyph("paste")
def _(p, c):
    _pen(p, c)
    p.drawRoundedRect(QRectF(2.5, 3, 11, 12), 1.2, 1.2)
    p.drawRoundedRect(QRectF(5.5, 1.5, 5, 3), 0.8, 0.8)


@_glyph("undo")
def _(p, c):
    _pen(p, c, 1.4)
    path = QPainterPath()
    path.moveTo(3, 7)
    path.cubicTo(5, 3, 12, 3, 13.5, 8)
    path.cubicTo(14, 11, 12, 13, 9, 13.5)
    p.drawPath(path)
    p.drawPolyline(QPolygonF([QPointF(2.5, 3), QPointF(3, 7.3), QPointF(7, 6.6)]))


@_glyph("redo")
def _(p, c):
    p.translate(16, 0)
    p.scale(-1, 1)
    _GLYPHS["undo"](p, c)


@_glyph("find")
def _(p, c):
    _pen(p, c, 1.4)
    p.drawEllipse(QPointF(6.5, 6.5), 4.5, 4.5)
    p.drawLine(QPointF(10, 10), QPointF(14.5, 14.5))


@_glyph("replace")
def _(p, c):
    _pen(p, c, 1.3)
    p.drawEllipse(QPointF(5.5, 5.5), 3.8, 3.8)
    p.drawLine(QPointF(8.3, 8.3), QPointF(10.5, 10.5))
    p.drawLine(QPointF(9, 14), QPointF(15, 14))
    p.drawPolyline(QPolygonF([QPointF(13, 12), QPointF(15, 14), QPointF(13, 16)]))


@_glyph("regex")
def _(p, c):
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(c)
    p.drawRoundedRect(QRectF(1.6, 10.6, 3.6, 3.6), 0.7, 0.7)
    _pen(p, c, 1.5)
    cx, cy, r = 10.6, 5.8, 4.3
    for dx, dy in ((0.0, 1.0), (0.866, 0.5), (-0.866, 0.5)):
        p.drawLine(QPointF(cx - r * dx, cy - r * dy), QPointF(cx + r * dx, cy + r * dy))


@_glyph("zoomin")
def _(p, c):
    _GLYPHS["find"](p, c)
    _pen(p, c, 1.2)
    p.drawLine(QPointF(4.5, 6.5), QPointF(8.5, 6.5))
    p.drawLine(QPointF(6.5, 4.5), QPointF(6.5, 8.5))


@_glyph("zoomout")
def _(p, c):
    _GLYPHS["find"](p, c)
    _pen(p, c, 1.2)
    p.drawLine(QPointF(4.5, 6.5), QPointF(8.5, 6.5))


@_glyph("wrap")
def _(p, c):
    _pen(p, c, 1.2)
    p.drawLine(QPointF(1.5, 3), QPointF(14.5, 3))
    path = QPainterPath()
    path.moveTo(1.5, 7.5)
    path.lineTo(12, 7.5)
    path.cubicTo(15.5, 7.5, 15.5, 12.5, 12, 12.5)
    path.lineTo(8, 12.5)
    p.drawPath(path)
    p.drawPolyline(QPolygonF([QPointF(10, 10.5), QPointF(8, 12.5), QPointF(10, 14.5)]))
    p.drawLine(QPointF(1.5, 12.5), QPointF(5, 12.5))


@_glyph("pilcrow")
def _(p, c):
    _pen(p, c, 1.3)
    p.drawLine(QPointF(8, 2), QPointF(8, 14.5))
    p.drawLine(QPointF(11.5, 2), QPointF(11.5, 14.5))
    p.drawLine(QPointF(6.5, 2), QPointF(13.5, 2))
    p.setBrush(QColor(c))
    path = QPainterPath()
    path.moveTo(8, 2)
    path.cubicTo(2, 2, 2, 9, 8, 9)
    p.drawPath(path)


@_glyph("guides")
def _(p, c):
    _pen(p, c, 1.0)
    for x in (2.5, 6.5):
        for y in range(2, 15, 2):
            p.drawPoint(QPointF(x, y))
    _pen(p, c, 1.3)
    p.drawLine(QPointF(10, 4), QPointF(15, 4))
    p.drawLine(QPointF(10, 8), QPointF(15, 8))
    p.drawLine(QPointF(10, 12), QPointF(15, 12))


@_glyph("json")
def _(p, c):
    _pen(p, c, 1.3)
    for sx in (1, -1):
        p.save()
        if sx < 0:
            p.translate(16, 0)
            p.scale(-1, 1)
        path = QPainterPath()
        path.moveTo(6, 2)
        path.cubicTo(3.5, 2, 4.5, 7, 2.5, 8)
        path.cubicTo(4.5, 9, 3.5, 14, 6, 14)
        p.drawPath(path)
        p.restore()
    p.drawPoint(QPointF(8, 8))


@_glyph("compare")
def _(p, c):
    _pen(p, c, 1.2)
    p.drawRoundedRect(QRectF(1.5, 2, 5.5, 12), 1, 1)
    p.drawRoundedRect(QRectF(9, 2, 5.5, 12), 1, 1)
    p.drawLine(QPointF(3, 6), QPointF(5.5, 6))
    p.drawLine(QPointF(10.5, 9), QPointF(13, 9))


@_glyph("disk")
def _(p, c):
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor(c))
    p.drawRoundedRect(QRectF(2, 2, 12, 12), 1.6, 1.6)
    p.setBrush(QColor("#FFFFFF"))
    p.drawRect(QRectF(5, 2.6, 6, 3.6))
    p.drawRoundedRect(QRectF(4.5, 9, 7, 4.5), 0.6, 0.6)


@_glyph("folder")
def _(p, c):
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#E0A11B"))
    p.drawRoundedRect(QRectF(1.5, 2.8, 6, 3), 1, 1)
    p.setBrush(QColor("#FFC83D"))
    p.drawRoundedRect(QRectF(1.5, 4.5, 13, 9), 1.1, 1.1)


@_glyph("bookmark")
def _(p, c):
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor(c))
    p.drawEllipse(QPointF(8, 8), 5.5, 5.5)


# ======================================================================================
# L'éditeur
# ======================================================================================

BRACE_LANGS = {"json", "javascript", "groovy", "css", "bash"}
INDENT_LANGS = {"yaml", "python", "xml", "html", "markdown"}
FOLD_W, MARK_W = 16, 14


def default_eol():
    return "\r\n" if IS_WIN else "\n"


class Gutter(QWidget):
    """Marge de gauche : numéros de ligne, marque-pages et cases de repli ⊟/⊞."""

    def __init__(self, editor):
        super().__init__(editor)
        self.ed = editor
        self.setMouseTracking(True)

    def sizeHint(self):
        return QSize(self.ed.gutter_width(), 0)

    def paintEvent(self, ev):
        self.ed.paint_gutter(self, ev)

    def mousePressEvent(self, ev):
        self.ed.gutter_press(ev)

    def mouseMoveEvent(self, ev):
        self.ed.gutter_drag(ev)

    def wheelEvent(self, ev):
        self.ed.wheelEvent(ev)


class Editor(QPlainTextEdit):
    state_changed = Signal()
    files_dropped = Signal(list)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.path, self.untitled = "", ""
        self.encoding, self.eol = "utf-8", default_eol()
        self.lang, self.lang_forced, self.jinja = "text", False, False
        self.light = False
        self.tail = False
        self.disk_stamp = None
        self.disk_missing = False
        self.pending_reload = False
        self.bookmarks, self.marks, self.folded = [], [], []
        self.block_sel = None
        self._block_drag = False
        self._gutter_anchor = None
        self.folds, self.fold_depth = {}, {}
        self.fold_cover, self.fold_ends = [], set()
        self.line_labels = None
        self.row_colors = None
        self.show_ws = self.show_eol = False
        self.guides = True
        self.numbers = True
        self.tab_width, self.use_spaces = 4, True
        self.char_w = 8.0
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.setWordWrapMode(QTextOption.WrapMode.WrapAtWordBoundaryOrAnywhere)
        self.gutter = Gutter(self)
        self.highlighter = Highlighter(self.document(), self)
        self._fold_timer = QTimer(self)
        self._fold_timer.setSingleShot(True)
        self._fold_timer.setInterval(250)
        self._fold_timer.timeout.connect(self.compute_folds)
        self._extra_timer = QTimer(self)
        self._extra_timer.setSingleShot(True)
        self._extra_timer.setInterval(60)
        self._extra_timer.timeout.connect(self.refresh_extras)
        self.blockCountChanged.connect(lambda _n: self.update_gutter_width())
        self.updateRequest.connect(self._on_update_request)
        self.cursorPositionChanged.connect(self._on_cursor)
        self.selectionChanged.connect(self._schedule_extras)
        self.textChanged.connect(self._on_text_changed)
        self.document().modificationChanged.connect(lambda _m: self.state_changed.emit())
        self.verticalScrollBar().valueChanged.connect(lambda _v: self._schedule_extras())
        self.set_editor_font(editor_font())
        self.apply_theme()

    # --- contenu ---
    def text(self):
        return self.document().toRawText().replace(" ", "\n")

    def load_text(self, text, default):
        """Remplace tout le contenu (fichier ouvert) en gardant chaque fin de ligne d'origine."""
        lines, eols = split_eols(text)
        self.eol = main_eol(eols, default)
        self.light = len(text) > BIG_FILE
        self.highlighter.enabled = not self.light
        self.folded, self.bookmarks, self.marks, self.block_sel = [], [], [], None
        self.setPlainText("\n".join(lines))
        odd = [(i, e) for i, e in enumerate(eols) if e != self.eol]
        if odd:
            doc = self.document()
            cur = QTextCursor(doc)
            cur.beginEditBlock()
            for bn, e in odd:
                block = doc.findBlockByNumber(bn)
                fmt = block.blockFormat()
                fmt.setProperty(EOL_PROP, e)
                QTextCursor(block).setBlockFormat(fmt)
            cur.endEditBlock()
        self.document().clearUndoRedoStacks()
        self.document().setModified(False)
        self.compute_folds()

    def content(self):
        """Texte à enregistrer, avec la fin de ligne propre à chaque ligne."""
        parts = []
        block = self.document().begin()
        while block.isValid():
            parts.append(block.text())
            nxt = block.next()
            if nxt.isValid():
                parts.append(block.blockFormat().stringProperty(EOL_PROP) or self.eol)
            block = nxt
        return "".join(parts)

    def mixed_eol(self):
        block = self.document().begin()
        while block.isValid():
            if block.blockFormat().stringProperty(EOL_PROP) and block.next().isValid():
                return True
            block = block.next()
        return False

    def eol_of(self, block):
        return block.blockFormat().stringProperty(EOL_PROP) or self.eol

    def convert_eol(self, eol):
        doc = self.document()
        cur = QTextCursor(doc)
        cur.beginEditBlock()
        block = doc.begin()
        while block.isValid():
            if block.blockFormat().stringProperty(EOL_PROP):
                fmt = block.blockFormat()
                fmt.clearProperty(EOL_PROP)
                QTextCursor(block).setBlockFormat(fmt)
            block = block.next()
        cur.endEditBlock()
        changed = eol != self.eol
        self.eol = eol
        if changed:
            doc.setModified(True)
        self.viewport().update()
        self.state_changed.emit()

    def display_name(self):
        return os.path.basename(self.path) if self.path else self.untitled

    def set_language(self, lang, forced=True, jinja=None):
        self.lang = lang
        self.lang_forced = forced
        if jinja is not None:
            self.jinja = jinja
        self.highlighter.rehighlight()
        self.compute_folds()
        self.state_changed.emit()

    def indent_unit(self):
        if self.lang == "yaml":
            return "  "
        return " " * self.tab_width if self.use_spaces else "\t"

    def indent_width(self):
        return 2 if self.lang == "yaml" else self.tab_width

    # --- apparence ---
    def set_editor_font(self, font):
        self.setFont(font)
        self.document().setDefaultFont(font)
        self.gutter.setFont(font)
        self.char_w = QFontMetricsF(font).horizontalAdvance(" ")
        self.setTabStopDistance(self.tab_width * self.char_w)
        self.highlighter.rebuild(font)
        self.update_gutter_width()

    def set_tab_width(self, width):
        self.tab_width = width
        self.setTabStopDistance(width * self.char_w)
        self.viewport().update()

    def apply_theme(self):
        pal = self.palette()
        pal.setColor(QPalette.ColorRole.Base, Theme.ed("bg"))
        pal.setColor(QPalette.ColorRole.Text, Theme.ed("fg"))
        pal.setColor(QPalette.ColorRole.Highlight, Theme.ed("sel"))
        pal.setColor(QPalette.ColorRole.HighlightedText, Theme.ed("fg"))
        self.setPalette(pal)
        self.highlighter.rebuild(self.font())
        self.refresh_extras()
        self.gutter.update()

    def set_show_ws(self, on):
        self.show_ws = on
        opt = self.document().defaultTextOption()
        flags = opt.flags()
        if on:
            flags |= QTextOption.Flag.ShowTabsAndSpaces
        else:
            flags &= ~QTextOption.Flag.ShowTabsAndSpaces
        opt.setFlags(flags)
        self.document().setDefaultTextOption(opt)
        self.viewport().update()

    def set_show_eol(self, on):
        self.show_eol = on
        self.viewport().update()

    def set_wrap(self, on):
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth if on else QPlainTextEdit.LineWrapMode.NoWrap)

    # --- marge ---
    def gutter_width(self):
        digits = max(3, len(str(max(1, self.blockCount()))))
        if self.line_labels is not None:
            digits = max(3, max((len(x or "") for x in self.line_labels), default=3))
        numbers = int(digits * self.char_w + 14) if self.numbers else 4
        return numbers + MARK_W + FOLD_W

    def update_gutter_width(self):
        self.setViewportMargins(self.gutter_width(), 0, 0, 0)

    def resizeEvent(self, ev):
        super().resizeEvent(ev)
        cr = self.contentsRect()
        self.gutter.setGeometry(QRect(cr.left(), cr.top(), self.gutter_width(), cr.height()))

    def _on_update_request(self, rect, dy):
        if dy:
            self.gutter.scroll(0, dy)
        else:
            self.gutter.update(0, rect.y(), self.gutter.width(), rect.height())
        if rect.contains(self.viewport().rect()):
            self.update_gutter_width()

    def _visible_blocks(self, bottom_limit=None):
        """(bloc, haut, bas) pour chaque bloc visible à l'écran."""
        block = self.firstVisibleBlock()
        offset = self.contentOffset()
        top = self.blockBoundingGeometry(block).translated(offset).top()
        limit = self.viewport().height() if bottom_limit is None else bottom_limit
        while block.isValid() and top <= limit:
            height = self.blockBoundingRect(block).height()
            if block.isVisible():
                yield block, top, top + height
            top += height
            block = block.next()

    def paint_gutter(self, widget, ev):
        p = QPainter(widget)
        p.fillRect(ev.rect(), Theme.ed("gutter"))
        w = widget.width()
        fold_x = w - FOLD_W
        p.fillRect(QRect(fold_x, ev.rect().top(), FOLD_W, ev.rect().height()), Theme.ed("fold_bg"))
        num_w = w - FOLD_W - MARK_W
        cur_bn = self.textCursor().blockNumber()
        marked = {c.blockNumber() for c in self.bookmarks}
        folded = {c.blockNumber() for c in self.folded}
        line_h = self.fontMetrics().height()
        font = QFont(self.font())
        bold = QFont(font)
        bold.setBold(True)
        fold_pen = QPen(Theme.ed("fold_fg"))
        fold_pen.setWidthF(1.0)
        for block, top, bottom in self._visible_blocks(ev.rect().bottom()):
            if bottom < ev.rect().top():
                continue
            bn = block.blockNumber()
            if self.numbers:
                label = (self.line_labels[bn] if self.line_labels is not None and bn < len(self.line_labels)
                         else str(bn + 1))
                if label:
                    p.setFont(bold if bn == cur_bn else font)
                    p.setPen(Theme.ed("gutter_cur") if bn == cur_bn else Theme.ed("gutter_fg"))
                    p.drawText(QRectF(0, top, num_w - 6, line_h), Qt.AlignmentFlag.AlignRight
                               | Qt.AlignmentFlag.AlignVCenter, label)
            if bn in marked:
                glyph(p, "bookmark", QRectF(num_w + 1, top + (line_h - 12) / 2, 12, 12), Theme.ed("bookmark"))
            cx, cy = fold_x + FOLD_W / 2, top + line_h / 2
            p.setPen(fold_pen)
            inside = bn < len(self.fold_cover) and self.fold_cover[bn] > 0
            if bn in self.folds:
                box = QRectF(cx - 4.5, cy - 4.5, 9, 9)
                if inside:
                    p.drawLine(QPointF(cx, top), QPointF(cx, box.top()))
                p.setBrush(Theme.ed("fold_bg"))
                p.drawRect(box)
                p.drawLine(QPointF(cx - 2.5, cy), QPointF(cx + 2.5, cy))
                if bn in folded:
                    p.drawLine(QPointF(cx, cy - 2.5), QPointF(cx, cy + 2.5))
                elif inside or bn not in folded:
                    p.drawLine(QPointF(cx, box.bottom()), QPointF(cx, bottom))
            elif bn in self.fold_ends and inside:
                p.drawLine(QPointF(cx, top), QPointF(cx, cy))
                p.drawLine(QPointF(cx, cy), QPointF(cx + 5, cy))
                if bn < len(self.fold_cover) and self.fold_cover[bn] > 1:
                    p.drawLine(QPointF(cx, cy), QPointF(cx, bottom))
            elif inside:
                p.drawLine(QPointF(cx, top), QPointF(cx, bottom))
        p.end()

    def _gutter_block(self, y):
        for block, top, bottom in self._visible_blocks():
            if top <= y < bottom:
                return block
        return None

    def gutter_press(self, ev):
        y, x = ev.position().y(), ev.position().x()
        block = self._gutter_block(y)
        if block is None:
            return
        bn = block.blockNumber()
        w = self.gutter.width()
        if x >= w - FOLD_W:
            if bn in self.folds:
                self.toggle_fold(bn)
            return
        if x >= w - FOLD_W - MARK_W:
            self.toggle_bookmark(bn)
            return
        cur = QTextCursor(block)
        if ev.modifiers() & Qt.KeyboardModifier.ShiftModifier:
            cur = self.textCursor()
            cur.setPosition(block.position() + block.length() - 1 if block.next().isValid() else
                            block.position() + block.length() - 1, QTextCursor.MoveMode.KeepAnchor)
        else:
            self._gutter_anchor = bn
            cur.movePosition(QTextCursor.MoveOperation.NextBlock, QTextCursor.MoveMode.KeepAnchor)
            if not block.next().isValid():
                cur.movePosition(QTextCursor.MoveOperation.EndOfBlock, QTextCursor.MoveMode.KeepAnchor)
        self.setTextCursor(cur)

    def gutter_drag(self, ev):
        if not (ev.buttons() & Qt.MouseButton.LeftButton) or self._gutter_anchor is None:
            return
        block = self._gutter_block(ev.position().y())
        if block is None:
            return
        doc = self.document()
        a, b = sorted((self._gutter_anchor, block.blockNumber()))
        start = doc.findBlockByNumber(a)
        end = doc.findBlockByNumber(b)
        cur = QTextCursor(start)
        if end.next().isValid():
            cur.setPosition(end.next().position(), QTextCursor.MoveMode.KeepAnchor)
        else:
            cur.setPosition(end.position() + end.length() - 1, QTextCursor.MoveMode.KeepAnchor)
        self.setTextCursor(cur)

    # --- repli des blocs ---
    def _on_text_changed(self):
        if not self.light:
            self._fold_timer.start()
        self._schedule_extras()
        self.state_changed.emit()

    def compute_folds(self):
        folds, depth = {}, {}
        if not self.light:
            if self.lang in BRACE_LANGS:
                folds, depth = self._brace_folds()
            elif self.lang in INDENT_LANGS:
                folds, depth = self._indent_folds(self.lang == "yaml", comment="#" if self.lang in
                                                  ("yaml", "python") else None)
            elif self.lang == "ini":
                folds, depth = self._section_folds()
        self.folds, self.fold_depth = folds, depth
        starts = set(folds)
        self.folded = [c for c in self.folded if c.blockNumber() in starts]
        self._apply_visibility()

    def _brace_folds(self):
        quote = r'"(?:[^"\\]|\\.)*"?'
        if self.lang in ("javascript", "groovy", "css", "bash"):
            quote += r"|'(?:[^'\\]|\\.)*'?"
        comment = r"|//.*|/\*|\*/" if self.lang in ("javascript", "groovy", "css") else ""
        if self.lang == "bash":
            comment = r"|(?:^|(?<=\s))#.*"
        rx = re.compile(quote + comment + r"|[{}\[\]]")
        stack, folds, depth, in_block = [], {}, {}, False
        block, bn = self.document().begin(), 0
        while block.isValid():
            for m in rx.finditer(block.text()):
                tok = m.group()
                if in_block:
                    if tok == "*/":
                        in_block = False
                    continue
                if tok == "/*":
                    in_block = True
                elif tok in ("{", "["):
                    stack.append(bn)
                elif tok in ("}", "]"):
                    if stack:
                        start = stack.pop()
                        if bn > start and bn > folds.get(start, -1):
                            folds[start] = bn
                            depth[start] = len(stack)
            block, bn = block.next(), bn + 1
        return folds, depth

    def _indent_folds(self, yaml=False, comment=None):
        folds, depth, stack, last = {}, {}, [], -1
        block, bn = self.document().begin(), 0
        tw = self.tab_width
        while block.isValid():
            text = block.text()
            stripped = text.lstrip()
            if stripped and not (comment and stripped.startswith(comment)):
                ind = len(text[:len(text) - len(stripped)].expandtabs(tw))
                if yaml and (stripped.startswith("- ") or stripped == "-"):
                    ind += 1
                while stack and ind <= stack[-1][0]:
                    _lvl, start = stack.pop()
                    if last > start:
                        folds[start], depth[start] = last, len(stack)
                stack.append((ind, bn))
                last = bn
            block, bn = block.next(), bn + 1
        while stack:
            _lvl, start = stack.pop()
            if last > start:
                folds[start], depth[start] = last, len(stack)
        return folds, depth

    def _section_folds(self):
        folds, depth, start, last = {}, {}, None, -1
        block, bn = self.document().begin(), 0
        while block.isValid():
            text = block.text().strip()
            if text.startswith("["):
                if start is not None and last > start:
                    folds[start], depth[start] = last, 0
                start = bn
            if text:
                last = bn
            block, bn = block.next(), bn + 1
        if start is not None and last > start:
            folds[start], depth[start] = last, 0
        return folds, depth

    def _apply_visibility(self):
        """Montre/cache les lignes selon les blocs repliés, et recalcule les traits de la marge."""
        doc = self.document()
        n = doc.blockCount()
        hidden = bytearray(n)
        folded = sorted({c.blockNumber() for c in self.folded})
        for start in folded:
            end = self.folds.get(start)
            if end is not None:
                hidden[start + 1:end + 1] = b"\x01" * (end - start)
        changed_from = None
        block, bn = doc.begin(), 0
        while block.isValid():
            visible = not hidden[bn]
            if block.isVisible() != visible:
                block.setVisible(visible)
                if changed_from is None:
                    changed_from = block.position()
            block, bn = block.next(), bn + 1
        diff = [0] * (n + 1)
        ends = set()
        fset = set(folded)
        for start, end in self.folds.items():
            if start in fset or hidden[start]:
                continue
            diff[start + 1] += 1
            if end + 1 <= n:
                diff[end + 1] -= 1
            ends.add(end)
        cover, acc = [], 0
        for i in range(n):
            acc += diff[i]
            cover.append(acc)
        self.fold_cover, self.fold_ends = cover, ends
        if changed_from is not None:
            doc.markContentsDirty(changed_from, doc.characterCount() - changed_from)
            self.document().documentLayout().requestUpdate()
            self.viewport().update()
            cur_bn = self.textCursor().blockNumber()
            if not self.textCursor().block().isVisible():
                # Comme Notepad++ : le curseur remonte sur la ligne de tête du bloc replié.
                heads = [s for s in folded if s < cur_bn <= self.folds.get(s, -1)]
                if heads:
                    self.setTextCursor(QTextCursor(doc.findBlockByNumber(min(heads))))
            self.ensureCursorVisible()
        self.gutter.update()

    def is_folded(self, bn):
        return any(c.blockNumber() == bn for c in self.folded)

    def toggle_fold(self, bn):
        if self.is_folded(bn):
            self.folded = [c for c in self.folded if c.blockNumber() != bn]
        elif bn in self.folds:
            self.folded.append(QTextCursor(self.document().findBlockByNumber(bn)))
        self._apply_visibility()

    def fold_all(self, fold=True):
        doc = self.document()
        self.folded = [QTextCursor(doc.findBlockByNumber(s)) for s in self.folds] if fold else []
        self._apply_visibility()

    def fold_level(self, level, fold=True):
        doc = self.document()
        targets = {s for s, d in self.fold_depth.items() if d == level - 1}
        current = {c.blockNumber(): c for c in self.folded}
        if fold:
            for s in targets - set(current):
                self.folded.append(QTextCursor(doc.findBlockByNumber(s)))
        else:
            self.folded = [c for bn, c in current.items() if bn not in targets]
        self._apply_visibility()

    def toggle_current_fold(self):
        bn = self.textCursor().blockNumber()
        inner = [s for s, e in self.folds.items() if s <= bn <= e]
        if inner:
            self.toggle_fold(max(inner))

    def unfold_around(self, bn):
        keep = []
        for c in self.folded:
            s = c.blockNumber()
            if not (s < bn <= self.folds.get(s, -1)):
                keep.append(c)
        if len(keep) != len(self.folded):
            self.folded = keep
            self._apply_visibility()

    # --- marque-pages et marques ---
    def toggle_bookmark(self, bn=None):
        bn = self.textCursor().blockNumber() if bn is None else bn
        if any(c.blockNumber() == bn for c in self.bookmarks):
            self.bookmarks = [c for c in self.bookmarks if c.blockNumber() != bn]
        else:
            self.bookmarks.append(QTextCursor(self.document().findBlockByNumber(bn)))
        self.gutter.update()

    def bookmark_lines(self):
        return sorted({c.blockNumber() for c in self.bookmarks})

    def goto_bookmark(self, forward=True):
        lines = self.bookmark_lines()
        if not lines:
            return False
        bn = self.textCursor().blockNumber()
        nxt = [l for l in lines if l > bn] if forward else [l for l in lines if l < bn]
        target = (nxt[0] if forward else nxt[-1]) if nxt else (lines[0] if forward else lines[-1])
        self.goto_line(target + 1)
        return True

    def add_marks(self, spans, bookmark=False):
        """spans : [(début, fin)] en positions du document."""
        doc = self.document()
        for s, e in spans[:20000]:
            cur = QTextCursor(doc)
            cur.setPosition(s)
            cur.setPosition(e, QTextCursor.MoveMode.KeepAnchor)
            self.marks.append(cur)
            if bookmark:
                bn = cur.block().blockNumber()
                if not any(c.blockNumber() == bn for c in self.bookmarks):
                    self.bookmarks.append(QTextCursor(cur.block()))
        self.refresh_extras()
        self.gutter.update()

    def clear_marks(self):
        self.marks = []
        self.refresh_extras()

    # --- surlignages ---
    def _schedule_extras(self):
        self._extra_timer.start()

    def _on_cursor(self):
        block = self.textCursor().block()
        if not block.isVisible():
            self.unfold_around(block.blockNumber())
        self._schedule_extras()
        self.gutter.update()
        self.state_changed.emit()

    def _sel(self, cur, color, full=False):
        sel = QTextEdit.ExtraSelection()
        sel.format.setBackground(color)
        if full:
            sel.format.setProperty(QTextFormat.Property.FullWidthSelection, True)
        sel.cursor = cur
        return sel

    def visible_range(self):
        first = self.firstVisibleBlock()
        last = self.cursorForPosition(QPoint(0, self.viewport().height() - 1)).block()
        end = last.position() + last.length()
        return first.position(), end

    def refresh_extras(self):
        sels = []
        doc = self.document()
        if self.row_colors:
            for bn, color in enumerate(self.row_colors):
                if color:
                    cur = QTextCursor(doc.findBlockByNumber(bn))
                    sels.append(self._sel(cur, Theme.ed(color), True))
        cur = self.textCursor()
        line = QTextCursor(cur)
        line.clearSelection()
        if not self.row_colors:
            sels.append(self._sel(line, Theme.ed("line"), True))
        mark = Theme.ed("mark")
        sels += [self._sel(QTextCursor(m), mark) for m in self.marks if m.hasSelection()]
        if not self.light:
            sels += self._smart_highlight(cur)
            sels += self._brace_match(cur)
        if self.block_sel:
            color = Theme.ed("block")
            for bn, s, e, _pad in self.block_rows():
                if e > s:
                    c = QTextCursor(doc.findBlockByNumber(bn))
                    block = c.block()
                    c.setPosition(block.position() + s)
                    c.setPosition(block.position() + e, QTextCursor.MoveMode.KeepAnchor)
                    sels.append(self._sel(c, color))
        self.setExtraSelections(sels)
        self.viewport().update()

    def _smart_highlight(self, cur):
        word = cur.selectedText()
        if not word or len(word) > 200 or not re.fullmatch(r"\w+", word):
            return []
        start, end = self.visible_range()
        c = QTextCursor(self.document())
        c.setPosition(start)
        c.setPosition(min(end, self.document().characterCount() - 1), QTextCursor.MoveMode.KeepAnchor)
        chunk = c.selection().toRawText().replace(" ", "\n")
        pm = PosMap(chunk)
        color = Theme.ed("smart")
        out = []
        for m in re.finditer(r"(?<!\w)" + re.escape(word) + r"(?!\w)", chunk):
            s = start + pm.to_doc(m.start())
            if s == cur.selectionStart():
                continue
            h = QTextCursor(self.document())
            h.setPosition(s)
            h.setPosition(start + pm.to_doc(m.end()), QTextCursor.MoveMode.KeepAnchor)
            out.append(self._sel(h, color))
            if len(out) > 2000:
                break
        return out

    def _brace_match(self, cur):
        if cur.hasSelection():
            return []
        doc = self.document()
        pos = cur.position()
        pairs = {"(": ")", "[": "]", "{": "}"}
        closers = {v: k for k, v in pairs.items()}
        for p in (pos, pos - 1):
            if p < 0:
                continue
            ch = doc.characterAt(p)
            if ch in pairs or ch in closers:
                break
        else:
            return []
        forward = ch in pairs
        other = pairs.get(ch) or closers.get(ch)
        depth, q, steps, limit = 0, p, 0, doc.characterCount()
        match = None
        while 0 <= q < limit and steps < 200000:
            c = doc.characterAt(q)
            if c == ch:
                depth += 1
            elif c == other:
                depth -= 1
                if depth == 0:
                    match = q
                    break
            q += 1 if forward else -1
            steps += 1
        out = []
        for x in (p, match):
            if x is None:
                continue
            h = QTextCursor(doc)
            h.setPosition(x)
            h.setPosition(x + 1, QTextCursor.MoveMode.KeepAnchor)
            out.append(self._sel(h, Theme.ed("brace") if match is not None else Theme.ed("brace_bad")))
        return out

    def matching_brace(self):
        for sel in self._brace_match(self.textCursor()):
            if sel.cursor.selectionStart() not in (self.textCursor().position(), self.textCursor().position() - 1):
                return sel.cursor.selectionStart()
        return None

    # --- dessin par-dessus le texte ---
    def _badge(self, p, x, top, height, text, bg, fg):
        small = QFont(self.font())
        small.setPointSizeF(max(6.0, self.font().pointSizeF() * 0.72))
        fm = QFontMetricsF(small)
        w = fm.horizontalAdvance(text) + 6
        rect = QRectF(x, top + 2, w, height - 4)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(bg)
        p.drawRoundedRect(rect, 2, 2)
        p.setFont(small)
        p.setPen(fg)
        p.drawText(rect, Qt.AlignmentFlag.AlignCenter, text)
        return w

    def paintEvent(self, ev):
        super().paintEvent(ev)
        p = QPainter(self.viewport())
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        offset = self.contentOffset()
        left = offset.x() + self.document().documentMargin()
        line_h = self.fontMetrics().height()
        folded = {c.blockNumber() for c in self.folded}
        guide_pen = QPen(Theme.ed("guide"))
        guide_pen.setStyle(Qt.PenStyle.DotLine)
        iw = self.indent_width()
        prev_indent = 0
        for block, top, bottom in self._visible_blocks():
            text = block.text()
            bn = block.blockNumber()
            if self.guides and not self.light:
                stripped = text.lstrip(" \t")
                indent = len(text[:len(text) - len(stripped)].expandtabs(self.tab_width)) if stripped else prev_indent
                if stripped:
                    prev_indent = indent
                p.setPen(guide_pen)
                k = iw
                while k < indent:
                    x = left + k * self.char_w
                    p.drawLine(QPointF(x, top), QPointF(x, bottom))
                    k += iw
            end_cur = QTextCursor(block)
            end_cur.movePosition(QTextCursor.MoveOperation.EndOfBlock)
            end_rect = self.cursorRect(end_cur)
            x = end_rect.left() + 3
            if self.show_eol and block.next().isValid():
                eol = self.eol_of(block)
                for part in (("CR",) if eol == "\r" else ("CR", "LF") if eol == "\r\n" else ("LF",)):
                    x += self._badge(p, x, end_rect.top(), line_h, part, Theme.ed("badge_bg"),
                                     Theme.ed("badge_fg")) + 1
            if bn in folded:
                box = QRectF(x + 4, end_rect.top() + 3, 24, line_h - 6)
                p.setPen(QPen(Theme.ed("folded"), 1))
                p.setBrush(Qt.BrushStyle.NoBrush)
                p.drawRoundedRect(box, 3, 3)
                p.setPen(Qt.PenStyle.NoPen)
                p.setBrush(Theme.ed("folded"))
                for k in (-6, 0, 6):
                    p.drawEllipse(QPointF(box.center().x() + k, box.center().y() + 0.5), 1.4, 1.4)
                p.setPen(QPen(Theme.ed("folded"), 1))
                p.drawLine(QPointF(0, bottom - 0.5), QPointF(self.viewport().width(), bottom - 0.5))
            if SPECIAL_RE.search(text):
                for m in SPECIAL_RE.finditer(text):
                    pm = PosMap(text)
                    c = QTextCursor(block)
                    c.setPosition(block.position() + pm.to_doc(m.start()))
                    r1 = self.cursorRect(c)
                    self._badge(p, r1.left() + 1, r1.top(), line_h, SPECIAL_CHARS[m.group()],
                                Theme.ed("special_bg"), Theme.ed("special_fg"))
        if self.block_sel:
            pen = QPen(Theme.ed("fg"))
            pen.setWidthF(1.5)
            p.setPen(pen)
            head_col = self.block_sel[3]
            for bn, _s, _e, _pad in self.block_rows():
                block = self.document().findBlockByNumber(bn)
                if not block.isVisible():
                    continue
                c = QTextCursor(block)
                r = self.cursorRect(c)
                x = left + head_col * self.char_w
                p.drawLine(QPointF(x, r.top()), QPointF(x, r.bottom()))
        p.end()

    # --- navigation ---
    def goto_line(self, line, col=1):
        block = self.document().findBlockByNumber(max(0, line - 1))
        if not block.isValid():
            block = self.document().lastBlock()
        if not block.isVisible():
            self.unfold_around(block.blockNumber())
        cur = QTextCursor(block)
        cur.movePosition(QTextCursor.MoveOperation.Right, QTextCursor.MoveMode.MoveAnchor,
                         min(max(0, col - 1), block.length() - 1))
        self.setTextCursor(cur)
        self.centerCursor()

    def select_range(self, start, end):
        cur = QTextCursor(self.document())
        cur.setPosition(start)
        cur.setPosition(end, QTextCursor.MoveMode.KeepAnchor)
        if not cur.block().isVisible():
            self.unfold_around(cur.block().blockNumber())
        self.setTextCursor(cur)
        self.centerCursor()

    def replace_range(self, start, end, text, select=True):
        cur = QTextCursor(self.document())
        cur.beginEditBlock()
        cur.setPosition(start)
        cur.setPosition(end, QTextCursor.MoveMode.KeepAnchor)
        cur.insertText(text)
        cur.endEditBlock()
        if select:
            cur.setPosition(start)
            cur.setPosition(start + u16(text), QTextCursor.MoveMode.KeepAnchor)
            self.setTextCursor(cur)

    def selected_line_range(self):
        """(premier bloc, dernier bloc) couverts par la sélection, ou None sans sélection."""
        cur = self.textCursor()
        if not cur.hasSelection():
            return None
        doc = self.document()
        first = doc.findBlock(cur.selectionStart()).blockNumber()
        last_block = doc.findBlock(cur.selectionEnd())
        last = last_block.blockNumber()
        if last > first and cur.selectionEnd() == last_block.position():
            last -= 1
        return first, last

    def lines_span(self, first, last):
        doc = self.document()
        a = doc.findBlockByNumber(first)
        b = doc.findBlockByNumber(last)
        return a.position(), b.position() + b.length() - 1

    def transform_lines(self, fn, whole_if_none=True):
        """Applique fn(liste de lignes) aux lignes sélectionnées (ou à tout le document)."""
        rng = self.selected_line_range()
        if rng is None:
            if not whole_if_none:
                bn = self.textCursor().blockNumber()
                rng = (bn, bn)
            else:
                rng = (0, self.blockCount() - 1)
        start, end = self.lines_span(*rng)
        cur = QTextCursor(self.document())
        cur.setPosition(start)
        cur.setPosition(end, QTextCursor.MoveMode.KeepAnchor)
        lines = cur.selection().toRawText().split(" ")
        new = fn(lines)
        if new is None or new == lines:
            return False
        self.replace_range(start, end, "\n".join(new))
        return True

    # --- édition en colonne ---
    def block_rows(self):
        """[(bloc, début, fin, espaces manquants)] pour chaque ligne de la sélection en colonne."""
        if not self.block_sel:
            return []
        l1, c1, l2, c2 = self.block_sel
        top, bottom = sorted((l1, l2))
        left, right = sorted((c1, c2))
        doc = self.document()
        rows = []
        for bn in range(top, bottom + 1):
            text = doc.findBlockByNumber(bn).text()
            s, pad = index_at_vcol(text, left, self.tab_width)
            e, _ = index_at_vcol(text, right, self.tab_width)
            pm = PosMap(text)
            rows.append((bn, pm.to_doc(s), pm.to_doc(e), pad))
        return rows

    def _point_to_lc(self, point):
        cur = self.cursorForPosition(point)
        offset = self.contentOffset().x() + self.document().documentMargin()
        col = max(0, int(round((point.x() - offset) / self.char_w)))
        return cur.blockNumber(), col

    def _cursor_lc(self):
        cur = self.textCursor()
        text = cur.block().text()
        return cur.blockNumber(), vcol_of(text, PosMap(text).to_py(cur.positionInBlock()), self.tab_width)

    def set_block_sel(self, sel):
        self.block_sel = sel
        if sel:
            cur = QTextCursor(self.document().findBlockByNumber(sel[2]))
            self.setTextCursor(cur)
        self.refresh_extras()
        self.state_changed.emit()

    def block_insert(self, text):
        rows = self.block_rows()
        if not rows:
            return
        l1, c1, l2, c2 = self.block_sel
        left = min(c1, c2)
        doc = self.document()
        cur = QTextCursor(doc)
        cur.beginEditBlock()
        for bn, s, e, pad in reversed(rows):
            block = doc.findBlockByNumber(bn)
            cur.setPosition(block.position() + s)
            cur.setPosition(block.position() + e, QTextCursor.MoveMode.KeepAnchor)
            cur.insertText(" " * pad + text)
        cur.endEditBlock()
        col = left + len(text)
        self.set_block_sel((l1, col, l2, col))

    def block_delete(self, backward=True):
        rows = self.block_rows()
        if not rows:
            return
        l1, c1, l2, c2 = self.block_sel
        left = min(c1, c2)
        doc = self.document()
        cur = QTextCursor(doc)
        cur.beginEditBlock()
        if c1 != c2:
            for bn, s, e, _pad in reversed(rows):
                block = doc.findBlockByNumber(bn)
                cur.setPosition(block.position() + s)
                cur.setPosition(block.position() + e, QTextCursor.MoveMode.KeepAnchor)
                cur.removeSelectedText()
            col = left
        else:
            for bn, s, _e, pad in reversed(rows):
                block = doc.findBlockByNumber(bn)
                if pad:
                    continue
                if backward and s > 0:
                    cur.setPosition(block.position() + s - 1)
                    cur.setPosition(block.position() + s, QTextCursor.MoveMode.KeepAnchor)
                    cur.removeSelectedText()
                elif not backward and s < block.length() - 1:
                    cur.setPosition(block.position() + s)
                    cur.setPosition(block.position() + s + 1, QTextCursor.MoveMode.KeepAnchor)
                    cur.removeSelectedText()
            col = max(0, left - 1) if backward else left
        cur.endEditBlock()
        self.set_block_sel((l1, col, l2, col))

    def block_text(self):
        doc = self.document()
        out = []
        for bn, s, e, _pad in self.block_rows():
            block = doc.findBlockByNumber(bn)
            c = QTextCursor(block)
            c.setPosition(block.position() + s)
            c.setPosition(block.position() + e, QTextCursor.MoveMode.KeepAnchor)
            out.append(c.selectedText())
        return out

    def column_paste(self, lines, line=None, col=None):
        """Colle des lignes en colonne à partir de (ligne, colonne)."""
        if line is None:
            line, col = self._cursor_lc()
        doc = self.document()
        cur = QTextCursor(doc)
        cur.beginEditBlock()
        for i, piece in enumerate(lines):
            bn = line + i
            if bn >= doc.blockCount():
                cur.movePosition(QTextCursor.MoveOperation.End)
                cur.insertText("\n")
            block = doc.findBlockByNumber(bn)
            text = block.text()
            idx, pad = index_at_vcol(text, col, self.tab_width)
            cur.setPosition(block.position() + PosMap(text).to_doc(idx))
            cur.insertText(" " * pad + piece)
        cur.endEditBlock()

    def do_copy(self):
        if self.block_sel:
            mime = QMimeData()
            mime.setText("\n".join(self.block_text()))
            mime.setData(RECT_MIME, QByteArray(b"1"))
            QApplication.clipboard().setMimeData(mime)
        else:
            self.copy()

    def do_cut(self):
        if self.block_sel:
            self.do_copy()
            if self.block_sel[1] != self.block_sel[3]:
                self.block_delete()
        else:
            self.cut()

    def do_paste(self):
        mime = QApplication.clipboard().mimeData()
        text = mime.text() if mime is not None else ""
        lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        if self.block_sel:
            rows = self.block_rows()
            if len(lines) == len(rows) and len(lines) > 1:
                l1, c1, l2, c2 = self.block_sel
                left = min(c1, c2)
                if c1 != c2:
                    self.block_delete()
                self.block_sel = None
                self.column_paste(lines, min(l1, l2), left)
                self.refresh_extras()
            else:
                self.block_insert(lines[0] if len(lines) == 1 else text.replace("\n", " "))
            return
        if mime is not None and mime.hasFormat(RECT_MIME):
            self.column_paste(lines)
            return
        self.paste()

    # --- clavier et souris ---
    def keyPressEvent(self, ev):
        key, mods = ev.key(), ev.modifiers()
        alt_shift = (mods & Qt.KeyboardModifier.AltModifier) and (mods & Qt.KeyboardModifier.ShiftModifier)
        arrows = {Qt.Key.Key_Up: (-1, 0), Qt.Key.Key_Down: (1, 0), Qt.Key.Key_Left: (0, -1), Qt.Key.Key_Right: (0, 1)}
        if alt_shift and key in arrows:
            if not self.block_sel:
                line, col = self._cursor_lc()
                self.block_sel = (line, col, line, col)
            l1, c1, l2, c2 = self.block_sel
            dl, dc = arrows[key]
            self.set_block_sel((l1, c1, max(0, min(self.blockCount() - 1, l2 + dl)), max(0, c2 + dc)))
            return
        if self.block_sel:
            if ev.matches(QKeySequence.StandardKey.Copy):
                self.do_copy()
                return
            if ev.matches(QKeySequence.StandardKey.Cut):
                self.do_cut()
                return
            if ev.matches(QKeySequence.StandardKey.Paste):
                self.do_paste()
                return
            if key == Qt.Key.Key_Escape:
                self.set_block_sel(None)
                return
            if key == Qt.Key.Key_Backspace:
                self.block_delete(True)
                return
            if key == Qt.Key.Key_Delete:
                self.block_delete(False)
                return
            text = ev.text()
            if text and text.isprintable() and not (mods & (Qt.KeyboardModifier.ControlModifier
                                                            | Qt.KeyboardModifier.MetaModifier)):
                if not self.isReadOnly():
                    self.block_insert(text)
                return
            if key in (Qt.Key.Key_Shift, Qt.Key.Key_Alt, Qt.Key.Key_Control, Qt.Key.Key_Meta):
                return
            self.set_block_sel(None)
        if self.isReadOnly():
            super().keyPressEvent(ev)
            return
        if key == Qt.Key.Key_Insert and not mods:
            self.setOverwriteMode(not self.overwriteMode())
            self.state_changed.emit()
            return
        if key in (Qt.Key.Key_Tab, Qt.Key.Key_Backtab) and not (mods & Qt.KeyboardModifier.ControlModifier):
            back = key == Qt.Key.Key_Backtab or bool(mods & Qt.KeyboardModifier.ShiftModifier)
            rng = self.selected_line_range()
            if back or (rng and rng[0] != rng[1]):
                self.indent_lines(not back)
                return
            if self.use_spaces or self.lang == "yaml":
                line, col = self._cursor_lc()
                width = self.indent_width()
                self.textCursor().insertText(" " * (width - col % width))
            else:
                self.textCursor().insertText("\t")
            return
        if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter) and not (mods & ~Qt.KeyboardModifier.KeypadModifier):
            cur = self.textCursor()
            text = cur.block().text()
            col = PosMap(text).to_py(cur.positionInBlock())
            lead = re.match(r"[ \t]*", text).group()[:col]
            before = text[:col].rstrip()
            extra = ""
            if self.lang in ("yaml", "python") and before.endswith(":"):
                extra = self.indent_unit()
            elif self.lang in BRACE_LANGS and before.endswith(("{", "[", "(")):
                extra = self.indent_unit()
            cur.insertText("\n" + lead + extra)
            self.ensureCursorVisible()
            return
        super().keyPressEvent(ev)

    def indent_lines(self, increase=True):
        rng = self.selected_line_range()
        bn = self.textCursor().blockNumber()
        first, last = rng if rng else (bn, bn)
        unit = self.indent_unit()
        width = self.indent_width()

        def fn(lines):
            out = []
            for line in lines:
                if increase:
                    out.append(unit + line if line.strip() else line)
                else:
                    if line.startswith("\t"):
                        out.append(line[1:])
                    else:
                        n = len(line) - len(line.lstrip(" "))
                        out.append(line[min(n, width):])
            return out
        start, end = self.lines_span(first, last)
        cur = QTextCursor(self.document())
        cur.setPosition(start)
        cur.setPosition(end, QTextCursor.MoveMode.KeepAnchor)
        lines = cur.selection().toRawText().split(" ")
        new = fn(lines)
        if new != lines:
            self.replace_range(start, end, "\n".join(new), select=rng is not None)

    def mousePressEvent(self, ev):
        if ev.button() == Qt.MouseButton.LeftButton and ev.modifiers() & Qt.KeyboardModifier.AltModifier:
            line, col = self._point_to_lc(ev.position().toPoint())
            self._block_drag = True
            self.set_block_sel((line, col, line, col))
            return
        if self.block_sel:
            self.set_block_sel(None)
        super().mousePressEvent(ev)

    def mouseMoveEvent(self, ev):
        if self._block_drag and ev.buttons() & Qt.MouseButton.LeftButton:
            line, col = self._point_to_lc(ev.position().toPoint())
            l1, c1, _l2, _c2 = self.block_sel
            self.set_block_sel((l1, c1, line, col))
            return
        super().mouseMoveEvent(ev)

    def mouseReleaseEvent(self, ev):
        if self._block_drag:
            self._block_drag = False
            return
        super().mouseReleaseEvent(ev)

    def wheelEvent(self, ev):
        if ev.modifiers() & Qt.KeyboardModifier.ControlModifier:
            win = self.window()
            if hasattr(win, "zoom"):
                win.zoom(1 if ev.angleDelta().y() > 0 else -1)
            return
        super().wheelEvent(ev)

    def contextMenuEvent(self, ev):
        win = self.window()
        if hasattr(win, "editor_menu"):
            win.editor_menu(self, ev.globalPos(), ev.pos())
        else:
            super().contextMenuEvent(ev)

    def url_at(self, pos):
        cur = self.cursorForPosition(pos)
        text = cur.block().text()
        col = PosMap(text).to_py(cur.positionInBlock())
        for m in URL_RE.finditer(text):
            if m.start() <= col <= m.end():
                return m.group()
        return ""

    def canInsertFromMimeData(self, source):
        return source.hasUrls() or super().canInsertFromMimeData(source)

    def insertFromMimeData(self, source):
        if source.hasUrls():
            paths = [u.toLocalFile() for u in source.urls() if u.isLocalFile()]
            if paths:
                self.files_dropped.emit(paths)
                return
        if source.hasFormat(RECT_MIME) and not self.block_sel:
            self.column_paste(source.text().replace("\r\n", "\n").split("\n"))
            return
        super().insertFromMimeData(source)

    def dropEvent(self, ev):
        mime = ev.mimeData()
        if mime.hasUrls() and any(u.isLocalFile() for u in mime.urls()):
            self.files_dropped.emit([u.toLocalFile() for u in mime.urls() if u.isLocalFile()])
            ev.acceptProposedAction()
            return
        super().dropEvent(ev)

    # --- informations pour la barre d'état ---
    def status_info(self):
        cur = self.textCursor()
        block = cur.block()
        text = block.text()
        col = vcol_of(text, PosMap(text).to_py(cur.positionInBlock()), self.tab_width) + 1
        sel_chars = len(cur.selectedText())
        sel_lines = 0
        if cur.hasSelection():
            doc = self.document()
            sel_lines = doc.findBlock(cur.selectionEnd()).blockNumber() - doc.findBlock(cur.selectionStart()).blockNumber() + 1
        if self.block_sel:
            rows = self.block_rows()
            sel_lines = len(rows)
            sel_chars = sum(e - s for _bn, s, e, _p in rows)
        chars = self.document().characterCount() - 1
        lines = self.blockCount()
        length = chars + ((lines - 1) if self.eol == "\r\n" else 0)
        return dict(line=block.blockNumber() + 1, col=col, pos=cur.position() + 1, length=length, lines=lines,
                    sel_chars=sel_chars, sel_lines=sel_lines)


# ======================================================================================
# Réglages, dossiers privés, copies de sécurité
# ======================================================================================

PREFS = {
    "theme": "auto", "font_family": "", "font_size": 12.0 if IS_MAC else 10.0, "tab_width": 4,
    "use_spaces": True, "session": True, "backups": True, "backup_count": 10, "auto_reload": False,
    "new_eol": "\r\n" if IS_WIN else "\n", "wrap": False, "show_ws": False, "show_eol": False,
    "guides": True, "numbers": True, "toolbar": True, "json_indent": "4", "docs_panel": False,
}


def conf():
    return QSettings(ORG_NAME, APP_NAME)


def pref(name):
    default = PREFS[name]
    value = conf().value(name, default)
    if isinstance(default, bool):
        return value in (True, 1, "true", "1", "True")
    if isinstance(default, float):
        try:
            return float(value)
        except (TypeError, ValueError):
            return default
    if isinstance(default, int):
        try:
            return int(value)
        except (TypeError, ValueError):
            return default
    return value if isinstance(value, str) else default


def set_pref(name, value):
    conf().setValue(name, value)


def data_dir(*parts):
    base = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.AppDataLocation)
    if not base:
        base = os.path.join(os.path.expanduser("~"), ".bloc-notes-pro")
    path = os.path.join(base, *parts)
    os.makedirs(path, mode=0o700, exist_ok=True)
    return path


def _backup_folder(path):
    key = hashlib.sha1(os.path.realpath(path).encode("utf-8")).hexdigest()[:16]
    return os.path.join(data_dir("copies"), key)


def make_backup(path, keep=10):
    """Garde la version actuelle du fichier avant de l'écraser (les `keep` dernières)."""
    if not os.path.isfile(path):
        return None
    folder = _backup_folder(path)
    os.makedirs(folder, mode=0o700, exist_ok=True)
    with open(os.path.join(folder, "origine.txt"), "w", encoding="utf-8") as fh:
        fh.write(os.path.realpath(path))
    stamp = time.strftime("%Y%m%d-%H%M%S")
    target = os.path.join(folder, f"{stamp}__{os.path.basename(path)}")
    n = 1
    while os.path.exists(target):
        n += 1
        target = os.path.join(folder, f"{stamp}-{n}__{os.path.basename(path)}")
    with open(path, "rb") as src, open(target, "wb") as dst:
        dst.write(src.read())
    copies = sorted(f for f in os.listdir(folder) if "__" in f)
    for old in copies[:-keep] if keep > 0 else copies:
        try:
            os.remove(os.path.join(folder, old))
        except OSError:
            pass
    return target


def list_backups(path):
    folder = _backup_folder(path)
    if not os.path.isdir(folder):
        return []
    out = []
    for name in sorted(os.listdir(folder), reverse=True):
        if "__" not in name:
            continue
        full = os.path.join(folder, name)
        stamp = name.split("__", 1)[0].split("-")
        try:
            when = datetime.datetime.strptime(stamp[0] + stamp[1], "%Y%m%d%H%M%S")
        except (ValueError, IndexError):
            continue
        out.append((full, when, os.path.getsize(full)))
    return out


def file_stamp(path):
    try:
        st = os.stat(path)
        return (st.st_mtime_ns, st.st_size)
    except OSError:
        return None


def open_in_explorer(folder):
    """« Ouvrir le dossier contenant » dans ton explorateur maison (seule commande permise)."""
    script = explorer_script()
    if not script or not os.path.isdir(folder):
        return False
    try:
        import subprocess
        subprocess.Popen([sys.executable, script, os.path.abspath(folder)], stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True,
                         start_new_session=True)
        return True
    except (OSError, PermissionError):
        return False


# ======================================================================================
# Panneaux : résultats de recherche, arbre JSON
# ======================================================================================

class ResultsPanel(QDockWidget):
    activated = Signal(object)

    def __init__(self, parent=None):
        super().__init__("Résultats de la recherche", parent)
        self.setObjectName("resultsDock")
        box = QWidget()
        lay = QVBoxLayout(box)
        lay.setContentsMargins(4, 2, 4, 4)
        lay.setSpacing(2)
        bar = QHBoxLayout()
        self.summary = QLabel("")
        bar.addWidget(self.summary, 1)
        clear = QPushButton("Effacer")
        clear.clicked.connect(self.clear)
        bar.addWidget(clear)
        lay.addLayout(bar)
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setUniformRowHeights(True)
        self.tree.itemActivated.connect(self._activate)
        self.tree.itemDoubleClicked.connect(self._activate)
        lay.addWidget(self.tree, 1)
        self.setWidget(box)

    def clear(self):
        self.tree.clear()
        self.summary.setText("")

    def new_search(self, title):
        for i in range(self.tree.topLevelItemCount()):
            self.tree.topLevelItem(i).setExpanded(False)
        top = QTreeWidgetItem([title])
        font = top.font(0)
        font.setBold(True)
        top.setFont(0, font)
        self.tree.insertTopLevelItem(0, top)
        top.setExpanded(True)
        self.show()
        self.raise_()
        return top

    def add_file(self, top, label, results, target):
        node = QTreeWidgetItem([f"{label}  ({len(results)})"])
        node.setForeground(0, QBrush(QColor("#2E7D32" if not Theme.dark else "#73C991")))
        for line, col, length, text in results[:5000]:
            shown = text.strip()
            if len(shown) > 300:
                shown = shown[:300] + "…"
            child = QTreeWidgetItem([f"Ligne {line} : {shown}"])
            child.setData(0, Qt.ItemDataRole.UserRole, (target, line, col, length))
            node.addChild(child)
        top.addChild(node)
        node.setExpanded(top.childCount() <= 20)
        return node

    def _activate(self, item, _col=0):
        data = item.data(0, Qt.ItemDataRole.UserRole)
        if data:
            self.activated.emit(data)


class JsonTreePanel(QDockWidget):
    """Arbre des clés d'un JSON : un clic emmène à la clé."""

    def __init__(self, win):
        super().__init__("Arbre JSON", win)
        self.setObjectName("jsonDock")
        self.win = win
        box = QWidget()
        lay = QVBoxLayout(box)
        lay.setContentsMargins(4, 2, 4, 4)
        refresh = QPushButton("Actualiser")
        refresh.clicked.connect(self.refresh)
        lay.addWidget(refresh)
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.itemClicked.connect(self._jump)
        lay.addWidget(self.tree, 1)
        self.setWidget(box)
        self.editor = None

    def refresh(self):
        self.tree.clear()
        ed = self.win.current()
        self.editor = ed
        if ed is None:
            return
        text = ed.text()
        try:
            node = json_parse(text)
        except JsonError as exc:
            line, col = line_col(text, exc.pos)
            QTreeWidgetItem(self.tree, [f"JSON invalide : {exc} (ligne {line}, colonne {col})"])
            return
        pm = PosMap(text)
        count = [0]

        def preview(n):
            if n[0] == "obj":
                return "{" + str(len(n[1])) + "}"
            if n[0] == "arr":
                return "[" + str(len(n[1])) + "]"
            raw = n[1]
            return raw if len(raw) <= 60 else raw[:57] + "…"

        def add(parent, label, n, pos, length):
            count[0] += 1
            if count[0] > 20000:
                return
            item = QTreeWidgetItem(parent, [f"{label} : {preview(n)}" if label else preview(n)])
            item.setData(0, Qt.ItemDataRole.UserRole, (pm.to_doc(pos), pm.to_doc(pos + length)))
            if n[0] == "obj":
                for key, kpos, child in n[1]:
                    try:
                        name = json.loads(key)
                    except ValueError:
                        name = key
                    add(item, str(name), child, kpos, len(key))
            elif n[0] == "arr":
                for i, child in enumerate(n[1]):
                    add(item, f"[{i}]", child, child[2], len(child[1]) if child[0] == "val" else 1)
            return item

        root = add(self.tree, "racine", node, node[2], 1)
        if root is not None:
            root.setExpanded(True)
            for i in range(min(root.childCount(), 200)):
                root.child(i).setExpanded(False)

    def _jump(self, item, _col):
        data = item.data(0, Qt.ItemDataRole.UserRole)
        ed = self.editor
        if data and ed is not None and ed in self.win.editors():
            ed.select_range(*data)
            ed.setFocus()


# ======================================================================================
# Rechercher / Remplacer / Fichiers / Marquer
# ======================================================================================

class FileSearch(QObject):
    found = Signal(str, list)
    finished = Signal(int, bool)

    def __init__(self, root, patterns, recursive, hidden, pattern):
        super().__init__()
        self.args = (root, patterns, recursive, hidden)
        self.pattern = pattern
        self.cancelled = False

    def start(self):
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        scanned = 0
        try:
            for path in iter_files(*self.args):
                if self.cancelled:
                    break
                scanned += 1
                got = read_text_file(path)
                if got is None:
                    continue
                res = find_in_text(got[0], self.pattern, limit=5000)
                if res:
                    self.found.emit(path, res)
        finally:
            try:
                self.finished.emit(scanned, self.cancelled)
            except RuntimeError:
                pass


class FindDialog(QDialog):
    TABS = ("Rechercher", "Remplacer", "Rechercher dans les fichiers", "Marquer")

    def __init__(self, win):
        super().__init__(win)
        self.win = win
        self.setWindowTitle("Rechercher")
        self.setModal(False)
        self.search_job = None
        root = QVBoxLayout(self)
        self.tabs = QTabBar()
        for name in self.TABS:
            self.tabs.addTab(name)
        self.tabs.currentChanged.connect(self._tab_changed)
        root.addWidget(self.tabs)
        body = QHBoxLayout()
        root.addLayout(body)
        left = QGridLayout()
        body.addLayout(left, 1)
        self.find_edit = self._combo("history_find")
        self.repl_edit = self._combo("history_repl")
        self.filter_edit = QLineEdit(pref_str("find_filters", "*.yml *.yaml *.json *.j2 *.sh *.py *.cfg *.ini *.txt"))
        self.dir_edit = QLineEdit(pref_str("find_dir", os.path.expanduser("~")))
        browse = QPushButton("…")
        browse.setFixedWidth(32)
        browse.clicked.connect(self._browse)
        here = QPushButton("Dossier du document")
        here.clicked.connect(self._doc_dir)
        self.lbl_repl = QLabel("Remplacer par :")
        self.lbl_filter = QLabel("Filtres :")
        self.lbl_dir = QLabel("Dossier :")
        left.addWidget(QLabel("Rechercher :"), 0, 0)
        left.addWidget(self.find_edit, 0, 1, 1, 3)
        left.addWidget(self.lbl_repl, 1, 0)
        left.addWidget(self.repl_edit, 1, 1, 1, 3)
        left.addWidget(self.lbl_filter, 2, 0)
        left.addWidget(self.filter_edit, 2, 1, 1, 3)
        left.addWidget(self.lbl_dir, 3, 0)
        left.addWidget(self.dir_edit, 3, 1)
        left.addWidget(browse, 3, 2)
        left.addWidget(here, 3, 3)
        opts = QHBoxLayout()
        col1, col2 = QVBoxLayout(), QVBoxLayout()
        self.word = QCheckBox("Mot entier uniquement")
        self.case = QCheckBox("Respecter la casse")
        self.wrap = QCheckBox("Boucler")
        self.wrap.setChecked(True)
        self.in_sel = QCheckBox("Dans la sélection")
        self.subdirs = QCheckBox("Sous-dossiers")
        self.subdirs.setChecked(True)
        self.hidden = QCheckBox("Fichiers cachés")
        self.bookmark = QCheckBox("Placer un marque-page sur les lignes")
        self.purge = QCheckBox("Effacer les marques précédentes")
        self.purge.setChecked(True)
        for w in (self.word, self.case, self.wrap, self.in_sel, self.subdirs, self.hidden, self.bookmark, self.purge):
            col1.addWidget(w)
        mode_box = QGroupBox("Mode de recherche")
        ml = QVBoxLayout(mode_box)
        self.m_normal = QRadioButton("Normal")
        self.m_ext = QRadioButton("Étendu (\\n, \\r, \\t, \\0, \\x…)")
        self.m_regex = QRadioButton("Expression régulière")
        self.dotall = QCheckBox(". correspond aussi aux retours à la ligne")
        self.m_normal.setChecked(True)
        for w in (self.m_normal, self.m_ext, self.m_regex, self.dotall):
            ml.addWidget(w)
        col2.addWidget(mode_box)
        self.alike = QCheckBox("Tirets, espaces et apostrophes similaires")
        self.alike.setToolTip("Trouve aussi « pf-be » écrit avec un tiret long ou insécable (– — ‑ −), une espace "
                              "insécable,\nune apostrophe typographique (’) ou des caractères invisibles : "
                              "fréquent dans un texte copié depuis\nOutlook, Teams, Word, un PDF ou une page web. "
                              "Sans effet en mode « Expression régulière ».")
        self.m_regex.toggled.connect(lambda on: self.alike.setEnabled(not on))
        col2.addWidget(self.alike)
        col2.addStretch(1)
        opts.addLayout(col1)
        opts.addLayout(col2)
        left.addLayout(opts, 4, 0, 1, 4)
        self.buttons = QVBoxLayout()
        body.addLayout(self.buttons)
        self.btn = {}
        for key, text, fn in (
                ("next", "Suivant", lambda: self.find(True)), ("prev", "Précédent", lambda: self.find(False)),
                ("count", "Compter", self.count), ("all_doc", "Tout rechercher dans\nle document courant",
                                                  lambda: self.find_all(False)),
                ("all_docs", "Tout rechercher dans tous\nles documents ouverts", lambda: self.find_all(True)),
                ("replace", "Remplacer", self.replace_one), ("replace_all", "Remplacer tout", lambda: self.replace_all(False)),
                ("replace_docs", "Remplacer tout dans tous\nles documents ouverts", lambda: self.replace_all(True)),
                ("files_find", "Tout rechercher", self.find_in_files), ("files_replace", "Remplacer dans\nles fichiers",
                                                                       self.replace_in_files),
                ("stop", "Arrêter", self.stop_files), ("mark", "Tout marquer", self.mark_all),
                ("unmark", "Effacer toutes\nles marques", self.clear_marks),
                ("copy_marked", "Copier le texte marqué", self.copy_marked), ("close", "Fermer", self.hide)):
            b = QPushButton(text)
            b.clicked.connect(fn)
            self.buttons.addWidget(b)
            self.btn[key] = b
        self.btn["next"].setDefault(True)
        self.buttons.addStretch(1)
        self.status = QLabel("")
        self.status.setWordWrap(True)
        root.addWidget(self.status)
        self._tab_changed(0)

    @staticmethod
    def _combo(key):
        combo = QComboBox()
        combo.setEditable(True)
        combo.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        combo.setMinimumWidth(360)
        hist = conf().value(key, [])
        if isinstance(hist, str):
            hist = [hist]
        combo.addItems([h for h in (hist or []) if isinstance(h, str)])
        combo.setCurrentText("")
        return combo

    def _remember(self, combo, key):
        text = combo.currentText()
        if not text:
            return
        hist = [combo.itemText(i) for i in range(combo.count()) if combo.itemText(i) != text]
        hist = [text] + hist[:19]
        combo.blockSignals(True)
        combo.clear()
        combo.addItems(hist)
        combo.setCurrentText(text)
        combo.blockSignals(False)
        conf().setValue(key, hist)

    def open_tab(self, index, text=""):
        self.tabs.setCurrentIndex(index)
        self._tab_changed(index)
        if text and "\n" not in text and " " not in text and len(text) < 300:
            self.find_edit.setCurrentText(text)
        self.show()
        self.raise_()
        self.activateWindow()
        self.find_edit.setFocus()
        self.find_edit.lineEdit().selectAll()

    def load(self, find, repl=None, case=False, word=False, dotall=False, mode="regex"):
        """Préremplit le dialogue (utilisé par le testeur d'expressions régulières)."""
        self.find_edit.setCurrentText(find)
        if repl is not None:
            self.repl_edit.setCurrentText(repl)
        {"regex": self.m_regex, "extended": self.m_ext}.get(mode, self.m_normal).setChecked(True)
        self.case.setChecked(case)
        self.word.setChecked(word)
        self.dotall.setChecked(dotall)

    def _tab_changed(self, index):
        show_repl = index in (1, 2)
        files = index == 2
        mark = index == 3
        for w in (self.lbl_repl, self.repl_edit):
            w.setVisible(show_repl)
        for w in (self.lbl_filter, self.filter_edit, self.lbl_dir, self.dir_edit, self.subdirs, self.hidden):
            w.setVisible(files)
        visible = {
            0: ("next", "prev", "count", "all_doc", "all_docs", "close"),
            1: ("next", "replace", "replace_all", "replace_docs", "close"),
            2: ("files_find", "files_replace", "stop", "close"),
            3: ("mark", "unmark", "copy_marked", "close"),
        }[index]
        for key, b in self.btn.items():
            b.setVisible(key in visible)
        self.wrap.setVisible(index in (0, 1))
        self.in_sel.setVisible(index in (1, 3))
        self.bookmark.setVisible(mark)
        self.purge.setVisible(mark)
        for w in self.findChildren(QPushButton):
            if w.text() in ("…", "Dossier du document"):
                w.setVisible(files)
        self.setWindowTitle(self.TABS[index])
        self.status.setText("")
        self.adjustSize()

    def _browse(self):
        folder = QFileDialog.getExistingDirectory(self, "Dossier où rechercher", self.dir_edit.text())
        if folder:
            self.dir_edit.setText(folder)

    def _doc_dir(self):
        ed = self.win.current()
        if ed is not None and ed.path:
            self.dir_edit.setText(os.path.dirname(ed.path))

    def mode(self):
        return "regex" if self.m_regex.isChecked() else ("extended" if self.m_ext.isChecked() else "normal")

    def pattern(self):
        self._remember(self.find_edit, "history_find")
        try:
            return build_pattern(self.find_edit.currentText(), self.mode(), self.case.isChecked(),
                                 self.word.isChecked(), self.dotall.isChecked(),
                                 lookalike=self.alike.isChecked() and self.mode() != "regex")
        except ValueError as exc:
            self.say(str(exc).capitalize(), error=True)
            return None

    def _alike_hint(self, editors):
        """Rien trouvé : y a-t-il le même texte écrit avec un tiret/espace/apostrophe « qui ressemble » ?"""
        if self.alike.isChecked():
            return ""
        h = lookalike_hint([ed.text() for ed in editors if ed is not None], self.find_edit.currentText(),
                           self.mode(), self.case.isChecked(), self.word.isChecked(), self.dotall.isChecked())
        if not h:
            return ""
        n, odd = h
        chars = ", ".join(describe_special(c) for c in odd[:3]) + (" …" if len(odd) > 3 else "")
        return (f" Mais {n} occurrence{'s' if n > 1 else ''} avec un caractère qui ressemble : {chars}. "
                "Coche « Tirets, espaces et apostrophes similaires ».")

    def say(self, text, error=False, ok=False):
        color = "#C42B1C" if error else ("#0F7B0F" if ok else "")
        self.status.setStyleSheet(f"color: {color};" if color else "")
        self.status.setText(text)
        if not self.isVisible():
            self.win.statusBar().showMessage(text, 5000)

    # --- dans le document ---
    def find(self, forward=True, pattern=None):
        ed = self.win.current()
        pattern = pattern or self.pattern()
        if ed is None or pattern is None:
            return False
        text = ed.text()
        pm = PosMap(text)
        cur = ed.textCursor()
        wrapped = False
        if forward:
            start = pm.to_py(cur.selectionEnd())
            m = pattern.search(text, start)
            if m and m.start() == m.end() == pm.to_py(cur.selectionStart()) and not cur.hasSelection():
                m = pattern.search(text, start + 1) if start < len(text) else None
            if m is None and self.wrap.isChecked():
                m = pattern.search(text, 0)
                wrapped = m is not None
        else:
            end = pm.to_py(cur.selectionStart())
            m = None
            for m2 in pattern.finditer(text, 0, end):
                m = m2
            if m is None and self.wrap.isChecked():
                for m2 in pattern.finditer(text, end):
                    m = m2
                wrapped = m is not None
        if m is None:
            self.say(f"Introuvable : « {self.find_edit.currentText()} ».{self._alike_hint([ed])}", error=True)
            QApplication.beep()
            return False
        ed.select_range(pm.to_doc(m.start()), pm.to_doc(m.end()))
        self.say("Fin du document atteinte : reprise au début." if wrapped and forward else
                 "Début du document atteint : reprise à la fin." if wrapped else "")
        return True

    def _region(self, ed, text, pm):
        cur = ed.textCursor()
        if self.in_sel.isChecked() and cur.hasSelection():
            return pm.to_py(cur.selectionStart()), pm.to_py(cur.selectionEnd())
        return 0, len(text)

    def count(self):
        ed, pattern = self.win.current(), self.pattern()
        if ed is None or pattern is None:
            return
        text = ed.text()
        n = sum(1 for _ in pattern.finditer(text))
        self.say(f"Compter : {n} occurrence{'s' if n > 1 else ''}." + ("" if n else self._alike_hint([ed])),
                 ok=n > 0, error=n == 0)

    def find_all(self, all_docs):
        pattern = self.pattern()
        if pattern is None:
            return
        editors = self.win.editors() if all_docs else [self.win.current()]
        panel = self.win.results
        top = panel.new_search(f"Rechercher « {self.find_edit.currentText()} »")
        total, files = 0, 0
        for ed in editors:
            if ed is None:
                continue
            res = find_in_text(ed.text(), pattern)
            if res:
                panel.add_file(top, ed.path or ed.display_name(), res, ed)
                total += len(res)
                files += 1
        top.setText(0, f"Rechercher « {self.find_edit.currentText()} » ({total} résultat{'s' if total > 1 else ''} "
                       f"dans {files} document{'s' if files > 1 else ''})")
        self.say(f"{total} résultat(s) dans {files} document(s)." + ("" if total else self._alike_hint(editors)),
                 ok=total > 0, error=total == 0)

    def replace_one(self):
        ed, pattern = self.win.current(), self.pattern()
        if ed is None or pattern is None or ed.isReadOnly():
            return
        self._remember(self.repl_edit, "history_repl")
        repl = make_replacer(self.repl_edit.currentText(), self.mode())
        cur = ed.textCursor()
        if cur.hasSelection():
            text = ed.text()
            pm = PosMap(text)
            s, e = pm.to_py(cur.selectionStart()), pm.to_py(cur.selectionEnd())
            m = pattern.match(text, s)
            if m and m.end() == e:
                try:
                    new = repl(m)
                except (re.error, IndexError) as exc:
                    self.say(f"Remplacement impossible : {exc}", error=True)
                    return
                ed.replace_range(cur.selectionStart(), cur.selectionEnd(), new, select=False)
                c = ed.textCursor()
                c.setPosition(cur.selectionStart() + u16(new))
                ed.setTextCursor(c)
        self.find(True, pattern)

    def replace_all(self, all_docs):
        pattern = self.pattern()
        if pattern is None:
            return
        self._remember(self.repl_edit, "history_repl")
        repl = make_replacer(self.repl_edit.currentText(), self.mode())
        editors = self.win.editors() if all_docs else [self.win.current()]
        total, docs = 0, 0
        for ed in editors:
            if ed is None or ed.isReadOnly():
                continue
            try:
                n = self._replace_in_editor(ed, pattern, repl, use_sel=not all_docs)
            except (re.error, IndexError) as exc:
                self.say(f"Remplacement impossible : {exc}", error=True)
                return
            if n:
                total += n
                docs += 1
        self.say(f"Remplacer tout : {total} occurrence{'s' if total > 1 else ''} remplacée{'s' if total > 1 else ''}"
                 + (f" dans {docs} document(s)." if all_docs else ".")
                 + ("" if total else self._alike_hint(editors)), ok=total > 0, error=total == 0)

    def _replace_in_editor(self, ed, pattern, repl, use_sel=True):
        text = ed.text()
        pm = PosMap(text)
        a, b = self._region(ed, text, pm) if use_sel else (0, len(text))
        matches = list(pattern.finditer(text, a, b))
        if not matches:
            return 0
        if len(matches) > 400:
            new, n = pattern.subn(repl, text[a:b])
            ed.replace_range(pm.to_doc(a), pm.to_doc(b), new, select=False)
            return n
        doc = ed.document()
        cur = QTextCursor(doc)
        cur.beginEditBlock()
        for m in reversed(matches):
            cur.setPosition(pm.to_doc(m.start()))
            cur.setPosition(pm.to_doc(m.end()), QTextCursor.MoveMode.KeepAnchor)
            cur.insertText(repl(m))
        cur.endEditBlock()
        return len(matches)

    # --- marquer ---
    def mark_all(self):
        ed, pattern = self.win.current(), self.pattern()
        if ed is None or pattern is None:
            return
        if self.purge.isChecked():
            ed.clear_marks()
        text = ed.text()
        pm = PosMap(text)
        a, b = self._region(ed, text, pm)
        spans = [(pm.to_doc(m.start()), pm.to_doc(m.end())) for m in pattern.finditer(text, a, b) if m.end() > m.start()]
        ed.add_marks(spans, self.bookmark.isChecked())
        n = len(spans)
        self.say(f"Marquer : {n} occurrence{'s' if n > 1 else ''} marquée{'s' if n > 1 else ''}."
                 + ("" if n else self._alike_hint([ed])), ok=n > 0, error=n == 0)

    def clear_marks(self):
        ed = self.win.current()
        if ed is not None:
            ed.clear_marks()
            self.say("Marques effacées.")

    def copy_marked(self):
        ed = self.win.current()
        if ed is None or not ed.marks:
            self.say("Aucun texte marqué.", error=True)
            return
        parts = [m.selectedText() for m in sorted(ed.marks, key=lambda c: c.selectionStart())]
        QApplication.clipboard().setText("\n".join(parts))
        self.say(f"{len(parts)} texte(s) marqué(s) copié(s).", ok=True)

    # --- dans les fichiers ---
    def _files_args(self):
        folder = self.dir_edit.text().strip()
        if not os.path.isdir(folder):
            self.say("Ce dossier n'existe pas.", error=True)
            return None
        conf().setValue("find_dir", folder)
        conf().setValue("find_filters", self.filter_edit.text())
        return folder, self.filter_edit.text(), self.subdirs.isChecked(), self.hidden.isChecked()

    def find_in_files(self):
        pattern = self.pattern()
        args = self._files_args() if pattern else None
        if args is None:
            return
        self.stop_files()
        top = self.win.results.new_search(f"Rechercher « {self.find_edit.currentText()} » dans {args[0]} ({args[1]})")
        counter = {"hits": 0, "files": 0}
        job = FileSearch(*args, pattern)

        def found(path, res):
            self.win.results.add_file(top, path, res, path)
            counter["hits"] += len(res)
            counter["files"] += 1
            self.say(f"Recherche en cours… {counter['hits']} résultat(s) dans {counter['files']} fichier(s)")

        def done(scanned, cancelled):
            top.setText(0, top.text(0) + f" — {counter['hits']} résultat(s) dans {counter['files']} fichier(s)"
                        f" sur {scanned} parcouru(s)" + (" (arrêtée)" if cancelled else ""))
            self.say(("Recherche arrêtée : " if cancelled else "Terminé : ") +
                     f"{counter['hits']} résultat(s) dans {counter['files']} fichier(s) sur {scanned}.",
                     ok=counter["hits"] > 0, error=counter["hits"] == 0)
            self.search_job = None
        job.found.connect(found)
        job.finished.connect(done)
        self.search_job = job
        self.say("Recherche en cours…")
        job.start()

    def stop_files(self):
        if self.search_job is not None:
            self.search_job.cancelled = True

    def replace_in_files(self):
        pattern = self.pattern()
        args = self._files_args() if pattern else None
        if args is None:
            return
        self._remember(self.repl_edit, "history_repl")
        answer = QMessageBox.question(
            self, "Remplacer dans les fichiers",
            f"Remplacer « {self.find_edit.currentText()} » par « {self.repl_edit.currentText()} » dans les "
            f"fichiers {args[1]} de :\n{args[0]}{' (et sous-dossiers)' if args[2] else ''} ?\n\n"
            "Une copie de sécurité de chaque fichier modifié est gardée.")
        if answer != QMessageBox.StandardButton.Yes:
            return
        repl = make_replacer(self.repl_edit.currentText(), self.mode())
        top = self.win.results.new_search(f"Remplacer « {self.find_edit.currentText()} » dans {args[0]}")
        total, changed, skipped = 0, 0, []
        open_eds = {os.path.realpath(e.path): e for e in self.win.editors() if e.path}
        for i, path in enumerate(iter_files(*args)):
            if i % 20 == 0:
                QApplication.processEvents()
            got = read_text_file(path)
            if got is None:
                continue
            text, enc = got
            try:
                new, n = pattern.subn(repl, text)
            except (re.error, IndexError) as exc:
                self.say(f"Remplacement impossible : {exc}", error=True)
                return
            if not n:
                continue
            ed = open_eds.get(os.path.realpath(path))
            if ed is not None and ed.document().isModified():
                skipped.append(path)
                continue
            try:
                if pref("backups"):
                    make_backup(path, pref("backup_count"))
                data = encode_text(new, enc)
                with open(path, "wb") as fh:
                    fh.write(data)
            except (OSError, UnicodeEncodeError) as exc:
                skipped.append(f"{path} ({exc})")
                continue
            total += n
            changed += 1
            node = QTreeWidgetItem([f"{path}  ({n} remplacement{'s' if n > 1 else ''})"])
            top.addChild(node)
            if ed is not None:
                self.win.reload(ed, ask=False)
        if skipped:
            node = QTreeWidgetItem([f"Ignorés ({len(skipped)}) : ouverts avec des modifications non enregistrées"])
            for s in skipped:
                node.addChild(QTreeWidgetItem([s]))
            top.addChild(node)
        top.setText(0, top.text(0) + f" — {total} remplacement(s) dans {changed} fichier(s)")
        self.say(f"{total} remplacement(s) dans {changed} fichier(s)." +
                 (f" {len(skipped)} ignoré(s)." if skipped else ""), ok=total > 0, error=total == 0)


def pref_str(key, default):
    value = conf().value(key, default)
    return value if isinstance(value, str) else default


class FilterLinesDialog(QDialog):
    """Garder ou supprimer les lignes qui contiennent un texte (pour trier un log)."""

    def __init__(self, win):
        super().__init__(win)
        self.setWindowTitle("Filtrer les lignes")
        lay = QFormLayout(self)
        self.text = QLineEdit()
        self.regex = QCheckBox("Expression régulière")
        self.case = QCheckBox("Respecter la casse")
        self.keep = QRadioButton("Garder seulement les lignes qui contiennent")
        self.drop = QRadioButton("Supprimer les lignes qui contiennent")
        self.keep.setChecked(True)
        lay.addRow("Texte :", self.text)
        lay.addRow(self.keep)
        lay.addRow(self.drop)
        lay.addRow(self.regex)
        lay.addRow(self.case)
        box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        box.accepted.connect(self.accept)
        box.rejected.connect(self.reject)
        lay.addRow(box)

    def pattern(self):
        return build_pattern(self.text.text(), "regex" if self.regex.isChecked() else "normal", self.case.isChecked())


class ColumnEditorDialog(QDialog):
    """Éditeur de colonne (Alt+C) : insérer un texte ou une numérotation sur chaque ligne."""

    def __init__(self, win):
        super().__init__(win)
        self.setWindowTitle("Éditeur de colonne")
        lay = QVBoxLayout(self)
        self.r_text = QRadioButton("Texte à insérer")
        self.r_num = QRadioButton("Nombres à insérer")
        self.r_text.setChecked(True)
        self.text = QLineEdit()
        grid = QFormLayout()
        self.initial = QSpinBox()
        self.initial.setRange(-10 ** 9, 10 ** 9)
        self.initial.setValue(1)
        self.step = QSpinBox()
        self.step.setRange(-10 ** 6, 10 ** 6)
        self.step.setValue(1)
        self.repeat = QSpinBox()
        self.repeat.setRange(1, 10 ** 6)
        self.zeros = QCheckBox("Zéros en tête")
        self.fmt = QComboBox()
        self.fmt.addItems(["Décimal", "Hexadécimal", "Octal", "Binaire"])
        grid.addRow("Valeur initiale :", self.initial)
        grid.addRow("Incrément :", self.step)
        grid.addRow("Répéter :", self.repeat)
        grid.addRow("Format :", self.fmt)
        grid.addRow(self.zeros)
        lay.addWidget(self.r_text)
        lay.addWidget(self.text)
        lay.addWidget(self.r_num)
        lay.addLayout(grid)
        box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        box.accepted.connect(self.accept)
        box.rejected.connect(self.reject)
        lay.addWidget(box)

    def values(self, count):
        if self.r_text.isChecked():
            return [self.text.text()] * count
        base = {"Décimal": "d", "Hexadécimal": "X", "Octal": "o", "Binaire": "b"}[self.fmt.currentText()]
        nums = [self.initial.value() + (i // self.repeat.value()) * self.step.value() for i in range(count)]
        texts = [format(n, base) for n in nums]
        if self.zeros.isChecked():
            width = max(len(t.lstrip("-")) for t in texts)
            texts = [("-" if t.startswith("-") else "") + t.lstrip("-").rjust(width, "0") for t in texts]
        else:
            width = max(len(t) for t in texts)
            texts = [t.rjust(width) for t in texts]
        return texts


class HashDialog(QDialog):
    def __init__(self, win):
        super().__init__(win)
        self.win = win
        self.setWindowTitle("Empreinte (MD5, SHA…)")
        self.setMinimumWidth(560)
        lay = QFormLayout(self)
        self.source = QComboBox()
        self.source.addItems(["Sélection", "Document entier (tel qu'enregistré)", "Un fichier…"])
        self.algo = QComboBox()
        self.algo.addItems(HASHES)
        self.algo.setCurrentText("SHA-256")
        self.result = QLineEdit()
        self.result.setReadOnly(True)
        go = QPushButton("Calculer")
        go.clicked.connect(self.compute)
        copy = QPushButton("Copier")
        copy.clicked.connect(lambda: QApplication.clipboard().setText(self.result.text()))
        row = QHBoxLayout()
        row.addWidget(go)
        row.addWidget(copy)
        row.addStretch(1)
        lay.addRow("Source :", self.source)
        lay.addRow("Algorithme :", self.algo)
        lay.addRow("Résultat :", self.result)
        lay.addRow(row)

    def compute(self):
        ed = self.win.current()
        idx = self.source.currentIndex()
        if idx == 2:
            path, _ = QFileDialog.getOpenFileName(self, "Fichier à vérifier")
            if not path:
                return
            h = hashlib.new({"MD5": "md5", "SHA-1": "sha1", "SHA-256": "sha256", "SHA-512": "sha512"}[self.algo.currentText()])
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
            self.result.setText(h.hexdigest())
            return
        if ed is None:
            return
        if idx == 0:
            data = ed.textCursor().selection().toRawText().replace(" ", "\n").encode("utf-8")
        else:
            try:
                data = encode_text(ed.content(), ed.encoding)
            except UnicodeEncodeError:
                data = ed.content().encode("utf-8")
        self.result.setText(digest(data, self.algo.currentText()))


class PreferencesDialog(QDialog):
    def __init__(self, win):
        super().__init__(win)
        self.setWindowTitle("Préférences")
        lay = QFormLayout(self)
        self.theme = QComboBox()
        self.theme.addItems(["Automatique (comme macOS)", "Clair", "Sombre"])
        self.theme.setCurrentIndex({"auto": 0, "light": 1, "dark": 2}.get(pref("theme"), 0))
        self.font = QFontComboBox()
        self.font.setFontFilters(QFontComboBox.FontFilter.MonospacedFonts)
        self.font.setCurrentFont(win.font_for_editors())
        self.size = QSpinBox()
        self.size.setRange(6, 40)
        self.size.setValue(int(pref("font_size")))
        self.tab = QSpinBox()
        self.tab.setRange(1, 12)
        self.tab.setValue(pref("tab_width"))
        self.spaces = QCheckBox("Insérer des espaces à la place des tabulations")
        self.spaces.setChecked(pref("use_spaces"))
        self.eol = QComboBox()
        self.eol.addItems(["Unix (LF)", "Windows (CR LF)"])
        self.eol.setCurrentIndex(1 if pref("new_eol") == "\r\n" else 0)
        self.json = QComboBox()
        self.json.addItems(["2 espaces", "4 espaces", "Tabulation"])
        self.json.setCurrentIndex({"2": 0, "4": 1, "tab": 2}.get(pref("json_indent"), 1))
        self.session = QCheckBox("Rouvrir mes fichiers et les onglets non enregistrés au lancement")
        self.session.setChecked(pref("session"))
        self.backups = QCheckBox("Garder une copie de la version précédente à chaque enregistrement")
        self.backups.setChecked(pref("backups"))
        self.count = QSpinBox()
        self.count.setRange(1, 100)
        self.count.setValue(pref("backup_count"))
        self.reload = QCheckBox("Recharger sans demander un fichier modifié ailleurs (si pas de modifs ici)")
        self.reload.setChecked(pref("auto_reload"))
        lay.addRow("Thème :", self.theme)
        lay.addRow("Police :", self.font)
        lay.addRow("Taille :", self.size)
        lay.addRow("Largeur des tabulations :", self.tab)
        lay.addRow(self.spaces)
        lay.addRow("Nouveaux documents :", self.eol)
        lay.addRow("Indentation JSON :", self.json)
        lay.addRow(self.session)
        lay.addRow(self.backups)
        lay.addRow("Nombre de copies gardées :", self.count)
        lay.addRow(self.reload)
        where = QLabel(f"Dossier privé (session, copies) : {data_dir()}")
        where.setWordWrap(True)
        where.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        lay.addRow(where)
        box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        box.accepted.connect(self.accept)
        box.rejected.connect(self.reject)
        lay.addRow(box)

    def save(self):
        set_pref("theme", ("auto", "light", "dark")[self.theme.currentIndex()])
        set_pref("font_family", self.font.currentFont().family())
        set_pref("font_size", float(self.size.value()))
        set_pref("tab_width", self.tab.value())
        set_pref("use_spaces", self.spaces.isChecked())
        set_pref("new_eol", "\r\n" if self.eol.currentIndex() == 1 else "\n")
        set_pref("json_indent", ("2", "4", "tab")[self.json.currentIndex()])
        set_pref("session", self.session.isChecked())
        set_pref("backups", self.backups.isChecked())
        set_pref("backup_count", self.count.value())
        set_pref("auto_reload", self.reload.isChecked())


class VersionsDialog(QDialog):
    """Versions précédentes d'un fichier (copies de sécurité)."""

    def __init__(self, win, ed):
        super().__init__(win)
        self.win, self.ed = win, ed
        self.setWindowTitle(f"Versions précédentes — {ed.display_name()}")
        self.resize(520, 380)
        lay = QVBoxLayout(self)
        self.list = QListWidget()
        for full, when, size in list_backups(ed.path):
            item = QListWidgetItem(f"{when.strftime('%d/%m/%Y %H:%M:%S')}   —   {max(1, size // 1024)} Ko")
            item.setData(Qt.ItemDataRole.UserRole, full)
            self.list.addItem(item)
        if not self.list.count():
            self.list.addItem("Aucune copie pour l'instant : elles sont créées à chaque enregistrement.")
        lay.addWidget(self.list, 1)
        row = QHBoxLayout()
        for text, fn in (("Ouvrir dans un onglet", self.open_copy), ("Comparer avec le document", self.compare),
                         ("Fermer", self.reject)):
            b = QPushButton(text)
            b.clicked.connect(fn)
            row.addWidget(b)
        lay.addLayout(row)

    def _chosen(self):
        item = self.list.currentItem()
        return item.data(Qt.ItemDataRole.UserRole) if item else None

    def _read(self, path):
        with open(path, "rb") as fh:
            text, _enc = decode_bytes(fh.read())
        return text

    def open_copy(self):
        path = self._chosen()
        if path:
            name = os.path.basename(path).split("__", 1)[1]
            stamp = self.list.currentItem().text().split("   ")[0]
            self.win.new_tab_with(self._read(path), f"{name} ({stamp})", lang=self.ed.lang)
            self.accept()

    def compare(self):
        path = self._chosen()
        if path:
            stamp = self.list.currentItem().text().split("   ")[0]
            self.win.show_compare(f"Copie du {stamp}", self._read(path), self.ed.display_name(),
                                  self.ed.content(), self.ed.lang)
            self.accept()


# ======================================================================================
# Comparer deux documents
# ======================================================================================

def align_diff(a_lines, b_lines):
    """Lignes alignées pour l'affichage côte à côte : (gauche, droite, n° gauche, n° droit, état)."""
    rows = []
    sm = difflib.SequenceMatcher(None, a_lines, b_lines, autojunk=False)
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            for k in range(i2 - i1):
                rows.append((a_lines[i1 + k], b_lines[j1 + k], i1 + k + 1, j1 + k + 1, "equal"))
        else:
            n = max(i2 - i1, j2 - j1)
            for k in range(n):
                left = a_lines[i1 + k] if i1 + k < i2 else None
                right = b_lines[j1 + k] if j1 + k < j2 else None
                state = "changed" if left is not None and right is not None else ("removed" if right is None else "added")
                rows.append((left, right, i1 + k + 1 if left is not None else None,
                             j1 + k + 1 if right is not None else None, state))
    return rows


class CompareWindow(QWidget):
    def __init__(self, win, name_a, text_a, name_b, text_b, lang="text"):
        super().__init__(None, Qt.WindowType.Window)
        self.setWindowTitle(f"Comparer : {name_a}  ↔  {name_b}")
        self.setWindowIcon(glyph_icon("app"))
        self.resize(1200, 760)
        rows = align_diff(text_a.splitlines(), text_b.splitlines())
        self.rows = rows
        lay = QVBoxLayout(self)
        top = QHBoxLayout()
        stats = {"changed": 0, "added": 0, "removed": 0}
        for r in rows:
            if r[4] in stats:
                stats[r[4]] += 1
        summary = ("Les deux documents sont identiques." if not any(stats.values()) else
                   f"{stats['changed']} ligne(s) modifiée(s), {stats['added']} ajoutée(s), {stats['removed']} supprimée(s)")
        self.label = QLabel(summary)
        top.addWidget(self.label, 1)
        prev_b = QPushButton("◀ Différence précédente")
        next_b = QPushButton("Différence suivante ▶")
        prev_b.clicked.connect(lambda: self.jump(-1))
        next_b.clicked.connect(lambda: self.jump(1))
        top.addWidget(prev_b)
        top.addWidget(next_b)
        lay.addLayout(top)
        heads = QHBoxLayout()
        heads.addWidget(QLabel(f"<b>{name_a}</b>"), 1)
        heads.addWidget(QLabel(f"<b>{name_b}</b>"), 1)
        lay.addLayout(heads)
        split = QSplitter()
        self.left, self.right = Editor(), Editor()
        colors_l, colors_r = [], []
        for left, right, nl, nr, state in rows:
            colors_l.append({"changed": "changed", "removed": "removed", "added": "blank"}.get(state))
            colors_r.append({"changed": "changed", "added": "added", "removed": "blank"}.get(state))
        for ed, side, labels, colors in ((self.left, 0, [str(r[2]) if r[2] else "" for r in rows], colors_l),
                                         (self.right, 1, [str(r[3]) if r[3] else "" for r in rows], colors_r)):
            ed.line_labels = labels
            ed.row_colors = colors
            ed.setPlainText("\n".join((r[side] if r[side] is not None else "") for r in rows))
            ed.set_language(lang, forced=True)
            ed.setReadOnly(True)
            ed.set_editor_font(win.font_for_editors())
            ed.update_gutter_width()
            ed.refresh_extras()
            split.addWidget(ed)
        lay.addWidget(split, 1)
        self.left.verticalScrollBar().valueChanged.connect(self.right.verticalScrollBar().setValue)
        self.right.verticalScrollBar().valueChanged.connect(self.left.verticalScrollBar().setValue)
        self.left.horizontalScrollBar().valueChanged.connect(self.right.horizontalScrollBar().setValue)
        self.right.horizontalScrollBar().valueChanged.connect(self.left.horizontalScrollBar().setValue)
        self.diff_starts = [i for i, r in enumerate(rows) if r[4] != "equal" and (i == 0 or rows[i - 1][4] == "equal")]
        self.pos = -1

    def jump(self, step):
        if not self.diff_starts:
            return
        self.pos = (self.pos + step) % len(self.diff_starts)
        line = self.diff_starts[self.pos] + 1
        for ed in (self.left, self.right):
            ed.goto_line(line)
        self.label.setText(f"Différence {self.pos + 1} sur {len(self.diff_starts)}")


# ======================================================================================
# Testeur et générateur d'expressions régulières
# ======================================================================================

REGEX_LIVE_LIMIT = 300_000      # au-delà, on ne teste plus à chaque frappe (bouton « Tester »)
REGEX_MATCH_LIMIT = 10_000
REGEX_ROW_LIMIT = 1_000
REGEX_MATCH_COLORS = {False: ("#CFE6FF", "#D7F0CB"), True: ("#1F4A73", "#2E5228")}
REGEX_GROUP_COLORS = {False: ("#FFD27F", "#F7B3CF", "#A6E3DC", "#D6C4FF", "#FFE69A", "#C3E2A4"),
                      True: ("#7A5A10", "#7A2F4F", "#1F5F5A", "#4F3A7A", "#6B5A1A", "#3F5A2A")}
REGEX_DEMO = ("2026-11-25 08:30:12 INFO  srv-web-01 démarrage du service nginx\n"
              "2026-11-25 08:31:40 ERROR srv-db-02 connexion refusée vers 10.0.4.17:5432\n"
              "2026-11-25 08:32:05 WARN  srv-web-01 disque /var à 85 %\n"
              "- name: Installer nginx\n"
              "  ansible.builtin.package:\n"
              "    name: \"{{ paquet | default('nginx') }}\"\n")

REGEX_BRICKS = (
    ("Caractères", (
        (".", ".", "", "", "N'importe quel caractère (sauf retour à la ligne)"),
        (r"\d", r"\d", "", "", "Un chiffre (0 à 9)"),
        (r"\w", r"\w", "", "", "Une lettre, un chiffre ou _"),
        (r"\s", r"\s", "", "", "Un blanc : espace, tabulation…"),
        (r"\D", r"\D", "", "", "Tout sauf un chiffre"),
        (r"\W", r"\W", "", "", "Tout sauf lettre, chiffre ou _"),
        (r"\S", r"\S", "", "", "Tout sauf un blanc"),
        ("[abc]", "[", "]", "abc", "Un caractère parmi ceux listés"),
        ("[^abc]", "[^", "]", "abc", "Un caractère sauf ceux listés"),
        ("[a-z]", "[", "]", "a-z", "Un caractère compris dans l'intervalle"),
        (r"\.", r"\.", "", "", "Un vrai point (les caractères spéciaux . * + ? ( ) [ ] { } | ^ $ \\ "
                                "se protègent avec \\)"),
        (r"\t", r"\t", "", "", "Une tabulation"),
    )),
    ("Position", (
        ("^", "^", "", "", "Début de ligne"),
        ("$", "$", "", "", "Fin de ligne"),
        (r"\b", r"\b", "", "", "Limite de mot (avant ou après un mot)"),
        (r"\A", r"\A", "", "", "Tout début du texte"),
        (r"\Z", r"\Z", "", "", "Toute fin du texte"),
    )),
    ("Répétition", (
        ("*", "*", "", "", "0 fois ou plus"),
        ("+", "+", "", "", "1 fois ou plus"),
        ("?", "?", "", "", "Facultatif (0 ou 1 fois)"),
        ("{n}", "{", "}", "3", "Exactement n fois"),
        ("{n,m}", "{", "}", "2,5", "Entre n et m fois"),
        ("{n,}", "{", ",}", "2", "Au moins n fois"),
        ("*?", "*?", "", "", "0 fois ou plus, le moins possible"),
        ("+?", "+?", "", "", "1 fois ou plus, le moins possible"),
    )),
    ("Groupes", (
        ("( … )", "(", ")", "", "Groupe capturé : réutilisable avec $1, $2…"),
        ("(?: … )", "(?:", ")", "", "Groupe non capturé (juste pour regrouper)"),
        ("(?P<nom> … )", "(?P<nom>", ")", "", "Groupe nommé : réutilisable avec ${nom}"),
        ("|", "|", "", "", "Ou (l'un ou l'autre)"),
        (r"\1", r"\1", "", "", "Le même texte que celui du groupe 1"),
        ("(?= … )", "(?=", ")", "", "Suivi de… (sans le prendre)"),
        ("(?! … )", "(?!", ")", "", "Non suivi de…"),
        ("(?<= … )", "(?<=", ")", "", "Précédé de… (longueur fixe)"),
        ("(?<! … )", "(?<!", ")", "", "Non précédé de… (longueur fixe)"),
    )),
)


def _fold(text):
    """Minuscules sans accents, pour filtrer la bibliothèque."""
    return "".join(c for c in unicodedata.normalize("NFKD", text.casefold()) if not unicodedata.combining(c))


def _shown(text, limit=200):
    if text == "":
        return "(vide)"
    text = text.replace("\n", "⏎").replace("\t", "⇥")
    return text if len(text) <= limit else text[:limit] + "…"


def _html(text):
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class RegexDialog(QDialog):
    def __init__(self, win):
        super().__init__(win)
        self.win = win
        self.setWindowTitle("Testeur et générateur d'expressions régulières")
        self.setModal(False)
        self.resize(1180, 790)
        self.pattern = None
        self.spans = []
        self.mono = editor_font(pref("font_size"))
        self.timer = QTimer(self)
        self.timer.setSingleShot(True)
        self.timer.setInterval(220)
        self.timer.timeout.connect(self.run)
        root = QVBoxLayout(self)

        top = QGridLayout()
        self.expr = self._history_combo("history_regex")
        self.expr.lineEdit().setPlaceholderText("Tape ton expression, ou prends-en une dans la bibliothèque à gauche…")
        self.test_btn = QPushButton("Tester")
        self.test_btn.clicked.connect(self.run)
        copy = QPushButton("Copier")
        copy.setToolTip("Copier l'expression")
        copy.clicked.connect(lambda: QApplication.clipboard().setText(self.expr.currentText()))
        top.addWidget(QLabel("Expression :"), 0, 0)
        top.addWidget(self.expr, 0, 1)
        top.addWidget(self.test_btn, 0, 2)
        top.addWidget(copy, 0, 3)
        opts = QHBoxLayout()
        self.case = QCheckBox("Respecter la casse")
        self.word = QCheckBox("Mot entier uniquement")
        self.dotall = QCheckBox(". correspond aussi aux retours à la ligne")
        for w in (self.case, self.word, self.dotall):
            opts.addWidget(w)
            w.toggled.connect(self.schedule)
        opts.addStretch(1)
        top.addLayout(opts, 1, 1, 1, 3)
        top.setColumnStretch(1, 1)
        root.addLayout(top)
        self.status = QLabel(" ")
        self.status.setWordWrap(True)
        root.addWidget(self.status)

        split = QSplitter(Qt.Orientation.Horizontal)
        root.addWidget(split, 1)
        split.addWidget(self._build_generator())
        right = QSplitter(Qt.Orientation.Vertical)
        split.addWidget(right)

        test_box = QWidget()
        tl = QVBoxLayout(test_box)
        tl.setContentsMargins(0, 0, 0, 0)
        head = QHBoxLayout()
        head.addWidget(QLabel("Texte à tester :"))
        head.addStretch(1)
        for text, fn in (("Prendre la sélection", self.take_selection), ("Prendre tout le document", self.take_document),
                         ("Vider", lambda: self.set_test(""))):
            b = QPushButton(text)
            b.clicked.connect(fn)
            head.addWidget(b)
        tl.addLayout(head)
        self.test = self._text_area(read_only=False)
        self.test.textChanged.connect(self.schedule)
        tl.addWidget(self.test)
        right.addWidget(test_box)

        self.tabs = QTabWidget()
        self.table = QTreeWidget()
        self.table.setRootIsDecorated(False)
        self.table.setUniformRowHeights(True)
        self.table.setAlternatingRowColors(True)
        self.table.itemSelectionChanged.connect(self._row_selected)
        self.tabs.addTab(self.table, "Correspondances")
        repl_box = QWidget()
        rl = QVBoxLayout(repl_box)
        row = QHBoxLayout()
        row.addWidget(QLabel("Remplacer par :"))
        self.repl = self._history_combo("history_regex_repl")
        row.addWidget(self.repl, 1)
        rl.addLayout(row)
        hint = QLabel("$1, ${1} ou \\1 : groupe 1   ·   ${nom} : groupe nommé   ·   $& ou $0 : tout le texte "
                      "trouvé   ·   \\$ : un vrai $   ·   \\n, \\t : retour à la ligne, tabulation")
        hint.setWordWrap(True)
        hint.setStyleSheet("color: #808080;")
        rl.addWidget(hint)
        self.repl_status = QLabel(" ")
        rl.addWidget(self.repl_status)
        self.preview = self._text_area()
        rl.addWidget(self.preview)
        self.tabs.addTab(repl_box, "Remplacement")
        self.explain = self._text_area(wrap=True)
        self.tabs.addTab(self.explain, "Explication")
        usage_box = QWidget()
        ul = QVBoxLayout(usage_box)
        self.usage = self._text_area()
        ul.addWidget(self.usage)
        urow = QHBoxLayout()
        note = QLabel("Prêt à copier : les antislashs sont déjà doublés là où il le faut (YAML, Jinja2, shell).")
        note.setStyleSheet("color: #808080;")
        urow.addWidget(note, 1)
        ucopy = QPushButton("Tout copier")
        ucopy.clicked.connect(lambda: QApplication.clipboard().setText(self.usage.toPlainText()))
        urow.addWidget(ucopy)
        ul.addLayout(urow)
        self.tabs.addTab(usage_box, "Python · Ansible · grep")
        right.addWidget(self.tabs)
        right.setSizes([340, 320])
        split.setSizes([380, 800])
        split.setStretchFactor(1, 1)

        bottom = QHBoxLayout()
        for text, tab, tip in (("Rechercher dans le document", 0, "Ouvre « Rechercher » avec cette expression"),
                               ("Remplacer dans le document…", 1, "Ouvre « Remplacer » : rien n'est modifié tant "
                                                                 "que tu ne cliques pas sur Remplacer"),
                               ("Marquer dans le document", 3, "Surligne toutes les correspondances du document")):
            b = QPushButton(text)
            b.setToolTip(tip)
            b.clicked.connect(lambda _c=False, t=tab: self.send(t))
            bottom.addWidget(b)
        bottom.addStretch(1)
        close = QPushButton("Fermer")
        close.clicked.connect(self.hide)
        bottom.addWidget(close)
        root.addLayout(bottom)

        for b in self.findChildren(QPushButton):     # Entrée ne doit jamais déclencher un autre bouton
            b.setAutoDefault(False)
        self.test_btn.setDefault(True)
        self.expr.editTextChanged.connect(self.schedule)
        self.repl.editTextChanged.connect(self.schedule)
        self._restore()
        self._fill_library()

    # ------------------------------------------------------------------ construction
    def _history_combo(self, key):
        combo = QComboBox()
        combo.setEditable(True)
        combo.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        combo.setMinimumWidth(320)
        combo.setFont(self.mono)
        # la feuille de style de l'application écrase setFont() sur les listes déroulantes : on la précise ici
        combo.setStyleSheet(f'font-family: "{self.mono.family()}"; font-size: {self.mono.pointSizeF():g}pt;')
        hist = conf().value(key, [])
        if isinstance(hist, str):
            hist = [hist]
        combo.addItems([h for h in (hist or []) if isinstance(h, str)])
        combo.setCurrentText("")
        return combo

    def _remember(self, combo, key):
        text = combo.currentText()
        if not text:
            return
        hist = [text] + [combo.itemText(i) for i in range(combo.count()) if combo.itemText(i) != text][:29]
        combo.blockSignals(True)
        combo.clear()
        combo.addItems(hist)
        combo.setCurrentText(text)
        combo.blockSignals(False)
        conf().setValue(key, hist)

    def _text_area(self, read_only=True, wrap=False):
        area = QPlainTextEdit()
        area.setFont(self.mono)
        area.setReadOnly(read_only)
        area.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth if wrap else QPlainTextEdit.LineWrapMode.NoWrap)
        area.setTabStopDistance(QFontMetricsF(self.mono).horizontalAdvance(" ") * 4)
        return area

    def _build_generator(self):
        tabs = QTabWidget()
        self.gen_tabs = tabs
        # -- bibliothèque
        lib = QWidget()
        ll = QVBoxLayout(lib)
        self.lib_filter = QLineEdit()
        self.lib_filter.setPlaceholderText("Filtrer : ip, date, yaml, log…")
        self.lib_filter.setClearButtonEnabled(True)
        self.lib_filter.textChanged.connect(self._fill_library)
        ll.addWidget(self.lib_filter)
        self.lib_tree = QTreeWidget()
        self.lib_tree.setHeaderHidden(True)
        self.lib_tree.itemSelectionChanged.connect(self._lib_selected)
        self.lib_tree.itemDoubleClicked.connect(lambda item, _c: self.use_library() if item.parent() else None)
        ll.addWidget(self.lib_tree, 1)
        self.lib_desc = QLabel(" ")
        self.lib_desc.setWordWrap(True)
        ll.addWidget(self.lib_desc)
        self.lib_regex = QPlainTextEdit()
        self.lib_regex.setReadOnly(True)
        self.lib_regex.setFont(self.mono)
        self.lib_regex.setWordWrapMode(QTextOption.WrapMode.WrapAnywhere)
        self.lib_regex.setMaximumHeight(76)
        ll.addWidget(self.lib_regex)
        r1 = QHBoxLayout()
        use = QPushButton("Utiliser")
        use.setToolTip("Met l'expression dans le champ du haut (double-clic aussi)")
        use.clicked.connect(lambda: self.use_library())
        sample = QPushButton("Utiliser avec son exemple")
        sample.setToolTip("Met aussi un texte d'exemple dans la zone de test")
        sample.clicked.connect(lambda: self.use_library(with_sample=True))
        r1.addWidget(use)
        r1.addWidget(sample)
        ll.addLayout(r1)
        r2 = QHBoxLayout()
        save = QPushButton("Garder l'expression actuelle…")
        save.setToolTip("L'ajoute à « Mes expressions »")
        save.clicked.connect(self.save_custom)
        self.lib_delete = QPushButton("Retirer")
        self.lib_delete.setToolTip("Retire une de « Mes expressions » (demande confirmation)")
        self.lib_delete.clicked.connect(self.delete_custom)
        self.lib_delete.setEnabled(False)
        r2.addWidget(save)
        r2.addWidget(self.lib_delete)
        ll.addLayout(r2)
        tabs.addTab(lib, "Bibliothèque")
        # -- à partir d'exemples
        gen = QWidget()
        gl = QVBoxLayout(gen)
        lab = QLabel("Colle un ou plusieurs exemples de ce que tu veux reconnaître, <b>un par ligne</b> :")
        lab.setWordWrap(True)
        gl.addWidget(lab)
        self.examples = self._text_area(read_only=False)
        gl.addWidget(self.examples, 1)
        take = QPushButton("Prendre la sélection du document")
        take.clicked.connect(self.take_examples)
        gl.addWidget(take)
        self.g_same = QCheckBox("Garder tel quel ce qui est identique partout")
        self.g_same.setChecked(True)
        self.g_same.setToolTip("Avec au moins deux exemples : un mot présent partout (sshd, ERROR…) reste écrit en clair")
        self.g_words = QCheckBox("Garder les mots tels quels (ERROR|WARN…)")
        self.g_flex = QCheckBox("Longueurs souples (\\d+) plutôt qu'exactes (\\d{4})")
        self.g_anchor = QCheckBox("Ligne entière (^ … $)")
        self.g_capture = QCheckBox("Capturer chaque partie variable ($1, $2…)")
        for w in (self.g_same, self.g_words, self.g_flex, self.g_anchor, self.g_capture):
            gl.addWidget(w)
        go = QPushButton("Générer l'expression")
        go.clicked.connect(self.generate)
        gl.addWidget(go)
        self.g_info = QLabel(" ")
        self.g_info.setWordWrap(True)
        gl.addWidget(self.g_info)
        tabs.addTab(gen, "À partir d'exemples")
        # -- briques
        bricks = QWidget()
        bl = QVBoxLayout(bricks)
        intro = QLabel("Clique pour insérer à l'endroit du curseur. Si du texte est sélectionné dans l'expression, "
                       "les groupes l'entourent.")
        intro.setWordWrap(True)
        bl.addWidget(intro)
        for title, items in REGEX_BRICKS:
            box = QGroupBox(title)
            grid = QGridLayout(box)
            grid.setSpacing(4)
            for k, (label, before, after, inner, tip) in enumerate(items):
                b = QPushButton(label)
                b.setFont(self.mono)
                b.setToolTip(tip)
                b.clicked.connect(lambda _c=False, bf=before, af=after, inn=inner: self.insert_brick(bf, af, inn))
                grid.addWidget(b, k // 3, k % 3)
            bl.addWidget(box)
        bl.addStretch(1)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(bricks)
        tabs.addTab(scroll, "Briques")
        tabs.setMinimumWidth(330)
        return tabs

    # ------------------------------------------------------------------ état
    def _restore(self):
        c = conf()
        self.expr.setCurrentText(str(c.value("regex_expr", "") or ""))
        self.repl.setCurrentText(str(c.value("regex_repl", "") or ""))
        opts = str(c.value("regex_opts", "") or "")
        self.case.setChecked("c" in opts)
        self.word.setChecked("w" in opts)
        self.dotall.setChecked("s" in opts)
        test = c.value("regex_test", None)
        self.test.setPlainText(REGEX_DEMO if test is None else str(test))
        self.examples.setPlainText(str(c.value("regex_examples", "") or ""))

    def save_state(self):
        c = conf()
        c.setValue("regex_expr", self.expr.currentText())
        c.setValue("regex_repl", self.repl.currentText())
        c.setValue("regex_opts", ("c" if self.case.isChecked() else "") + ("w" if self.word.isChecked() else "")
                   + ("s" if self.dotall.isChecked() else ""))
        c.setValue("regex_test", self.test_text()[:100_000])
        c.setValue("regex_examples", self.examples.toPlainText()[:20_000])
        if self.pattern is not None:
            self._remember(self.expr, "history_regex")

    def hideEvent(self, event):
        self.save_state()
        super().hideEvent(event)

    def present(self, selection=""):
        if selection:
            self.set_test(selection)
        self.show()
        self.raise_()
        self.activateWindow()
        self.expr.setFocus()
        self.run()

    # ------------------------------------------------------------------ texte à tester
    def test_text(self):
        return self.test.document().toRawText().replace(" ", "\n").replace(" ", "\n")

    def set_test(self, text):
        cur = self.test.textCursor()
        cur.select(QTextCursor.SelectionType.Document)
        cur.insertText(text)            # garde l'annulation (Cmd+Z) possible

    def _selection(self):
        ed = self.win.current()
        if ed is None or not ed.textCursor().hasSelection():
            return ""
        return ed.textCursor().selection().toRawText().replace(" ", "\n")

    def take_selection(self):
        sel = self._selection()
        if sel:
            self.set_test(sel)
        else:
            self._say("Rien n'est sélectionné dans le document.", "warn")

    def take_document(self):
        ed = self.win.current()
        if ed is not None:
            self.set_test(ed.text())

    def take_examples(self):
        sel = self._selection()
        if sel:
            self.examples.setPlainText(sel)
        else:
            self.g_info.setText("Sélectionne d'abord une ou plusieurs lignes dans le document.")

    # ------------------------------------------------------------------ test
    def schedule(self, *_args):
        if self.test.document().characterCount() > REGEX_LIVE_LIMIT:
            self.timer.stop()
            self._say("Texte long : clique sur « Tester » (ou Entrée) pour lancer la recherche.", "warn")
            return
        self.timer.start()

    def _say(self, text, kind=""):
        color = {"error": "#C42B1C", "ok": "#0F7B0F", "warn": "#C86400"}.get(kind, "")
        self.status.setStyleSheet(f"color: {color};" if color else "")
        self.status.setText(text)

    def options(self):
        return self.case.isChecked(), self.word.isChecked(), self.dotall.isChecked()

    def run(self):
        self.timer.stop()
        src = self.expr.currentText()
        text = self.test_text()
        self.pattern, self.spans = None, []
        if not src:
            self._say("Tape une expression, choisis-en une dans la bibliothèque ou génère-la depuis des exemples.")
            self._clear()
            return
        try:
            pat = build_pattern(src, "regex", *self.options())
        except ValueError as exc:
            msg = str(exc).replace("expression régulière invalide : ", "")
            pos = getattr(exc, "pos", None)
            where = ""
            if isinstance(pos, int) and 0 <= pos <= len(src):
                where = "\n" + src + "\n" + " " * pos + "▲"
                self.status.setFont(self.mono)
            self._say("✗ " + msg[:1].upper() + msg[1:] + where, "error")
            self._clear()
            return
        self.status.setFont(self.font())
        self.pattern = pat
        start = time.perf_counter()
        truncated = False
        for m in pat.finditer(text):
            self.spans.append((m.start(), m.end(), [m.span(g) for g in range(1, pat.groups + 1)]))
            if len(self.spans) >= REGEX_MATCH_LIMIT:
                truncated = True
                break
        elapsed = (time.perf_counter() - start) * 1000
        self._highlight(text)
        self._fill_table(text)
        warnings = self._refresh_side(text)
        n = len(self.spans)
        if n:
            msg = f"✓ {n} correspondance{'s' if n > 1 else ''}" + (" (on s'arrête aux 10 000 premières)" if truncated
                                                                   else "")
        else:
            msg = "Aucune correspondance dans le texte à tester"
        msg += f"   ·   {pat.groups} groupe{'s' if pat.groups > 1 else ''}   ·   {elapsed:.1f} ms"
        if warnings:
            msg += "\n⚠ " + "\n⚠ ".join(warnings)
        self._say(msg, "ok" if n and not warnings else "warn")

    def _clear(self):
        self.test.setExtraSelections([])
        self.table.clear()
        self.table.setHeaderLabels(["N°", "Ligne", "Col.", "Texte trouvé"])
        self.preview.setPlainText("")
        self.repl_status.setText(" ")
        self.explain.setPlainText("")
        self.usage.setPlainText("")

    def _selection_at(self, doc, a, b, color):
        sel = QTextEdit.ExtraSelection()
        cur = QTextCursor(doc)
        cur.setPosition(a)
        cur.setPosition(b, QTextCursor.MoveMode.KeepAnchor)
        sel.cursor = cur
        sel.format.setBackground(QColor(color))
        return sel

    def _highlight(self, text):
        pm = PosMap(text)
        doc = self.test.document()
        mc, gc = REGEX_MATCH_COLORS[Theme.dark], REGEX_GROUP_COLORS[Theme.dark]
        sels = []
        for k, (s, e, groups) in enumerate(self.spans):
            if e > s:
                sels.append(self._selection_at(doc, pm.to_doc(s), pm.to_doc(e), mc[k % 2]))
            for g, (gs, ge) in enumerate(groups):
                if gs >= 0 and ge > gs:
                    sels.append(self._selection_at(doc, pm.to_doc(gs), pm.to_doc(ge), gc[g % len(gc)]))
        self.test.setExtraSelections(sels)

    def _fill_table(self, text):
        pat = self.pattern
        names = {v: k for k, v in pat.groupindex.items()}
        headers = ["N°", "Ligne", "Col.", "Texte trouvé"] + [
            f"{g} « {names[g]} »" if g in names else f"Groupe {g}" for g in range(1, pat.groups + 1)]
        self.table.clear()
        self.table.setColumnCount(len(headers))
        self.table.setHeaderLabels(headers)
        newlines = [m.start() for m in re.finditer("\n", text)]
        gc = REGEX_GROUP_COLORS[Theme.dark]
        items = []
        for k, (s, e, groups) in enumerate(self.spans[:REGEX_ROW_LIMIT], 1):
            line = bisect_left(newlines, s)
            col = s - (newlines[line - 1] + 1 if line else 0)
            cells = [str(k), str(line + 1), str(col + 1), _shown(text[s:e])]
            cells += [_shown(text[gs:ge]) if gs >= 0 else "—" for gs, ge in groups]
            item = QTreeWidgetItem(cells)
            item.setData(0, Qt.ItemDataRole.UserRole, (s, e))
            for g in range(len(groups)):
                item.setBackground(4 + g, QBrush(QColor(gc[g % len(gc)])))
            items.append(item)
        self.table.addTopLevelItems(items)
        for c in range(len(headers)):
            self.table.resizeColumnToContents(c)
            self.table.setColumnWidth(c, min(self.table.columnWidth(c), 360))
        if len(self.spans) > REGEX_ROW_LIMIT:
            more = QTreeWidgetItem(["…", "", "", f"(+ {len(self.spans) - REGEX_ROW_LIMIT} autres, non affichées)"])
            self.table.addTopLevelItem(more)

    def _row_selected(self):
        items = self.table.selectedItems()
        data = items[0].data(0, Qt.ItemDataRole.UserRole) if items else None
        if not data:
            return
        s, e = data
        pm = PosMap(self.test_text())
        cur = self.test.textCursor()
        cur.setPosition(pm.to_doc(s))
        cur.setPosition(pm.to_doc(e), QTextCursor.MoveMode.KeepAnchor)
        self.test.setTextCursor(cur)
        self.test.ensureCursorVisible()

    def _refresh_side(self, text):
        pat = self.pattern
        repl = self.repl.currentText()
        # aperçu du remplacement
        fn = make_replacer(repl, "regex")
        out, marks, last, pos, count = [], [], 0, 0, 0
        try:
            for m in pat.finditer(text):
                piece = fn(m)
                out.append(text[last:m.start()])
                pos += m.start() - last
                out.append(piece)
                marks.append((pos, pos + len(piece)))
                pos += len(piece)
                last = m.end()
                count += 1
                if count >= REGEX_MATCH_LIMIT:
                    break
            out.append(text[last:])
            result = "".join(out)
            self.preview.setPlainText(result)
            pm = PosMap(result)
            color = REGEX_MATCH_COLORS[Theme.dark][1]
            self.preview.setExtraSelections([self._selection_at(self.preview.document(), pm.to_doc(a), pm.to_doc(b),
                                                                color) for a, b in marks if b > a][:REGEX_MATCH_LIMIT])
            self.repl_status.setStyleSheet("")
            self.repl_status.setText(f"{count} remplacement{'s' if count > 1 else ''} (aperçu : le document "
                                     "n'est pas modifié)")
        except (re.error, IndexError) as exc:
            msg = french_re_error(exc)[0] if isinstance(exc, re.error) else "groupe inexistant"
            self.preview.setPlainText("")
            self.repl_status.setStyleSheet("color: #C42B1C;")
            self.repl_status.setText(f"✗ Remplacement impossible : {msg}")
        # explication
        explanation, warnings = explain_regex(pat)
        self.explain.setPlainText(explanation)
        # utilisation
        try:
            self.usage.setPlainText(regex_usage(self.expr.currentText(), *self.options(), repl=repl or None))
        except ValueError as exc:
            self.usage.setPlainText(str(exc))
        return warnings

    # ------------------------------------------------------------------ vers Rechercher / Remplacer / Marquer
    def send(self, tab):
        if self.pattern is None:
            self.run()
            if self.pattern is None:
                return
        self.save_state()
        if self.repl.currentText():
            self._remember(self.repl, "history_regex_repl")
        self.win.regex_to_find(tab, self.expr.currentText(), self.repl.currentText(), *self.options())

    # ------------------------------------------------------------------ briques
    def insert_brick(self, before, after, inner):
        le = self.expr.lineEdit()
        selected = le.selectedText()
        start = le.selectionStart() if le.hasSelectedText() else le.cursorPosition()
        le.insert(before + (selected or inner) + after)
        if not selected and inner:
            le.setSelection(start + len(before), len(inner))
        elif not selected and after:
            le.setCursorPosition(start + len(before))
        self.expr.setFocus()

    # ------------------------------------------------------------------ bibliothèque
    def _custom(self):
        raw = conf().value("regex_custom", "")
        try:
            data = json.loads(raw) if isinstance(raw, str) and raw else []
        except ValueError:
            data = []
        return [d for d in data if isinstance(d, dict) and isinstance(d.get("regex"), str)]

    def _fill_library(self, *_args, select=None):
        needle = _fold(self.lib_filter.text().strip())
        self.lib_tree.clear()
        cats = []
        custom = self._custom()
        if custom:
            cats.append(("Mes expressions", [(d.get("name") or d["regex"], d["regex"], d.get("description", ""),
                                              d.get("sample", ""), True) for d in custom]))
        cats += [(cat, [(n, r, d, s, False) for n, r, d, s in items]) for cat, items in REGEX_LIBRARY]
        bold = QFont(self.font())
        bold.setBold(True)
        for cat, items in cats:
            top = None
            for name, regex, desc, sample, mine in items:
                if needle and needle not in _fold(f"{cat} {name} {desc}"):
                    continue
                if top is None:
                    top = QTreeWidgetItem([cat])
                    top.setFont(0, bold)
                    top.setFlags(top.flags() & ~Qt.ItemFlag.ItemIsSelectable)
                    self.lib_tree.addTopLevelItem(top)
                child = QTreeWidgetItem([name])
                child.setToolTip(0, desc)
                child.setData(0, Qt.ItemDataRole.UserRole, (name, regex, desc, sample, mine))
                top.addChild(child)
                if select is not None and mine and regex == select:
                    self.lib_tree.setCurrentItem(child)
            if top is not None:
                top.setExpanded(True)

    def _lib_data(self):
        item = self.lib_tree.currentItem()
        return item.data(0, Qt.ItemDataRole.UserRole) if item is not None else None

    def _lib_selected(self):
        data = self._lib_data()
        self.lib_delete.setEnabled(bool(data and data[4]))
        if not data:
            self.lib_desc.setText(" ")
            self.lib_regex.setPlainText("")
            return
        name, regex, desc, _sample, _mine = data
        self.lib_desc.setText(f"<b>{_html(name)}</b><br>{_html(desc)}")
        self.lib_regex.setPlainText(regex)

    def use_library(self, with_sample=False):
        data = self._lib_data()
        if not data:
            return
        _name, regex, _desc, sample, _mine = data
        self.expr.setCurrentText(regex)
        if sample and (with_sample or not self.test_text().strip()):
            self.set_test(sample)
        self.run()

    def save_custom(self):
        regex = self.expr.currentText()
        if not regex or self.pattern is None:
            self._say("Il faut d'abord une expression valide dans le champ du haut.", "warn")
            return
        name, ok = QInputDialog.getText(self, "Mes expressions", "Nom de l'expression :")
        if not ok or not name.strip():
            return
        custom = [d for d in self._custom() if d["regex"] != regex]
        sample = self.test_text()
        custom.insert(0, {"name": name.strip(), "regex": regex, "description": "Ajoutée par toi.",
                          "sample": sample if len(sample) <= 4000 else ""})
        conf().setValue("regex_custom", json.dumps(custom, ensure_ascii=False))
        self.lib_filter.clear()
        self._fill_library(select=regex)
        self.gen_tabs.setCurrentIndex(0)

    def delete_custom(self):
        data = self._lib_data()
        if not data or not data[4]:
            return
        name, regex = data[0], data[1]
        answer = QMessageBox.question(self, "Mes expressions", f"Retirer « {name} » de tes expressions ?")
        if answer != QMessageBox.StandardButton.Yes:
            return
        conf().setValue("regex_custom", json.dumps([d for d in self._custom() if d["regex"] != regex],
                                                   ensure_ascii=False))
        self._fill_library()

    # ------------------------------------------------------------------ générateur
    def generate_from(self, text):
        self.gen_tabs.setCurrentIndex(1)
        self.examples.setPlainText(text)
        self.generate()

    def generate(self):
        lines = self.examples.toPlainText().split("\n")
        try:
            regex, info = regex_from_examples(lines, self.g_same.isChecked(), self.g_words.isChecked(),
                                              self.g_flex.isChecked(), self.g_anchor.isChecked(),
                                              self.g_capture.isChecked())
        except ValueError as exc:
            self.g_info.setStyleSheet("color: #C42B1C;")
            self.g_info.setText(str(exc).capitalize() + ".")
            return
        samples = [l.rstrip("\r") for l in lines if l.strip()]
        try:
            pat = build_pattern(regex, "regex", *self.options())
            found = sum(1 for s in samples if pat.search(s))
        except ValueError:
            found = 0
        self.expr.setCurrentText(regex)
        if not self.test_text().strip():
            self.set_test("\n".join(samples))
        ok = found == len(samples)
        self.g_info.setStyleSheet("color: #0F7B0F;" if ok else "color: #C86400;")
        self.g_info.setText(info + f"\n{'✓' if ok else '⚠'} {found}/{len(samples)} exemple"
                            f"{'s' if len(samples) > 1 else ''} reconnu{'s' if found > 1 else ''}. "
                            "Vérifie ensuite sur ton vrai texte, à droite.")
        self.run()


# ======================================================================================
# La fenêtre principale
# ======================================================================================

def window_css():
    if Theme.dark:
        c = dict(bg="#202020", bar="#2B2B2B", menu="#2C2C2C", border="#3A3A3A", hover="#3A3A3A", text="#FFFFFF",
                 sub="#C5C5C5", tab="#1E1E1E", tab_off="#2B2B2B", accent="#4CC2FF", field="#2D2D2D")
    else:
        c = dict(bg="#F3F3F3", bar="#F3F3F3", menu="#F9F9F9", border="#E0E0E0", hover="#E6E6E6", text="#1A1A1A",
                 sub="#5F5F5F", tab="#FFFFFF", tab_off="#EBEBEB", accent="#005FB8", field="#FFFFFF")
    return f"""
QMainWindow, QDialog {{ background: {c['bg']}; color: {c['text']}; }}
QMenuBar {{ background: {c['bar']}; color: {c['text']}; padding: 2px 4px; }}
QMenuBar::item {{ padding: 4px 9px; border-radius: 4px; background: transparent; }}
QMenuBar::item:selected {{ background: {c['hover']}; }}
QMenu {{ background: {c['menu']}; color: {c['text']}; border: 1px solid {c['border']}; border-radius: 8px; padding: 4px; }}
QMenu::item {{ padding: 5px 28px 5px 24px; border-radius: 4px; }}
QMenu::item:selected {{ background: {c['hover']}; }}
QMenu::item:disabled {{ color: {c['sub']}; }}
QMenu::separator {{ height: 1px; background: {c['border']}; margin: 4px 8px; }}
QToolBar {{ background: {c['bar']}; border: none; spacing: 2px; padding: 2px 6px; }}
QToolBar::separator {{ background: {c['border']}; width: 1px; margin: 4px 5px; }}
QToolButton {{ border: none; border-radius: 4px; padding: 3px; color: {c['text']}; }}
QToolButton:hover {{ background: {c['hover']}; }}
QToolButton:checked {{ background: {c['hover']}; border: 1px solid {c['border']}; }}
QTabWidget::pane {{ border: none; border-top: 1px solid {c['border']}; }}
QTabBar {{ background: {c['bar']}; }}
QTabBar::tab {{ background: {c['tab_off']}; color: {c['sub']}; padding: 5px 10px; margin-right: 1px;
    border: 1px solid {c['border']}; border-bottom: none; border-top-left-radius: 6px; border-top-right-radius: 6px; }}
QTabBar::tab:selected {{ background: {c['tab']}; color: {c['text']}; border-top: 2px solid {c['accent']}; }}
QTabBar::tab:hover:!selected {{ background: {c['hover']}; }}
QStatusBar {{ background: {c['bar']}; color: {c['text']}; border-top: 1px solid {c['border']}; }}
QStatusBar QLabel {{ color: {c['text']}; border-left: 1px solid {c['border']}; padding: 1px 10px; }}
QStatusBar QLabel#first {{ border-left: none; }}
QDockWidget {{ color: {c['text']}; }}
QTreeWidget, QListWidget {{ background: {c['field']}; color: {c['text']}; border: 1px solid {c['border']}; }}
QLineEdit, QComboBox, QSpinBox, QFontComboBox {{ background: {c['field']}; color: {c['text']};
    border: 1px solid {c['border']}; border-radius: 4px; padding: 3px 6px; }}
QPushButton {{ background: {c['field']}; color: {c['text']}; border: 1px solid {c['border']}; border-radius: 4px;
    padding: 5px 12px; }}
QPushButton:hover {{ background: {c['hover']}; }}
QPushButton:default {{ border: 1px solid {c['accent']}; }}
QGroupBox {{ border: 1px solid {c['border']}; border-radius: 6px; margin-top: 10px; padding-top: 6px; color: {c['text']}; }}
QGroupBox::title {{ subcontrol-origin: margin; left: 8px; padding: 0 4px; }}
QCheckBox, QRadioButton, QLabel {{ color: {c['text']}; }}
""" + (dark_indicators_css(c) if Theme.dark else "")


def check_mark_image():
    """Petite coche des cases à cocher en thème sombre (créée dans le dossier privé)."""
    path = os.path.join(data_dir("theme"), "coche.png")
    if not os.path.isfile(path):
        pm = QPixmap(28, 28)
        pm.fill(Qt.GlobalColor.transparent)
        p = QPainter(pm)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        pen = QPen(QColor("#000000"))
        pen.setWidthF(3.2)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        p.setPen(pen)
        p.drawPolyline(QPolygonF([QPointF(6, 14.5), QPointF(11.5, 20), QPointF(22, 8.5)]))
        p.end()
        pm.save(path, "PNG")
    return path.replace("\\", "/")


def dark_indicators_css(c):
    """En sombre, les cases à cocher et boutons radio de Fusion sont presque invisibles : on les dessine."""
    return f"""
QCheckBox::indicator {{ width: 14px; height: 14px; border: 1px solid #9A9A9A; border-radius: 4px; background: {c['field']}; }}
QCheckBox::indicator:hover {{ border-color: #CFCFCF; }}
QCheckBox::indicator:checked {{ background: {c['accent']}; border-color: {c['accent']}; image: url("{check_mark_image()}"); }}
QCheckBox::indicator:disabled {{ border-color: #5A5A5A; }}
QRadioButton::indicator {{ width: 14px; height: 14px; border: 1px solid #9A9A9A; border-radius: 8px; background: {c['field']}; }}
QRadioButton::indicator:checked {{ border: 4px solid {c['accent']}; width: 8px; height: 8px; background: #000000; }}
"""


class StatusSeg(QLabel):
    clicked = Signal()
    double = Signal()

    def __init__(self, tip=""):
        super().__init__("")
        self.setToolTip(tip)

    def mousePressEvent(self, ev):
        if ev.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()

    def mouseDoubleClickEvent(self, ev):
        self.double.emit()


def sc(windows, mac=None):
    """Raccourci : Ctrl devient Cmd sur Mac (fait par Qt), avec quelques exceptions Mac."""
    keys = mac if (IS_MAC and mac is not None) else windows
    if isinstance(keys, (list, tuple)):
        return [QKeySequence(k) for k in keys]
    return [QKeySequence(keys)] if keys else []


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.setWindowIcon(glyph_icon("app"))
        self.resize(1150, 780)
        self.setAcceptDrops(True)
        self.menuBar().setNativeMenuBar(False)
        self.untitled_used = set()
        self.zoom_delta = 0
        self.compare_windows = []
        self.find_dialog = None
        self.regex_dialog = None
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.setTabsClosable(True)
        self.tabs.setMovable(True)
        self.tabs.setElideMode(Qt.TextElideMode.ElideNone)
        self.tabs.tabCloseRequested.connect(lambda i: self.close_tab(i))
        self.tabs.currentChanged.connect(self._on_tab)
        self.tabs.tabBarDoubleClicked.connect(lambda i: self.new_doc() if i < 0 else None)
        self.tabs.tabBar().setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tabs.tabBar().customContextMenuRequested.connect(self.tab_menu)
        self.setCentralWidget(self.tabs)
        self.results = ResultsPanel(self)
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, self.results)
        self.results.hide()
        self.results.activated.connect(self.open_result)
        self.json_panel = JsonTreePanel(self)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self.json_panel)
        self.json_panel.hide()
        self.fs = QFileSystemWatcher(self)
        self.fs.fileChanged.connect(self._file_changed)
        self.req_dir = data_dir("demandes")
        self.fs.addPath(self.req_dir)
        self.fs.directoryChanged.connect(lambda _p: self.process_requests())
        self._build_actions()
        self._build_menus()
        self._build_toolbar()
        self._build_status()
        self.apply_prefs()
        self._session_timer = QTimer(self)
        self._session_timer.setInterval(5000)
        self._session_timer.timeout.connect(self._autosave_session)
        self._session_timer.start()
        self._poll = QTimer(self)
        self._poll.setInterval(1000)
        self._poll.timeout.connect(self._poll_tick)
        self._poll.start()
        self._session_dirty = False
        QApplication.instance().applicationStateChanged.connect(self._app_state)
        geo = conf().value("geometry")
        if geo is not None:
            self.restoreGeometry(geo)

    # ------------------------------------------------------------------ outils de base
    def editors(self):
        return [self.tabs.widget(i) for i in range(self.tabs.count())]

    def current(self):
        return self.tabs.currentWidget()

    def font_for_editors(self):
        family = pref("font_family")
        font = editor_font(max(6.0, pref("font_size") + self.zoom_delta))
        if family:
            font.setFamily(family)
        return font

    def say(self, text, ms=5000):
        self.statusBar().showMessage(text, ms)

    def _act(self, text, slot=None, keys=(), checkable=False, icon=None, tip=None):
        action = QAction(text, self)
        if keys:
            action.setShortcuts(keys)
            action.setShortcutContext(Qt.ShortcutContext.WindowShortcut)
        if checkable:
            action.setCheckable(True)
        if icon:
            action.setData(icon)
        if tip:
            action.setToolTip(tip)
        if slot is not None:
            action.triggered.connect(lambda _c=False: slot())
        self.addAction(action)
        return action

    def _with_ed(self, fn):
        def run():
            ed = self.current()
            if ed is not None:
                fn(ed)
        return run

    # ------------------------------------------------------------------ actions et menus
    def _build_actions(self):
        A, E = self._act, self._with_ed
        self.a = a = {}
        a["new"] = A("Nouveau", self.new_doc, sc("Ctrl+N"), icon="new")
        a["open"] = A("Ouvrir…", self.open_dialog, sc("Ctrl+O"), icon="open")
        a["reload"] = A("Recharger depuis le disque", E(lambda ed: self.reload(ed)))
        a["save"] = A("Enregistrer", E(self.save), sc("Ctrl+S"), icon="save")
        a["saveas"] = A("Enregistrer sous…", E(self.save_as), sc("Ctrl+Alt+S", "Ctrl+Shift+S"))
        a["savecopy"] = A("Enregistrer une copie sous…", E(lambda ed: self.save_as(ed, copy=True)))
        a["saveall"] = A("Enregistrer tout", self.save_all, sc("Ctrl+Shift+S", "Ctrl+Alt+S"), icon="saveall")
        a["rename"] = A("Renommer…", E(self.rename))
        a["close"] = A("Fermer", lambda: self.close_tab(self.tabs.currentIndex()), sc("Ctrl+W"), icon="close")
        a["closeall"] = A("Fermer tout", self.close_all, sc("Ctrl+Shift+W"))
        a["closeothers"] = A("Fermer tout sauf le document courant", lambda: self.close_others(self.tabs.currentIndex()))
        a["versions"] = A("Versions précédentes…", E(self.show_versions))
        a["opendir"] = A("Ouvrir le dossier contenant", E(self.open_folder))
        a["quit"] = A("Quitter", self.close)
        a["undo"] = A("Annuler", E(lambda ed: ed.undo()), [QKeySequence(QKeySequence.StandardKey.Undo)], icon="undo")
        a["redo"] = A("Rétablir", E(lambda ed: ed.redo()), [QKeySequence(QKeySequence.StandardKey.Redo)], icon="redo")
        a["cut"] = A("Couper", E(lambda ed: ed.do_cut()), [QKeySequence(QKeySequence.StandardKey.Cut)], icon="cut")
        a["copy"] = A("Copier", E(lambda ed: ed.do_copy()), [QKeySequence(QKeySequence.StandardKey.Copy)], icon="copy")
        a["paste"] = A("Coller", E(lambda ed: ed.do_paste()), [QKeySequence(QKeySequence.StandardKey.Paste)],
                       icon="paste")
        for key in ("undo", "redo", "cut", "copy", "paste"):
            a[key].setShortcutContext(Qt.ShortcutContext.WidgetShortcut)
        a["selectall"] = A("Tout sélectionner", E(lambda ed: ed.selectAll()))
        a["copypath"] = A("Chemin complet", E(lambda ed: self._clip(ed.path or ed.display_name())))
        a["copyname"] = A("Nom du fichier", E(lambda ed: self._clip(ed.display_name())))
        a["copydir"] = A("Dossier", E(lambda ed: self._clip(os.path.dirname(ed.path) if ed.path else "")))
        a["indent"] = A("Augmenter le retrait", E(lambda ed: ed.indent_lines(True)))
        a["unindent"] = A("Diminuer le retrait", E(lambda ed: ed.indent_lines(False)))
        a["upper"] = A("MAJUSCULES", E(lambda ed: self.case(ed, str.upper)), sc("Ctrl+Shift+U"))
        a["lower"] = A("minuscules", E(lambda ed: self.case(ed, str.lower)), sc("Ctrl+U"))
        a["title"] = A("Casse De Titre", E(lambda ed: self.case(ed, title_case)))
        a["invert"] = A("iNVERSER la casse", E(lambda ed: self.case(ed, str.swapcase)))
        a["dup"] = A("Dupliquer la ligne", E(self.duplicate), sc("Ctrl+D"))
        a["delline"] = A("Supprimer la ligne", E(self.delete_lines), sc("Ctrl+Shift+L"))
        a["up"] = A("Monter la ligne", E(lambda ed: self.move_lines(ed, True)), sc("Ctrl+Shift+Up"))
        a["down"] = A("Descendre la ligne", E(lambda ed: self.move_lines(ed, False)), sc("Ctrl+Shift+Down"))
        a["join"] = A("Joindre les lignes", E(self.join_lines), sc("Ctrl+J"))
        lines_ops = (
            ("sort", "Trier (croissant)", lambda ls: sort_lines(ls)),
            ("sortd", "Trier (décroissant)", lambda ls: sort_lines(ls, reverse=True)),
            ("sorti", "Trier sans tenir compte de la casse", lambda ls: sort_lines(ls, ci=True)),
            ("sortn", "Trier comme des nombres", lambda ls: sort_lines(ls, numeric=True)),
            ("reverse", "Inverser l'ordre des lignes", lambda ls: ls[::-1]),
            ("uniq", "Supprimer les doublons", lambda ls: unique_lines(ls)),
            ("uniqc", "Supprimer les doublons consécutifs", lambda ls: unique_lines(ls, True)),
            ("noempty", "Supprimer les lignes vides", lambda ls: remove_empty(ls)),
            ("noblank", "Supprimer les lignes vides (avec blancs)", lambda ls: remove_empty(ls, True)),
            ("trimr", "Supprimer les espaces de fin", lambda ls: [l.rstrip() for l in ls]),
            ("triml", "Supprimer les espaces de début", lambda ls: [l.lstrip() for l in ls]),
            ("trimb", "Supprimer les espaces de début et de fin", lambda ls: [l.strip() for l in ls]),
        )
        self.line_ops = []
        for key, text, fn in lines_ops:
            a[key] = A(text, E(lambda ed, f=fn, t=text: self.lines_op(ed, f, t)))
            self.line_ops.append(key)
        a["tabs2sp"] = A("Tabulations → espaces", E(lambda ed: self.lines_op(
            ed, lambda ls: [l.expandtabs(ed.tab_width) for l in ls], "Tabulations → espaces")))
        a["sp2tabs"] = A("Espaces de début → tabulations", E(lambda ed: self.lines_op(
            ed, lambda ls: [leading_to_tabs(l, ed.tab_width) for l in ls], "Espaces → tabulations")))
        a["special"] = A("Remplacer les caractères invisibles (NBSP, ZWSP…)", E(self.clean_special))
        a["typo"] = A("Remplacer tirets, apostrophes et guillemets typographiques (– ’ “…)", E(self.clean_typo))
        a["comment"] = A("Basculer le commentaire", E(lambda ed: self.comment(ed, "toggle")),
                         sc("Ctrl+Q", ["Ctrl+/", "Meta+Q"]))
        a["comment_add"] = A("Commenter", E(lambda ed: self.comment(ed, "add")), sc("Ctrl+K"))
        a["comment_del"] = A("Décommenter", E(lambda ed: self.comment(ed, "remove")), sc("Ctrl+Shift+K"))
        a["coleditor"] = A("Éditeur de colonne…", E(self.column_editor), sc("Alt+C"))
        a["readonly"] = A("Lecture seule", E(self.toggle_readonly), checkable=True)
        a["find"] = A("Rechercher…", lambda: self.open_find(0), sc("Ctrl+F"), icon="find")
        a["replace"] = A("Remplacer…", lambda: self.open_find(1), sc("Ctrl+H", ["Ctrl+Alt+F", "Meta+H"]), icon="replace")
        a["findfiles"] = A("Rechercher dans les fichiers…", lambda: self.open_find(2), sc("Ctrl+Shift+F"))
        a["mark"] = A("Marquer…", lambda: self.open_find(3))
        a["next"] = A("Suivant", lambda: self.find_again(True), sc("F3"))
        a["prev"] = A("Précédent", lambda: self.find_again(False), sc("Shift+F3"))
        a["goto"] = A("Aller à la ligne…", E(self.goto), sc("Ctrl+G"))
        a["brace"] = A("Aller à l'accolade correspondante", E(self.goto_brace), sc("Ctrl+B"))
        a["filter"] = A("Filtrer les lignes…", E(self.filter_lines))
        a["regex"] = A("Testeur et générateur de regex…", self.open_regex, sc("Ctrl+R"), icon="regex")
        a["regexgen"] = A("Générer une regex depuis la sélection", E(self.regex_from_selection))
        a["clearmarks"] = A("Effacer toutes les marques", E(lambda ed: ed.clear_marks()))
        a["bm"] = A("Basculer le marque-page", E(lambda ed: ed.toggle_bookmark()), sc("Ctrl+F2"))
        a["bmnext"] = A("Marque-page suivant", E(lambda ed: ed.goto_bookmark(True)), sc("F2"))
        a["bmprev"] = A("Marque-page précédent", E(lambda ed: ed.goto_bookmark(False)), sc("Shift+F2"))
        a["bmclear"] = A("Effacer tous les marque-pages", E(self.clear_bookmarks))
        a["bmcut"] = A("Couper les lignes marquées", E(lambda ed: self.bookmark_op(ed, "cut")))
        a["bmcopy"] = A("Copier les lignes marquées", E(lambda ed: self.bookmark_op(ed, "copy")))
        a["bmdel"] = A("Supprimer les lignes marquées", E(lambda ed: self.bookmark_op(ed, "delete")))
        a["bmkeep"] = A("Supprimer les lignes non marquées", E(lambda ed: self.bookmark_op(ed, "keep")))
        a["bminv"] = A("Inverser les marque-pages", E(lambda ed: self.bookmark_op(ed, "invert")))
        a["wrap"] = A("Retour à la ligne automatique", lambda: self.toggle_view("wrap"), checkable=True, icon="wrap")
        a["ws"] = A("Afficher les espaces et tabulations", lambda: self.toggle_view("show_ws"), checkable=True)
        a["eol"] = A("Afficher les fins de ligne", lambda: self.toggle_view("show_eol"), checkable=True)
        a["all"] = A("Afficher tous les caractères", lambda: self.toggle_view("all"), checkable=True,
                     icon="pilcrow")
        a["guides"] = A("Guides d'indentation", lambda: self.toggle_view("guides"), checkable=True, icon="guides")
        a["numbers"] = A("Numéros de ligne", lambda: self.toggle_view("numbers"), checkable=True)
        a["toolbar"] = A("Barre d'outils", lambda: self.toggle_view("toolbar"), checkable=True)
        a["zoomin"] = A("Agrandir", lambda: self.zoom(1), [QKeySequence(QKeySequence.StandardKey.ZoomIn)],
                        icon="zoomin")
        a["zoomout"] = A("Réduire", lambda: self.zoom(-1), [QKeySequence(QKeySequence.StandardKey.ZoomOut)],
                         icon="zoomout")
        a["zoomreset"] = A("Taille normale", lambda: self.zoom(0), sc("Ctrl+/", "Ctrl+0"))
        a["foldall"] = A("Tout replier", E(lambda ed: ed.fold_all(True)), sc("Alt+0"))
        a["unfoldall"] = A("Tout déplier", E(lambda ed: ed.fold_all(False)), sc("Alt+Shift+0"))
        a["foldcur"] = A("Replier / déplier le bloc courant", E(lambda ed: ed.toggle_current_fold()),
                         sc("Ctrl+Alt+F", "Ctrl+Alt+K"))
        for n in range(1, 9):
            a[f"fold{n}"] = A(f"Replier le niveau {n}", E(lambda ed, k=n: ed.fold_level(k, True)), sc(f"Alt+{n}"))
            a[f"unfold{n}"] = A(f"Déplier le niveau {n}", E(lambda ed, k=n: ed.fold_level(k, False)),
                                sc(f"Alt+Shift+{n}"))
        a["tail"] = A("Surveiller le fichier (tail -f)", E(self.toggle_tail), checkable=True)
        a["results"] = A("Résultats de la recherche", lambda: self.results.setVisible(not self.results.isVisible()))
        a["jsontree"] = A("Arbre JSON", self.toggle_json_panel)
        a["json_fmt"] = A("Formater le JSON", E(lambda ed: self.json_tool(ed, "format")),
                          sc("Ctrl+Alt+Shift+M"), icon="json")
        a["json_sort"] = A("Formater en triant les clés", E(lambda ed: self.json_tool(ed, "sort")))
        a["json_min"] = A("Compacter le JSON (une ligne)", E(lambda ed: self.json_tool(ed, "minify")),
                          sc("Ctrl+Alt+Shift+C"))
        a["json_check"] = A("Valider le JSON", E(lambda ed: self.json_tool(ed, "check")))
        a["b64"] = A("Encoder en Base64 (avec padding)", E(lambda ed: self.mime(ed, lambda t: b64_encode(t))))
        a["b64np"] = A("Encoder en Base64 (sans padding)", E(lambda ed: self.mime(ed, lambda t: b64_encode(t, False))))
        a["b64u"] = A("Encoder en Base64 URL (avec padding)", E(lambda ed: self.mime(ed, lambda t: b64_encode(t, True, True))))
        a["b64unp"] = A("Encoder en Base64 URL (sans padding)",
                        E(lambda ed: self.mime(ed, lambda t: b64_encode(t, False, True))))
        a["b64d"] = A("Décoder le Base64", E(lambda ed: self.mime_bytes(ed, b64_decode, "Base64")))
        a["urle"] = A("Encoder pour une URL (%20…)", E(lambda ed: self.mime(ed, url_encode)))
        a["urld"] = A("Décoder une URL", E(lambda ed: self.mime(ed, url_decode)))
        a["hexe"] = A("Texte → hexadécimal", E(lambda ed: self.mime(ed, to_hex)))
        a["hexd"] = A("Hexadécimal → texte", E(lambda ed: self.mime_bytes(ed, from_hex, "hexadécimal")))
        a["jwt"] = A("Décoder un JWT", E(self.decode_jwt))
        a["hash"] = A("Empreinte (MD5, SHA-256…)…", lambda: HashDialog(self).exec())
        a["compare"] = A("Comparer avec un autre document…", E(self.compare_dialog), icon="compare")
        a["prefs"] = A("Préférences…", self.preferences, [QKeySequence(QKeySequence.StandardKey.Preferences)]
                       if IS_MAC else [])
        a["about"] = A("À propos de Bloc-notes Pro", self.about)

    def _build_menus(self):
        mb = self.menuBar()
        a = self.a

        def menu(title, keys, parent=None):
            m = (parent or mb).addMenu(title)
            for k in keys:
                if k == "-":
                    m.addSeparator()
                elif isinstance(k, QMenu):
                    m.addMenu(k)
                else:
                    m.addAction(a[k])
            return m

        f = menu("Fichier", ["new", "open"])
        self.recent_menu = f.addMenu("Fichiers récents")
        self.recent_menu.aboutToShow.connect(self._fill_recent)
        for k in ("-", "reload", "opendir", "-", "save", "saveas", "savecopy", "saveall", "rename", "-",
                  "versions", "-", "close", "closeall", "closeothers", "-", "quit"):
            f.addSeparator() if k == "-" else f.addAction(a[k])
        e = menu("Édition", ["undo", "redo", "-", "cut", "copy", "paste", "selectall", "-"])
        menu("Copier dans le presse-papiers", ["copypath", "copyname", "copydir"], e)
        menu("Retrait", ["indent", "unindent"], e)
        menu("Convertir la casse", ["upper", "lower", "title", "invert"], e)
        menu("Opérations sur les lignes", ["dup", "delline", "up", "down", "join", "-"] + self.line_ops[:5]
             + ["-"] + self.line_ops[5:9], e)
        menu("Commentaires", ["comment", "comment_add", "comment_del"], e)
        menu("Blancs", self.line_ops[9:] + ["-", "tabs2sp", "sp2tabs", "-", "special", "typo"], e)
        e.addSeparator()
        e.addAction(a["coleditor"])
        hint = e.addAction("Sélection en colonne : Option (Alt) + glisser, ou Option+Maj+flèches")
        hint.setEnabled(False)
        e.addSeparator()
        e.addAction(a["readonly"])
        r = menu("Recherche", ["find", "findfiles", "next", "prev", "replace", "-", "goto", "brace", "-", "mark",
                               "clearmarks"])
        menu("Marque-pages", ["bm", "bmnext", "bmprev", "bmclear", "-", "bmcut", "bmcopy", "bmdel", "bmkeep",
                              "bminv"], r)
        r.addAction(a["filter"])
        r.addSeparator()
        r.addAction(a["regex"])
        v = menu("Affichage", ["wrap"])
        menu("Symboles spéciaux", ["ws", "eol", "all"], v)
        for k in ("guides", "numbers", "toolbar"):
            v.addAction(a[k])
        v.addSeparator()
        fold = menu("Repli", ["foldall", "unfoldall", "foldcur", "-"], v)
        lv = fold.addMenu("Replier le niveau")
        ulv = fold.addMenu("Déplier le niveau")
        for n in range(1, 9):
            lv.addAction(a[f"fold{n}"])
            ulv.addAction(a[f"unfold{n}"])
        menu("Zoom", ["zoomin", "zoomout", "zoomreset"], v)
        v.addSeparator()
        theme = v.addMenu("Thème")
        self.theme_group = QActionGroup(self)
        for code, label in (("auto", "Automatique (comme macOS)"), ("light", "Clair"), ("dark", "Sombre")):
            act = theme.addAction(label)
            act.setCheckable(True)
            act.setData(code)
            self.theme_group.addAction(act)
            act.triggered.connect(lambda _c=False, cd=code: (set_pref("theme", cd), self.apply_theme()))
        v.addSeparator()
        for k in ("tail", "results", "jsontree"):
            v.addAction(a[k])
        enc = mb.addMenu("Encodage")
        self.encoding_menu = enc
        conv = enc
        for code in ("utf-8", "utf-8-bom", "ansi", "utf-16-le", "utf-16-be"):
            act = conv.addAction(f"Encoder en {ENCODINGS[code]}")
            act.triggered.connect(lambda _c=False, cd=code: self.set_encoding(cd))
        enc.addSeparator()
        rel = enc.addMenu("Relire le fichier en")
        for code, label in (("utf-8", "UTF-8"), ("ansi", "ANSI (Windows-1252)"), ("latin-1", "ISO-8859-1"),
                            ("utf-16-le", "UTF-16 LE"), ("utf-16-be", "UTF-16 BE")):
            act = rel.addAction(label)
            act.triggered.connect(lambda _c=False, cd=code: self.reread_as(cd))
        enc.addSeparator()
        self.eol_menu = enc.addMenu("Fins de ligne")
        for eol, label in EOL_LABELS.items():
            act = self.eol_menu.addAction(f"Convertir en {label}")
            act.triggered.connect(lambda _c=False, e=eol: self._with_ed(lambda ed: ed.convert_eol(e))())
        lang = mb.addMenu("Langage")
        self.lang_menu = lang
        auto = lang.addAction("Détection automatique")
        auto.triggered.connect(self._with_ed(self.auto_language))
        lang.addSeparator()
        self.lang_group = QActionGroup(self)
        self.lang_actions = {}
        for code, (label, _exts) in LANGS.items():
            act = lang.addAction(label)
            act.setCheckable(True)
            self.lang_group.addAction(act)
            act.triggered.connect(lambda _c=False, cd=code: self._with_ed(lambda ed: ed.set_language(cd))())
            self.lang_actions[code] = act
        jinja = lang.addAction("Jinja2 ({{ }} et {% %}) en plus")
        jinja.setCheckable(True)
        self.jinja_action = jinja
        jinja.triggered.connect(self._with_ed(lambda ed: ed.set_language(ed.lang, ed.lang_forced,
                                                                         not ed.jinja)))
        tools = mb.addMenu("Outils")
        tools.addAction(a["regex"])
        tools.addAction(a["regexgen"])
        tools.addSeparator()
        menu("JSON", ["json_fmt", "json_sort", "json_min", "json_check", "-", "jsontree"], tools)
        menu("Base64, URL, hexadécimal", ["b64", "b64np", "b64u", "b64unp", "b64d", "-", "urle", "urld", "-",
                                          "hexe", "hexd", "-", "jwt"], tools)
        for k in ("hash", "compare", "-", "prefs"):
            tools.addSeparator() if k == "-" else tools.addAction(a[k])
        menu("?", ["about"])

    def _build_toolbar(self):
        tb = QToolBar("Barre d'outils")
        tb.setObjectName("toolbar")
        tb.setMovable(False)
        tb.setIconSize(QSize(18, 18))
        for k in ("new", "open", "save", "saveall", "close", "-", "cut", "copy", "paste", "-", "undo", "redo", "-",
                  "find", "replace", "regex", "-", "zoomin", "zoomout", "-", "wrap", "all", "guides", "-", "json_fmt",
                  "compare"):
            if k == "-":
                tb.addSeparator()
            else:
                act = self.a[k]
                shortcut = act.shortcut().toString(QKeySequence.SequenceFormat.NativeText)
                act.setToolTip(act.text() + (f"  ({shortcut})" if shortcut else ""))
                tb.addAction(act)
        self.addToolBar(tb)
        self.toolbar = tb

    def _build_status(self):
        sb = QStatusBar()
        self.setStatusBar(sb)
        self.s_lang = StatusSeg("Langage — cliquer pour changer")
        self.s_lang.setObjectName("first")
        self.s_size = StatusSeg("Taille du document")
        self.s_pos = StatusSeg("Position — double-clic : aller à la ligne")
        self.s_eol = StatusSeg("Fins de ligne — cliquer pour convertir")
        self.s_enc = StatusSeg("Encodage — cliquer pour changer")
        self.s_mode = StatusSeg("Insertion / refrappe — cliquer pour basculer")
        sb.addWidget(self.s_lang, 1)
        for seg in (self.s_size, self.s_pos, self.s_eol, self.s_enc, self.s_mode):
            sb.addPermanentWidget(seg)
        self.s_version = StatusSeg(version_details() + " — cliquer pour « À propos »")
        self.s_version.setText(f"v{VERSION}")
        sb.addPermanentWidget(self.s_version)
        self.s_version.clicked.connect(self.about)
        self.s_lang.clicked.connect(lambda: self.lang_menu.exec(QCursor_pos()))
        self.s_eol.clicked.connect(lambda: self.eol_menu.exec(QCursor_pos()))
        self.s_enc.clicked.connect(lambda: self.encoding_menu.exec(QCursor_pos()))
        self.s_pos.double.connect(self._with_ed(self.goto))
        self.s_mode.clicked.connect(self._with_ed(self.toggle_overwrite))

    # ------------------------------------------------------------------ réglages et thème
    def apply_prefs(self):
        for k, name in (("wrap", "wrap"), ("ws", "show_ws"), ("eol", "show_eol"), ("guides", "guides"),
                        ("numbers", "numbers"), ("toolbar", "toolbar")):
            self.a[k].setChecked(pref(name))
        self.a["all"].setChecked(pref("show_ws") and pref("show_eol"))
        self.toolbar.setVisible(pref("toolbar"))
        for act in self.theme_group.actions():
            act.setChecked(act.data() == pref("theme"))
        self.apply_theme()
        for ed in self.editors():
            self.configure(ed)

    def configure(self, ed):
        ed.set_tab_width(pref("tab_width"))
        ed.use_spaces = pref("use_spaces")
        ed.set_editor_font(self.font_for_editors())
        ed.set_wrap(pref("wrap"))
        ed.set_show_ws(pref("show_ws"))
        ed.set_show_eol(pref("show_eol"))
        ed.guides = pref("guides")
        ed.numbers = pref("numbers")
        ed.update_gutter_width()
        ed.apply_theme()

    def apply_theme(self):
        choice = pref("theme")
        if choice == "auto":
            try:
                Theme.dark = QGuiApplication.styleHints().colorScheme() == Qt.ColorScheme.Dark
            except AttributeError:
                Theme.dark = False
        else:
            Theme.dark = choice == "dark"
        app = QApplication.instance()
        app.setStyle("Fusion")
        pal = QPalette()
        dark = Theme.dark
        for role, light_c, dark_c in ((QPalette.ColorRole.Window, "#F3F3F3", "#202020"),
                                      (QPalette.ColorRole.WindowText, "#1A1A1A", "#FFFFFF"),
                                      (QPalette.ColorRole.Base, "#FFFFFF", "#1E1E1E"),
                                      (QPalette.ColorRole.AlternateBase, "#F7F7F7", "#262626"),
                                      (QPalette.ColorRole.Text, "#1A1A1A", "#E6E6E6"),
                                      (QPalette.ColorRole.Button, "#FBFBFB", "#2D2D2D"),
                                      (QPalette.ColorRole.ButtonText, "#1A1A1A", "#FFFFFF"),
                                      (QPalette.ColorRole.Highlight, "#005FB8", "#4CC2FF"),
                                      (QPalette.ColorRole.HighlightedText, "#FFFFFF", "#000000"),
                                      (QPalette.ColorRole.ToolTipBase, "#F9F9F9", "#2B2B2B"),
                                      (QPalette.ColorRole.ToolTipText, "#1A1A1A", "#FFFFFF")):
            pal.setColor(role, QColor(dark_c if dark else light_c))
        app.setPalette(pal)
        app.setStyleSheet(window_css())
        for act in self.findChildren(QAction):
            icon = act.data()
            if isinstance(icon, str) and icon in _GLYPHS:
                act.setIcon(glyph_icon(icon))
        for ed in self.editors():
            ed.apply_theme()
            self._update_tab(ed)

    def toggle_view(self, what):
        if what == "all":
            on = self.a["all"].isChecked()
            set_pref("show_ws", on)
            set_pref("show_eol", on)
        else:
            key = {"wrap": "wrap", "show_ws": "ws", "show_eol": "eol", "guides": "guides", "numbers": "numbers",
                   "toolbar": "toolbar"}[what]
            set_pref(what, self.a[key].isChecked())
        self.apply_prefs()

    def zoom(self, step):
        self.zoom_delta = 0 if step == 0 else max(-6, min(30, self.zoom_delta + step))
        font = self.font_for_editors()
        for ed in self.editors():
            ed.set_editor_font(font)

    def preferences(self):
        dlg = PreferencesDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            dlg.save()
            self.apply_prefs()

    # ------------------------------------------------------------------ onglets
    def new_editor(self):
        ed = Editor()
        ed.session_id = os.urandom(6).hex()
        self.configure(ed)
        ed.state_changed.connect(lambda e=ed: self._ed_changed(e))
        ed.files_dropped.connect(self.open_files)
        ed.document().modificationChanged.connect(lambda _m, e=ed: self._update_tab(e))
        return ed

    def _next_untitled(self):
        n = 1
        while n in self.untitled_used:
            n += 1
        self.untitled_used.add(n)
        return f"nouveau {n}"

    def _free_untitled(self, ed):
        m = re.fullmatch(r"nouveau (\d+)", ed.untitled or "")
        if m:
            self.untitled_used.discard(int(m.group(1)))

    def add_tab(self, ed, focus=True):
        index = self.tabs.addTab(ed, ed.display_name())
        self._update_tab(ed)
        if focus:
            self.tabs.setCurrentIndex(index)
            ed.setFocus()
        return index

    def new_doc(self):
        ed = self.new_editor()
        ed.untitled = self._next_untitled()
        ed.eol = pref("new_eol")
        self.add_tab(ed)
        return ed

    def new_tab_with(self, text, name, lang="text"):
        ed = self.new_editor()
        ed.untitled = name
        ed.load_text(text, pref("new_eol"))
        ed.set_language(lang, forced=True)
        ed.document().setModified(True)
        self.add_tab(ed)
        return ed

    def _update_tab(self, ed):
        i = self.tabs.indexOf(ed)
        if i < 0:
            return
        if ed.isReadOnly():
            color = "#8A8A8A"
        elif ed.document().isModified():
            color = "#E3242B"
        else:
            color = "#2B7BD8"
        self.tabs.setTabIcon(i, glyph_icon("disk", color))
        self.tabs.setTabText(i, ed.display_name())
        tip = ed.path or ed.untitled
        if ed.disk_missing:
            tip += "\n(supprimé du disque)"
        self.tabs.setTabToolTip(i, tip)
        if ed is self.current():
            self._update_title()
        self._session_dirty = True

    def _update_title(self):
        ed = self.current()
        if ed is None:
            self.setWindowTitle(APP_NAME)
            return
        star = "*" if ed.document().isModified() else ""
        self.setWindowTitle(f"{star}{ed.path or ed.untitled} - {APP_NAME}")

    def _on_tab(self, _index):
        ed = self.current()
        if ed is None:
            return
        self._update_title()
        self.update_status()
        if ed.pending_reload:
            QTimer.singleShot(50, self, lambda e=ed: self._ask_reload(e))
        if self.json_panel.isVisible():
            self.json_panel.refresh()

    def _ed_changed(self, ed):
        self._session_dirty = True
        if ed is self.current():
            self.update_status()

    def tab_menu(self, pos):
        index = self.tabs.tabBar().tabAt(pos)
        if index < 0:
            return
        ed = self.tabs.widget(index)
        menu = QMenu(self)
        menu.addAction("Fermer", lambda: self.close_tab(index))
        menu.addAction("Fermer tous les autres", lambda: self.close_others(index))
        menu.addAction("Fermer tous à gauche", lambda: self.close_side(index, left=True))
        menu.addAction("Fermer tous à droite", lambda: self.close_side(index, left=False))
        menu.addAction("Fermer tous les onglets non modifiés", self.close_unchanged)
        menu.addSeparator()
        menu.addAction("Enregistrer", lambda: self.save(ed))
        menu.addAction("Enregistrer sous…", lambda: self.save_as(ed))
        menu.addAction("Renommer…", lambda: self.rename(ed))
        menu.addSeparator()
        menu.addAction("Copier le chemin complet", lambda: self._clip(ed.path or ed.display_name()))
        menu.addAction("Copier le nom du fichier", lambda: self._clip(ed.display_name()))
        menu.addAction("Copier le dossier", lambda: self._clip(os.path.dirname(ed.path) if ed.path else ""))
        menu.addSeparator()
        act = menu.addAction("Ouvrir le dossier contenant", lambda: self.open_folder(ed))
        act.setEnabled(bool(ed.path))
        menu.addSeparator()
        ro = menu.addAction("Lecture seule", lambda: self.toggle_readonly(ed))
        ro.setCheckable(True)
        ro.setChecked(ed.isReadOnly())
        menu.exec(self.tabs.tabBar().mapToGlobal(pos))

    # ------------------------------------------------------------------ ouvrir / enregistrer
    def open_dialog(self):
        ed = self.current()
        start = os.path.dirname(ed.path) if ed is not None and ed.path else conf().value("last_dir", os.path.expanduser("~"))
        paths, _ = QFileDialog.getOpenFileNames(self, "Ouvrir", start, "Tous les fichiers (*)")
        if paths:
            conf().setValue("last_dir", os.path.dirname(paths[0]))
            self.open_files(paths)

    def open_files(self, paths):
        last = None
        for path in paths:
            last = self.open_path(path) or last
        return last

    def open_path(self, path, encoding=None):
        path = os.path.abspath(path)
        for ed in self.editors():
            if ed.path and os.path.normcase(os.path.realpath(ed.path)) == os.path.normcase(os.path.realpath(path)):
                self.tabs.setCurrentWidget(ed)
                return ed
        if os.path.isdir(path):
            self.say(f"« {path} » est un dossier.")
            return None
        try:
            size = os.path.getsize(path)
        except OSError as exc:
            QMessageBox.warning(self, APP_NAME, f"Impossible d'ouvrir « {path} » :\n{exc.strerror}")
            return None
        if size > HUGE_FILE:
            QMessageBox.warning(self, APP_NAME, f"« {os.path.basename(path)} » fait {size // (1024 * 1024)} Mo : "
                                "c'est trop gros pour l'éditeur.")
            return None
        if size > BIG_FILE and QMessageBox.question(
                self, APP_NAME, f"« {os.path.basename(path)} » fait {size // (1024 * 1024)} Mo.\nL'ouvrir en mode "
                "allégé (sans coloration ni repli) ?") != QMessageBox.StandardButton.Yes:
            return None
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            QMessageBox.warning(self, APP_NAME, f"Impossible de lire « {path} » :\n{exc.strerror}")
            return None
        binary = looks_binary(data)
        if binary and QMessageBox.question(
                self, APP_NAME, f"« {os.path.basename(path)} » ressemble à un fichier binaire.\n"
                "L'ouvrir quand même, en lecture seule ?") != QMessageBox.StandardButton.Yes:
            return None
        text, enc = decode_bytes(data, "latin-1" if binary else encoding)
        cur = self.current()
        reuse = (cur is not None and not cur.path and not cur.document().isModified()
                 and cur.document().isEmpty() and cur.untitled.startswith("nouveau "))
        ed = cur if reuse else self.new_editor()
        if reuse:
            self._free_untitled(ed)
        ed.path, ed.untitled, ed.encoding = path, "", enc
        ed.load_text(text, pref("new_eol"))
        lang, jinja = detect_language(path, text[:20000])
        ed.set_language(lang, forced=False, jinja=jinja)
        ed.setReadOnly(binary or not os.access(path, os.W_OK))
        ed.disk_stamp = file_stamp(path)
        ed.disk_missing = False
        self._watch(path)
        if reuse:
            self._update_tab(ed)
        else:
            self.add_tab(ed)
        self._add_recent(path)
        self.update_status()
        return ed

    def _watch(self, path):
        if path and os.path.exists(path) and path not in self.fs.files():
            self.fs.addPath(path)

    def _unwatch(self, path):
        if path and path in self.fs.files():
            self.fs.removePath(path)

    def reload(self, ed, ask=True, encoding=None):
        if not ed.path or not os.path.exists(ed.path):
            return False
        if ask and ed.document().isModified() and QMessageBox.question(
                self, APP_NAME, f"Recharger « {ed.display_name()} » ?\nLes modifications non enregistrées seront "
                "perdues.") != QMessageBox.StandardButton.Yes:
            return False
        try:
            with open(ed.path, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            self.say(f"Rechargement impossible : {exc.strerror}")
            return False
        line = ed.textCursor().blockNumber()
        scroll = ed.verticalScrollBar().value()
        text, enc = decode_bytes(data, encoding)
        ed.encoding = enc
        readonly = ed.isReadOnly()
        ed.load_text(text, ed.eol)
        ed.setReadOnly(readonly)
        if not ed.lang_forced:
            lang, jinja = detect_language(ed.path, text[:20000])
            ed.set_language(lang, forced=False, jinja=jinja)
        ed.disk_stamp = file_stamp(ed.path)
        ed.pending_reload = False
        ed.disk_missing = False
        if ed.tail:
            ed.moveCursor(QTextCursor.MoveOperation.End)
            ed.ensureCursorVisible()
        else:
            ed.goto_line(line + 1)
            ed.verticalScrollBar().setValue(scroll)
        self._update_tab(ed)
        self.update_status()
        return True

    def save(self, ed=None):
        ed = ed or self.current()
        if ed is None:
            return False
        if not ed.path:
            return self.save_as(ed)
        return self._write(ed, ed.path)

    def _encode_for_save(self, ed):
        text = ed.content()
        if ed.encoding in ("ansi", "latin-1"):
            bad = unencodable(text, ed.encoding)
            if bad:
                sample = " ".join(bad[:10])
                if QMessageBox.question(
                        self, APP_NAME, f"Ces caractères n'existent pas en {ENCODINGS[ed.encoding]} : {sample}\n\n"
                        "Enregistrer en UTF-8 à la place ?") != QMessageBox.StandardButton.Yes:
                    return None
                ed.encoding = "utf-8"
        return encode_text(text, ed.encoding)

    def _write(self, ed, path, keep_state=False):
        data = self._encode_for_save(ed)
        if data is None:
            return False
        if pref("backups") and os.path.isfile(path):
            try:
                make_backup(path, pref("backup_count"))
            except OSError as exc:
                self.say(f"Copie de sécurité impossible : {exc.strerror}")
        self._unwatch(path)
        try:
            with open(path, "wb") as fh:
                fh.write(data)
        except OSError as exc:
            QMessageBox.critical(self, APP_NAME, f"Impossible d'enregistrer « {path} » :\n{exc.strerror}")
            self._watch(ed.path)
            return False
        if not keep_state:
            ed.document().setModified(False)
            ed.disk_stamp = file_stamp(path)
            ed.disk_missing = False
            self._watch(path)
            self._add_recent(path)
            self._update_tab(ed)
            self.update_status()
        else:
            self._watch(ed.path)
        self.say(f"Enregistré : {path}")
        return True

    def save_as(self, ed=None, copy=False):
        ed = ed or self.current()
        if ed is None:
            return False
        start = ed.path or os.path.join(conf().value("last_dir", os.path.expanduser("~")), ed.untitled + ".txt")
        path, _ = QFileDialog.getSaveFileName(self, "Enregistrer une copie sous" if copy else "Enregistrer sous",
                                              start, "Tous les fichiers (*)")
        if not path:
            return False
        conf().setValue("last_dir", os.path.dirname(path))
        if copy:
            return self._write(ed, path, keep_state=True)
        for other in self.editors():
            if other is not ed and other.path and os.path.realpath(other.path) == os.path.realpath(path):
                QMessageBox.warning(self, APP_NAME, "Ce fichier est déjà ouvert dans un autre onglet.")
                return False
        self._unwatch(ed.path)
        self._free_untitled(ed)
        ed.path, ed.untitled = path, ""
        if not ed.lang_forced:
            lang, jinja = detect_language(path, ed.text()[:20000])
            ed.set_language(lang, forced=False, jinja=jinja)
        return self._write(ed, path)

    def save_all(self):
        for ed in self.editors():
            if ed.document().isModified() and not ed.isReadOnly():
                self.tabs.setCurrentWidget(ed)
                if not self.save(ed):
                    return False
        return True

    def rename(self, ed=None):
        ed = ed or self.current()
        if ed is None:
            return
        name, ok = QInputDialog.getText(self, "Renommer", "Nouveau nom :", text=ed.display_name())
        if not ok or not name.strip() or "/" in name or "\\" in name:
            return
        name = name.strip()
        if not ed.path:
            self._free_untitled(ed)
            ed.untitled = name
            self._update_tab(ed)
            return
        target = os.path.join(os.path.dirname(ed.path), name)
        if os.path.exists(target):
            QMessageBox.warning(self, APP_NAME, f"« {name} » existe déjà.")
            return
        try:
            self._unwatch(ed.path)
            os.rename(ed.path, target)
        except OSError as exc:
            QMessageBox.warning(self, APP_NAME, f"Impossible de renommer :\n{exc.strerror}")
            self._watch(ed.path)
            return
        ed.path = target
        ed.disk_stamp = file_stamp(target)
        self._watch(target)
        if not ed.lang_forced:
            lang, jinja = detect_language(target, ed.text()[:20000])
            ed.set_language(lang, forced=False, jinja=jinja)
        self._update_tab(ed)

    def close_tab(self, index, ask=True):
        ed = self.tabs.widget(index)
        if ed is None:
            return True
        if ask and ed.document().isModified() and not (not ed.path and ed.document().isEmpty()):
            self.tabs.setCurrentIndex(index)
            box = QMessageBox(QMessageBox.Icon.Question, APP_NAME,
                              f"Enregistrer les modifications de « {ed.display_name()} » ?", parent=self)
            save = box.addButton("Enregistrer", QMessageBox.ButtonRole.AcceptRole)
            box.addButton("Ne pas enregistrer", QMessageBox.ButtonRole.DestructiveRole)
            cancel = box.addButton("Annuler", QMessageBox.ButtonRole.RejectRole)
            box.exec()
            if box.clickedButton() is cancel:
                return False
            if box.clickedButton() is save and not self.save(ed):
                return False
        self._unwatch(ed.path)
        self._free_untitled(ed)
        self.tabs.removeTab(self.tabs.indexOf(ed))
        ed.deleteLater()
        if self.tabs.count() == 0:
            self.new_doc()
        self._session_dirty = True
        return True

    def close_all(self):
        for ed in list(self.editors()):
            if not self.close_tab(self.tabs.indexOf(ed)):
                return False
        return True

    def close_others(self, index):
        keep = self.tabs.widget(index)
        for ed in list(self.editors()):
            if ed is not keep and not self.close_tab(self.tabs.indexOf(ed)):
                return

    def close_side(self, index, left=True):
        keep = self.tabs.widget(index)
        eds = self.editors()
        pos = eds.index(keep)
        for ed in (eds[:pos] if left else eds[pos + 1:]):
            if not self.close_tab(self.tabs.indexOf(ed)):
                return

    def close_unchanged(self):
        for ed in list(self.editors()):
            if not ed.document().isModified():
                self.close_tab(self.tabs.indexOf(ed))

    def _add_recent(self, path):
        recent = conf().value("recent", [])
        if isinstance(recent, str):
            recent = [recent]
        recent = [p for p in (recent or []) if isinstance(p, str) and p != path]
        conf().setValue("recent", [path] + recent[:14])

    def _fill_recent(self):
        self.recent_menu.clear()
        recent = conf().value("recent", [])
        if isinstance(recent, str):
            recent = [recent]
        for path in recent or []:
            if isinstance(path, str):
                act = self.recent_menu.addAction(path, lambda p=path: self.open_path(p))
                act.setEnabled(os.path.exists(path))
        if not recent:
            self.recent_menu.addAction("(aucun)").setEnabled(False)
        else:
            self.recent_menu.addSeparator()
            self.recent_menu.addAction("Vider la liste", lambda: conf().setValue("recent", []))

    def open_folder(self, ed=None):
        ed = ed or self.current()
        if ed is None or not ed.path:
            return
        if not open_in_explorer(os.path.dirname(ed.path)):
            self.say("Explorateur maison introuvable à côté de Bloc-notes Pro.")

    def show_versions(self, ed):
        if not ed.path:
            self.say("Ce document n'a pas encore été enregistré.")
            return
        VersionsDialog(self, ed).exec()

    def _clip(self, text):
        QApplication.clipboard().setText(text)
        self.say("Copié dans le presse-papiers.")

    def dragEnterEvent(self, ev):
        if ev.mimeData().hasUrls():
            ev.acceptProposedAction()

    def dropEvent(self, ev):
        paths = [u.toLocalFile() for u in ev.mimeData().urls() if u.isLocalFile()]
        if paths:
            self.open_files(paths)

    # ------------------------------------------------------------------ fichiers modifiés ailleurs
    def _file_changed(self, path):
        for ed in self.editors():
            if ed.path == path:
                self._check_disk(ed)
        if os.path.exists(path):
            QTimer.singleShot(200, self, lambda p=path: self._watch(p))

    def _check_disk(self, ed):
        if not ed.path:
            return
        stamp = file_stamp(ed.path)
        if stamp is None:
            if not ed.disk_missing:
                ed.disk_missing = True
                self._update_tab(ed)
                self.say(f"« {ed.display_name()} » a été supprimé ou déplacé du disque.")
            return
        if stamp == ed.disk_stamp:
            return
        ed.disk_missing = False
        if ed.tail or (not ed.document().isModified() and pref("auto_reload")):
            self.reload(ed, ask=False)
        elif ed is self.current() and self.isActiveWindow():
            self._ask_reload(ed)
        else:
            ed.pending_reload = True

    def _ask_reload(self, ed):
        ed.pending_reload = False
        stamp = file_stamp(ed.path)
        if stamp is None or stamp == ed.disk_stamp:
            return
        extra = "\nVos modifications non enregistrées seront perdues." if ed.document().isModified() else ""
        answer = QMessageBox.question(self, APP_NAME, f"« {ed.path} »\n\na été modifié par un autre programme.\n"
                                      f"Voulez-vous le recharger ?{extra}")
        if answer == QMessageBox.StandardButton.Yes:
            self.reload(ed, ask=False)
        else:
            ed.disk_stamp = stamp

    def _app_state(self, state):
        if state == Qt.ApplicationState.ApplicationActive:
            ed = self.current()
            if ed is not None:
                self._check_disk(ed)

    def _poll_tick(self):
        for ed in self.editors():
            if ed.tail:
                self._check_disk(ed)
        self.process_requests()

    def toggle_tail(self, ed):
        if not ed.path:
            self.a["tail"].setChecked(False)
            self.say("Enregistre d'abord le document pour pouvoir le surveiller.")
            return
        ed.tail = not ed.tail
        if ed.tail:
            ed.setReadOnly(True)
            self.reload(ed, ask=True)
            self.say("Surveillance activée : le fichier se met à jour tout seul (lecture seule).")
        else:
            ed.setReadOnly(not os.access(ed.path, os.W_OK))
            self.say("Surveillance arrêtée.")
        self._update_tab(ed)
        self.update_status()

    # ------------------------------------------------------------------ barre d'état
    def update_status(self):
        ed = self.current()
        if ed is None:
            return
        info = ed.status_info()
        label = LANGS.get(ed.lang, ("Texte",))[0]
        if ed.jinja and ed.lang != "yaml":
            label += " + Jinja2"
        if ed.light:
            label += " (mode allégé)"
        self.s_lang.setText(label)
        num = lambda n: f"{n:,}".replace(",", " ")  # noqa: E731
        self.s_size.setText(f"longueur : {num(info['length'])}    lignes : {num(info['lines'])}")
        pos = f"Ln : {num(info['line'])}    Col : {info['col']}    Pos : {num(info['pos'])}"
        if info["sel_chars"] or info["sel_lines"] > 1:
            pos += f"    Sel : {num(info['sel_chars'])} | {info['sel_lines']}"
        self.s_pos.setText(pos)
        self.s_eol.setText(EOL_LABELS.get(ed.eol, "?"))
        self.s_enc.setText(ENCODINGS.get(ed.encoding, ed.encoding))
        if ed.tail:
            mode = "SURVEILLÉ"
        elif ed.isReadOnly():
            mode = "LECTURE SEULE"
        else:
            mode = "RFP" if ed.overwriteMode() else "INS"
        self.s_mode.setText(mode)
        if ed.lang in self.lang_actions:
            self.lang_actions[ed.lang].setChecked(True)
        self.jinja_action.setChecked(ed.jinja)
        self.a["readonly"].setChecked(ed.isReadOnly())
        self.a["tail"].setChecked(ed.tail)
        self._update_title()

    def toggle_overwrite(self, ed):
        if not ed.isReadOnly():
            ed.setOverwriteMode(not ed.overwriteMode())
            self.update_status()

    def toggle_readonly(self, ed):
        ed.setReadOnly(not ed.isReadOnly())
        self._update_tab(ed)
        self.update_status()

    def set_encoding(self, code):
        ed = self.current()
        if ed is None:
            return
        if ed.encoding != code:
            ed.encoding = code
            ed.document().setModified(True)
        self.update_status()
        self.say(f"Le document sera enregistré en {ENCODINGS[code]}.")

    def reread_as(self, code):
        ed = self.current()
        if ed is not None and ed.path:
            self.reload(ed, ask=True, encoding=code)

    def auto_language(self, ed):
        lang, jinja = detect_language(ed.path or ed.untitled, ed.text()[:20000])
        ed.set_language(lang, forced=False, jinja=jinja)

    # ------------------------------------------------------------------ recherche
    def open_find(self, tab):
        if self.find_dialog is None:
            self.find_dialog = FindDialog(self)
        ed = self.current()
        text = ed.textCursor().selectedText() if ed is not None else ""
        if not text and ed is not None:
            cur = ed.textCursor()
            cur.select(QTextCursor.SelectionType.WordUnderCursor)
            text = cur.selectedText()
        self.find_dialog.open_tab(tab, text)

    def open_regex(self, selection=None):
        if self.regex_dialog is None:
            self.regex_dialog = RegexDialog(self)
        if selection is None:
            ed = self.current()
            selection = ""
            if ed is not None and ed.textCursor().hasSelection():
                selection = ed.textCursor().selection().toRawText().replace("\u2029", "\n")
        self.regex_dialog.present(selection)
        return self.regex_dialog

    def regex_from_selection(self, ed):
        sel = ed.textCursor().selection().toRawText().replace("\u2029", "\n")
        dlg = self.open_regex(selection=sel)
        if sel.strip():
            dlg.generate_from(sel)
        else:
            dlg.gen_tabs.setCurrentIndex(1)

    def regex_to_find(self, tab, find, repl, case, word, dotall):
        if self.find_dialog is None:
            self.find_dialog = FindDialog(self)
        fd = self.find_dialog
        fd.open_tab(tab)
        fd.load(find, repl, case, word, dotall)
        if tab == 0:
            fd.find(True)
        elif tab == 3:
            fd.mark_all()

    def find_again(self, forward):
        if self.find_dialog is None or not self.find_dialog.find_edit.currentText():
            self.open_find(0)
            return
        self.find_dialog.find(forward)

    def open_result(self, data):
        target, line, col, length = data
        if isinstance(target, str):
            ed = self.open_path(target)
        else:
            ed = target if target in self.editors() else None
            if ed is not None:
                self.tabs.setCurrentWidget(ed)
        if ed is None:
            return
        block = ed.document().findBlockByNumber(line - 1)
        if not block.isValid():
            return
        pm = PosMap(block.text())
        start = block.position() + pm.to_doc(col)
        ed.select_range(start, start + pm.to_doc(col + length) - pm.to_doc(col))
        ed.setFocus()

    def goto(self, ed):
        n = ed.blockCount()
        line, ok = QInputDialog.getInt(self, "Aller à", f"Ligne (1 – {n}) :", ed.textCursor().blockNumber() + 1, 1, n)
        if ok:
            ed.goto_line(line)

    def goto_brace(self, ed):
        pos = ed.matching_brace()
        if pos is not None:
            cur = ed.textCursor()
            cur.setPosition(pos)
            ed.setTextCursor(cur)

    def filter_lines(self, ed):
        dlg = FilterLinesDialog(self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            pattern = dlg.pattern()
        except ValueError as exc:
            QMessageBox.warning(self, APP_NAME, str(exc))
            return
        keep = dlg.keep.isChecked()
        self._whole_lines(ed, lambda ls: [l for l in ls if bool(pattern.search(l)) == keep], "Filtrer les lignes")

    # ------------------------------------------------------------------ opérations d'édition
    def _whole_lines(self, ed, fn, label):
        if ed.isReadOnly():
            return
        start, end = 0, ed.document().characterCount() - 1
        lines = ed.text().split("\n")
        new = fn(lines)
        if new != lines:
            ed.replace_range(start, end, "\n".join(new), select=False)
            self.say(f"{label} : {len(lines) - len(new)} ligne(s) en moins." if len(new) != len(lines) else label)

    def lines_op(self, ed, fn, label):
        if ed.isReadOnly():
            return
        if ed.transform_lines(fn):
            self.say(label)

    def case(self, ed, fn):
        if ed.isReadOnly():
            return
        cur = ed.textCursor()
        if not cur.hasSelection():
            cur.select(QTextCursor.SelectionType.WordUnderCursor)
        if not cur.hasSelection():
            return
        start, end = cur.selectionStart(), cur.selectionEnd()
        text = cur.selection().toRawText().replace(" ", "\n")
        ed.replace_range(start, end, fn(text))

    def duplicate(self, ed):
        if ed.isReadOnly():
            return
        cur = ed.textCursor()
        if cur.hasSelection():
            text = cur.selection().toRawText().replace(" ", "\n")
            end = cur.selectionEnd()
            c = QTextCursor(ed.document())
            c.setPosition(end)
            c.insertText(text)
            return
        block = cur.block()
        c = QTextCursor(block)
        c.movePosition(QTextCursor.MoveOperation.EndOfBlock)
        c.insertText("\n" + block.text())

    def delete_lines(self, ed):
        if ed.isReadOnly():
            return
        rng = ed.selected_line_range()
        bn = ed.textCursor().blockNumber()
        first, last = rng if rng else (bn, bn)
        doc = ed.document()
        a, b = doc.findBlockByNumber(first), doc.findBlockByNumber(last)
        cur = QTextCursor(doc)
        if b.next().isValid():
            cur.setPosition(a.position())
            cur.setPosition(b.next().position(), QTextCursor.MoveMode.KeepAnchor)
        elif a.previous().isValid():
            prev = a.previous()
            cur.setPosition(prev.position() + prev.length() - 1)
            cur.setPosition(b.position() + b.length() - 1, QTextCursor.MoveMode.KeepAnchor)
        else:
            cur.setPosition(a.position())
            cur.setPosition(b.position() + b.length() - 1, QTextCursor.MoveMode.KeepAnchor)
        cur.removeSelectedText()

    def move_lines(self, ed, up):
        if ed.isReadOnly():
            return
        rng = ed.selected_line_range()
        bn = ed.textCursor().blockNumber()
        first, last = rng if rng else (bn, bn)
        if (up and first == 0) or (not up and last >= ed.blockCount() - 1):
            return
        lo, hi = (first - 1, last) if up else (first, last + 1)
        start, end = ed.lines_span(lo, hi)
        lines = ed.text().split("\n")[lo:hi + 1]
        moved = lines[1:] + lines[:1] if up else lines[-1:] + lines[:-1]
        ed.replace_range(start, end, "\n".join(moved), select=False)
        nf, nl = (first - 1, last - 1) if up else (first + 1, last + 1)
        doc = ed.document()
        cur = QTextCursor(doc.findBlockByNumber(nf))
        if rng:
            endb = doc.findBlockByNumber(nl)
            cur.setPosition(endb.position() + endb.length() - 1, QTextCursor.MoveMode.KeepAnchor)
        ed.setTextCursor(cur)

    def join_lines(self, ed):
        if ed.isReadOnly():
            return
        rng = ed.selected_line_range()
        bn = ed.textCursor().blockNumber()
        first, last = rng if rng and rng[1] > rng[0] else (bn, min(bn + 1, ed.blockCount() - 1))
        if first == last:
            return
        start, end = ed.lines_span(first, last)
        lines = ed.text().split("\n")[first:last + 1]
        joined = " ".join([lines[0].rstrip()] + [l.strip() for l in lines[1:] if l.strip()])
        ed.replace_range(start, end, joined, select=False)

    def comment(self, ed, mode):
        if ed.isReadOnly():
            return
        if COMMENTS.get(ed.lang) is None:
            self.say(f"Pas de commentaire en {LANGS[ed.lang][0]}.")
            return
        ed.transform_lines(lambda ls: comment_lines(ls, ed.lang, mode), whole_if_none=False)

    def clean_special(self, ed):
        if ed.isReadOnly():
            return
        start, end, text, _sel = self._target(ed)
        new, count = clean_special(text)
        if count:
            ed.replace_range(start, end, new, select=_sel)
        self.say(f"{count} caractère(s) invisible(s) remplacé(s)." if count else "Aucun caractère invisible trouvé.")

    def clean_typo(self, ed):
        """Texte copié d'Outlook, Teams, Word… : – — ‑ − → -, ’ → ', “ ” → ", espaces spéciales → espace."""
        if ed.isReadOnly():
            return
        start, end, text, _sel = self._target(ed)
        new, count = to_plain_typo(text)
        if count:
            ed.replace_range(start, end, new, select=_sel)
        self.say(f"{count} caractère(s) typographique(s) remplacé(s) par leur version clavier." if count
                 else "Aucun tiret, apostrophe ou guillemet typographique trouvé.")

    def clear_bookmarks(self, ed):
        ed.bookmarks = []
        ed.gutter.update()

    def bookmark_op(self, ed, op):
        marked = set(ed.bookmark_lines())
        if op == "invert":
            ed.bookmarks = [QTextCursor(ed.document().findBlockByNumber(i)) for i in range(ed.blockCount())
                            if i not in marked]
            ed.gutter.update()
            return
        if not marked:
            self.say("Aucun marque-page.")
            return
        lines = ed.text().split("\n")
        if op in ("copy", "cut"):
            QApplication.clipboard().setText("\n".join(lines[i] for i in sorted(marked)))
            if op == "copy":
                self.say(f"{len(marked)} ligne(s) marquée(s) copiée(s).")
                return
        if ed.isReadOnly():
            return
        keep = op == "keep"
        new = [l for i, l in enumerate(lines) if (i in marked) == keep]
        ed.replace_range(0, ed.document().characterCount() - 1, "\n".join(new), select=False)
        ed.bookmarks = []
        ed.gutter.update()
        self.say(f"{len(lines) - len(new)} ligne(s) supprimée(s).")

    def column_editor(self, ed):
        if ed.isReadOnly():
            return
        if ed.block_sel:
            l1, c1, l2, c2 = ed.block_sel
            line, col, count = min(l1, l2), min(c1, c2), abs(l2 - l1) + 1
        else:
            line, col = ed._cursor_lc()
            count = ed.blockCount() - line
        dlg = ColumnEditorDialog(self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        ed.block_sel = None
        ed.column_paste(dlg.values(count), line, col)
        ed.refresh_extras()

    # ------------------------------------------------------------------ outils
    def _target(self, ed):
        cur = ed.textCursor()
        if cur.hasSelection():
            return (cur.selectionStart(), cur.selectionEnd(),
                    cur.selection().toRawText().replace(" ", "\n"), True)
        return 0, ed.document().characterCount() - 1, ed.text(), False

    def json_tool(self, ed, action):
        start, end, text, has_sel = self._target(ed)
        indent = {"2": "  ", "4": "    ", "tab": "\t"}.get(pref("json_indent"), "    ")
        try:
            if action == "check":
                json_parse(text)
                QMessageBox.information(self, APP_NAME, "JSON valide ✓")
                return
            new = json_minify(text) if action == "minify" else json_format(text, indent, action == "sort")
        except JsonError as exc:
            line, col = line_col(text, exc.pos)
            pos = start + PosMap(text).to_doc(exc.pos)
            cur = ed.textCursor()
            cur.setPosition(min(pos, ed.document().characterCount() - 1))
            ed.setTextCursor(cur)
            ed.centerCursor()
            QMessageBox.warning(self, APP_NAME, f"JSON invalide : {exc}\n(ligne {line}, colonne {col})")
            return
        if ed.isReadOnly():
            self.new_tab_with(new, "JSON formaté", "json")
            return
        ed.replace_range(start, end, new, select=has_sel)
        if not has_sel:
            if ed.lang != "json":
                ed.set_language("json", forced=False)
            ed.moveCursor(QTextCursor.MoveOperation.Start)
        self.say({"minify": "JSON compacté.", "sort": "JSON formaté (clés triées)."}.get(action, "JSON formaté."))

    def mime(self, ed, fn):
        start, end, text, has_sel = self._target(ed)
        try:
            new = fn(text)
        except ValueError as exc:
            QMessageBox.warning(self, APP_NAME, str(exc).capitalize())
            return
        if ed.isReadOnly():
            self.new_tab_with(new, "résultat")
            return
        ed.replace_range(start, end, new, select=has_sel)

    def mime_bytes(self, ed, fn, label):
        start, end, text, has_sel = self._target(ed)
        try:
            data = fn(text)
        except ValueError as exc:
            QMessageBox.warning(self, APP_NAME, f"{label} invalide : {exc}")
            return
        result = bytes_to_text(data)
        if result is None:
            answer = QMessageBox.question(
                self, APP_NAME, f"Le résultat n'est pas du texte ({len(data)} octets : image, binaire…).\n"
                "L'enregistrer dans un fichier ?")
            if answer == QMessageBox.StandardButton.Yes:
                path, _ = QFileDialog.getSaveFileName(self, "Enregistrer le résultat",
                                                      conf().value("last_dir", os.path.expanduser("~")))
                if path:
                    with open(path, "wb") as fh:
                        fh.write(data)
                    self.say(f"Enregistré : {path}")
            return
        if ed.isReadOnly():
            self.new_tab_with(result, "résultat")
            return
        ed.replace_range(start, end, result, select=has_sel)

    def decode_jwt(self, ed):
        _s, _e, text, _sel = self._target(ed)
        try:
            pretty = jwt_decode(text)
        except ValueError as exc:
            QMessageBox.warning(self, APP_NAME, str(exc).capitalize())
            return
        self.new_tab_with(pretty, "JWT décodé", "json").document().setModified(False)

    def compare_dialog(self, ed):
        others = [e for e in self.editors() if e is not ed]
        if not others:
            self.say("Ouvre un deuxième document pour comparer.")
            return
        names = [e.path or e.display_name() for e in others]
        name, ok = QInputDialog.getItem(self, "Comparer", f"Comparer « {ed.display_name()} » avec :", names, 0, False)
        if ok:
            other = others[names.index(name)]
            self.show_compare(ed.display_name(), ed.content(), other.display_name(), other.content(), ed.lang)

    def show_compare(self, name_a, text_a, name_b, text_b, lang="text"):
        win = CompareWindow(self, name_a, text_a, name_b, text_b, lang)
        self.compare_windows = [w for w in self.compare_windows if w.isVisible()] + [win]
        win.show()
        win.jump(1)

    def toggle_json_panel(self):
        visible = not self.json_panel.isVisible()
        self.json_panel.setVisible(visible)
        if visible:
            self.json_panel.refresh()

    def editor_menu(self, ed, global_pos, local_pos):
        menu = QMenu(self)
        a = self.a
        for k in ("undo", "redo", None, "cut", "copy", "paste", "selectall"):
            menu.addSeparator() if k is None else menu.addAction(a[k])
        url = ed.url_at(local_pos)
        if url:
            menu.addSeparator()
            menu.addAction(f"Copier le lien ({url[:50]}{'…' if len(url) > 50 else ''})", lambda: self._clip(url))
        menu.addSeparator()
        for k in ("comment", "upper", "lower"):
            menu.addAction(a[k])
        menu.addSeparator()
        for k in ("b64", "b64np", "b64d"):
            menu.addAction(a[k])
        menu.addSeparator()
        if ed.textCursor().hasSelection():
            menu.addAction(a["regexgen"])
        menu.addAction(a["regex"])
        if ed.lang == "json":
            menu.addSeparator()
            menu.addAction(a["json_fmt"])
            menu.addAction(a["json_min"])
        menu.exec(global_pos)

    def about(self):
        problems = controle_reseau()
        state = "actif ✓ — aucun module réseau chargé" if not problems and _VERROU["actif"] else \
            ("actif" if _VERROU["actif"] else "inactif (mode test)")
        import PySide6
        home = os.path.expanduser("~")
        prive = data_dir()
        prive = "~" + prive[len(home):] if prive.startswith(home + os.sep) else prive
        QMessageBox.about(self, APP_NAME, f"<b>{APP_NAME}</b> — version {VERSION} du {VERSION_DATE}<br>"
                                          f"Éditeur de texte façon Notepad++.<br><br>"
                                          f"Python {sys.version.split()[0]} · PySide6 {PySide6.__version__}<br>"
                                          f"Verrou anti-réseau : {state}<br>"
                                          f"Dossier privé : {prive.replace('&', '&amp;').replace('<', '&lt;')}")

    # ------------------------------------------------------------------ session
    def save_session(self):
        folder = data_dir("session")
        tabs, keep = [], set()
        for ed in self.editors():
            entry = {"path": ed.path, "untitled": ed.untitled, "encoding": ed.encoding, "eol": ed.eol,
                     "lang": ed.lang if ed.lang_forced else "", "jinja": ed.jinja,
                     "cursor": ed.textCursor().position(), "scroll": ed.verticalScrollBar().value(),
                     "modified": ed.document().isModified(), "readonly": ed.isReadOnly(), "tail": ed.tail,
                     "buffer": ""}
            if ed.document().isModified() or (not ed.path and not ed.document().isEmpty()):
                name = f"{ed.session_id}.txt"
                with open(os.path.join(folder, name), "w", encoding="utf-8", newline="") as fh:
                    fh.write(ed.content())
                entry["buffer"] = name
                keep.add(name)
            if ed.path or entry["buffer"]:
                tabs.append(entry)
        for name in os.listdir(folder):
            if name.endswith(".txt") and name not in keep:
                try:
                    os.remove(os.path.join(folder, name))
                except OSError:
                    pass
        data = {"tabs": tabs, "current": self.tabs.currentIndex()}
        target = os.path.join(data_dir(), "session.json")
        with open(target + ".tmp", "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=1)
        os.replace(target + ".tmp", target)
        self._session_dirty = False

    def _autosave_session(self):
        if self._session_dirty and pref("session"):
            try:
                self.save_session()
            except OSError as exc:
                self.say(f"Session non enregistrée : {exc.strerror}")

    def restore_session(self):
        try:
            with open(os.path.join(data_dir(), "session.json"), "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return 0
        folder = data_dir("session")
        restored = 0
        for entry in data.get("tabs", []):
            try:
                ed = self._restore_tab(entry, folder)
            except (OSError, ValueError, KeyError, TypeError):
                ed = None
            restored += ed is not None
        cur = data.get("current", 0)
        if isinstance(cur, int) and 0 <= cur < self.tabs.count():
            self.tabs.setCurrentIndex(cur)
        return restored

    def _restore_tab(self, entry, folder):
        buffer = entry.get("buffer") or ""
        path = entry.get("path") or ""
        if buffer and os.path.isfile(os.path.join(folder, buffer)):
            with open(os.path.join(folder, buffer), "r", encoding="utf-8", newline="") as fh:
                text = fh.read()
            ed = self.new_editor()
            ed.path = path
            ed.untitled = entry.get("untitled", "") if not path else ""
            m = re.fullmatch(r"nouveau (\d+)", ed.untitled)
            if m:
                self.untitled_used.add(int(m.group(1)))
            if not path and not ed.untitled:
                ed.untitled = self._next_untitled()
            ed.encoding = entry.get("encoding", "utf-8") if entry.get("encoding") in ENCODINGS else "utf-8"
            ed.load_text(text, entry.get("eol") or pref("new_eol"))
            if entry.get("modified", True) or not path:
                ed.document().setModified(True)        # un brouillon reste « non enregistré »
            if path:
                ed.disk_stamp = file_stamp(path)
                ed.disk_missing = ed.disk_stamp is None
                self._watch(path)
            self.add_tab(ed, focus=False)
        elif path and os.path.isfile(path):
            ed = self.open_path(path, None)
            if ed is None:
                return None
        else:
            return None
        lang = entry.get("lang")
        if lang in LANGS:
            ed.set_language(lang, forced=True, jinja=bool(entry.get("jinja")))
        elif not ed.lang_forced:
            lg, jinja = detect_language(ed.path or ed.untitled, ed.text()[:20000])
            ed.set_language(lg, forced=False, jinja=jinja or bool(entry.get("jinja")))
        if entry.get("tail") and ed.path:
            ed.tail = True
            ed.setReadOnly(True)
        elif entry.get("readonly"):
            ed.setReadOnly(True)
        cur = ed.textCursor()
        cur.setPosition(min(int(entry.get("cursor", 0)), ed.document().characterCount() - 1))
        ed.setTextCursor(cur)
        QTimer.singleShot(0, ed, lambda e=ed, v=int(entry.get("scroll", 0)): e.verticalScrollBar().setValue(v))
        self._update_tab(ed)
        return ed

    # ------------------------------------------------------------------ une seule fenêtre
    def process_requests(self):
        try:
            names = sorted(n for n in os.listdir(self.req_dir) if n.endswith(".json") and not n.startswith("."))
        except OSError:
            return
        for name in names:
            full = os.path.join(self.req_dir, name)
            try:
                with open(full, "r", encoding="utf-8") as fh:
                    paths = json.load(fh).get("paths", [])
            except (OSError, ValueError, AttributeError):
                paths = []
            try:
                os.remove(full)
            except OSError:
                pass
            self.open_files([p for p in paths if isinstance(p, str)])
            if self.isMinimized():
                self.showNormal()
            self.show()
            self.raise_()
            self.activateWindow()

    def closeEvent(self, ev):
        if pref("session"):
            try:
                self.save_session()
            except OSError:
                pass
        else:
            for ed in list(self.editors()):
                if ed.document().isModified() and not self.close_tab(self.tabs.indexOf(ed)):
                    ev.ignore()
                    return
        conf().setValue("geometry", self.saveGeometry())
        if self.find_dialog is not None:
            self.find_dialog.stop_files()
            self.find_dialog.hide()
        if self.regex_dialog is not None:
            self.regex_dialog.hide()
        for win in self.compare_windows:
            win.close()
        ev.accept()


def QCursor_pos():
    from PySide6.QtGui import QCursor
    return QCursor.pos()


def send_request(paths):
    """Une fenêtre est déjà ouverte : on lui confie les fichiers (fichier déposé localement)."""
    folder = data_dir("demandes")
    name = f"{os.getpid()}-{int(time.time() * 1000)}.json"
    tmp = os.path.join(folder, "." + name)
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({"paths": paths}, fh)
    os.replace(tmp, os.path.join(folder, name))


def verifier_pyside():
    """PySide6 6.12 plante avec Python 3.9 à 3.11 (« deallocating None ») : message clair au lieu d'un plantage."""
    import PySide6
    try:
        ver = tuple(int(x) for x in PySide6.__version__.split(".")[:2])
    except ValueError:
        return
    if sys.version_info < (3, 12) and ver >= (6, 12):
        raise SystemExit(f"PySide6 {PySide6.__version__} plante avec Python {sys.version.split()[0]}.\n"
                         "Corrige le venv avec :  pip install \"PySide6-Essentials<6.12\"\n"
                         "(ou recrée-le avec Python 3.12 ou plus récent).")



def main():
    if "--version" in sys.argv[1:]:
        print(f"{APP_NAME} {VERSION} du {VERSION_DATE}")
        return 0
    verifier_pyside()
    installer_verrou()
    QApplication.setOrganizationName(ORG_NAME)
    QApplication.setApplicationName(APP_NAME)
    QApplication.setApplicationVersion(VERSION)
    app = QApplication(sys.argv[:1])
    app.setWindowIcon(glyph_icon("app"))
    paths = [os.path.abspath(a) for a in sys.argv[1:] if not a.startswith("-psn")]
    lock = QLockFile(os.path.join(data_dir(), "instance.lock"))
    lock.setStaleLockTime(0)
    if not lock.tryLock(200):
        send_request(paths)
        return 0
    problems = controle_reseau()
    if problems:
        print("[verrou] arrêt, bibliothèques réseau présentes : " + ", ".join(problems), file=sys.stderr)
        return 3
    win = MainWindow()
    if pref("session"):
        win.restore_session()
    if paths:
        win.open_files(paths)
    if win.tabs.count() == 0:
        win.new_doc()
    win.show()
    check = QTimer(win)
    check.setInterval(60000)
    check.timeout.connect(lambda: controle_reseau() and app.quit())
    check.start()
    try:
        app.styleHints().colorSchemeChanged.connect(lambda *_a: pref("theme") == "auto" and win.apply_theme())
    except AttributeError:
        pass
    code = app.exec()
    lock.unlock()
    return code


if __name__ == "__main__":
    sys.exit(main())
