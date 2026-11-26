#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Barre des tâches façon Windows 11 pour macOS.

* Même environnement que l'explorateur : PySide6-Essentials + bibliothèque standard
  de Python. macOS est appelé directement avec ctypes (aucun module en plus).
* Aucun accès réseau : un verrou (« audit hook » Python, impossible à retirer une fois
  posé) bloque sockets, HTTP et modules réseau, n'autorise qu'une liste fixe de
  commandes Apple locales et refuse toute adresse web.
* Ni droits administrateur, ni autorisation « Accessibilité », « Surveillance de
  l'entrée » ou « Enregistrement de l'écran ».

Lancement :  ~/mac/explorer/venv/bin/python ~/mac/explorer/win_barre.py

Astuce : garde le Dock affiché en bas (sans masquage automatique). La barre se pose
par-dessus et les fenêtres agrandies s'arrêtent au-dessus d'elle.
"""

import contextlib
import ctypes
import math
import os
import re
import subprocess
import sys
import threading
import time
import unicodedata

APP_NAME = "Barre des tâches"
VERSION = "1.2"          # à augmenter à chaque modification
VERSION_DATE = "26/11/2026"
ORG_NAME = "explorateur-maison"
IS_MAC = sys.platform == "darwin"
HERE = os.path.dirname(os.path.abspath(__file__))
HOME = os.path.expanduser("~")


def version_details():
    """Version du script, de Python et de PySide6 (pour comparer avec un collègue)."""
    try:
        import PySide6
        qt = PySide6.__version__
    except ImportError:
        qt = "absent"
    return f"{APP_NAME} {VERSION} du {VERSION_DATE} — Python {sys.version.split()[0]}, PySide6 {qt}"


EMPREINTE = "bc73c4aa04c4b567"          # remplie à la livraison : sert à voir si le fichier a été abîmé en le copiant
REPERES = "3888:7c2ba68a,814da036,b6a3a771,6dfc2cc4,00524c0d,7bd588e9,60cac986,a1db85eb,63f6f98a,d2a185a5,976600d6,9e21a13b,263c8941,eb81ebbf,8c8a077e,89a7503c"            # remplis à la livraison : nombre de lignes et empreinte de chaque tranche de 250 lignes


def _texte_compare(path):
    """Texte du script tel qu'on le compare. Les différences sans effet sur le programme sont gommées :
    fins de ligne Windows, BOM, accents décomposés, espaces en fin de ligne, lignes vides en fin de fichier
    (ce que font souvent un copier-coller ou un éditeur web comme celui de git)."""
    import re as _re
    import unicodedata
    try:
        with open(path, "rb") as fh:
            text = fh.read().decode("utf-8", "replace")
    except OSError:
        return None
    text = unicodedata.normalize("NFC", text.lstrip("\ufeff").replace("\r\n", "\n").replace("\r", "\n"))
    text = "\n".join(line.rstrip(" \t") for line in text.split("\n")).rstrip("\n") + "\n"
    text = _re.sub(r'^EMPREINTE = "[0-9a-f]*"', 'EMPREINTE = ""', text, count=1, flags=_re.M)
    return _re.sub(r'^REPERES = "[0-9a-f:,]*"', 'REPERES = ""', text, count=1, flags=_re.M)


def empreinte_fichier(path):
    """Empreinte d'un script (voir _texte_compare) ; None si illisible."""
    import hashlib
    text = _texte_compare(path)
    return None if text is None else hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def reperes_fichier(path, tranche=250):
    """« 7442:ab12cd34,… » : nombre de lignes puis une empreinte courte par tranche de lignes."""
    import hashlib
    text = _texte_compare(path)
    if text is None:
        return ""
    lines = text.split("\n")[:-1]
    parts = [hashlib.sha256("\n".join(lines[i:i + tranche]).encode("utf-8")).hexdigest()[:8]
             for i in range(0, len(lines), tranche)]
    return f"{len(lines)}:" + ",".join(parts)


def ecart_fichier(path=None, reperes=None, tranche=250):
    """Où le fichier diffère de la livraison, en clair ; "" si on ne peut pas le dire."""
    reperes = REPERES if reperes is None else reperes
    got = reperes_fichier(path or os.path.abspath(__file__), tranche) if ":" in (reperes or "") else ""
    if not got:
        return ""
    (n_ref, ref), (n_got, cur) = reperes.split(":", 1), got.split(":", 1)
    ref, cur = ref.split(","), cur.split(",")
    out = [f"{n_got} lignes au lieu de {n_ref}"] if n_ref != n_got else []
    first = next((i for i, (a, b) in enumerate(zip(ref, cur)) if a != b), None)
    if first is None and len(ref) != len(cur):
        first = min(len(ref), len(cur))
    if first is not None:
        out.append(f"première différence entre les lignes {first * tranche + 1} et {(first + 1) * tranche}")
    return " ; ".join(out)


def fichier_intact():
    """True : tel que livré ; False : modifié ou abîmé pendant la copie ; None : impossible à dire."""
    if not EMPREINTE:
        return None
    got = empreinte_fichier(os.path.abspath(__file__))
    return None if got is None else got == EMPREINTE


def avertir_si_abime():
    if fichier_intact() is False:
        from PySide6.QtWidgets import QMessageBox
        name = os.path.basename(os.path.abspath(__file__))
        ecart = ecart_fichier()
        QMessageBox.warning(None, APP_NAME, f"Le fichier {name} n'est pas tel qu'il a été livré : il a été modifié "
                                            "ou abîmé pendant sa copie (caractères disparus, fichier coupé…)."
                                            + (f"\n\nÉcart repéré : {ecart}." if ecart else "") +
                                            "\n\nCertaines fonctions peuvent mal marcher. Recopie-le en entier "
                                            "depuis la dernière livraison, en vérifiant que la fin du fichier "
                                            "(« sys.exit(main()) ») est bien là.")

# Toujours le chemin complet : un programme du même nom posé ailleurs ne peut pas
# être lancé à la place du vrai.
CMD = {
    "open": "/usr/bin/open",
    "pmset": "/usr/bin/pmset",
    "scutil": "/usr/sbin/scutil",
    "networksetup": "/usr/sbin/networksetup",
    "ps": "/bin/ps",
    "mdfind": "/usr/bin/mdfind",
}

# Tes propres outils, s'ils sont rangés à côté de la barre.
SCRIPTS = {
    "script:explorateur": ("Explorateur de fichiers", ("win_explorer.py", "explor.py", "explorateur.py")),
    "script:annoteur": ("Annoteur", ("annoteur.py", "annoter.py")),
    "script:blocnotes": ("Bloc-notes Pro", ("blocnotespro.py", "blocnotes.py")),
    "script:terminal": ("Terminal Pro", ("terminal_psm.py", "terminal.py")),
}

FINDER = "/System/Library/CoreServices/Finder.app"
MISSION_CONTROL = "/System/Applications/Mission Control.app"
ACTIVITY_MONITOR = "/System/Applications/Utilities/Activity Monitor.app"
SYSTEM_SETTINGS = "/System/Applications/System Settings.app"
TERMINAL = "/System/Applications/Utilities/Terminal.app"
APP_DIRS = ("/Applications", "/Applications/Utilities", "/System/Applications",
            "/System/Applications/Utilities", os.path.join(HOME, "Applications"))


def script_path(key):
    info = SCRIPTS.get(key)
    if not info:
        return ""
    for name in info[1]:
        path = os.path.join(HERE, name)
        if os.path.isfile(path):
            return path
    return ""


_VERSION_RE = re.compile(r'^VERSION\s*=\s*"([^"\n]{1,20})"', re.M)
_DATE_RE = re.compile(r'^VERSION_DATE\s*=\s*"([^"\n]{1,20})"', re.M)
_EMPREINTE_RE = re.compile(r'^EMPREINTE = "([0-9a-f]*)"', re.M)


def script_version(path):
    """(version, date) lues dans l'en-tête du script ; ("", "") pour une version sans numéro."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            head = f.read(20000)
    except OSError:
        return "", ""
    v, d = _VERSION_RE.search(head), _DATE_RE.search(head)
    return (v.group(1) if v else ""), (d.group(1) if d else "")


def script_intact(path):
    """True / False (abîmé ou modifié) / None (pas d'empreinte dans le fichier)."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            m = _EMPREINTE_RE.search(f.read(30000))
    except OSError:
        return None
    if not m or not m.group(1):
        return None
    return empreinte_fichier(path) == m.group(1)


def versions_text():
    """Une ligne par outil : utile pour voir d'un coup ce qui est à mettre à jour ou à retélécharger."""
    abime = " — fichier abîmé ou modifié : à retélécharger"
    lines = [f"{APP_NAME} {VERSION} du {VERSION_DATE}" + (abime if fichier_intact() is False else "")]
    for key, (name, _files) in SCRIPTS.items():
        path = script_path(key)
        if not path:
            continue
        ver, date = script_version(path)
        line = (f"{name} {ver}" + (f" du {date}" if date else "") if ver
                else f"{name} : ancienne version, à mettre à jour")
        if ver and script_intact(path) is False:
            line += abime
        lines.append(line)
    return "\n".join(lines)


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
_LIBS_OK = frozenset({
    "/usr/lib/libobjc.A.dylib",
    "/usr/lib/libSystem.B.dylib",
    "/System/Library/Frameworks/CoreAudio.framework/CoreAudio",
})
# Bibliothèques natives qui ne doivent jamais être chargées dans la barre.
_LIBS_FORBIDDEN = ("QtNetwork", "Qt6Network", "qpdf", "QtPdf", "Qt6Pdf", "QtWebEngine", "Qt6WebEngine",
                   "QtWebSockets", "Qt6WebSockets", "QtHttpServer", "_ssl.", "_socket.")
SETTINGS_URL = "x-apple.systempreferences:"
_PANE_RE = re.compile(r"x-apple\.systempreferences:[A-Za-z0-9._-]{1,80}")
_URL_SHORTCUTS = (".webloc", ".url", ".inetloc", ".fileloc", ".mailloc")
_SCRIPTS_OK = frozenset(os.path.realpath(p) for p in (script_path(k) for k in SCRIPTS) if p)
_VERROU = {"actif": False}


def module_reseau(name):
    """Vrai pour tout module capable de parler au réseau."""
    if not isinstance(name, str):
        return False
    parts = name.split(".")
    if parts[0] in _NET_MODULES or ".".join(parts[:2]) in _NET_SUBMODULES:
        return True
    return parts[0] == "PySide6" and len(parts) > 1 and parts[1] in _QT_NET


def _arg_open_ok(arg):
    if arg in ("-a", "-n", "-R", "-g"):
        return True
    if arg.startswith(SETTINGS_URL):
        return bool(_PANE_RE.fullmatch(arg))
    return (arg.startswith("/") and "\x00" not in arg
            and not arg.lower().rstrip("/").endswith(_URL_SHORTCUTS))


def commande_autorisee(argv):
    """Liste blanche : seules ces commandes Apple locales peuvent être lancées."""
    if isinstance(argv, (str, bytes)) or not argv:
        return False
    try:
        argv = [os.fsdecode(a) for a in argv]
    except TypeError:
        return False
    prog, rest = argv[0], argv[1:]
    if prog == CMD["open"]:
        # Applications, fichiers et dossiers locaux, ou un panneau des Réglages Système.
        # Jamais d'adresse web : rien ne peut sortir par le navigateur.
        return bool(rest) and all(_arg_open_ok(a) for a in rest) and any(not a.startswith("-") for a in rest)
    if prog == sys.executable:
        return (1 <= len(rest) <= 2 and os.path.realpath(rest[0]) in _SCRIPTS_OK
                and all(a.startswith("/") and "\x00" not in a for a in rest[1:]))
    if prog == CMD["pmset"]:
        return rest in (["-g", "batt"], ["sleepnow"])
    if prog == CMD["scutil"]:
        return rest == ["--nwi"]
    if prog == CMD["networksetup"]:
        return rest == ["-listallhardwareports"]
    if prog == CMD["ps"]:
        return len(rest) == 4 and rest[:3] == ["-o", "command=", "-p"] and rest[3].isdigit()
    if prog == CMD["mdfind"]:
        return (len(rest) == 4 and rest[0] == "-onlyin" and rest[1] == HOME and rest[2] == "-name"
                and 0 < len(rest[3]) <= 200 and "\x00" not in rest[3])
    return False


def installer_verrou():
    """Pose le verrou. Python ne permet pas de le retirer ensuite."""
    if _VERROU["actif"]:
        return
    already = sorted(m for m in list(sys.modules) if module_reseau(m))
    if already:
        raise SystemExit("[verrou] modules réseau déjà chargés : " + ", ".join(already))
    devnull = os.devnull
    write_flags = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC

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
            argv = args[1]
            if not commande_autorisee(argv) or os.fsdecode(args[0]) != os.fsdecode(argv[0]):
                raise PermissionError("[verrou] commande refusée")
        elif event == "ctypes.dlopen":
            if args[0] is not None and os.fsdecode(args[0]) not in _LIBS_OK:
                raise PermissionError(f"[verrou] bibliothèque refusée : {args[0]!r}")
        elif event == "open":
            path, mode, flags = args
            writing = ((isinstance(mode, str) and any(c in mode for c in "wax+"))
                       or (mode is None and isinstance(flags, int) and flags & write_flags))
            if writing and not isinstance(path, int) and os.fsdecode(path) != devnull:
                # Python n'écrit rien sur le disque ; les réglages passent par Qt.
                raise PermissionError(f"[verrou] écriture refusée : {path!r}")

    sys.addaudithook(hook)
    _VERROU["actif"] = True


def bibliotheques_chargees():
    """Bibliothèques natives présentes dans le processus."""
    if sys.platform.startswith("linux"):
        try:
            with open("/proc/self/maps", "r", encoding="utf-8", errors="replace") as fh:
                return sorted({line.split()[-1] for line in fh if "/" in line})
        except OSError:
            return []
    if IS_MAC:
        try:
            libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
            libc._dyld_image_count.restype = ctypes.c_uint32
            libc._dyld_get_image_name.restype = ctypes.c_char_p
            libc._dyld_get_image_name.argtypes = [ctypes.c_uint32]
            names = (libc._dyld_get_image_name(i) for i in range(libc._dyld_image_count()))
            return sorted({n.decode("utf-8", "replace") for n in names if n})
        except (OSError, AttributeError):
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
# Commandes locales
# ======================================================================================

_CHILDREN = []


def run_cmd(argv, timeout=3):
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                              stdin=subprocess.DEVNULL).stdout
    except (OSError, subprocess.SubprocessError, ValueError):
        return ""


def spawn(argv, new_session=False):
    """Lance un programme sans attendre (la liste blanche du verrou s'applique)."""
    env = dict(os.environ)
    env.pop("QT_MAC_DISABLE_FOREGROUND_APPLICATION_TRANSFORM", None)
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, close_fds=True, env=env,
                                start_new_session=new_session, cwd=HERE)
    except (OSError, ValueError) as exc:
        print(f"[barre] lancement impossible : {exc}", file=sys.stderr)
        return None
    _CHILDREN.append(proc)
    return proc


def reap_children():
    _CHILDREN[:] = [p for p in _CHILDREN if p.poll() is None]


def open_app(path, new=False):
    return spawn([CMD["open"]] + (["-n"] if new else []) + ["-a", path])


def open_path(path):
    """Ouvre un fichier avec son application, ou un dossier dans l'explorateur maison."""
    if os.path.isdir(path) and not path.endswith(".app") and script_path("script:explorateur"):
        return run_script("script:explorateur", [path])
    return spawn([CMD["open"], path])


def reveal_file(path):
    folder = os.path.dirname(path.rstrip("/"))
    if script_path("script:explorateur"):
        return run_script("script:explorateur", [folder])
    return spawn([CMD["open"], "-R", path])


def open_pane(pane):
    return spawn([CMD["open"], SETTINGS_URL + pane])


def run_script(key, extra=()):
    path = script_path(key)
    if not path:
        return None
    return spawn([sys.executable, path] + list(extra), new_session=True)


def parse_pmset(text):
    """« 85%; discharging » → {'percent': 85, 'charging': False, 'plugged': False}."""
    if not text or "InternalBattery" not in text:
        return None
    m = re.search(r"(\d{1,3})%;\s*([^;\n]+)", text)
    if not m:
        return None
    state = m.group(2).strip().lower()
    plugged = "'AC Power'" in text
    return {"percent": max(0, min(100, int(m.group(1)))), "charging": state == "charging",
            "plugged": plugged or state in ("charged", "finishing charge", "ac attached")}


def parse_hardware_ports(text):
    """Appareils Wi-Fi d'après « networksetup -listallhardwareports »."""
    wifi, port = set(), ""
    for line in (text or "").splitlines():
        if line.startswith("Hardware Port:"):
            port = line.split(":", 1)[1].strip()
        elif line.startswith("Device:") and port in ("Wi-Fi", "AirPort"):
            wifi.add(line.split(":", 1)[1].strip())
    return wifi


def parse_nwi(text, wifi_devices):
    """État du réseau d'après « scutil --nwi » : wifi, ethernet ou offline."""
    m = re.search(r"Network interfaces:\s*(.*)", text or "")
    ifaces = m.group(1).split() if m else []
    if not ifaces:
        return "offline"
    if any(i in wifi_devices for i in ifaces):
        return "wifi"
    return "ethernet"


_WIFI_DEVICES = []


def read_battery():
    if not IS_MAC:
        return None
    return parse_pmset(run_cmd([CMD["pmset"], "-g", "batt"]))


def read_network():
    if not IS_MAC:
        return "ethernet"
    if not _WIFI_DEVICES:
        _WIFI_DEVICES.append(parse_hardware_ports(run_cmd([CMD["networksetup"], "-listallhardwareports"])))
    return parse_nwi(run_cmd([CMD["scutil"], "--nwi"]), _WIFI_DEVICES[0])


def detect_script(pid):
    """Reconnaît l'explorateur ou l'annoteur parmi les processus Python."""
    out = run_cmd([CMD["ps"], "-o", "command=", "-p", str(int(pid))], timeout=1)
    tokens = out.split()
    for key in SCRIPTS:
        path = script_path(key)
        if not path:
            continue
        base = os.path.basename(path)
        if any(t == path or t == base or t.endswith("/" + base) for t in tokens):
            return key
    return ""


def search_documents(query):
    """Recherche locale de fichiers par leur nom (index Spotlight du Mac)."""
    if not IS_MAC or not query:
        return []
    out = run_cmd([CMD["mdfind"], "-onlyin", HOME, "-name", query], timeout=2)
    found = []
    for line in out.splitlines():
        if not line.startswith(HOME + "/"):
            continue
        rel = line[len(HOME) + 1:]
        if rel.startswith("Library/") or any(part.startswith(".") for part in rel.split("/")):
            continue
        found.append(line)
        if len(found) >= 8:
            break
    return found


def fold(text):
    """Minuscules sans accents, pour chercher « reglages » et trouver « Réglages »."""
    norm = unicodedata.normalize("NFKD", text or "")
    return "".join(c for c in norm if not unicodedata.combining(c)).casefold()


def norm_app(path):
    return os.path.realpath(path.rstrip("/"))


# ======================================================================================
# macOS en direct (ctypes)
# ======================================================================================

class RunningApp:
    __slots__ = ("pid", "name", "path", "bundle_id", "hidden")

    def __init__(self, pid, name, path="", bundle_id="", hidden=False):
        self.pid, self.name, self.path, self.bundle_id, self.hidden = pid, name, path, bundle_id, hidden


class Backend:
    """Version neutre (Linux/Windows, ou si macOS refuse) : la barre lance, sans plus."""
    native = False

    def setup_app(self):
        pass

    def configure_window(self, widget, role):
        pass

    def make_key(self, widget):
        widget.raise_()
        widget.activateWindow()

    def is_key(self, widget):
        return widget.isActiveWindow()

    def activate_self(self):
        pass

    def mouse_buttons(self):
        from PySide6.QtWidgets import QApplication
        return int(QApplication.mouseButtons().value)

    def running_apps(self):
        return []

    def front_pid(self):
        return 0

    def hide_app(self, pid):
        pass

    def unhide_app(self, pid):
        pass

    def activate_pid(self, pid):
        pass

    def quit_app(self, pid):
        pass

    def display_name(self, path):
        name = os.path.basename(path.rstrip("/"))
        return name[:-4] if name.endswith(".app") else name

    def volume(self):
        return None

    def set_volume(self, level):
        pass

    def set_muted(self, muted):
        pass


class ObjC:
    """Quelques appels directs à macOS, sans module externe."""

    def __init__(self):
        lib = ctypes.CDLL("/usr/lib/libobjc.A.dylib")
        lib.objc_getClass.restype = ctypes.c_void_p
        lib.objc_getClass.argtypes = [ctypes.c_char_p]
        lib.sel_registerName.restype = ctypes.c_void_p
        lib.sel_registerName.argtypes = [ctypes.c_char_p]
        for fn in (lib.class_getInstanceMethod, lib.class_getClassMethod):
            fn.restype = ctypes.c_void_p
            fn.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        lib.objc_autoreleasePoolPush.restype = ctypes.c_void_p
        lib.objc_autoreleasePoolPush.argtypes = []
        lib.objc_autoreleasePoolPop.restype = None
        lib.objc_autoreleasePoolPop.argtypes = [ctypes.c_void_p]
        self.lib = lib
        self._msg = ctypes.cast(lib.objc_msgSend, ctypes.c_void_p).value
        self._protos, self._sels, self._classes = {}, {}, {}

    def cls(self, name):
        found = self._classes.get(name)
        if found is None:
            found = self._classes[name] = self.lib.objc_getClass(name.encode()) or 0
        return found

    def sel(self, name):
        found = self._sels.get(name)
        if found is None:
            found = self._sels[name] = self.lib.sel_registerName(name.encode())
        return found

    def has(self, class_name, selector):
        klass = self.cls(class_name)
        if not klass:
            return False
        if selector.startswith("+"):
            return bool(self.lib.class_getClassMethod(klass, self.sel(selector[1:])))
        return bool(self.lib.class_getInstanceMethod(klass, self.sel(selector)))

    def send(self, obj, selector, *args, restype=ctypes.c_void_p, argtypes=()):
        if not obj:
            return None
        key = (restype, tuple(argtypes))
        fn = self._protos.get(key)
        if fn is None:
            fn = ctypes.CFUNCTYPE(restype, ctypes.c_void_p, ctypes.c_void_p, *argtypes)(self._msg)
            self._protos[key] = fn
        return fn(obj, self.sel(selector), *args)

    def text(self, nsstring):
        if not nsstring:
            return ""
        raw = self.send(nsstring, "UTF8String", restype=ctypes.c_char_p)
        return raw.decode("utf-8", "replace") if raw else ""

    def nsstring(self, text):
        return self.send(self.cls("NSString"), "stringWithUTF8String:", text.encode("utf-8"),
                         argtypes=(ctypes.c_char_p,))

    @contextlib.contextmanager
    def pool(self):
        token = self.lib.objc_autoreleasePoolPush()
        try:
            yield
        finally:
            self.lib.objc_autoreleasePoolPop(token)


class _AudioAddress(ctypes.Structure):
    _fields_ = [("selector", ctypes.c_uint32), ("scope", ctypes.c_uint32), ("element", ctypes.c_uint32)]


def _fourcc(code):
    return int.from_bytes(code.encode("ascii"), "big")


class Audio:
    """Volume de la sortie son par défaut (CoreAudio, sans script ni autorisation)."""

    def __init__(self):
        ca = ctypes.CDLL("/System/Library/Frameworks/CoreAudio.framework/CoreAudio")
        addr = ctypes.POINTER(_AudioAddress)
        self._get = ca.AudioObjectGetPropertyData
        self._get.argtypes = [ctypes.c_uint32, addr, ctypes.c_uint32, ctypes.c_void_p,
                              ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p]
        self._get.restype = ctypes.c_int32
        self._set = ca.AudioObjectSetPropertyData
        self._set.argtypes = [ctypes.c_uint32, addr, ctypes.c_uint32, ctypes.c_void_p,
                              ctypes.c_uint32, ctypes.c_void_p]
        self._set.restype = ctypes.c_int32
        self._has = ca.AudioObjectHasProperty
        self._has.argtypes = [ctypes.c_uint32, addr]
        self._has.restype = ctypes.c_ubyte

    def _read(self, obj, address, value):
        size = ctypes.c_uint32(ctypes.sizeof(value))
        return self._get(obj, ctypes.byref(address), 0, None, ctypes.byref(size), ctypes.byref(value)) == 0

    def _device(self):
        dev = ctypes.c_uint32(0)
        address = _AudioAddress(_fourcc("dOut"), _fourcc("glob"), 0)
        return dev.value if self._read(1, address, dev) else 0

    def _addr(self, what):
        return _AudioAddress(_fourcc(what), _fourcc("outp"), 0)

    def get(self):
        dev = self._device()
        vol_addr, mute_addr = self._addr("vmvc"), self._addr("mute")
        if not dev or not self._has(dev, ctypes.byref(vol_addr)):
            return None
        vol, muted = ctypes.c_float(0.0), ctypes.c_uint32(0)
        if not self._read(dev, vol_addr, vol):
            return None
        if self._has(dev, ctypes.byref(mute_addr)):
            self._read(dev, mute_addr, muted)
        return max(0.0, min(1.0, vol.value)), bool(muted.value)

    def set_level(self, level):
        dev = self._device()
        if dev:
            val = ctypes.c_float(max(0.0, min(1.0, float(level))))
            self._set(dev, ctypes.byref(self._addr("vmvc")), 0, None, ctypes.sizeof(val), ctypes.byref(val))

    def set_muted(self, muted):
        dev = self._device()
        address = self._addr("mute")
        if dev and self._has(dev, ctypes.byref(address)):
            val = ctypes.c_uint32(1 if muted else 0)
            self._set(dev, ctypes.byref(address), 0, None, ctypes.sizeof(val), ctypes.byref(val))


_REQUIRED = (
    ("NSWorkspace", "+sharedWorkspace"), ("NSWorkspace", "runningApplications"),
    ("NSWorkspace", "frontmostApplication"),
    ("NSRunningApplication", "+runningApplicationWithProcessIdentifier:"),
    ("NSRunningApplication", "activationPolicy"), ("NSRunningApplication", "processIdentifier"),
    ("NSRunningApplication", "localizedName"), ("NSRunningApplication", "bundleIdentifier"),
    ("NSRunningApplication", "bundleURL"), ("NSRunningApplication", "isHidden"),
    ("NSRunningApplication", "isTerminated"), ("NSRunningApplication", "hide"),
    ("NSRunningApplication", "unhide"), ("NSRunningApplication", "terminate"),
    ("NSRunningApplication", "activateWithOptions:"),
    ("NSArray", "count"), ("NSArray", "objectAtIndex:"), ("NSURL", "path"),
    ("NSString", "+stringWithUTF8String:"), ("NSString", "UTF8String"),
    ("NSApplication", "+sharedApplication"), ("NSApplication", "setActivationPolicy:"),
    ("NSApplication", "activateIgnoringOtherApps:"), ("NSEvent", "+pressedMouseButtons"),
    ("NSFileManager", "+defaultManager"), ("NSFileManager", "displayNameAtPath:"),
    ("NSView", "window"), ("NSWindow", "setLevel:"), ("NSWindow", "setCollectionBehavior:"),
    ("NSWindow", "styleMask"), ("NSWindow", "setStyleMask:"), ("NSWindow", "setHidesOnDeactivate:"),
    ("NSWindow", "setCanHide:"), ("NSWindow", "makeKeyAndOrderFront:"),
    ("NSWindow", "makeFirstResponder:"), ("NSWindow", "isKeyWindow"),
    ("NSObject", "isKindOfClass:"), ("NSObject", "respondsToSelector:"),
)

_LEVELS = {"bar": 25, "flyout": 101, "tip": 102, "dialog": 3}
_ALL_SPACES, _STATIONARY, _IGNORES_CYCLE = 1 << 0, 1 << 4, 1 << 6
_NONACTIVATING = 1 << 7
_POLICY_REGULAR, _POLICY_ACCESSORY = 0, 1
_ACTIVATE_ALL_WINDOWS, _ACTIVATE_IGNORING_OTHERS = 1, 2


class MacBackend(Backend):
    native = True

    def __init__(self):
        self.o = ObjC()
        missing = [f"{c} {s}" for c, s in _REQUIRED if not self.o.has(c, s)]
        if missing or not self.o.cls("NSPanel"):
            raise RuntimeError("fonctions macOS absentes : " + ", ".join(missing))
        o = self.o
        self.ws = o.send(o.cls("NSWorkspace"), "sharedWorkspace")
        self.nsapp = o.send(o.cls("NSApplication"), "sharedApplication")
        self.own_pid = os.getpid()
        try:
            self.audio = Audio()
        except (OSError, AttributeError):
            self.audio = None

    # --- l'application elle-même ---
    def setup_app(self):
        # Ni icône dans le Dock, ni entrée dans Cmd+Tab : comme le Dock ou Spotlight.
        self.o.send(self.nsapp, "setActivationPolicy:", _POLICY_ACCESSORY,
                    restype=ctypes.c_bool, argtypes=(ctypes.c_long,))

    def activate_self(self):
        self.o.send(self.nsapp, "activateIgnoringOtherApps:", True, restype=None, argtypes=(ctypes.c_bool,))

    def _window(self, widget):
        view = int(widget.winId())
        return view, (self.o.send(view, "window") if view else None)

    def configure_window(self, widget, role):
        o = self.o
        with o.pool():
            _view, win = self._window(widget)
            if not win:
                return
            o.send(win, "setLevel:", _LEVELS.get(role, 3), restype=None, argtypes=(ctypes.c_long,))
            behavior = _ALL_SPACES | _IGNORES_CYCLE | (_STATIONARY if role == "bar" else 0)
            o.send(win, "setCollectionBehavior:", behavior, restype=None, argtypes=(ctypes.c_ulong,))
            o.send(win, "setHidesOnDeactivate:", False, restype=None, argtypes=(ctypes.c_bool,))
            o.send(win, "setCanHide:", False, restype=None, argtypes=(ctypes.c_bool,))
            is_panel = o.send(win, "isKindOfClass:", o.cls("NSPanel"), restype=ctypes.c_bool,
                              argtypes=(ctypes.c_void_p,))
            if role in ("bar", "flyout") and is_panel:
                # Panneau « non activant » : cliquer dessus ne vole pas le focus.
                mask = o.send(win, "styleMask", restype=ctypes.c_ulong) or 0
                o.send(win, "setStyleMask:", mask | _NONACTIVATING, restype=None, argtypes=(ctypes.c_ulong,))
                if o.send(win, "respondsToSelector:", o.sel("_setPreventsActivation:"),
                          restype=ctypes.c_bool, argtypes=(ctypes.c_void_p,)):
                    o.send(win, "_setPreventsActivation:", True, restype=None, argtypes=(ctypes.c_bool,))

    def make_key(self, widget):
        o = self.o
        with o.pool():
            view, win = self._window(widget)
            if win:
                o.send(win, "makeKeyAndOrderFront:", None, restype=None, argtypes=(ctypes.c_void_p,))
                o.send(win, "makeFirstResponder:", view, restype=ctypes.c_bool, argtypes=(ctypes.c_void_p,))

    def is_key(self, widget):
        with self.o.pool():
            _view, win = self._window(widget)
            return bool(win and self.o.send(win, "isKeyWindow", restype=ctypes.c_bool))

    def mouse_buttons(self):
        return int(self.o.send(self.o.cls("NSEvent"), "pressedMouseButtons", restype=ctypes.c_ulong) or 0)

    # --- les autres applications ---
    def running_apps(self):
        o, out = self.o, []
        with o.pool():
            arr = o.send(self.ws, "runningApplications")
            count = o.send(arr, "count", restype=ctypes.c_ulong) or 0
            for i in range(count):
                app = o.send(arr, "objectAtIndex:", i, argtypes=(ctypes.c_ulong,))
                if o.send(app, "activationPolicy", restype=ctypes.c_long) != _POLICY_REGULAR:
                    continue
                pid = o.send(app, "processIdentifier", restype=ctypes.c_int)
                if not pid or pid == self.own_pid or o.send(app, "isTerminated", restype=ctypes.c_bool):
                    continue
                url = o.send(app, "bundleURL")
                out.append(RunningApp(
                    pid, o.text(o.send(app, "localizedName")),
                    o.text(o.send(url, "path")) if url else "",
                    o.text(o.send(app, "bundleIdentifier")),
                    bool(o.send(app, "isHidden", restype=ctypes.c_bool))))
        return out

    def front_pid(self):
        with self.o.pool():
            app = self.o.send(self.ws, "frontmostApplication")
            return int(self.o.send(app, "processIdentifier", restype=ctypes.c_int) or 0) if app else 0

    def _app(self, pid):
        return self.o.send(self.o.cls("NSRunningApplication"), "runningApplicationWithProcessIdentifier:",
                           int(pid), argtypes=(ctypes.c_int,))

    def _call(self, pid, selector):
        with self.o.pool():
            app = self._app(pid)
            if app:
                self.o.send(app, selector, restype=ctypes.c_bool)

    def hide_app(self, pid):
        self._call(pid, "hide")

    def unhide_app(self, pid):
        self._call(pid, "unhide")

    def quit_app(self, pid):
        self._call(pid, "terminate")

    def activate_pid(self, pid):
        with self.o.pool():
            app = self._app(pid)
            if app:
                self.o.send(app, "unhide", restype=ctypes.c_bool)
                self.o.send(app, "activateWithOptions:", _ACTIVATE_ALL_WINDOWS | _ACTIVATE_IGNORING_OTHERS,
                            restype=ctypes.c_bool, argtypes=(ctypes.c_ulong,))

    def display_name(self, path):
        o = self.o
        with o.pool():
            fm = o.send(o.cls("NSFileManager"), "defaultManager")
            name = o.text(o.send(fm, "displayNameAtPath:", o.nsstring(path), argtypes=(ctypes.c_void_p,)))
        name = name or os.path.basename(path.rstrip("/"))
        return name[:-4] if name.endswith(".app") else name

    # --- son ---
    def volume(self):
        return self.audio.get() if self.audio else None

    def set_volume(self, level):
        if self.audio:
            self.audio.set_level(level)
            if level > 0:
                self.audio.set_muted(False)

    def set_muted(self, muted):
        if self.audio:
            self.audio.set_muted(muted)


# ======================================================================================
# Qt (uniquement QtCore, QtGui et QtWidgets)
# ======================================================================================

from PySide6.QtCore import (QDate, QDir, QEasingCurve, QEvent, QFileInfo, QLocale, QLockFile,  # noqa: E402
                            QObject, QParallelAnimationGroup, QPoint, QPointF, QPropertyAnimation, QRect, QRectF, QSettings,
                            QSize, QTime, QTimer, Qt, Signal)
from PySide6.QtGui import (QColor, QCursor, QFont, QFontMetrics, QGuiApplication, QIcon,  # noqa: E402
                           QLinearGradient, QPainter, QPainterPath, QPalette, QPen, QPixmap, QPolygonF)
from PySide6.QtWidgets import (QAbstractButton, QAbstractItemView, QApplication, QComboBox,  # noqa: E402
                               QFileIconProvider, QFrame, QGridLayout, QHBoxLayout, QLabel, QLineEdit,
                               QListView, QListWidget, QListWidgetItem, QMenu, QPushButton, QSlider,
                               QStackedWidget, QStyle, QStyledItemDelegate, QToolButton, QVBoxLayout, QWidget)

NATIVE = Backend()
FRENCH = QLocale(QLocale.Language.French, QLocale.Country.France)


# ---- thème ---------------------------------------------------------------------------

_PAL = {
    True: {
        "bar": (32, 32, 32, 238), "bar_line": (255, 255, 255, 22), "text": (255, 255, 255, 255),
        "sub": (255, 255, 255, 205), "dim": (255, 255, 255, 140), "hover": (255, 255, 255, 18),
        "press": (255, 255, 255, 11), "active": (255, 255, 255, 15), "running": (255, 255, 255, 140),
        "accent": (76, 194, 255, 255), "on_accent": (0, 0, 0, 255), "fly": (40, 40, 40, 250),
        "fly_border": (255, 255, 255, 30), "fly_bottom": (31, 31, 31, 250), "field": (255, 255, 255, 14),
        "field_border": (255, 255, 255, 24), "pill": (255, 255, 255, 15), "pill_hover": (255, 255, 255, 26),
        "card": (255, 255, 255, 13), "tip": (43, 43, 43, 250), "hover_menu": (255, 255, 255, 16),
        "knob_ring": (69, 69, 69, 255), "settings_bg": (32, 32, 32, 255), "search_box": (255, 255, 255, 12),
    },
    False: {
        "bar": (238, 238, 238, 242), "bar_line": (0, 0, 0, 22), "text": (26, 26, 26, 255),
        "sub": (0, 0, 0, 180), "dim": (0, 0, 0, 120), "hover": (255, 255, 255, 175),
        "press": (255, 255, 255, 110), "active": (255, 255, 255, 150), "running": (0, 0, 0, 115),
        "accent": (0, 95, 184, 255), "on_accent": (255, 255, 255, 255), "fly": (249, 249, 249, 252),
        "fly_border": (0, 0, 0, 32), "fly_bottom": (238, 238, 238, 252), "field": (255, 255, 255, 255),
        "field_border": (0, 0, 0, 28), "pill": (255, 255, 255, 210), "pill_hover": (246, 246, 246, 255),
        "card": (255, 255, 255, 225), "tip": (249, 249, 249, 252), "hover_menu": (0, 0, 0, 11),
        "knob_ring": (255, 255, 255, 255), "settings_bg": (243, 243, 243, 255), "search_box": (255, 255, 255, 200),
    },
}


class Theme:
    dark = True

    @classmethod
    def detect(cls):
        try:
            cls.dark = QGuiApplication.styleHints().colorScheme() == Qt.ColorScheme.Dark
        except (AttributeError, RuntimeError):
            cls.dark = False
        return cls.dark

    @classmethod
    def c(cls, name):
        return QColor(*_PAL[cls.dark][name])

    @classmethod
    def css(cls, name):
        r, g, b, a = _PAL[cls.dark][name]
        return f"rgba({r}, {g}, {b}, {a})"


def app_css():
    t = Theme.css
    return f"""
QMenu {{ background: {t('fly')}; border: 1px solid {t('fly_border')}; border-radius: 8px; padding: 4px; }}
QMenu::item {{ padding: 7px 28px 7px 10px; border-radius: 4px; margin: 1px 0; color: {t('text')}; background: transparent; }}
QMenu::item:selected {{ background: {t('hover_menu')}; }}
QMenu::item:disabled {{ color: {t('dim')}; }}
QMenu::icon {{ padding-left: 8px; }}
QMenu::separator {{ height: 1px; background: {t('fly_border')}; margin: 4px 6px; }}
QLabel {{ color: {t('text')}; background: transparent; }}
QLabel#section {{ font-size: 14px; font-weight: 600; }}
QLabel#pageTitle {{ font-size: 26px; font-weight: 600; }}
QLabel#dim {{ color: {t('dim')}; font-size: 12px; }}
QLabel#sub {{ color: {t('sub')}; font-size: 12px; }}
QLineEdit#startSearch {{ background: {t('field')}; border: 1px solid {t('field_border')}; border-radius: 18px;
    padding: 0 14px 0 6px; color: {t('text')}; font-size: 14px;
    selection-background-color: {t('accent')}; selection-color: {t('on_accent')}; }}
QLineEdit#startSearch:focus {{ border-bottom: 2px solid {t('accent')}; }}
QPushButton#pill {{ background: {t('pill')}; border: 1px solid {t('field_border')}; border-radius: 4px;
    padding: 4px 10px; color: {t('text')}; font-size: 12px; }}
QPushButton#pill:hover {{ background: {t('pill_hover')}; }}
QPushButton#flat, QToolButton#flat {{ background: transparent; border: none; border-radius: 4px;
    color: {t('text')}; padding: 6px 8px; text-align: left; }}
QPushButton#flat:hover, QToolButton#flat:hover {{ background: {t('hover_menu')}; }}
QToolButton#tile {{ background: {t('card')}; border: 1px solid {t('field_border')}; border-radius: 4px; }}
QToolButton#tile:hover {{ background: {t('pill_hover')}; }}
QListWidget {{ background: transparent; border: none; outline: none; color: {t('text')}; }}
QScrollBar:vertical {{ background: transparent; width: 8px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: {t('dim')}; border-radius: 2px; min-height: 30px; margin: 0 2px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}
QSlider::groove:horizontal {{ height: 4px; background: {t('dim')}; border-radius: 2px; }}
QSlider::sub-page:horizontal {{ background: {t('accent')}; border-radius: 2px; }}
QSlider::handle:horizontal {{ width: 12px; height: 12px; margin: -8px 0; border-radius: 10px;
    background: {t('accent')}; border: 4px solid {t('knob_ring')}; }}
QFrame#line {{ background: {t('fly_border')}; border: none; }}
QWidget#settings {{ background: {t('settings_bg')}; }}
QFrame#card {{ background: {t('card')}; border: 1px solid {t('field_border')}; border-radius: 6px; }}
QComboBox {{ background: {t('pill')}; border: 1px solid {t('field_border')}; border-radius: 4px;
    padding: 5px 10px; color: {t('text')}; min-width: 200px; }}
QComboBox QAbstractItemView {{ background: {t('fly')}; color: {t('text')}; border: 1px solid {t('fly_border')};
    selection-background-color: {t('hover_menu')}; selection-color: {t('text')}; outline: none; }}
"""


def apply_theme(app):
    app.setStyle("Fusion")
    pal = QPalette()
    text, base = Theme.c("text"), QColor(*_PAL[Theme.dark]["settings_bg"])
    for role, col in ((QPalette.ColorRole.Window, base), (QPalette.ColorRole.Base, Theme.c("fly")),
                      (QPalette.ColorRole.Text, text), (QPalette.ColorRole.WindowText, text),
                      (QPalette.ColorRole.Button, Theme.c("fly")), (QPalette.ColorRole.ButtonText, text),
                      (QPalette.ColorRole.Highlight, Theme.c("accent")),
                      (QPalette.ColorRole.HighlightedText, Theme.c("on_accent")),
                      (QPalette.ColorRole.PlaceholderText, Theme.c("dim"))):
        pal.setColor(role, col)
    app.setPalette(pal)
    app.setStyleSheet(app_css())


# ---- icônes dessinées (aucune image de Microsoft) -------------------------------------

_GLYPHS = {}


def _glyph(name):
    def register(fn):
        _GLYPHS[name] = fn
        return fn
    return register


def _pen(p, color, width=1.3):
    pen = QPen(QColor(color))
    pen.setWidthF(width)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    p.setPen(pen)
    p.setBrush(Qt.BrushStyle.NoBrush)


def glyph(p, name, rect, color=None, **kw):
    """Dessine une icône (grille de 16 × 16) dans le rectangle donné."""
    rect = QRectF(rect)
    p.save()
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.translate(rect.x(), rect.y())
    p.scale(rect.width() / 16.0, rect.height() / 16.0)
    _GLYPHS[name](p, QColor(color) if color is not None else Theme.c("text"), **kw)
    p.restore()


def glyph_icon(name, color=None, **kw):
    icon = QIcon()
    for px in (16, 20, 24, 32, 40, 48, 64, 128, 256):
        pm = QPixmap(px, px)
        pm.fill(Qt.GlobalColor.transparent)
        p = QPainter(pm)
        glyph(p, name, QRectF(0, 0, px, px), color, **kw)
        p.end()
        icon.addPixmap(pm)
    return icon


@_glyph("start")
def _(p, c):
    # Bouton Démarrer : une grille générique, pas le logo de Microsoft.
    grad = QLinearGradient(1, 1, 15, 15)
    grad.setColorAt(0, QColor("#5CC8FF"))
    grad.setColorAt(1, QColor("#0A64C8"))
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(grad)
    size, gap = 4.0, 1.2
    x0 = (16 - (3 * size + 2 * gap)) / 2
    for i in range(3):
        for j in range(3):
            p.drawRoundedRect(QRectF(x0 + j * (size + gap), x0 + i * (size + gap), size, size), 1.1, 1.1)


@_glyph("search")
def _(p, c):
    _pen(p, c, 1.5)
    p.drawEllipse(QPointF(9.4, 6.6), 4.6, 4.6)
    p.drawLine(QPointF(6.0, 10.0), QPointF(1.8, 14.2))


@_glyph("taskview")
def _(p, c):
    _pen(p, c, 1.2)
    p.drawRoundedRect(QRectF(1.6, 5.0, 9.6, 9.4), 1.6, 1.6)
    path = QPainterPath()
    path.moveTo(5.0, 2.6)
    path.lineTo(12.4, 2.6)
    path.quadTo(14.4, 2.6, 14.4, 4.6)
    path.lineTo(14.4, 11.4)
    p.drawPath(path)


@_glyph("wifi")
def _(p, c):
    _pen(p, c, 1.35)
    for r in (3.4, 6.4, 9.4):
        p.drawArc(QRectF(8 - r, 13.2 - r, 2 * r, 2 * r), 45 * 16, 90 * 16)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(c)
    p.drawEllipse(QPointF(8, 13.0), 1.15, 1.15)


@_glyph("ethernet")
def _(p, c):
    _pen(p, c, 1.2)
    p.drawRoundedRect(QRectF(1.6, 2.4, 12.8, 8.6), 1.2, 1.2)
    p.drawLine(QPointF(8, 11.2), QPointF(8, 13.6))
    p.drawLine(QPointF(4.6, 13.8), QPointF(11.4, 13.8))


@_glyph("offline")
def _(p, c):
    _pen(p, c, 1.1)
    p.drawEllipse(QPointF(8, 8), 6.2, 6.2)
    p.drawEllipse(QPointF(8, 8), 2.6, 6.2)
    p.drawLine(QPointF(1.8, 8), QPointF(14.2, 8))
    _pen(p, c, 1.4)
    p.drawLine(QPointF(2.6, 13.4), QPointF(13.4, 2.6))


@_glyph("speaker")
def _(p, c, level=60, muted=False):
    _pen(p, c, 1.15)
    path = QPainterPath()
    path.moveTo(1.6, 6.0)
    path.lineTo(4.2, 6.0)
    path.lineTo(7.6, 2.9)
    path.lineTo(7.6, 13.1)
    path.lineTo(4.2, 10.0)
    path.lineTo(1.6, 10.0)
    path.closeSubpath()
    p.drawPath(path)
    if muted:
        p.drawLine(QPointF(10.2, 6.0), QPointF(14.2, 10.0))
        p.drawLine(QPointF(14.2, 6.0), QPointF(10.2, 10.0))
        return
    for threshold, r in ((0, 2.6), (33, 4.6), (66, 6.6)):
        if level > threshold:
            p.drawArc(QRectF(7.6 - r, 8 - r, 2 * r, 2 * r), -50 * 16, 100 * 16)


@_glyph("battery")
def _(p, c, percent=100, charging=False):
    _pen(p, c, 1.1)
    p.drawRoundedRect(QRectF(1.0, 4.6, 12.2, 6.8), 1.7, 1.7)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(c)
    p.drawRoundedRect(QRectF(13.7, 6.6, 1.5, 2.8), 0.6, 0.6)
    width = 9.8 * max(0, min(100, percent)) / 100.0
    fill = QColor("#E81123") if percent <= 10 and not charging else c
    p.setBrush(fill)
    p.drawRoundedRect(QRectF(2.2, 5.8, max(width, 0.6), 4.4), 0.8, 0.8)
    if charging:
        bolt = QPolygonF([QPointF(8.4, 3.4), QPointF(5.4, 8.5), QPointF(7.6, 8.5), QPointF(6.6, 12.6),
                          QPointF(10.2, 7.3), QPointF(8.0, 7.3), QPointF(9.0, 3.4)])
        pen = QPen(Theme.c("bar"))
        pen.setWidthF(0.9)
        p.setPen(pen)
        p.setBrush(c)
        p.drawPolygon(bolt)


@_glyph("power")
def _(p, c):
    _pen(p, c, 1.4)
    p.drawArc(QRectF(2.4, 2.8, 11.2, 11.2), 125 * 16, 290 * 16)
    p.drawLine(QPointF(8, 1.6), QPointF(8, 7.6))


@_glyph("gear")
def _(p, c):
    _pen(p, c, 1.1)
    pts = []
    for i in range(8):
        base = i * 45
        for da, r in ((-14, 5.3), (-8, 7.0), (8, 7.0), (14, 5.3)):
            ang = math.radians(base + da)
            pts.append(QPointF(8 + r * math.cos(ang), 8 + r * math.sin(ang)))
    p.drawPolygon(QPolygonF(pts))
    p.drawEllipse(QPointF(8, 8), 2.3, 2.3)


@_glyph("folder")
def _(p, c):
    p.setPen(Qt.PenStyle.NoPen)
    back = QPainterPath()
    back.moveTo(1.5, 4.0)
    back.quadTo(1.5, 2.8, 2.7, 2.8)
    back.lineTo(6.0, 2.8)
    back.lineTo(7.4, 4.2)
    back.lineTo(13.3, 4.2)
    back.quadTo(14.5, 4.2, 14.5, 5.4)
    back.lineTo(14.5, 12.3)
    back.quadTo(14.5, 13.5, 13.3, 13.5)
    back.lineTo(2.7, 13.5)
    back.quadTo(1.5, 13.5, 1.5, 12.3)
    back.closeSubpath()
    p.setBrush(QColor("#E0A11B"))
    p.drawPath(back)
    front = QPainterPath()
    front.addRoundedRect(QRectF(1.5, 5.7, 13.0, 7.8), 1.1, 1.1)
    grad = QLinearGradient(0, 5.7, 0, 13.5)
    grad.setColorAt(0, QColor("#FFD96A"))
    grad.setColorAt(1, QColor("#FFC22F"))
    p.setBrush(grad)
    p.drawPath(front)


@_glyph("annoteur")
def _(p, c):
    p.setPen(Qt.PenStyle.NoPen)
    grad = QLinearGradient(0, 2, 0, 14)
    grad.setColorAt(0, QColor("#5FB6F8"))
    grad.setColorAt(1, QColor("#2B7FDA"))
    p.setBrush(grad)
    p.drawRoundedRect(QRectF(1.2, 2.2, 13.6, 11.6), 2.0, 2.0)
    _pen(p, "#FFFFFF", 1.4)
    p.drawRoundedRect(QRectF(4.0, 5.0, 6.4, 4.6), 0.8, 0.8)
    _pen(p, "#E81123", 1.6)
    p.drawLine(QPointF(13.0, 12.0), QPointF(9.2, 8.2))


@_glyph("blocnotes")
def _(p, c):
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#FFFFFF"))
    p.drawRect(QRectF(2.5, 1.2, 11, 13.6))
    _pen(p, "#7A8696", 0.8)
    p.drawRect(QRectF(2.5, 1.2, 11, 13.6))
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#1A9E8F"))
    p.drawRect(QRectF(2.5, 1.2, 11, 2.6))
    p.setBrush(QColor("#5B6B7F"))
    for y, w in ((6.2, 8.0), (8.3, 6.2), (10.4, 7.2), (12.5, 4.8)):
        p.drawRoundedRect(QRectF(4.0, y, w, 0.9), 0.4, 0.4)
    _pen(p, "#E8A317", 1.7)
    p.drawLine(QPointF(15.0, 7.0), QPointF(10.2, 13.4))


@_glyph("terminalpro")
def _(p, c):
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#1B1D21"))
    p.drawRoundedRect(QRectF(1.0, 2.0, 14.0, 12.0), 2.2, 2.2)
    p.setBrush(QColor("#3A3F47"))
    p.drawRoundedRect(QRectF(1.0, 2.0, 14.0, 2.6), 2.2, 2.2)
    p.drawRect(QRectF(1.0, 3.6, 14.0, 1.0))
    _pen(p, "#4CC2FF", 1.5)
    p.drawPolyline(QPolygonF([QPointF(3.6, 6.8), QPointF(6.2, 9.0), QPointF(3.6, 11.2)]))
    _pen(p, "#FFFFFF", 1.4)
    p.drawLine(QPointF(7.6, 11.4), QPointF(10.4, 11.4))
    _pen(p, "#FCE100", 1.1)
    p.drawEllipse(QPointF(12.4, 7.4), 1.2, 1.2)
    p.drawLine(QPointF(12.4, 8.6), QPointF(12.4, 12.4))


@_glyph("appwin")
def _(p, c):
    p.setPen(Qt.PenStyle.NoPen)
    grad = QLinearGradient(0, 2, 0, 14)
    grad.setColorAt(0, QColor("#9AA5B4"))
    grad.setColorAt(1, QColor("#6B7686"))
    p.setBrush(grad)
    p.drawRoundedRect(QRectF(1.4, 2.4, 13.2, 11.2), 2.0, 2.0)
    p.setBrush(QColor("#F4F6F8"))
    p.drawRoundedRect(QRectF(2.6, 5.2, 10.8, 7.2), 1.0, 1.0)


@_glyph("headphones")
def _(p, c):
    _pen(p, c, 1.2)
    p.drawArc(QRectF(2.2, 2.4, 11.6, 11.6), 0, 180 * 16)
    p.drawRoundedRect(QRectF(1.8, 8.2, 2.8, 5.0), 1.0, 1.0)
    p.drawRoundedRect(QRectF(11.4, 8.2, 2.8, 5.0), 1.0, 1.0)


@_glyph("moon")
def _(p, c):
    _pen(p, c, 1.2)
    outer = QPainterPath()
    outer.addEllipse(QPointF(7.6, 8.4), 5.6, 5.6)
    cut = QPainterPath()
    cut.addEllipse(QPointF(11.0, 5.2), 4.8, 4.8)
    p.drawPath(outer.subtracted(cut))


@_glyph("display")
def _(p, c):
    _pen(p, c, 1.2)
    p.drawRoundedRect(QRectF(1.6, 2.6, 12.8, 8.4), 1.2, 1.2)
    p.drawLine(QPointF(6.0, 13.6), QPointF(10.0, 13.6))
    p.drawLine(QPointF(8.0, 11.0), QPointF(8.0, 13.6))


@_glyph("dock")
def _(p, c):
    _pen(p, c, 1.2)
    p.drawRoundedRect(QRectF(1.6, 2.4, 12.8, 11.2), 1.4, 1.4)
    p.drawLine(QPointF(1.6, 10.6), QPointF(14.4, 10.6))
    for x in (5.0, 8.0, 11.0):
        p.drawPoint(QPointF(x, 12.2))


@_glyph("access")
def _(p, c):
    _pen(p, c, 1.2)
    p.drawEllipse(QPointF(8, 8), 6.4, 6.4)
    p.drawEllipse(QPointF(8, 4.9), 0.9, 0.9)
    p.drawLine(QPointF(4.6, 6.9), QPointF(11.4, 6.9))
    p.drawLine(QPointF(8, 6.9), QPointF(8, 9.6))
    p.drawLine(QPointF(8, 9.6), QPointF(6.2, 12.6))
    p.drawLine(QPointF(8, 9.6), QPointF(9.8, 12.6))


@_glyph("user")
def _(p, c):
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#7A7A7A") if Theme.dark else QColor("#C8C8C8"))
    p.drawEllipse(QRectF(0.5, 0.5, 15, 15))
    p.setBrush(QColor("#EDEDED") if Theme.dark else QColor("#FFFFFF"))
    p.drawEllipse(QPointF(8, 6.2), 2.7, 2.7)
    body = QPainterPath()
    body.moveTo(3.2, 13.6)
    body.quadTo(3.6, 9.6, 8, 9.6)
    body.quadTo(12.4, 9.6, 12.8, 13.6)
    body.quadTo(8, 16.2, 3.2, 13.6)
    p.drawPath(body)


@_glyph("dots")
def _(p, c):
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(c)
    for x in (3.4, 8.0, 12.6):
        p.drawEllipse(QPointF(x, 8.0), 1.2, 1.2)


@_glyph("chevron")
def _(p, c, direction="right"):
    _pen(p, c, 1.3)
    pts = {"right": ((6, 3.5), (10.5, 8), (6, 12.5)), "left": ((10, 3.5), (5.5, 8), (10, 12.5)),
           "up": ((3.5, 10), (8, 5.5), (12.5, 10)), "down": ((3.5, 6), (8, 10.5), (12.5, 6))}[direction]
    p.drawPolyline(QPolygonF([QPointF(*xy) for xy in pts]))


# ---- icônes des applications ---------------------------------------------------------

_ICONS = {}
_PROVIDER = []


def icon_provider():
    if not _PROVIDER:
        _PROVIDER.append(QFileIconProvider())
    return _PROVIDER[0]


def icon_for(key, path=""):
    icon = _ICONS.get(key)
    if icon is None:
        if key == "script:explorateur":
            icon = glyph_icon("folder")
        elif key == "script:annoteur":
            icon = glyph_icon("annoteur")
        elif key == "script:blocnotes":
            icon = glyph_icon("blocnotes")
        elif key == "script:terminal":
            icon = glyph_icon("terminalpro")
        elif path and os.path.exists(path):
            icon = icon_provider().icon(QFileInfo(path))
        else:
            icon = QIcon()
        if icon.isNull():
            icon = glyph_icon("appwin")
        _ICONS[key] = icon
    return icon


_NAMES = {}


def display_name(path):
    name = _NAMES.get(path)
    if name is None:
        name = _NAMES[path] = NATIVE.display_name(path)
    return name


def find_app(name):
    for folder in APP_DIRS:
        path = os.path.join(folder, name + ".app")
        if os.path.isdir(path):
            return norm_app(path)
    return ""


def scan_apps():
    """Toutes les applications installées : (clé, nom affiché)."""
    seen = {}
    for folder in APP_DIRS:
        try:
            entries = list(os.scandir(folder))
        except OSError:
            continue
        for entry in entries:
            if entry.name.startswith("."):
                continue
            if entry.name.endswith(".app"):
                seen.setdefault(norm_app(entry.path), None)
            elif folder in ("/Applications", APP_DIRS[-1]) and entry.name != "Utilities":
                try:
                    if entry.is_dir(follow_symlinks=False):
                        for sub in os.scandir(entry.path):
                            if sub.name.endswith(".app") and not sub.name.startswith("."):
                                seen.setdefault(norm_app(sub.path), None)
                except OSError:
                    continue
    apps = [(key, display_name(key)) for key in seen]
    apps += [(key, SCRIPTS[key][0]) for key in SCRIPTS if script_path(key)]
    apps.sort(key=lambda kv: fold(kv[1]))
    return apps


class Catalog:
    _apps, _when = None, 0.0

    @classmethod
    def apps(cls):
        if cls._apps is None or time.monotonic() - cls._when > 120:
            cls._apps, cls._when = scan_apps(), time.monotonic()
        return cls._apps


def rank(items, query):
    """Classe (clé, nom) : début du nom, puis début d'un mot, puis contenu."""
    q = fold(query.strip())
    if not q:
        return []
    scored = []
    for key, name in items:
        n = fold(name)
        if n.startswith(q):
            score = 0
        elif any(w.startswith(q) for w in re.split(r"[\s\-_.()]+", n)):
            score = 1
        elif q in n:
            score = 2
        else:
            continue
        scored.append((score, n, key, name))
    scored.sort()
    return [(key, name) for _s, _n, key, name in scored]


# Panneaux des Réglages Système (macOS 13 et plus récents).
PANES = (
    ("Wi-Fi", "com.apple.wifi-settings-extension", "wifi", "internet sans fil"),
    ("Réseau", "com.apple.Network-Settings.extension", "ethernet", "internet vpn ethernet"),
    ("Bluetooth", "com.apple.BluetoothSettings", "headphones", "casque souris clavier"),
    ("Son", "com.apple.Sound-Settings.extension", "speaker", "volume haut-parleur micro audio"),
    ("Concentration", "com.apple.Focus-Settings.extension", "moon", "ne pas déranger"),
    ("Notifications", "com.apple.Notifications-Settings.extension", "gear", "alertes"),
    ("Écrans", "com.apple.Displays-Settings.extension", "display", "affichage moniteur résolution luminosité"),
    ("Bureau et Dock", "com.apple.Desktop-Settings.extension", "dock", "dock barre des tâches"),
    ("Fond d'écran", "com.apple.Wallpaper-Settings.extension", "display", "image arrière-plan"),
    ("Apparence", "com.apple.Appearance-Settings.extension", "display", "mode sombre clair thème"),
    ("Accessibilité", "com.apple.Accessibility-Settings.extension", "access", "zoom"),
    ("Batterie", "com.apple.Battery-Settings.extension", "battery", "énergie alimentation"),
    ("Clavier", "com.apple.Keyboard-Settings.extension", "gear", "touches raccourcis"),
    ("Souris", "com.apple.Mouse-Settings.extension", "gear", "pointeur"),
    ("Trackpad", "com.apple.Trackpad-Settings.extension", "gear", "pavé tactile"),
    ("Imprimantes et scanners", "com.apple.Print-Scan-Settings.extension", "gear", "imprimer"),
    ("Date et heure", "com.apple.Date-Time-Settings.extension", "gear", "horloge fuseau"),
    ("Confidentialité et sécurité", "com.apple.settings.PrivacySecurity.extension", "gear", "autorisations"),
    ("Utilisateurs et groupes", "com.apple.Users-Groups-Settings.extension", "user", "compte"),
    ("Ouverture (éléments de connexion)", "com.apple.LoginItems-Settings.extension", "gear", "démarrage"),
    ("Mise à jour de logiciels", "com.apple.Software-Update-Settings.extension", "gear", "update"),
)


def rank_panes(query):
    q = fold(query.strip())
    if not q:
        return []
    out = []
    for name, pane, icon, words in PANES:
        hay = fold(name + " " + words)
        if q in hay:
            out.append((0 if fold(name).startswith(q) else 1, name, pane, icon))
    out.sort()
    return [(name, pane, icon) for _s, name, pane, icon in out]


# ---- réglages ------------------------------------------------------------------------

DEFAULTS = {"align": "center", "search": "box", "taskview": True, "finder": False,
            "docs": True, "show_name": True, "all_screens": True, "autohide": False}


def conf():
    return QSettings(ORG_NAME, "Barre")


def opt(name):
    default = DEFAULTS[name]
    value = conf().value(name, default)
    if isinstance(default, bool):
        return value in (True, 1, "true", "1", "True")
    return value if isinstance(value, str) else default


def set_opt(name, value):
    conf().setValue(name, value)


def _norm_key(key):
    return key if key.startswith("script:") else norm_app(key)


def get_pins(which):
    s = conf()
    if not opt_bool(s.value(f"{which}_init", False)):
        pins = default_taskbar_pins() if which == "taskbar" else default_start_pins()
        set_pins(which, pins)
        return pins
    value = s.value(f"{which}_pins", [])
    if isinstance(value, str):
        value = [value] if value else []
    out = []
    for key in value or []:
        if isinstance(key, str) and key:
            key = _norm_key(key)
            if key not in out:
                out.append(key)
    return out


def opt_bool(value):
    return value in (True, 1, "true", "1", "True")


def set_pins(which, pins):
    s = conf()
    s.setValue(f"{which}_pins", list(pins))
    s.setValue(f"{which}_init", True)


def default_taskbar_pins():
    pins = ["script:explorateur"] if script_path("script:explorateur") else []
    for name in ("Microsoft Edge", "Google Chrome", "Firefox", "Safari"):
        path = find_app(name)
        if path:
            pins.append(path)
            break
    for name in ("Microsoft Outlook", "Microsoft Teams", "Microsoft Teams (work or school)",
                 "Visual Studio Code", "Terminal"):
        path = find_app(name)
        if path and path not in pins:
            pins.append(path)
    return pins


def default_start_pins():
    pins = [k for k in SCRIPTS if script_path(k)]
    for name in ("Microsoft Edge", "Google Chrome", "Firefox", "Safari", "Microsoft Outlook",
                 "Microsoft Word", "Microsoft Excel", "Microsoft PowerPoint", "Microsoft Teams",
                 "Microsoft Teams (work or school)", "Microsoft OneNote", "Visual Studio Code", "Terminal",
                 "Notes", "Calendar", "Calculator", "Preview", "Activity Monitor", "System Settings"):
        path = find_app(name)
        if path and path not in pins:
            pins.append(path)
    return pins[:24]


def entry_for_key(key):
    """Élément épinglé (même s'il n'est pas lancé)."""
    if key.startswith("script:"):
        path = script_path(key)
        return Entry(key, SCRIPTS[key][0], path, "script") if path else None
    if key.endswith(".app") and os.path.isdir(key):
        return Entry(key, display_name(key), key, "app")
    return None


# Une barre par écran : elles partagent les épingles, les réglages et l'état du système.
BARS = []
_SHARED = {}
_SETTINGS = []
MANAGER = []


def shared_state():
    if not _SHARED:
        _SHARED.update(pins=get_pins("taskbar"), start_pins=get_pins("start"),
                       options={k: opt(k) for k in DEFAULTS},
                       status={"battery": None, "network": "wifi" if IS_MAC else "ethernet", "volume": None})
    return _SHARED


def main_bar():
    return next((b for b in BARS if b.is_main), BARS[0] if BARS else None)


def refresh_all():
    for bar in list(BARS):
        bar.refresh(force=True)


def apply_all():
    """Après un changement de réglage : toutes les barres suivent."""
    shared_state()["options"].update({k: opt(k) for k in DEFAULTS})
    if MANAGER:
        MANAGER[0].sync()
    for bar in list(BARS):
        if not bar.options.get("autohide"):
            bar.reveal()
        bar.refresh(force=True)
        bar.relayout()
        start = bar._flyouts.get("start")
        if start:
            start.retheme()


def settings_window():
    return _SETTINGS[0] if _SETTINGS else None


def quit_all():
    for bar in list(BARS):
        bar._quitting = True
        for fly in bar._flyouts.values():
            fly.hide()
        bar.tip.hide()
    win = settings_window()
    if win is not None:
        win.hide()
    QApplication.instance().quit()


def account_name():
    return os.environ.get("USER") or os.path.basename(HOME) or "Utilisateur"


# ---- petites briques -----------------------------------------------------------------

class Async(QObject):
    """Lance une lecture lente (batterie, réseau, recherche) hors de l'interface."""
    done = Signal(str, object)

    def run(self, key, fn):
        def work():
            try:
                result = fn()
            except Exception as exc:  # une lecture ratée ne doit jamais faire tomber la barre
                print(f"[barre] {key} : {exc}", file=sys.stderr)
                result = None
            try:
                self.done.emit(key, result)
            except RuntimeError:
                pass            # la barre a été retirée entre-temps
        threading.Thread(target=work, daemon=True).start()


class Entry:
    """Un bouton d'application de la barre."""

    def __init__(self, key, name, path, kind):
        self.key, self.name, self.path, self.kind = key, name, path, kind
        self.pinned, self.pids, self.hidden_flags = False, [], []
        self.active = self.hidden = False

    @property
    def running(self):
        return bool(self.pids)


class Item:
    __slots__ = ("kind", "rect", "entry")

    def __init__(self, kind, rect, entry=None):
        self.kind, self.rect, self.entry = kind, rect, entry


def make_menu(parent=None):
    menu = QMenu(parent)
    menu.setWindowFlags(menu.windowFlags() | Qt.WindowType.FramelessWindowHint
                        | Qt.WindowType.NoDropShadowWindowHint)
    menu.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
    return menu


def add_action(menu, text, fn, icon=None, enabled=True):
    act = menu.addAction(text)
    if icon is not None:
        act.setIcon(icon if isinstance(icon, QIcon) else glyph_icon(icon))
    act.setEnabled(enabled)
    act.triggered.connect(lambda _checked=False: fn())
    return act


class Tip(QWidget):
    """Info-bulle façon Windows 11 au-dessus d'un bouton."""

    def __init__(self):
        super().__init__(None, Qt.WindowType.Tool | Qt.WindowType.FramelessWindowHint
                         | Qt.WindowType.WindowStaysOnTopHint | Qt.WindowType.WindowTransparentForInput
                         | Qt.WindowType.WindowDoesNotAcceptFocus)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)
        self.setAttribute(Qt.WidgetAttribute.WA_MacAlwaysShowToolWindow)
        self.text = ""

    def show_text(self, text, anchor, above_y):
        self.text = text
        fm = QFontMetrics(self.font())
        lines = text.split("\n")
        w = max(fm.horizontalAdvance(line) for line in lines) + 18
        h = fm.height() * len(lines) + 12
        x = int(anchor.center().x() - w / 2)
        screen = QGuiApplication.screenAt(anchor.center()) or QGuiApplication.primaryScreen()
        geo = screen.geometry()
        x = max(geo.x() + 4, min(x, geo.x() + geo.width() - w - 4))
        self.setGeometry(x, above_y - h - 10, w, h)
        self.show()
        NATIVE.configure_window(self, "tip")
        self.update()

    def paintEvent(self, _ev):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        r = QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5)
        p.setPen(QPen(Theme.c("fly_border"), 1))
        p.setBrush(Theme.c("tip"))
        p.drawRoundedRect(r, 4, 4)
        p.setPen(Theme.c("text"))
        p.drawText(self.rect().adjusted(9, 6, -9, -6), Qt.AlignmentFlag.AlignCenter, self.text)


class Toggle(QAbstractButton):
    """Interrupteur Windows 11."""

    def __init__(self, checked=False, parent=None):
        super().__init__(parent)
        self.setCheckable(True)
        self.setChecked(checked)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def sizeHint(self):
        return QSize(40, 20)

    def paintEvent(self, _ev):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        r = QRectF(0.5, 0.5, 39, 19)
        if self.isChecked():
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(Theme.c("accent"))
            p.drawRoundedRect(r, 10, 10)
            p.setBrush(Theme.c("on_accent"))
            p.drawEllipse(QPointF(30, 10), 5, 5)
        else:
            p.setPen(QPen(Theme.c("sub"), 1))
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawRoundedRect(r, 10, 10)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(Theme.c("sub"))
            p.drawEllipse(QPointF(10, 10), 5, 5)


def hline():
    line = QFrame()
    line.setObjectName("line")
    line.setFixedHeight(1)
    return line


# ======================================================================================
# Fenêtres volantes (Démarrer, calendrier, réglages rapides)
# ======================================================================================

class Flyout(QWidget):
    closed = Signal()
    footer_h = 0

    def __init__(self, bar):
        super().__init__(None, Qt.WindowType.Tool | Qt.WindowType.FramelessWindowHint
                         | Qt.WindowType.WindowStaysOnTopHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setAttribute(Qt.WidgetAttribute.WA_MacAlwaysShowToolWindow)
        self.bar = bar
        self._was_key = False
        self._anims = []

    def popup_at(self, rect):
        self.setGeometry(rect)
        self.setWindowOpacity(0.0)
        self.show()
        self.raise_()
        NATIVE.configure_window(self, "flyout")
        NATIVE.make_key(self)
        self.focus_first()
        QTimer.singleShot(150, self, self._ensure_key)
        fade = QPropertyAnimation(self, b"windowOpacity", self)
        fade.setDuration(140)
        fade.setStartValue(0.0)
        fade.setEndValue(1.0)
        slide = QPropertyAnimation(self, b"pos", self)
        slide.setDuration(180)
        slide.setStartValue(rect.topLeft() + QPoint(0, 14))
        slide.setEndValue(rect.topLeft())
        slide.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._anims = [fade, slide]
        for anim in self._anims:
            anim.start()

    def focus_first(self):
        pass

    def _ensure_key(self):
        if not self.isVisible():
            return
        if NATIVE.is_key(self):
            self._was_key = True
            return
        # Plan B : la barre prend le focus le temps du panneau, comme sous Windows.
        NATIVE.activate_self()
        self.activateWindow()
        self.raise_()
        self.focus_first()
        self.bar.note_self_activated()
        QTimer.singleShot(200, self, lambda: setattr(self, "_was_key", NATIVE.is_key(self)))

    def check_focus(self):
        """Ferme le panneau quand on clique ailleurs (appelé par la barre)."""
        if not self.isVisible():
            return
        if NATIVE.is_key(self):
            self._was_key = True
        elif self._was_key and QApplication.activePopupWidget() is None:
            self.close_flyout()

    def close_flyout(self):
        if not self.isVisible():
            return
        for anim in self._anims:
            anim.stop()
        self.hide()
        self._was_key = False
        self.closed.emit()

    def keyPressEvent(self, ev):
        if ev.key() == Qt.Key.Key_Escape:
            self.close_flyout()
            return
        super().keyPressEvent(ev)

    def paintEvent(self, _ev):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        r = QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5)
        path = QPainterPath()
        path.addRoundedRect(r, 8, 8)
        p.fillPath(path, Theme.c("fly"))
        if self.footer_h:
            p.save()
            p.setClipPath(path)
            foot = QRectF(r.x(), r.bottom() - self.footer_h, r.width(), self.footer_h)
            p.fillRect(foot, Theme.c("fly_bottom"))
            p.setPen(QPen(Theme.c("fly_border"), 1))
            p.drawLine(foot.topLeft(), foot.topRight())
            p.restore()
        p.setPen(QPen(Theme.c("fly_border"), 1))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawPath(path)


ROLE_KEY = Qt.ItemDataRole.UserRole
ROLE_KIND = Qt.ItemDataRole.UserRole + 1
ROLE_SUB = Qt.ItemDataRole.UserRole + 2


class TileDelegate(QStyledItemDelegate):
    """Tuile du menu Démarrer : icône 32 px et nom en dessous."""

    def sizeHint(self, option, index):
        return QSize(94, 86)

    def paint(self, p, option, index):
        p.save()
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        r = QRectF(option.rect).adjusted(3, 2, -3, -2)
        if option.state & (QStyle.StateFlag.State_MouseOver | QStyle.StateFlag.State_Selected):
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(Theme.c("hover_menu"))
            p.drawRoundedRect(r, 4, 4)
        icon = index.data(Qt.ItemDataRole.DecorationRole)
        if isinstance(icon, QIcon):
            icon.paint(p, QRect(int(r.center().x()) - 16, int(r.y()) + 12, 32, 32))
        p.setPen(Theme.c("text"))
        font = QFont(option.font)
        font.setPixelSize(12)
        p.setFont(font)
        text = QFontMetrics(font).elidedText(index.data(Qt.ItemDataRole.DisplayRole) or "",
                                             Qt.TextElideMode.ElideRight, int(r.width()) - 8)
        p.drawText(QRectF(r.x() + 4, r.y() + 50, r.width() - 8, 20), Qt.AlignmentFlag.AlignCenter, text)
        p.restore()


class RowDelegate(QStyledItemDelegate):
    """Ligne de liste : titre de section, application, document ou réglage."""

    def sizeHint(self, option, index):
        kind = index.data(ROLE_KIND)
        return QSize(100, 34 if kind == "header" else (52 if kind == "doc" else 40))

    def paint(self, p, option, index):
        p.save()
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        kind = index.data(ROLE_KIND)
        r = QRectF(option.rect).adjusted(2, 1, -6, -1)
        font = QFont(option.font)
        if kind == "header":
            font.setPixelSize(13)
            font.setWeight(QFont.Weight.DemiBold)
            p.setFont(font)
            p.setPen(Theme.c("text"))
            p.drawText(r.adjusted(12, 0, 0, 0), Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
                       index.data(Qt.ItemDataRole.DisplayRole) or "")
            p.restore()
            return
        if option.state & (QStyle.StateFlag.State_MouseOver | QStyle.StateFlag.State_Selected):
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(Theme.c("hover_menu"))
            p.drawRoundedRect(r, 4, 4)
            if option.state & QStyle.StateFlag.State_Selected:
                p.setBrush(Theme.c("accent"))
                p.drawRoundedRect(QRectF(r.x(), r.center().y() - 8, 3, 16), 1.5, 1.5)
        icon = index.data(Qt.ItemDataRole.DecorationRole)
        size = 24
        if isinstance(icon, QIcon):
            icon.paint(p, QRect(int(r.x()) + 12, int(r.center().y()) - size // 2, size, size))
        font.setPixelSize(13)
        p.setFont(font)
        p.setPen(Theme.c("text"))
        text_x = r.x() + 12 + size + 12
        width = r.right() - text_x - 8
        fm = QFontMetrics(font)
        name = fm.elidedText(index.data(Qt.ItemDataRole.DisplayRole) or "", Qt.TextElideMode.ElideRight, int(width))
        sub = index.data(ROLE_SUB) or ""
        if sub:
            p.drawText(QRectF(text_x, r.y() + 7, width, 20), Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, name)
            small = QFont(font)
            small.setPixelSize(11)
            p.setFont(small)
            p.setPen(Theme.c("dim"))
            p.drawText(QRectF(text_x, r.y() + 26, width, 18), Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                       QFontMetrics(small).elidedText(sub, Qt.TextElideMode.ElideMiddle, int(width)))
        else:
            p.drawText(QRectF(text_x, r.y(), width, r.height()), Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, name)
        p.restore()


def _list_common(view):
    view.setFrameShape(QFrame.Shape.NoFrame)
    view.setMouseTracking(True)
    view.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    view.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
    view.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)


class StartMenu(Flyout):
    footer_h = 64

    def __init__(self, bar):
        super().__init__(bar)
        self.setObjectName("startMenu")
        self._doc_token = 0
        self._docs = ("", [])
        self.async_ = Async(self)
        self.async_.done.connect(self._on_docs)
        self._doc_timer = QTimer(self)
        self._doc_timer.setSingleShot(True)
        self._doc_timer.setInterval(280)
        self._doc_timer.timeout.connect(self._search_docs)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        top = QVBoxLayout()
        top.setContentsMargins(32, 28, 32, 6)
        self.search = QLineEdit()
        self.search.setObjectName("startSearch")
        self.search.setPlaceholderText("Rechercher des applications, des paramètres et des documents")
        self.search.setFixedHeight(36)
        self.search.addAction(glyph_icon("search", Theme.c("sub")), QLineEdit.ActionPosition.LeadingPosition)
        self.search.textChanged.connect(self._on_text)
        self.search.installEventFilter(self)
        top.addWidget(self.search)
        root.addLayout(top)

        self.stack = QStackedWidget()
        root.addWidget(self.stack, 1)

        home = QWidget()
        hl = QVBoxLayout(home)
        hl.setContentsMargins(28, 18, 28, 8)
        head = QHBoxLayout()
        head.setContentsMargins(4, 0, 4, 0)
        lab = QLabel("Épinglé")
        lab.setObjectName("section")
        head.addWidget(lab)
        head.addStretch(1)
        btn = QPushButton("Toutes les applications  ›")
        btn.setObjectName("pill")
        btn.clicked.connect(self.show_all)
        head.addWidget(btn)
        hl.addLayout(head)
        hl.addSpacing(6)
        self.grid = QListWidget()
        _list_common(self.grid)
        self.grid.setViewMode(QListView.ViewMode.IconMode)
        self.grid.setMovement(QListView.Movement.Static)
        self.grid.setResizeMode(QListView.ResizeMode.Adjust)
        self.grid.setFlow(QListView.Flow.LeftToRight)
        self.grid.setWrapping(True)
        self.grid.setGridSize(QSize(94, 86))
        self.grid.setIconSize(QSize(32, 32))
        self.grid.setUniformItemSizes(True)
        self.grid.setItemDelegate(TileDelegate(self.grid))
        hl.addWidget(self.grid, 1)
        self.stack.addWidget(home)

        allw = QWidget()
        al = QVBoxLayout(allw)
        al.setContentsMargins(32, 18, 24, 8)
        head2 = QHBoxLayout()
        lab2 = QLabel("Toutes les applications")
        lab2.setObjectName("section")
        head2.addWidget(lab2)
        head2.addStretch(1)
        back = QPushButton("‹  Précédent")
        back.setObjectName("pill")
        back.clicked.connect(self.show_home)
        head2.addWidget(back)
        al.addLayout(head2)
        al.addSpacing(6)
        self.all_list = QListWidget()
        _list_common(self.all_list)
        self.all_list.setItemDelegate(RowDelegate(self.all_list))
        al.addWidget(self.all_list, 1)
        self.stack.addWidget(allw)

        resw = QWidget()
        rl = QVBoxLayout(resw)
        rl.setContentsMargins(24, 14, 24, 8)
        self.results = QListWidget()
        _list_common(self.results)
        self.results.setItemDelegate(RowDelegate(self.results))
        rl.addWidget(self.results, 1)
        self.stack.addWidget(resw)

        self._launched_at = 0.0
        for view in (self.grid, self.all_list, self.results):
            view.itemClicked.connect(self.launch_item)
            view.installEventFilter(self)
            view.customContextMenuRequested.connect(lambda pos, v=view: self.item_menu(v, pos))

        foot = QWidget()
        foot.setFixedHeight(self.footer_h)
        fl = QHBoxLayout(foot)
        fl.setContentsMargins(44, 0, 36, 0)
        fl.setSpacing(4)
        self.user_btn = QPushButton()
        self.user_btn.setObjectName("flat")
        self.user_btn.setIconSize(QSize(32, 32))
        self.user_btn.clicked.connect(lambda: self._run(lambda: open_pane("com.apple.Users-Groups-Settings.extension")))
        fl.addWidget(self.user_btn)
        fl.addStretch(1)
        self.foot_buttons = []
        for icon, tip, fn in (("gear", "Paramètres", lambda: self._run(lambda: open_app(SYSTEM_SETTINGS))),
                              ("folder", "Explorateur de fichiers", lambda: self._run(lambda: self.bar.launch_key("script:explorateur"))),
                              ("power", "Marche/Arrêt", self.power_menu)):
            b = QToolButton()
            b.setObjectName("flat")
            b.setFixedSize(40, 40)
            b.setIconSize(QSize(18, 18))
            b.setToolTip(tip)
            b.setProperty("glyph", icon)
            b.clicked.connect(fn)
            fl.addWidget(b)
            self.foot_buttons.append(b)
        root.addWidget(foot)
        self.retheme()

    def retheme(self):
        self.search.actions()[0].setIcon(glyph_icon("search", Theme.c("sub")))
        for b in self.foot_buttons:
            name = b.property("glyph")
            b.setIcon(glyph_icon(name) if name == "folder" else glyph_icon(name, Theme.c("text")))
        self.user_btn.setIcon(glyph_icon("user"))
        self.user_btn.setText("  " + (account_name() if opt("show_name") else "Utilisateur"))
        self.update()

    # --- ouverture ---
    def open(self, search=False):
        self.retheme()
        self.search.blockSignals(True)
        self.search.clear()
        self.search.blockSignals(False)
        self.fill_home()
        self.stack.setCurrentIndex(0)
        self.popup_at(self.bar.flyout_rect("start", QSize(640, 660)))

    def focus_first(self):
        self.search.setFocus(Qt.FocusReason.PopupFocusReason)

    def show_all(self):
        self.fill_all()
        self.stack.setCurrentIndex(1)
        self.all_list.scrollToTop()

    def show_home(self):
        self.stack.setCurrentIndex(0)

    def _item(self, view, kind, text, key="", icon=None, sub=""):
        item = QListWidgetItem(icon or QIcon(), text)
        item.setData(ROLE_KIND, kind)
        item.setData(ROLE_KEY, key)
        item.setData(ROLE_SUB, sub)
        if kind == "header":
            item.setFlags(Qt.ItemFlag.ItemIsEnabled)
        view.addItem(item)
        return item

    def fill_home(self):
        self.grid.clear()
        for key in self.bar.start_pins:
            entry = entry_for_key(key)
            if entry:
                self._item(self.grid, entry.kind, entry.name, key, icon_for(key, entry.path))

    def fill_all(self):
        self.all_list.clear()
        letter = None
        for key, name in Catalog.apps():
            first = fold(name[:1]).upper() if name else "#"
            first = first if first.isalpha() else "#"
            if first != letter:
                letter = first
                self._item(self.all_list, "header", letter)
            self._item(self.all_list, "script" if key.startswith("script:") else "app", name, key,
                       icon_for(key, "" if key.startswith("script:") else key))

    # --- recherche ---
    def _on_text(self, text):
        if not text.strip():
            self.stack.setCurrentIndex(0)
            return
        self.stack.setCurrentIndex(2)
        self.fill_results(text)
        if opt("docs") and NATIVE.native:
            self._doc_timer.start()

    def fill_results(self, text):
        self.results.clear()
        apps = rank(Catalog.apps(), text)[:8]
        panes = rank_panes(text)[:4]
        docs = self._docs[1] if self._docs[0] == text.strip() else []
        if apps:
            self._item(self.results, "header", "Applications")
            for key, name in apps:
                self._item(self.results, "script" if key.startswith("script:") else "app", name, key,
                           icon_for(key, "" if key.startswith("script:") else key))
        if panes:
            self._item(self.results, "header", "Paramètres")
            for name, pane, icon in panes:
                self._item(self.results, "pane", name, pane, glyph_icon(icon, Theme.c("text")), "Réglages Système")
        if docs:
            self._item(self.results, "header", "Documents")
            for path in docs:
                self._item(self.results, "doc", os.path.basename(path), path,
                           icon_provider().icon(QFileInfo(path)),
                           "~" + os.path.dirname(path)[len(HOME):] if path.startswith(HOME) else os.path.dirname(path))
        if not (apps or panes or docs):
            self._item(self.results, "header", "Aucun résultat")
        self.select_first()

    def select_first(self):
        for i in range(self.results.count()):
            if self.results.item(i).data(ROLE_KIND) != "header":
                self.results.setCurrentRow(i)
                return

    def _search_docs(self):
        text = self.search.text().strip()
        if not text:
            return
        self._doc_token += 1
        token = self._doc_token
        self.async_.run(f"{token}", lambda: (text, search_documents(text)))

    def _on_docs(self, key, result):
        if not result or key != str(self._doc_token):
            return
        text, docs = result
        self._docs = (text, docs)
        if self.isVisible() and self.search.text().strip() == text and docs:
            current = self.results.currentRow()
            self.fill_results(text)
            if current > 0:
                self.results.setCurrentRow(min(current, self.results.count() - 1))

    def eventFilter(self, obj, ev):
        if (ev.type() == QEvent.Type.KeyPress and obj in (self.grid, self.all_list, self.results)
                and ev.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter)):
            item = obj.currentItem()
            if item is not None:
                self.launch_item(item)
            return True
        if obj is self.search and ev.type() == QEvent.Type.KeyPress:
            key = ev.key()
            if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
                view = self.results if self.stack.currentIndex() == 2 else None
                item = view.currentItem() if view else None
                if item is not None:
                    self.launch_item(item)
                return True
            if key in (Qt.Key.Key_Down, Qt.Key.Key_Up) and self.stack.currentIndex() == 2:
                step = 1 if key == Qt.Key.Key_Down else -1
                row = self.results.currentRow()
                for _ in range(self.results.count()):
                    row = (row + step) % max(1, self.results.count())
                    if self.results.item(row).data(ROLE_KIND) != "header":
                        self.results.setCurrentRow(row)
                        break
                return True
            if key == Qt.Key.Key_Escape:
                if self.search.text():
                    self.search.clear()
                else:
                    self.close_flyout()
                return True
        return super().eventFilter(obj, ev)

    # --- actions ---
    def _run(self, fn):
        self.close_flyout()
        fn()

    def launch_item(self, item):
        kind, key = item.data(ROLE_KIND), item.data(ROLE_KEY)
        if kind in (None, "header") or not self.isVisible():
            return
        if time.monotonic() - self._launched_at < 0.5:
            return                       # un double-clic ne lance pas deux fois
        self._launched_at = time.monotonic()
        if kind == "pane":
            self._run(lambda: open_pane(key))
        elif kind == "doc":
            self._run(lambda: open_path(key))
        else:
            self._run(lambda: self.bar.launch_key(key))

    def item_menu(self, view, pos):
        item = view.itemAt(pos)
        if item is None or item.data(ROLE_KIND) in (None, "header", "pane"):
            return
        kind, key = item.data(ROLE_KIND), item.data(ROLE_KEY)
        menu = make_menu(self)
        if kind == "doc":
            add_action(menu, "Ouvrir", lambda: self._run(lambda: open_path(key)))
            add_action(menu, "Ouvrir l'emplacement du fichier", lambda: self._run(lambda: reveal_file(key)), "folder")
        else:
            bar = self.bar
            if key in bar.start_pins:
                add_action(menu, "Détacher du menu Démarrer", lambda: (bar.unpin("start", key), self.fill_home()))
                if bar.start_pins.index(key) > 0:
                    add_action(menu, "Déplacer en premier", lambda: (bar.move_first("start", key), self.fill_home()))
            else:
                add_action(menu, "Épingler au menu Démarrer", lambda: bar.pin("start", key))
            if key in bar.pins:
                add_action(menu, "Détacher de la barre des tâches", lambda: bar.unpin("taskbar", key))
            else:
                add_action(menu, "Épingler à la barre des tâches", lambda: bar.pin("taskbar", key))
            if kind == "app":
                menu.addSeparator()
                add_action(menu, "Ouvrir l'emplacement du fichier", lambda: self._run(lambda: reveal_file(key)), "folder")
        menu.exec(view.viewport().mapToGlobal(pos))
        menu.deleteLater()

    def power_menu(self):
        menu = make_menu(self)
        add_action(menu, "Mettre en veille", lambda: self._run(lambda: spawn([CMD["pmset"], "sleepnow"])),
                   glyph_icon("moon", Theme.c("text")))
        btn = self.foot_buttons[-1]
        size = menu.sizeHint()
        top = btn.mapToGlobal(QPoint(btn.width() // 2, 0))
        menu.exec(QPoint(top.x() - size.width() // 2, top.y() - size.height() - 6))
        menu.deleteLater()


class MonthGrid(QWidget):
    """Mois du calendrier, dessiné comme celui de Windows 11."""
    CELL = 44

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMouseTracking(True)
        today = QDate.currentDate()
        self.year, self.month = today.year(), today.month()
        self.hover = None
        self.setFixedSize(7 * self.CELL, 30 + 6 * self.CELL)

    def first_cell_date(self):
        first = QDate(self.year, self.month, 1)
        return first.addDays(-(first.dayOfWeek() - 1))

    def shift(self, months):
        d = QDate(self.year, self.month, 1).addMonths(months)
        self.year, self.month = d.year(), d.month()
        self.update()

    def go_today(self):
        today = QDate.currentDate()
        self.year, self.month = today.year(), today.month()
        self.update()

    def mouseMoveEvent(self, ev):
        pos = ev.position().toPoint()
        cell = None
        if pos.y() >= 30:
            cell = ((pos.y() - 30) // self.CELL) * 7 + pos.x() // self.CELL
        if cell != self.hover:
            self.hover = cell
            self.update()

    def leaveEvent(self, _ev):
        self.hover = None
        self.update()

    def wheelEvent(self, ev):
        self.shift(-1 if ev.angleDelta().y() > 0 else 1)
        if isinstance(self.parent(), QWidget):
            self.parent().update()
        cb = getattr(self, "on_change", None)
        if cb:
            cb()

    def paintEvent(self, _ev):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        font = QFont(self.font())
        font.setPixelSize(13)
        p.setFont(font)
        for i, name in enumerate(("lu", "ma", "me", "je", "ve", "sa", "di")):
            p.setPen(Theme.c("text"))
            p.drawText(QRect(i * self.CELL, 0, self.CELL, 30), Qt.AlignmentFlag.AlignCenter, name)
        day = self.first_cell_date()
        today = QDate.currentDate()
        for cell in range(42):
            row, col = divmod(cell, 7)
            rect = QRect(col * self.CELL, 30 + row * self.CELL, self.CELL, self.CELL)
            center = QRectF(rect).center()
            if day == today:
                p.setPen(Qt.PenStyle.NoPen)
                p.setBrush(Theme.c("accent"))
                p.drawEllipse(center, 18, 18)
                p.setPen(Theme.c("on_accent"))
            else:
                if cell == self.hover:
                    p.setPen(Qt.PenStyle.NoPen)
                    p.setBrush(Theme.c("hover_menu"))
                    p.drawEllipse(center, 18, 18)
                p.setPen(Theme.c("text") if day.month() == self.month else Theme.c("dim"))
            p.drawText(rect, Qt.AlignmentFlag.AlignCenter, str(day.day()))
            day = day.addDays(1)


class CalendarFlyout(Flyout):
    def __init__(self, bar):
        super().__init__(bar)
        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 10)
        v.setSpacing(0)
        self.date_btn = QPushButton()
        self.date_btn.setObjectName("flat")
        font = self.date_btn.font()
        font.setPixelSize(14)
        font.setWeight(QFont.Weight.DemiBold)
        self.date_btn.setFont(font)
        self.date_btn.clicked.connect(self._today)
        head = QHBoxLayout()
        head.setContentsMargins(10, 10, 10, 10)
        head.addWidget(self.date_btn)
        head.addStretch(1)
        v.addLayout(head)
        v.addWidget(hline())
        row = QHBoxLayout()
        row.setContentsMargins(20, 10, 10, 4)
        self.month_lab = QLabel()
        self.month_lab.setObjectName("section")
        row.addWidget(self.month_lab)
        row.addStretch(1)
        self.arrows = []
        for direction, step in (("up", -1), ("down", 1)):
            b = QToolButton()
            b.setObjectName("flat")
            b.setFixedSize(32, 32)
            b.setProperty("glyph", direction)
            b.clicked.connect(lambda _c=False, s=step: self._shift(s))
            row.addWidget(b)
            self.arrows.append(b)
        v.addLayout(row)
        self.grid = MonthGrid(self)
        self.grid.on_change = self._labels
        gl = QHBoxLayout()
        gl.setContentsMargins(12, 0, 12, 0)
        gl.addWidget(self.grid)
        v.addLayout(gl)

    def open(self):
        for b in self.arrows:
            b.setIcon(glyph_icon("chevron", Theme.c("text"), direction=b.property("glyph")))
        self.grid.go_today()
        self._labels()
        self.popup_at(self.bar.flyout_rect("calendar", self.sizeHint()))

    def _labels(self):
        text = FRENCH.toString(QDate.currentDate(), "dddd d MMMM")
        self.date_btn.setText(text[:1].upper() + text[1:])
        month = FRENCH.toString(QDate(self.grid.year, self.grid.month, 1), "MMMM yyyy")
        self.month_lab.setText(month[:1].upper() + month[1:])

    def _shift(self, step):
        self.grid.shift(step)
        self._labels()

    def _today(self):
        self.grid.go_today()
        self._labels()


class QuickFlyout(Flyout):
    """Réglages rapides : raccourcis vers les Réglages Système, volume et batterie."""
    footer_h = 48

    def __init__(self, bar):
        super().__init__(bar)
        self.setFixedWidth(360)
        v = QVBoxLayout(self)
        v.setContentsMargins(20, 20, 20, 0)
        v.setSpacing(14)
        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(4)
        self.tiles = []
        tiles = (("wifi", "Réseau", "com.apple.Network-Settings.extension"),
                 ("headphones", "Bluetooth", "com.apple.BluetoothSettings"),
                 ("moon", "Concentration", "com.apple.Focus-Settings.extension"),
                 ("display", "Écrans", "com.apple.Displays-Settings.extension"),
                 ("dock", "Bureau et Dock", "com.apple.Desktop-Settings.extension"),
                 ("access", "Accessibilité", "com.apple.Accessibility-Settings.extension"))
        for i, (icon, label, pane) in enumerate(tiles):
            b = QToolButton()
            b.setObjectName("tile")
            b.setFixedSize(98, 48)
            b.setIconSize(QSize(18, 18))
            b.setProperty("glyph", icon)
            b.setToolTip(f"Ouvrir les réglages « {label} »")
            b.clicked.connect(lambda _c=False, pn=pane: self._run(lambda: open_pane(pn)))
            lab = QLabel(label)
            lab.setObjectName("sub")
            lab.setAlignment(Qt.AlignmentFlag.AlignHCenter)
            row, col = divmod(i, 3)
            grid.addWidget(b, row * 2, col, Qt.AlignmentFlag.AlignHCenter)
            grid.addWidget(lab, row * 2 + 1, col, Qt.AlignmentFlag.AlignHCenter)
            self.tiles.append(b)
        v.addLayout(grid)
        vol = QHBoxLayout()
        vol.setSpacing(8)
        self.mute_btn = QToolButton()
        self.mute_btn.setObjectName("flat")
        self.mute_btn.setFixedSize(36, 36)
        self.mute_btn.setIconSize(QSize(18, 18))
        self.mute_btn.clicked.connect(self._toggle_mute)
        self.slider = QSlider(Qt.Orientation.Horizontal)
        self.slider.setRange(0, 100)
        self.slider.valueChanged.connect(self._volume_changed)
        self.vol_lab = QLabel("")
        self.vol_lab.setFixedWidth(30)
        vol.addWidget(self.mute_btn)
        vol.addWidget(self.slider, 1)
        vol.addWidget(self.vol_lab)
        v.addLayout(vol)
        v.addSpacing(6)
        foot = QWidget()
        foot.setFixedHeight(self.footer_h)
        fl = QHBoxLayout(foot)
        fl.setContentsMargins(4, 0, 0, 0)
        self.battery_lab = QLabel("")
        self.battery_icon = QLabel()
        fl.addWidget(self.battery_icon)
        fl.addWidget(self.battery_lab)
        fl.addStretch(1)
        self.gear = QToolButton()
        self.gear.setObjectName("flat")
        self.gear.setFixedSize(36, 36)
        self.gear.setIconSize(QSize(18, 18))
        self.gear.setToolTip("Réglages Système")
        self.gear.clicked.connect(lambda: self._run(lambda: open_app(SYSTEM_SETTINGS)))
        fl.addWidget(self.gear)
        v.addWidget(foot)

    def _run(self, fn):
        self.close_flyout()
        fn()

    def open(self):
        net = self.bar.status.get("network") or "wifi"
        for b in self.tiles:
            name = b.property("glyph")
            if name == "wifi":
                name = {"wifi": "wifi", "ethernet": "ethernet"}.get(net, "offline")
            b.setIcon(glyph_icon(name, Theme.c("text")))
        self.gear.setIcon(glyph_icon("gear", Theme.c("text")))
        self.sync()
        self.adjustSize()
        self.popup_at(self.bar.flyout_rect("quick", self.sizeHint()))

    def sync(self):
        vol = NATIVE.volume()
        self.slider.blockSignals(True)
        if vol is None:
            self.slider.setEnabled(False)
            self.mute_btn.setEnabled(False)
            self.vol_lab.setText("")
            level, muted = 0, False
        else:
            level, muted = int(round(vol[0] * 100)), vol[1]
            self.slider.setEnabled(True)
            self.mute_btn.setEnabled(True)
            self.slider.setValue(level)
            self.vol_lab.setText(str(level))
        self.slider.blockSignals(False)
        self.mute_btn.setIcon(glyph_icon("speaker", Theme.c("text"), level=level, muted=muted))
        bat = self.bar.status.get("battery")
        if bat:
            pm = QPixmap(20, 20)
            pm.fill(Qt.GlobalColor.transparent)
            p = QPainter(pm)
            glyph(p, "battery", QRectF(0, 0, 20, 20), Theme.c("text"), percent=bat["percent"], charging=bat["charging"])
            p.end()
            self.battery_icon.setPixmap(pm)
            state = " (en charge)" if bat["charging"] else (" (branché)" if bat["plugged"] else "")
            self.battery_lab.setText(f"{bat['percent']} %{state}")
        else:
            self.battery_icon.clear()
            self.battery_lab.setText("")

    def _volume_changed(self, value):
        NATIVE.set_volume(value / 100.0)
        self.vol_lab.setText(str(value))
        self.mute_btn.setIcon(glyph_icon("speaker", Theme.c("text"), level=value, muted=False))
        self.bar.read_volume()

    def _toggle_mute(self):
        vol = NATIVE.volume()
        if vol is not None:
            NATIVE.set_muted(not vol[1])
            self.sync()
            self.bar.read_volume()


class TaskbarSettings(QWidget):
    """Paramètres de la barre des tâches, présentés comme dans Windows 11."""

    def __init__(self, bar):
        super().__init__(None, Qt.WindowType.Window)
        self.bar = bar
        self.setObjectName("settings")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground)
        self.setWindowTitle("Paramètres de la barre des tâches")
        self.resize(620, 800)
        self.setMinimumSize(560, 760)
        v = QVBoxLayout(self)
        v.setContentsMargins(36, 28, 36, 24)
        v.setSpacing(6)
        title = QLabel("Personnalisation  ›  Barre des tâches")
        title.setObjectName("pageTitle")
        v.addWidget(title)
        v.addSpacing(14)

        def section(text):
            lab = QLabel(text)
            lab.setObjectName("section")
            v.addSpacing(8)
            v.addWidget(lab)

        def card(icon, text, sub, control):
            frame = QFrame()
            frame.setObjectName("card")
            h = QHBoxLayout(frame)
            h.setContentsMargins(16, 10, 16, 10)
            h.setSpacing(14)
            ic = QLabel()
            ic.setPixmap(glyph_icon(icon, Theme.c("text")).pixmap(20, 20))
            h.addWidget(ic)
            col = QVBoxLayout()
            col.setSpacing(0)
            col.addWidget(QLabel(text))
            if sub:
                s = QLabel(sub)
                s.setObjectName("dim")
                s.setWordWrap(True)
                col.addWidget(s)
            h.addLayout(col, 1)
            h.addWidget(control)
            v.addWidget(frame)

        section("Éléments de la barre des tâches")
        self.search_combo = QComboBox()
        self.search_combo.addItems(["Masquer", "Icône de recherche uniquement", "Zone de recherche"])
        self.search_combo.setCurrentIndex({"hidden": 0, "icon": 1, "box": 2}.get(opt("search"), 2))
        self.search_combo.currentIndexChanged.connect(
            lambda i: self._set("search", ("hidden", "icon", "box")[i]))
        card("search", "Rechercher", "", self.search_combo)
        self.tv = Toggle(opt("taskview"))
        self.tv.toggled.connect(lambda on: self._set("taskview", on))
        card("taskview", "Vue des tâches", "Ouvre Mission Control", self.tv)

        section("Comportements de la barre des tâches")
        self.align_combo = QComboBox()
        self.align_combo.addItems(["Centre", "Gauche"])
        self.align_combo.setCurrentIndex(0 if opt("align") == "center" else 1)
        self.align_combo.currentIndexChanged.connect(lambda i: self._set("align", ("center", "left")[i]))
        card("dock", "Alignement de la barre des tâches", "", self.align_combo)
        self.finder = Toggle(opt("finder"))
        self.finder.toggled.connect(lambda on: self._set("finder", on))
        card("folder", "Afficher le Finder", "Le Finder tourne toujours : masqué par défaut", self.finder)
        self.docs = Toggle(opt("docs"))
        self.docs.toggled.connect(lambda on: self._set("docs", on))
        card("search", "Rechercher aussi dans mes documents",
             "Recherche locale (index Spotlight du Mac), rien ne sort de l'ordinateur", self.docs)
        self.name = Toggle(opt("show_name"))
        self.name.toggled.connect(lambda on: self._set("show_name", on))
        self.autohide = Toggle(opt("autohide"))
        self.autohide.toggled.connect(lambda on: self._set("autohide", on))
        card("dock", "Masquer automatiquement la barre des tâches",
             "Elle réapparaît quand la souris touche le bas de l'écran", self.autohide)
        self.screens = Toggle(opt("all_screens"))
        self.screens.toggled.connect(lambda on: self._set("all_screens", on))
        card("display", "Afficher ma barre des tâches sur tous les écrans", "", self.screens)
        card("user", "Afficher mon nom de compte dans Démarrer",
             "À couper avant de faire des captures d'écran", self.name)

        note = QLabel("Réglages du Dock (Réglages Système › Bureau et Dock) :\n"
                      "• barre toujours visible : Dock en bas, sans masquage automatique, à la hauteur de la "
                      "barre ; les fenêtres agrandies s'arrêtent au-dessus d'elle.\n"
                      "• barre masquée automatiquement : Dock sur le côté, avec masquage automatique ; "
                      "sinon il apparaît quand la barre se retire.")
        note.setObjectName("dim")
        note.setWordWrap(True)
        v.addSpacing(10)
        v.addWidget(note)
        v.addStretch(1)
        row = QHBoxLayout()
        self.versions = QLabel()
        self.versions.setObjectName("dim")
        self.versions.setToolTip(version_details())
        self.versions.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        row.addWidget(self.versions, 0, Qt.AlignmentFlag.AlignBottom)
        row.addStretch(1)
        quit_btn = QPushButton("Quitter la barre des tâches")
        quit_btn.setObjectName("pill")
        quit_btn.clicked.connect(quit_all)
        row.addWidget(quit_btn, 0, Qt.AlignmentFlag.AlignBottom)
        v.addLayout(row)

    def _set(self, name, value):
        set_opt(name, value)
        apply_all()

    def sync(self):
        """Remet chaque contrôle sur la valeur enregistrée (la fenêtre est réutilisée)."""
        self.versions.setText(versions_text())
        values = ((self.search_combo, {"hidden": 0, "icon": 1, "box": 2}.get(opt("search"), 2)),
                  (self.align_combo, 0 if opt("align") == "center" else 1))
        for combo, index in values:
            combo.blockSignals(True)
            combo.setCurrentIndex(index)
            combo.blockSignals(False)
        for toggle, name in ((self.tv, "taskview"), (self.finder, "finder"), (self.docs, "docs"),
                             (self.name, "show_name"), (self.autohide, "autohide"), (self.screens, "all_screens")):
            toggle.blockSignals(True)
            toggle.setChecked(opt(name))
            toggle.blockSignals(False)
            toggle.update()

    def closeEvent(self, ev):
        super().closeEvent(ev)
        bar = main_bar()
        if bar is not None:
            bar.note_self_activated()
            bar.restore_focus_soon()


# ======================================================================================
# La barre
# ======================================================================================

BTN_W, BTN_H, GAP = 44, 40, 2
SEARCH_W = 200
DESKTOP_W = 10
DEFAULT_H = 48


def bar_geometry(screen_geo, avail_geo):
    """Rectangle de la barre : par-dessus le Dock s'il est en bas, sinon 48 px en bas."""
    reserved = (screen_geo.y() + screen_geo.height()) - (avail_geo.y() + avail_geo.height())
    height = reserved if 30 <= reserved <= 96 else DEFAULT_H
    return QRect(screen_geo.x(), screen_geo.y() + screen_geo.height() - height, screen_geo.width(), height)


class Bar(QWidget):
    def __init__(self, backend=None, screen=None, main=True):
        flags = (Qt.WindowType.Tool | Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint
                 | Qt.WindowType.WindowDoesNotAcceptFocus | Qt.WindowType.NoDropShadowWindowHint)
        super().__init__(None, flags)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setAttribute(Qt.WidgetAttribute.WA_MacAlwaysShowToolWindow)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)
        self.setMouseTracking(True)
        self.setAcceptDrops(True)
        self.setWindowTitle(APP_NAME)
        self.backend = backend or NATIVE
        self.own_pid = os.getpid()
        self.entries, self.items = [], []
        self.hover = self.pressed = None
        self.front_pid = 0
        self._sig = None
        self._order, self._script_pids, self._ps_cache = [], {}, {}
        self._desktop_hidden, self._desktop_front = [], 0
        self._bounce = {}
        self._drag = None
        self._drag_x = 0
        self._press_pos = QPoint()
        self._quitting = False
        self._self_activated = False
        self._flyouts = {}
        self.flyout = None
        self._closed_at = ("", 0.0)
        self._buttons_prev = 0
        self._tick = 0
        self._autohidden = False            # masquage automatique : barre retirée
        self._edge_since = None
        self._leave_at = None
        self._hide_anims = []
        self.fixed_screen = screen          # None : suit le Dock (une seule barre)
        self.is_main = main                 # la principale porte les icônes réseau/son/batterie
        shared = shared_state()
        self.pins, self.start_pins = shared["pins"], shared["start_pins"]
        self.options, self.status = shared["options"], shared["status"]
        BARS.append(self)
        self.tip = Tip()
        self._tip_timer = QTimer(self)
        self._tip_timer.setSingleShot(True)
        self._tip_timer.setInterval(550)
        self._tip_timer.timeout.connect(self._show_tip)
        self.async_ = Async(self)
        self.async_.done.connect(self._on_async)
        self._fast = QTimer(self)
        self._fast.setInterval(40)
        self._fast.timeout.connect(self._poll_fast)
        self._slow = QTimer(self)
        self._slow.setInterval(1000)
        self._slow.timeout.connect(self._poll_slow)
        self._anim = QTimer(self)
        self._anim.setInterval(16)
        self._anim.timeout.connect(self._anim_tick)
        self._place_timer = QTimer(self)
        self._place_timer.setSingleShot(True)
        self._place_timer.setInterval(300)
        self._place_timer.timeout.connect(self.place)
        app = QGuiApplication.instance()
        app.screenAdded.connect(self._watch_screen)
        app.screenRemoved.connect(self._schedule_place)
        for screen in QGuiApplication.screens():
            self._watch_screen(screen)
        self.refresh(force=True)
        self.place()
        self.read_volume()
        self._status_timer = QTimer(self)
        self._status_timer.setInterval(30000)
        self._status_timer.timeout.connect(self.read_status)
        if self.is_main:
            self.read_status()
            self._status_timer.start()
        self._fast.start()
        self._slow.start()

    # --- position ---
    def _watch_screen(self, screen):
        screen.availableGeometryChanged.connect(self._schedule_place)
        screen.geometryChanged.connect(self._schedule_place)
        self._place_timer.start()

    def _schedule_place(self, *_args):
        self._place_timer.start()

    def target_screen(self):
        best, best_reserved = QGuiApplication.primaryScreen(), 0
        for screen in QGuiApplication.screens():
            g, a = screen.geometry(), screen.availableGeometry()
            reserved = (g.y() + g.height()) - (a.y() + a.height())
            if reserved > best_reserved:
                best, best_reserved = screen, reserved
        return best

    def place(self):
        screen = self.fixed_screen or self.target_screen()
        if screen is None:
            return
        rect = bar_geometry(screen.geometry(), screen.availableGeometry())
        if rect != self.geometry():
            self.setGeometry(rect)
        self.relayout()

    def showEvent(self, ev):
        super().showEvent(ev)
        QTimer.singleShot(0, self, lambda: self.backend.configure_window(self, "bar"))

    def resizeEvent(self, ev):
        super().resizeEvent(ev)
        self.relayout()

    # --- modèle ---
    def _key_for(self, app):
        if app.pid == self.own_pid:
            return None
        key = self._script_pids.get(app.pid)
        if key:
            return key
        if app.bundle_id == "com.apple.finder" and not self.options["finder"] and norm_app(FINDER) not in self.pins:
            return None
        bid, base = app.bundle_id.lower(), os.path.basename(app.path).lower()
        if bid.startswith("org.python") or base.startswith("python") or app.name.lower().startswith("python"):
            key = self._ps_cache.get(app.pid)
            if key is None:
                key = self._ps_cache[app.pid] = detect_script(app.pid) or f"pid:{app.pid}"
            return key
        if app.path.endswith(".app"):
            return norm_app(app.path)
        return f"pid:{app.pid}"

    def _new_entry(self, key, app):
        if key.startswith("script:"):
            return Entry(key, SCRIPTS[key][0], script_path(key), "script")
        if key.startswith("pid:"):
            return Entry(key, app.name or "Application", app.path, "process")
        return Entry(key, app.name or display_name(key), key, "app")

    def refresh(self, force=False):
        running = self.backend.running_apps()
        alive = {a.pid for a in running}
        self._ps_cache = {pid: k for pid, k in self._ps_cache.items() if pid in alive}
        self._script_pids = {pid: k for pid, k in self._script_pids.items() if pid in alive}
        groups = {}
        for app in running:
            key = self._key_for(app)
            if key is None:
                continue
            entry = groups.get(key)
            if entry is None:
                entry = groups[key] = self._new_entry(key, app)
            entry.pids.append(app.pid)
            entry.hidden_flags.append(app.hidden)
        for key in groups:
            if key not in self._order:
                self._order.append(key)
        self._order = [k for k in self._order if k in groups]
        entries = []
        for key in self.pins:
            entry = groups.get(key) or entry_for_key(key)
            if entry is None:
                continue
            entry.pinned = True
            entries.append(entry)
        entries += [groups[k] for k in self._order if k not in self.pins]
        self._update_front()
        for entry in entries:
            entry.hidden = bool(entry.pids) and all(entry.hidden_flags)
            entry.active = self.front_pid in entry.pids and not entry.hidden
        if self._desktop_hidden:
            back = {a.pid for a in running if not a.hidden}
            if back & set(self._desktop_hidden):
                self._desktop_hidden = []
        sig = tuple((e.key, tuple(e.pids), e.active, e.pinned, e.hidden, e.name) for e in entries)
        if force or sig != self._sig:
            self.entries, self._sig = entries, sig
            self.relayout()

    def _update_front(self):
        pid = self.backend.front_pid()
        if pid and pid != self.own_pid and pid != self.front_pid:
            self.front_pid = pid
            return True
        return False

    def note_self_activated(self):
        self._self_activated = True

    def restore_focus_soon(self):
        QTimer.singleShot(150, self, self._restore_focus)

    def _restore_focus(self):
        """Rend le focus à l'application d'avant si la barre l'avait pris."""
        if not self._self_activated:
            return
        if any(f.isVisible() for f in self._flyouts.values()):
            return
        if settings_window() is not None and settings_window().isVisible():
            return
        self._self_activated = False
        if self.backend.front_pid() == self.own_pid and self.front_pid:
            self.backend.activate_pid(self.front_pid)

    # --- mise en page ---
    def _clock_texts(self):
        now = QTime.currentTime()
        return now.toString("HH:mm"), QDate.currentDate().toString("dd/MM/yyyy")

    def _small_font(self):
        font = QFont(self.font())
        font.setPixelSize(12)
        return font

    def relayout(self):
        w, h = self.width(), self.height()
        if w <= 0 or h <= 0:
            return
        cy = h // 2
        top = cy - BTN_H // 2
        items = []
        x = w - DESKTOP_W
        items.append(Item("desktop", QRect(x, 0, DESKTOP_W, h)))
        fm = QFontMetrics(self._small_font())
        clock_w = max(fm.horizontalAdvance(t) for t in self._clock_texts()) + 24
        x -= clock_w + 4
        items.append(Item("clock", QRect(x, top, clock_w, BTN_H)))
        if self.is_main:                    # comme Windows : icônes système sur la barre principale
            tray_n = 3 if self.status.get("battery") else 2
            tray_w = tray_n * 22 + 14
            x -= tray_w + 4
            items.append(Item("tray", QRect(x, top, tray_w, BTN_H)))
        right_edge = x - 12

        fixed = [("start", BTN_W)]
        search_mode = self.options["search"]
        if search_mode == "box":
            fixed.append(("search", SEARCH_W))
        elif search_mode == "icon":
            fixed.append(("search", BTN_W))
        if self.options["taskview"]:
            fixed.append(("taskview", BTN_W))
        fixed_w = sum(fw for _k, fw in fixed) + GAP * len(fixed)
        apps = list(self.entries)
        capacity = max(0, (right_edge - 12 - fixed_w) // (BTN_W + GAP))
        overflow = []
        if len(apps) > capacity:
            keep = max(0, capacity - 1)
            apps, overflow = apps[:keep], apps[keep:]
        total = fixed_w + (len(apps) + (1 if overflow else 0)) * (BTN_W + GAP) - GAP
        if self.options["align"] == "center":
            x0 = (w - total) // 2
            x0 = min(x0, right_edge - total)
        else:
            x0 = 12
        x0 = max(12, x0)
        x = x0
        for kind, fw in fixed:
            rect = QRect(x, top, fw, BTN_H)
            if kind == "search" and fw == SEARCH_W:
                rect = QRect(x, cy - 17, fw, 34)
            items.append(Item(kind, rect))
            x += fw + GAP
        for entry in apps:
            items.append(Item("app", QRect(x, top, BTN_W, BTN_H), entry))
            x += BTN_W + GAP
        if overflow:
            item = Item("overflow", QRect(x, top, BTN_W, BTN_H))
            item.entry = overflow
            items.append(item)
        self.items = items
        self.hover = None if self.hover is None or self.hover >= len(items) else self.hover
        self.update()

    def item_at(self, pos):
        for i, item in enumerate(self.items):
            if item.rect.contains(pos):
                return i
        if pos.y() >= 0 and pos.x() >= self.width() - DESKTOP_W:
            return next((i for i, it in enumerate(self.items) if it.kind == "desktop"), None)
        return None

    # --- dessin ---
    def paintEvent(self, _ev):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        p.fillRect(self.rect(), Theme.c("bar"))
        p.fillRect(QRect(0, 0, self.width(), 1), Theme.c("bar_line"))
        for i, item in enumerate(self.items):
            if self._drag and item.kind == "app" and item.entry.key == self._drag:
                continue
            self._paint_item(p, i, item)
        if self._drag:
            self._paint_drag(p)
        p.end()

    def _flyout_open(self, name):
        fly = self._flyouts.get(name)
        return fly is not None and fly.isVisible()

    def _paint_bg(self, p, rect, i, active=False):
        color = None
        if self.pressed == i and self.hover == i:
            color = Theme.c("press")
        elif self.hover == i:
            color = Theme.c("hover")
        elif active:
            color = Theme.c("active")
        if color is not None:
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(color)
            p.drawRoundedRect(QRectF(rect), 4, 4)

    def _icon_rect(self, rect, i, size=24, key=None):
        scale = 0.86 if (self.pressed == i and self.hover == i) else 1.0
        s = size * scale
        dy = 0.0
        if key and key in self._bounce:
            t = time.monotonic() - self._bounce[key]
            if t < 0.45:
                dy = -5 * math.sin(math.pi * t / 0.45)
        c = QRectF(rect).center()
        return QRectF(c.x() - s / 2, c.y() - s / 2 + dy - 1, s, s)

    def _paint_item(self, p, i, item):
        kind, rect = item.kind, item.rect
        text = Theme.c("text")
        if kind == "start":
            self._paint_bg(p, rect, i, self._flyout_open("start"))
            glyph(p, "start", self._icon_rect(rect, i, 22))
        elif kind == "search":
            if rect.width() == SEARCH_W:
                r = QRectF(rect).adjusted(0.5, 0.5, -0.5, -0.5)
                p.setPen(QPen(Theme.c("field_border"), 1))
                p.setBrush(Theme.c("hover") if self.hover == i else Theme.c("search_box"))
                p.drawRoundedRect(r, r.height() / 2, r.height() / 2)
                glyph(p, "search", QRectF(r.x() + 14, r.center().y() - 8, 16, 16), Theme.c("sub"))
                font = QFont(self.font())
                font.setPixelSize(13)
                p.setFont(font)
                p.setPen(Theme.c("dim"))
                p.drawText(r.adjusted(40, 0, -8, 0), Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
                           "Rechercher")
            else:
                self._paint_bg(p, rect, i)
                glyph(p, "search", self._icon_rect(rect, i, 20), text)
        elif kind == "taskview":
            self._paint_bg(p, rect, i)
            glyph(p, "taskview", self._icon_rect(rect, i, 20), text)
        elif kind == "app":
            entry = item.entry
            self._paint_bg(p, rect, i, entry.active)
            icon_for(entry.key, entry.path).paint(p, self._icon_rect(rect, i, 24, entry.key).toRect())
            if entry.running:
                p.setPen(Qt.PenStyle.NoPen)
                if entry.active:
                    p.setBrush(Theme.c("accent"))
                    p.drawRoundedRect(QRectF(rect.center().x() - 8, rect.bottom() - 2.5, 16, 3), 1.5, 1.5)
                else:
                    p.setBrush(Theme.c("running"))
                    p.drawRoundedRect(QRectF(rect.center().x() - 3, rect.bottom() - 2.5, 6, 3), 1.5, 1.5)
        elif kind == "overflow":
            self._paint_bg(p, rect, i)
            glyph(p, "dots", self._icon_rect(rect, i, 18), text)
        elif kind == "tray":
            self._paint_bg(p, rect, i, self._flyout_open("quick"))
            x = rect.x() + 9
            cy = rect.center().y()
            net = self.status.get("network")
            glyph(p, {"wifi": "wifi", "ethernet": "ethernet"}.get(net, "offline"), QRectF(x, cy - 8, 16, 16), text)
            vol = self.status.get("volume")
            level, muted = (int(vol[0] * 100), vol[1]) if vol else (60, False)
            glyph(p, "speaker", QRectF(x + 22, cy - 8, 16, 16), text, level=level, muted=muted)
            bat = self.status.get("battery")
            if bat:
                glyph(p, "battery", QRectF(x + 44, cy - 8, 16, 16), text,
                      percent=bat["percent"], charging=bat["charging"])
        elif kind == "clock":
            self._paint_bg(p, rect, i, self._flyout_open("calendar"))
            p.setFont(self._small_font())
            p.setPen(text)
            t, d = self._clock_texts()
            half = rect.height() // 2
            p.drawText(QRect(rect.x(), rect.y() + 3, rect.width(), half - 2),
                       Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignBottom, t)
            p.drawText(QRect(rect.x(), rect.y() + half + 1, rect.width(), half - 4),
                       Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop, d)
        elif kind == "desktop":
            if self.hover == i:
                p.fillRect(QRect(rect.x() + 2, rect.y() + 12, 1, rect.height() - 24), Theme.c("dim"))

    def _paint_drag(self, p):
        entry = next((it.entry for it in self.items if it.kind == "app" and it.entry.key == self._drag), None)
        if entry is None:
            return
        target = self._drop_index(self._drag_x, exclude=self._drag)
        pinned = [it for it in self.items if it.kind == "app" and it.entry.pinned and it.entry.key != self._drag]
        if pinned:
            if target < len(pinned):
                mx = pinned[target].rect.x() - GAP
            else:
                mx = pinned[-1].rect.right() + GAP
            p.fillRect(QRect(mx - 1, (self.height() - 28) // 2, 2, 28), Theme.c("accent"))
        rect = QRect(self._drag_x - BTN_W // 2, (self.height() - BTN_H) // 2, BTN_W, BTN_H)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(Theme.c("hover"))
        p.drawRoundedRect(QRectF(rect), 4, 4)
        icon_for(entry.key, entry.path).paint(p, QRect(rect.center().x() - 12, rect.center().y() - 12, 24, 24))

    def _drop_index(self, x, exclude=None):
        pinned = [it for it in self.items if it.kind == "app" and it.entry.pinned and it.entry.key != exclude]
        return sum(1 for it in pinned if it.rect.center().x() < x)

    # --- souris ---
    def _set_hover(self, idx):
        if idx != self.hover:
            self.hover = idx
            self.tip.hide()
            if idx is not None:
                self._tip_timer.start()
            else:
                self._tip_timer.stop()
            self.update()

    def _tip_text(self, item):
        kind = item.kind
        if kind == "start":
            return "Démarrer"
        if kind == "search":
            return "Rechercher"
        if kind == "taskview":
            return "Vue des tâches"
        if kind == "app":
            return item.entry.name
        if kind == "overflow":
            return "Afficher plus d'applications"
        if kind == "desktop":
            return "Afficher le bureau"
        if kind == "clock":
            text = FRENCH.toString(QDate.currentDate(), "dddd d MMMM yyyy")
            return text[:1].upper() + text[1:]
        if kind == "tray":
            net = {"wifi": "Wi-Fi : connecté", "ethernet": "Réseau : connecté"}.get(
                self.status.get("network"), "Pas d'accès réseau")
            lines = [net]
            vol = self.status.get("volume")
            if vol:
                lines.append("Son : muet" if vol[1] else f"Son : {int(round(vol[0] * 100))} %")
            bat = self.status.get("battery")
            if bat:
                lines.append(f"Batterie : {bat['percent']} %" + (" (en charge)" if bat["charging"] else ""))
            return "\n".join(lines)
        return ""

    def _show_tip(self):
        if self.hover is None or self.pressed is not None or self._drag or self.hover >= len(self.items):
            return
        if self.flyout is not None and self.flyout.isVisible():
            return
        item = self.items[self.hover]
        text = self._tip_text(item)
        if text:
            anchor = QRect(self.mapToGlobal(item.rect.topLeft()), item.rect.size())
            self.tip.show_text(text, anchor, self.geometry().y())

    def mousePressEvent(self, ev):
        if ev.button() == Qt.MouseButton.RightButton:
            return
        pos = ev.position().toPoint()
        self.pressed = self.item_at(pos)
        self.hover = self.pressed
        self._press_pos = pos
        self.tip.hide()
        self._tip_timer.stop()
        self.update()

    def mouseMoveEvent(self, ev):
        pos = ev.position().toPoint()
        if self.pressed is not None and ev.buttons() & Qt.MouseButton.LeftButton:
            item = self.items[self.pressed] if self.pressed < len(self.items) else None
            if (not self._drag and item is not None and item.kind == "app" and item.entry.pinned
                    and abs(pos.x() - self._press_pos.x()) > 6):
                self._drag = item.entry.key
            if self._drag:
                self._drag_x = pos.x()
                self.update()
                return
        self._set_hover(self.item_at(pos))

    def mouseReleaseEvent(self, ev):
        pos = ev.position().toPoint()
        if self._drag:
            self._finish_drag(pos.x())
            self.pressed = None
            return
        idx, pressed = self.item_at(pos), self.pressed
        self.pressed = None
        self.update()
        if idx is None or idx != pressed or idx >= len(self.items):
            return
        item = self.items[idx]
        if ev.button() == Qt.MouseButton.LeftButton:
            new = bool(ev.modifiers() & Qt.KeyboardModifier.ShiftModifier)
            self.activate_item(item, new)
        elif ev.button() == Qt.MouseButton.MiddleButton and item.kind == "app":
            self.click_entry(item.entry, new=True)

    def leaveEvent(self, _ev):
        if self.pressed is None:
            self._set_hover(None)

    def wheelEvent(self, ev):
        idx = self.item_at(ev.position().toPoint())
        if idx is not None and self.items[idx].kind == "tray":
            vol = self.backend.volume()
            if vol is not None:
                step = 0.02 if ev.angleDelta().y() > 0 else -0.02
                self.backend.set_volume(max(0.0, min(1.0, vol[0] + step)))
                self.read_volume()

    def contextMenuEvent(self, ev):
        idx = self.item_at(ev.pos())
        self.pressed = None
        item = self.items[idx] if idx is not None else None
        self.tip.hide()
        if item is None:
            self.empty_menu(ev.globalPos())
        elif item.kind == "app":
            self.app_menu(item)
        elif item.kind == "start":
            self.start_context(item)
        elif item.kind == "tray":
            self.tray_menu(item)
        elif item.kind == "clock":
            self._menu_above(item, [("Ajuster la date et l'heure",
                                     lambda: open_pane("com.apple.Date-Time-Settings.extension"), None)])
        else:
            self.empty_menu(ev.globalPos())

    def _poll_fast(self):
        self._tick += 1
        if self._tick % 6 == 0 and self._update_front():
            self.refresh(force=True)
        pos = QCursor.pos()
        geo = self.geometry()
        near = geo.adjusted(0, -160, 0, 0).contains(pos)
        if self.options.get("autohide"):
            self.autohide_tick(pos, time.monotonic())
        elif self._autohidden:
            self.reveal()
        if self._autohidden:
            interval = 40 if near else 150
            if self._fast.interval() != interval:
                self._fast.setInterval(interval)
            return
        if geo.contains(pos):
            if self.pressed is None and not self._drag:
                self._set_hover(self.item_at(pos - geo.topLeft()))
        elif self.hover is not None and self.pressed is None:
            self._set_hover(None)
        fly = self.flyout
        busy = fly is not None and fly.isVisible()
        if busy:
            buttons = self.backend.mouse_buttons()
            if buttons and not self._buttons_prev and QApplication.activePopupWidget() is None:
                if not fly.geometry().contains(pos) and not geo.contains(pos):
                    fly.close_flyout()
            self._buttons_prev = buttons
            fly.check_focus()
        else:
            self._buttons_prev = 0
        interval = 40 if (near or busy or self._drag) else 150
        if self._fast.interval() != interval:
            self._fast.setInterval(interval)

    # --- masquage automatique (comme le Dock) ---
    def _keep_visible(self):
        fly = self.flyout
        return ((fly is not None and fly.isVisible()) or self.pressed is not None or bool(self._drag)
                or QApplication.activePopupWidget() is not None)

    def autohide_tick(self, pos, now):
        """Appelé ~25 fois par seconde : sort la barre au bord, la range quand on s'en va."""
        geo = self.geometry()
        if self._autohidden:
            at_edge = geo.left() <= pos.x() <= geo.right() and geo.bottom() - 1 <= pos.y() <= geo.bottom() + 1
            if not at_edge:
                self._edge_since = None
            elif self._edge_since is None:
                self._edge_since = now
            elif now - self._edge_since >= 0.06:
                self.reveal()
            return
        if geo.adjusted(0, -6, 0, 0).contains(pos) or self._keep_visible():
            self._leave_at = None
        elif self._leave_at is None:
            self._leave_at = now
        elif now - self._leave_at >= 0.6:
            self.conceal()

    def _stop_hide_anims(self):
        for group in self._hide_anims:
            group.stop()
        self._hide_anims = []

    def _slide(self, start, end, fade_from, fade_to, curve, on_done=None):
        group = QParallelAnimationGroup(self)
        fade = QPropertyAnimation(self, b"windowOpacity", group)
        fade.setDuration(150)
        fade.setStartValue(fade_from)
        fade.setEndValue(fade_to)
        slide = QPropertyAnimation(self, b"pos", group)
        slide.setDuration(160)
        slide.setStartValue(start)
        slide.setEndValue(end)
        slide.setEasingCurve(curve)
        group.addAnimation(fade)
        group.addAnimation(slide)
        if on_done:
            group.finished.connect(on_done)   # une fois les DEUX animations terminées
        self._hide_anims = [group]
        group.start()

    def conceal(self):
        if self._autohidden:
            return
        self._autohidden, self._leave_at, self._edge_since = True, None, None
        self.tip.hide()
        self._tip_timer.stop()
        self._set_hover(None)
        self._stop_hide_anims()
        start = self._home = self.pos()

        def done():
            if self._autohidden:
                self.hide()                 # cachée pour de bon : elle ne capte plus aucun clic
                self.move(start)
                self.setWindowOpacity(1.0)
        # Elle s'efface sur place (Qt réapplique la dernière position après l'animation :
        # glisser vers le bas la laisserait décalée).
        self._slide(start, start, 1.0, 0.0, QEasingCurve.Type.InCubic, done)

    def reveal(self):
        if not self._autohidden:
            return
        self._autohidden, self._leave_at, self._edge_since = False, None, None
        self._stop_hide_anims()
        if getattr(self, "_home", None) is not None:
            self.move(self._home)           # au cas où l'animation de sortie n'était pas finie
        self.place()                        # et si l'écran a changé entre-temps, on se recale
        target = self.pos()
        self.setWindowOpacity(0.0)
        self.move(target + QPoint(0, 12))
        self.show()
        self._slide(target + QPoint(0, 12), target, 0.0, 1.0, QEasingCurve.Type.OutCubic)

    def _poll_slow(self):
        self.refresh()
        self.read_volume()
        reap_children()
        minute = QTime.currentTime().minute()
        if getattr(self, "_minute", None) != minute:
            self._minute = minute
            self.relayout()
        self._slow_ticks = getattr(self, "_slow_ticks", 0) + 1
        if self._slow_ticks % 2 == 0:
            self.backend.configure_window(self, "bar")
        if self._slow_ticks % 60 == 0:
            problems = controle_reseau()
            if problems:
                print("[verrou] bibliothèque réseau détectée, arrêt : " + ", ".join(problems), file=sys.stderr)
                self.quit_bar()

    def _anim_tick(self):
        now = time.monotonic()
        self._bounce = {k: t for k, t in self._bounce.items() if now - t < 0.45}
        if not self._bounce:
            self._anim.stop()
        self.update()

    def bounce(self, key):
        self._bounce[key] = time.monotonic()
        self._anim.start()

    # --- état (son, réseau, batterie) ---
    def read_volume(self):
        vol = self.backend.volume()
        if vol != self.status.get("volume"):
            self.status["volume"] = vol
            self.update()

    def read_status(self):
        self.async_.run("battery", read_battery)
        self.async_.run("network", read_network)

    def _on_async(self, key, result):
        if key in ("battery", "network") and result != self.status.get(key):
            if key == "network" and result is None:
                return
            self.status[key] = result
            for bar in list(BARS) or [self]:
                bar.relayout()

    # --- actions ---
    def activate_item(self, item, new=False):
        kind = item.kind
        self.tip.hide()
        if kind == "start":
            self.toggle_flyout("start")
        elif kind == "search":
            self.toggle_flyout("start")
        elif kind == "taskview":
            open_app(MISSION_CONTROL)
        elif kind == "app":
            self.click_entry(item.entry, new)
        elif kind == "overflow":
            self.overflow_menu(item)
        elif kind == "tray":
            self.toggle_flyout("quick")
        elif kind == "clock":
            self.toggle_flyout("calendar")
        elif kind == "desktop":
            self.toggle_desktop()

    def click_entry(self, entry, new=False):
        """Clic sur une application, comme sous Windows."""
        self._desktop_hidden = []
        if new or not entry.running:
            self.launch_entry(entry, new)
        elif entry.active:
            for pid in entry.pids:                      # déjà au premier plan : on la réduit
                self.backend.hide_app(pid)
        else:
            self.bring_front(entry)
        QTimer.singleShot(200, self, lambda: self.refresh(force=True))
        QTimer.singleShot(900, self, lambda: self.refresh(force=True))

    def launch_entry(self, entry, new=False):
        if entry.kind == "script":
            proc = run_script(entry.key)
            if proc is not None:
                self._script_pids[proc.pid] = entry.key
        elif entry.kind == "app":
            open_app(entry.path)
        elif entry.pids:
            self.backend.activate_pid(entry.pids[0])
            return
        self.bounce(entry.key)
        for delay in (300, 900, 2000):
            QTimer.singleShot(delay, self, lambda: self.refresh(force=True))

    def launch_key(self, key):
        """Ouverture depuis Démarrer : lance, ou ramène au premier plan (sans jamais réduire)."""
        entry = next((e for e in self.entries if e.key == key), None) or entry_for_key(key)
        if entry is None:
            if not key.startswith("script:"):
                open_app(key)
            return
        if not entry.running or entry.kind == "script":
            self.launch_entry(entry, new=entry.running)      # l'explorateur : nouvelle fenêtre
        else:
            self.bring_front(entry)

    def bring_front(self, entry):
        for pid in entry.pids:
            self.backend.unhide_app(pid)
        if entry.kind == "app":
            open_app(entry.path)                        # comme un clic dans le Dock
        else:
            pid = entry.pids[0]
            self.backend.activate_pid(pid)
            # macOS 14 peut ignorer la demande d'une appli en arrière-plan : on réessaie
            # en passant d'abord par la barre (c'est l'utilisateur qui a cliqué).
            QTimer.singleShot(250, self, lambda: self._activate_retry(pid))
        self.front_pid = entry.pids[0]

    def _activate_retry(self, pid):
        if self.backend.front_pid() != pid:
            self.backend.activate_self()
            self.backend.activate_pid(pid)

    def toggle_desktop(self):
        """Afficher le bureau, puis un second clic remet tout comme avant."""
        if self._desktop_hidden:
            for pid in self._desktop_hidden:
                self.backend.unhide_app(pid)
            if self._desktop_front:
                self.backend.activate_pid(self._desktop_front)
            self._desktop_hidden = []
        else:
            visible = [a.pid for a in self.backend.running_apps() if not a.hidden and a.pid != self.own_pid]
            if not visible:
                return
            self._desktop_front = self.front_pid
            for pid in visible:
                self.backend.hide_app(pid)
            self._desktop_hidden = visible
        QTimer.singleShot(250, self, lambda: self.refresh(force=True))

    # --- épingles ---
    def _pins(self, which):
        return self.pins if which == "taskbar" else self.start_pins

    def pin(self, which, key, index=None):
        pins = self._pins(which)
        if key in pins:
            return
        pins.insert(len(pins) if index is None else index, key)
        set_pins(which, pins)
        refresh_all()

    def unpin(self, which, key):
        pins = self._pins(which)
        if key in pins:
            pins.remove(key)
            set_pins(which, pins)
            refresh_all()

    def move_first(self, which, key):
        pins = self._pins(which)
        if key in pins:
            pins.remove(key)
            pins.insert(0, key)
            set_pins(which, pins)

    def _finish_drag(self, x):
        key, self._drag = self._drag, None
        index = self._drop_index(x, exclude=key)
        if key in self.pins:
            self.pins.remove(key)
            self.pins.insert(index, key)
            set_pins("taskbar", self.pins)
        refresh_all()

    @staticmethod
    def app_paths(mime):
        out = []
        for url in mime.urls() if mime.hasUrls() else []:
            if url.isLocalFile():
                path = url.toLocalFile().rstrip("/")
                if path.endswith(".app") and os.path.isdir(path):
                    out.append(norm_app(path))
        return out

    def dragEnterEvent(self, ev):
        if self.app_paths(ev.mimeData()):
            ev.acceptProposedAction()

    def dragMoveEvent(self, ev):
        if self.app_paths(ev.mimeData()):
            ev.acceptProposedAction()

    def dropEvent(self, ev):
        paths = self.app_paths(ev.mimeData())
        if not paths:
            return
        index = self._drop_index(ev.position().toPoint().x())
        for path in paths:
            if path not in self.pins:
                self.pins.insert(index, path)
                index += 1
        set_pins("taskbar", self.pins)
        ev.acceptProposedAction()
        refresh_all()

    # --- menus ---
    def _menu_above(self, item, actions, menu=None):
        menu = menu or make_menu(self)
        for text, fn, icon in actions:
            if text is None:
                menu.addSeparator()
            else:
                add_action(menu, text, fn, icon)
        size = menu.sizeHint()
        center = self.mapToGlobal(item.rect.center())
        x = center.x() - size.width() // 2
        menu.exec(QPoint(x, self.geometry().y() - size.height() - 8))
        menu.deleteLater()

    def app_menu(self, item):
        entry = item.entry
        actions = []
        if entry.kind != "process":
            actions.append((entry.name, lambda: self.click_entry(entry, new=True), icon_for(entry.key, entry.path)))
        if entry.kind in ("app", "script"):
            if entry.pinned:
                actions.append(("Détacher de la barre des tâches", lambda: self.unpin("taskbar", entry.key), None))
            else:
                actions.append(("Épingler à la barre des tâches", lambda: self.pin("taskbar", entry.key), None))
        if entry.running:
            actions.append(("Fermer toutes les fenêtres", lambda: self.quit_entry(entry), None))
        self._menu_above(item, actions)

    def quit_entry(self, entry):
        for pid in entry.pids:
            self.backend.quit_app(pid)
        QTimer.singleShot(600, self, lambda: self.refresh(force=True))

    def start_context(self, item):
        explorer = lambda: self.launch_key("script:explorateur")  # noqa: E731
        self._menu_above(item, [
            ("Applications installées", lambda: open_path("/Applications"), None),
            ("Moniteur d'activité", lambda: open_app(ACTIVITY_MONITOR), None),
            ("Paramètres", lambda: open_app(SYSTEM_SETTINGS), None),
            ("Explorateur de fichiers", explorer, None),
            ("Rechercher", lambda: self.toggle_flyout("start"), None),
            ("Terminal", lambda: open_app(TERMINAL), None),
            (None, None, None),
            ("Mettre en veille", lambda: spawn([CMD["pmset"], "sleepnow"]), None),
            (None, None, None),
            ("Bureau", self.toggle_desktop, None),
        ])

    def tray_menu(self, item):
        actions = [("Paramètres réseau", lambda: open_pane("com.apple.Network-Settings.extension"), None),
                   ("Paramètres du son", lambda: open_pane("com.apple.Sound-Settings.extension"), None)]
        if self.status.get("battery"):
            actions.append(("Paramètres de la batterie", lambda: open_pane("com.apple.Battery-Settings.extension"), None))
        self._menu_above(item, actions)

    def empty_menu(self, global_pos):
        menu = make_menu(self)
        add_action(menu, "Moniteur d'activité", lambda: open_app(ACTIVITY_MONITOR))
        add_action(menu, "Paramètres de la barre des tâches", self.open_settings, "gear")
        menu.addSeparator()
        add_action(menu, "Quitter la barre des tâches", self.quit_bar)
        menu.addSeparator()
        add_action(menu, f"{APP_NAME} {VERSION}", lambda: None, enabled=False)
        size = menu.sizeHint()
        menu.exec(QPoint(global_pos.x(), self.geometry().y() - size.height() - 8))
        menu.deleteLater()

    def overflow_menu(self, item):
        menu = make_menu(self)
        for entry in item.entry:
            add_action(menu, entry.name, lambda e=entry: self.click_entry(e), icon_for(entry.key, entry.path))
        self._menu_above(item, [], menu)

    # --- panneaux ---
    def flyout_rect(self, name, size):
        bar = self.geometry()
        screen = (self.screen() or QGuiApplication.primaryScreen()).availableGeometry()
        w = size.width()
        h = min(size.height(), bar.y() - screen.y() - 24)
        if name == "start":
            x = bar.center().x() - w // 2 if self.options["align"] == "center" else bar.x() + 12
        else:
            x = bar.right() - w - 12
        return QRect(x, bar.y() - h - 12, w, h)

    def toggle_flyout(self, name):
        fly = self._flyouts.get(name)
        if fly is not None and fly.isVisible():
            fly.close_flyout()
            return
        last, when = self._closed_at
        if last == name and time.monotonic() - when < 0.3:
            return              # le clic qui vient de le fermer ne doit pas le rouvrir
        if self.flyout is not None and self.flyout.isVisible():
            self.flyout.close_flyout()
        if fly is None:
            fly = {"start": StartMenu, "calendar": CalendarFlyout, "quick": QuickFlyout}[name](self)
            fly.closed.connect(lambda n=name: self._on_flyout_closed(n))
            self._flyouts[name] = fly
        self.flyout = fly
        fly.open()
        self.update()

    def _on_flyout_closed(self, name):
        self._closed_at = (name, time.monotonic())
        self.update()
        self.restore_focus_soon()

    def open_settings(self):
        if not _SETTINGS:
            _SETTINGS.append(TaskbarSettings(self))
        win = _SETTINGS[0]
        win.sync()
        win.show()
        self.backend.configure_window(win, "dialog")
        self.backend.activate_self()
        win.raise_()
        win.activateWindow()
        self.note_self_activated()

    def apply_settings(self):
        apply_all()

    def retheme(self):
        for key in [k for k in _ICONS if k.startswith("script:")]:
            _ICONS.pop(key, None)
        for fly in self._flyouts.values():
            if hasattr(fly, "retheme"):
                fly.retheme()
            fly.update()
        if _SETTINGS:
            win = _SETTINGS.pop()
            win.close()
            win.deleteLater()
        self.update()

    def quit_bar(self):
        quit_all()

    def dispose(self):
        """Retire cette barre (écran débranché ou réglage changé)."""
        if self in BARS:
            BARS.remove(self)
        self._quitting = True
        for timer in (self._fast, self._slow, self._anim, self._place_timer, self._tip_timer, self._status_timer):
            timer.stop()
        self._stop_hide_anims()
        for fly in self._flyouts.values():
            fly.hide()
            fly.deleteLater()
        self._flyouts.clear()
        self.flyout = None
        self.tip.hide()
        self.tip.deleteLater()
        self.hide()
        self.deleteLater()

    def closeEvent(self, ev):
        # Cmd+Q ne ferme pas la barre par accident : on passe par « Quitter la barre des tâches ».
        if self._quitting:
            ev.accept()
        else:
            ev.ignore()


class Taskbars(QObject):
    """Une barre sur chaque écran (réglage Windows « sur tous les écrans »), ou une seule."""

    def __init__(self, backend):
        super().__init__()
        self.backend = backend
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(400)
        self._timer.timeout.connect(self.sync)
        app = QGuiApplication.instance()
        app.screenAdded.connect(self._later)
        app.screenRemoved.connect(self._removed)
        app.primaryScreenChanged.connect(self._later)
        self.sync()

    def _later(self, *_args):
        self._timer.start()

    def _removed(self, screen):
        # L'écran va disparaître : sa barre part tout de suite.
        for bar in [b for b in BARS if b.fixed_screen is screen]:
            bar.dispose()
        self._timer.start()

    @staticmethod
    def wanted():
        screens = QGuiApplication.screens()
        if opt("all_screens") and len(screens) > 1:
            primary = QGuiApplication.primaryScreen()
            return [(s, s is primary) for s in screens]
        return [(None, True)]                 # une barre, qui suit le Dock

    def sync(self):
        wanted = self.wanted()
        current = [(b.fixed_screen, b.is_main) for b in BARS]
        if len(current) == len(wanted) and all(a is c and m == n for (a, m), (c, n) in zip(current, wanted)):
            return
        for bar in list(BARS):
            bar.dispose()
        for screen, main in wanted:
            bar = Bar(self.backend, screen, main)
            bar.show()

    def retheme(self):
        for bar in list(BARS):
            bar.retheme()


# ======================================================================================

def make_backend():
    if IS_MAC:
        try:
            return MacBackend()
        except (OSError, RuntimeError, AttributeError) as exc:
            print(f"[barre] mode simplifié ({exc})", file=sys.stderr)
    return Backend()


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
        etat = {True: "fichier intact", False: "FICHIER MODIFIÉ OU ABÎMÉ : à retélécharger",
                None: "fichier non vérifié"}[fichier_intact()]
        ecart = ecart_fichier() if fichier_intact() is False else ""
        print(f"{APP_NAME} {VERSION} du {VERSION_DATE} — {etat}" + (f" ({ecart})" if ecart else ""))
        return 0
    verifier_pyside()
    global NATIVE
    installer_verrou()
    if IS_MAC:
        # La barre ne doit pas devenir une application « normale » (icône du Dock, Cmd+Tab).
        os.environ["QT_MAC_DISABLE_FOREGROUND_APPLICATION_TRANSFORM"] = "1"
    app = QApplication([sys.argv[0]])
    os.environ.pop("QT_MAC_DISABLE_FOREGROUND_APPLICATION_TRANSFORM", None)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(VERSION)
    app.setOrganizationName(ORG_NAME)
    app.setQuitOnLastWindowClosed(False)
    lock = QLockFile(os.path.join(QDir.tempPath(), "barre-des-taches.lock"))
    lock.setStaleLockTime(0)
    if not lock.tryLock(200):
        print("[barre] déjà lancée", file=sys.stderr)
        return 0
    NATIVE = make_backend()
    NATIVE.setup_app()
    Theme.detect()
    apply_theme(app)
    problems = controle_reseau()
    if problems:
        print("[verrou] arrêt, bibliothèques réseau présentes : " + ", ".join(problems), file=sys.stderr)
        return 3
    MANAGER.append(Taskbars(NATIVE))

    def on_scheme(*_args):
        Theme.detect()
        apply_theme(app)
        MANAGER[0].retheme()
    try:
        app.styleHints().colorSchemeChanged.connect(on_scheme)
    except AttributeError:
        pass
    QTimer.singleShot(500, avertir_si_abime)
    code = app.exec()
    lock.unlock()
    return code


if __name__ == "__main__":
    sys.exit(main())
