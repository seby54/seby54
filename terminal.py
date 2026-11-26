#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Terminal Pro — terminal à onglets façon Windows Terminal, pour le Mac du travail.

* Même environnement que l'explorateur : PySide6-Essentials + bibliothèque standard.
* Connexions SSH directes ou via CyberArk PSMP : tu tapes toi-même PIN + code RSA,
  le terminal tape la raison PSM au bon moment (et te prévient quand le code est demandé).
* Verrou anti-exfiltration (« audit hook » Python, impossible à retirer une fois posé) :
  - le programme ne lance que ton shell et ssh, rien d'autre ;
  - il n'ouvre lui-même aucune connexion, sauf vers l'adresse exacte de ta base
    Elasticsearch (https, certificat toujours vérifié) ;
  - aucun mot de passe n'est enregistré.

Lancement :  ~/mac/explorer/venv/bin/python ~/mac/explorer/terminal.py [dossier]
"""

import copy
import datetime
import fcntl
import json
import os
import re
import shlex
import shutil
import signal
import struct
import sys
import termios
import time
import unicodedata
from collections import deque
from dataclasses import dataclass, field
from functools import lru_cache

APP_NAME = "Terminal Pro"
ORG_NAME = "explorateur-maison"
VERSION = "1.2"          # à augmenter à chaque modification
VERSION_DATE = "26/11/2026"
IS_MAC = sys.platform == "darwin"
HERE = os.path.dirname(os.path.abspath(__file__))


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
# Verrou anti-exfiltration (version terminal)
# ======================================================================================

_BLOCKED_MODULES = frozenset({
    "ftplib", "smtplib", "imaplib", "poplib", "nntplib", "telnetlib", "xmlrpc", "socketserver", "asyncio",
    "webbrowser", "requests", "httpx", "aiohttp", "paramiko", "multiprocessing", "mailbox", "urllib3",
    "http.server", "http.cookiejar", "urllib.request", "urllib.robotparser", "wsgiref", "smtpd", "ctypes",
})
_QT_NET = frozenset({
    "QtNetwork", "QtNetworkAuth", "QtWebEngineCore", "QtWebEngineWidgets", "QtWebEngineQuick",
    "QtWebSockets", "QtWebChannel", "QtWebView", "QtHttpServer", "QtRemoteObjects",
    "QtBluetooth", "QtNfc", "QtMqtt", "QtCoap", "QtSerialBus", "QtPdf", "QtPdfWidgets",
})
_EVENTS_FORBIDDEN = frozenset({
    "os.system", "os.spawn", "os.startfile", "os.posix_spawn", "os.posix_spawnp", "pty.spawn",
    "subprocess.Popen", "webbrowser.open", "urllib.Request", "socket.bind", "socket.sendto", "socket.sendmsg",
    "socket.gethostbyname", "socket.gethostbyname_ex", "socket.gethostbyaddr", "socket.getnameinfo",
    "socket.sethostname", "ctypes.dlopen", "ctypes.dlsym", "ctypes.cdata",
})
_LIBS_FORBIDDEN = ("QtNetwork", "Qt6Network", "QtWebEngine", "Qt6WebEngine", "QtWebSockets", "Qt6WebSockets",
                   "QtHttpServer", "qpdf", "QtPdf", "Qt6Pdf")
_VERROU = {"actif": False}
_EXEC_AUTORISES = set()                 # chemins réels des programmes que l'on a le droit de lancer
_RESEAU = {"hotes": set(), "ips": set()}  # (hôte, port) autorisés, puis (ip, port) résolues pour eux


def module_interdit(name):
    if not isinstance(name, str):
        return False
    parts = name.split(".")
    if parts[0] in _BLOCKED_MODULES or ".".join(parts[:2]) in _BLOCKED_MODULES:
        return True
    return parts[0] == "PySide6" and len(parts) > 1 and parts[1] in _QT_NET


def ssh_path():
    for cand in (shutil.which("ssh"), "/usr/bin/ssh"):
        if cand and os.path.isfile(cand):
            return cand
    return "/usr/bin/ssh"


def shells_disponibles():
    """Shells déclarés dans /etc/shells (plus celui du compte), qui existent vraiment."""
    found = []
    try:
        import pwd
        login = pwd.getpwuid(os.getuid()).pw_shell
    except (ImportError, KeyError):
        login = ""
    cands = [os.environ.get("SHELL", ""), login]
    try:
        with open("/etc/shells", "r", encoding="utf-8", errors="replace") as fh:
            cands += [l.strip() for l in fh if l.strip().startswith("/")]
    except OSError:
        pass
    cands += ["/bin/zsh", "/bin/bash", "/bin/sh"]
    for c in cands:
        if c and os.path.isabs(c) and os.path.isfile(c) and os.access(c, os.X_OK) and c not in found:
            found.append(c)
    return found


def autoriser_executable(path):
    if path and os.path.isfile(path):
        _EXEC_AUTORISES.add(os.path.realpath(path))


def executable_autorise(path):
    try:
        return os.path.realpath(os.fsdecode(path)) in _EXEC_AUTORISES
    except (TypeError, ValueError):
        return False


def _norm_host(host):
    if isinstance(host, bytes):
        host = host.decode("idna", "replace")
    return str(host or "").strip().lower().rstrip(".").strip("[]")


def autoriser_hote(host, port):
    """Seul appel qui ouvre le réseau : l'adresse exacte d'une base Elasticsearch déclarée."""
    _RESEAU["hotes"].add((_norm_host(host), int(port)))


def hotes_autorises():
    return sorted(f"{h}:{p}" for h, p in _RESEAU["hotes"])


def installer_verrou():
    """Pose le verrou. Python ne permet pas de le retirer ensuite."""
    if _VERROU["actif"]:
        return
    already = sorted(m for m in list(sys.modules) if module_interdit(m))
    if already:
        raise SystemExit("[verrou] modules interdits déjà chargés : " + ", ".join(already))

    def hook(event, args):
        if event == "import":
            if module_interdit(args[0]):
                raise ImportError(f"[verrou] module interdit : {args[0]}")
        elif event in _EVENTS_FORBIDDEN:
            if event == "ctypes.dlopen" and args and args[0] is None:
                return
            raise PermissionError(f"[verrou] interdit : {event}")
        elif event == "os.exec":
            if not executable_autorise(args[0]):
                raise PermissionError(f"[verrou] programme refusé : {args[0]!r}"[:300])
        elif event == "socket.getaddrinfo":
            try:
                port = int(args[1])
            except (TypeError, ValueError):
                port = -1
            if (_norm_host(args[0]), port) not in _RESEAU["hotes"]:
                raise PermissionError(f"[verrou] adresse non autorisée : {args[0]}:{args[1]}")
        elif event == "socket.connect":
            addr = args[1]
            if not (isinstance(addr, tuple) and len(addr) >= 2 and (str(addr[0]), int(addr[1])) in _RESEAU["ips"]):
                raise PermissionError(f"[verrou] connexion refusée : {addr!r}"[:200])

    sys.addaudithook(hook)
    _VERROU["actif"] = True


def resoudre_autorise(host, port):
    """Résout une adresse autorisée et retient ses IP : seules celles-ci pourront être contactées."""
    import socket
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    for info in infos:
        _RESEAU["ips"].add((str(info[4][0]), int(port)))
    return infos


def bibliotheques_chargees():
    if sys.platform.startswith("linux"):
        try:
            with open("/proc/self/maps", "r", encoding="utf-8", errors="replace") as fh:
                return sorted({line.split()[-1] for line in fh if "/" in line})
        except OSError:
            return []
    return []


def controle_reseau():
    """Auto-contrôle : rien d'interdit ne doit être chargé."""
    problems = [m for m in list(sys.modules) if module_interdit(m)]
    problems += [lib for lib in bibliotheques_chargees() if any(x in lib for x in _LIBS_FORBIDDEN)]
    return problems


# ======================================================================================
# Stockage (dossier privé du compte, copies de sécurité avant chaque écriture)
# ======================================================================================

def data_dir(*parts):
    if IS_MAC:
        base = os.path.expanduser("~/Library/Application Support/" + APP_NAME)
    else:
        base = os.path.join(os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share"), "terminal-pro")
    path = os.path.join(base, *parts)
    os.makedirs(path, mode=0o700, exist_ok=True)
    return path


DEFAULT_FIELD_MAPPING = {
    "hostnameField": "_id",
    "displayNameFields": ["infos.alias", "infos.hostname", "infos.fqdn"],
    "subtitleFields": [],
    "statusField": "infos.status",
    "statusAliveValue": "alive",
    "nodeField": "external.tower.node",
    "osField": "infos.os",
    "tagFields": ["source.environment", "source.type", "infos.hosted"],
    "detailFields": [],
}
DEFAULT_DB = {
    "name": "", "url": "", "index": "servers", "authType": "none", "basicAuthUsername": "", "caFile": "",
    "fieldMapping": copy.deepcopy(DEFAULT_FIELD_MAPPING), "psmpGatewayHost": "", "psmpGatewayPort": 22,
    "psmpUsernameTemplate": "${node}", "defaultSshPort": 22, "defaultUsername": "", "defaultPsmpReason": "",
    "favoriteCategoryName": "★ Elasticsearch",
}
# Raisons prédéfinies de la passerelle (texte exact, à envoyer sans la moindre variation)
PSM_REASONS = [
    ("Morning checks", "To be used only for morning check access. The access should be performed in the "
                       "morning (before 11 AM)."),
    ("Audit & configuration checks", "To be used in case of audit access or configuration check out of the "
                                     "morning checks."),
    ("Suspected incident", "To be used in case of accessing infrastructure is needed for a suspected incident "
                           "before raising it."),
    ("New server implementation", "In the case of a accessing a new server for ongoing migration."),
    ("Security patch", "To use for Security patch update on PRE-PRODUCTION and BACKUP environments."),
]
DEFAULT_PSM_REASON = "Audit & configuration checks"
REASON_PATTERN = r"(?i)(reason|raison|motif|justification)[^:\r\n]*:\s*$"
CODE_PATTERN = r"(?i)(passcode|pin|password|mot de passe|code)[^:\r\n]*:\s*$"
DEFAULT_SETTINGS = {
    "fontFamily": "", "fontSize": 13 if IS_MAC else 11, "colorScheme": "Campbell", "cursorShape": "bar",
    "cursorBlink": True, "scrollback": 10000, "defaultProfile": "", "closeOnExit": "graceful",
    "copyOnSelect": False, "confirmClose": True, "sidebarVisible": False, "sidebarWidth": 330,
    "psmpUserLogin": "", "askReason": True, "defaultReason": DEFAULT_PSM_REASON, "reasonPattern": REASON_PATTERN,
    "reasonChoices": [list(r) for r in PSM_REASONS],
    "codePattern": CODE_PATTERN, "autoWindow": 180, "optionAsMeta": False, "geometry": "", "warnPaste": True,
    "reasonAscii": False, "reasonMaxLen": 0,
}


def normalize_db(d):
    out = copy.deepcopy(DEFAULT_DB)
    out.update({k: v for k, v in (d or {}).items() if k in DEFAULT_DB and k != "fieldMapping"})
    fm = copy.deepcopy(DEFAULT_FIELD_MAPPING)
    fm.update({k: v for k, v in ((d or {}).get("fieldMapping") or {}).items() if k in DEFAULT_FIELD_MAPPING})
    out["fieldMapping"] = fm
    if out["authType"] not in ("none", "apiKey", "basic"):
        out["authType"] = "basic" if out.get("basicAuthUsername") else "none"
    for k in ("psmpGatewayPort", "defaultSshPort"):
        try:
            out[k] = int(out[k] or 22)
        except (TypeError, ValueError):
            out[k] = 22
    return out


def db_slug(name):
    return re.sub(r"[^a-z0-9]+", "_", (name or "").lower())[:40]


class Config:
    def __init__(self, folder=None):
        self.dir = folder or data_dir()
        self.path = os.path.join(self.dir, "config.json")
        self.data = {"version": 1, "settings": dict(DEFAULT_SETTINGS), "ssh": {"nodes": {}, "rootIds": []},
                     "es": {"databases": [], "selected": 0}, "psmpNodeMappings": {}, "reasons": []}
        self.load()

    def load(self):
        if not os.path.isfile(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
        except (OSError, ValueError):
            try:
                shutil.copy2(self.path, self.path + ".illisible")
            except OSError:
                pass
            return
        for key, value in loaded.items():
            if key == "settings" and isinstance(value, dict):
                self.data["settings"].update({k: v for k, v in value.items() if k in DEFAULT_SETTINGS})
            elif key in self.data:
                self.data[key] = value
        self.data["es"]["databases"] = [normalize_db(d) for d in self.data["es"].get("databases", [])]

    def save(self):
        if os.path.isfile(self.path):          # copie de sécurité avant d'écraser
            folder = data_dir("copies")
            stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
            try:
                shutil.copy2(self.path, os.path.join(folder, f"config-{stamp}.json"))
                for old in sorted(f for f in os.listdir(folder) if f.startswith("config-"))[:-10]:
                    os.remove(os.path.join(folder, old))
            except OSError:
                pass
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.data, fh, indent=2, ensure_ascii=False)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)

    @property
    def settings(self):
        return self.data["settings"]

    def add_reason(self, reason):
        if not reason:
            return
        hist = [reason] + [r for r in self.data.get("reasons", []) if r != reason]
        self.data["reasons"] = hist[:15]


def new_id():
    return hex(int(time.time() * 1000))[2:] + os.urandom(4).hex()


# ======================================================================================
# Connexions : arbre, variables, commandes ssh / PSMP, réponses automatiques
# ======================================================================================

AUTH_TYPES = [("agent", "Clé SSH / agent (par défaut)"), ("privateKey", "Clé privée précise"),
              ("password", "Mot de passe (tu le tapes)"), ("psmp", "CyberArk PSMP")]


class SshStore:
    def __init__(self, data):
        self.data = data
        data.setdefault("nodes", {})
        data.setdefault("rootIds", [])
        self._repair()

    @property
    def nodes(self):
        return self.data["nodes"]

    @property
    def root_ids(self):
        return self.data["rootIds"]

    def _repair(self):
        nodes = self.nodes
        for nid, n in nodes.items():
            n["id"] = nid
            n.setdefault("variables", [])
            if n.get("type") == "category":
                n["children"] = [c for c in n.get("children", []) if c in nodes]
        self.data["rootIds"] = [r for r in self.root_ids if r in nodes]
        referenced = set(self.root_ids)
        for n in nodes.values():
            if n.get("type") == "category":
                referenced.update(n["children"])
        for nid, n in nodes.items():
            if nid not in referenced:
                n["parentId"] = None
                self.root_ids.append(nid)

    def get(self, nid):
        return self.nodes.get(nid)

    def children(self, nid):
        ids = self.root_ids if nid is None else (self.get(nid) or {}).get("children", [])
        return [self.nodes[i] for i in ids if i in self.nodes]

    def ancestors(self, nid):
        out, seen = [], set()
        n = self.get(nid)
        while n and n.get("parentId") and n["parentId"] not in seen:
            seen.add(n["parentId"])
            p = self.get(n["parentId"])
            if not p:
                break
            out.insert(0, p)
            n = p
        return out

    def add(self, node, parent_id=None):
        nid = node.get("id") or new_id()
        node["id"] = nid
        node.setdefault("variables", [])
        if node.get("type") == "category":
            node.setdefault("children", [])
        self.nodes[nid] = node
        if parent_id and parent_id in self.nodes:
            node["parentId"] = parent_id
            self.nodes[parent_id].setdefault("children", []).append(nid)
        else:
            node["parentId"] = None
            self.root_ids.append(nid)
        return node

    def update(self, nid, values):
        n = self.nodes[nid]
        for k, v in values.items():
            if k in ("id", "children", "parentId"):
                continue
            if v is None:
                n.pop(k, None)
            else:
                n[k] = v

    def _detach(self, nid):
        pid = self.nodes[nid].get("parentId")
        if pid and pid in self.nodes:
            ch = self.nodes[pid].get("children", [])
            if nid in ch:
                ch.remove(nid)
        elif nid in self.root_ids:
            self.root_ids.remove(nid)

    def delete(self, nid):
        if nid not in self.nodes:
            return []
        removed = []
        self._detach(nid)

        def rec(i):
            n = self.nodes.pop(i, None)
            if n:
                removed.append(i)
                for c in n.get("children", []):
                    rec(c)
        rec(nid)
        return removed

    def is_descendant(self, nid, ancestor_id):
        return any(a["id"] == ancestor_id for a in self.ancestors(nid))

    def move(self, nid, new_parent_id, index=None):
        if nid == new_parent_id or (new_parent_id and self.is_descendant(new_parent_id, nid)):
            return False
        self._detach(nid)
        n = self.nodes[nid]
        if new_parent_id and new_parent_id in self.nodes:
            lst = self.nodes[new_parent_id].setdefault("children", [])
            n["parentId"] = new_parent_id
        else:
            lst, n["parentId"] = self.root_ids, None
        if index is None or index > len(lst):
            lst.append(nid)
        else:
            lst.insert(index, nid)
        return True

    def find_root_category(self, name):
        for n in self.children(None):
            if n.get("type") == "category" and n.get("name") == name:
                return n
        return None

    def all_connections(self):
        return [n for n in self.nodes.values() if n.get("type") == "connection"]


_VAR_RE = re.compile(r"\$\{([^}]+)\}")


def resolve(template, variables):
    if not template:
        return ""
    return _VAR_RE.sub(lambda m: str(variables.get(m.group(1), m.group(0))), str(template))


def effective_variables(store, node):
    out = {}
    chain = []
    if node.get("id") in store.nodes:
        chain = store.ancestors(node["id"])
    elif node.get("parentId") in store.nodes:
        parent = store.nodes[node["parentId"]]
        chain = store.ancestors(parent["id"]) + [parent]
    for a in chain + [node]:
        for v in a.get("variables", []):
            if v.get("key"):
                out[v["key"]] = v.get("value", "")
    return out


def inherited_variables(store, parent_id):
    seen = {}
    if parent_id and parent_id in store.nodes:
        for a in store.ancestors(parent_id) + [store.nodes[parent_id]]:
            for v in a.get("variables", []):
                if v.get("key"):
                    seen[v["key"]] = (v["key"], v.get("value", ""), a.get("name", ""))
    return list(seen.values())


def _int(value, default=22):
    try:
        return int(value or default)
    except (TypeError, ValueError):
        return default


@dataclass
class SshPlan:
    argv: list
    display: str
    psm_string: str = ""
    target: str = ""
    psmp: bool = False


def build_plan(conn, variables, psmp_default_login="", ssh=None):
    ssh = ssh or ssh_path()
    host = resolve(conn.get("host"), variables).strip()
    if not host:
        raise ValueError("hôte manquant")
    user = resolve(conn.get("username"), variables).strip()
    port = _int(resolve(conn.get("port"), variables))
    extra = shlex.split(resolve(conn.get("extraArgs", ""), variables)) if conn.get("extraArgs") else []
    auth = conn.get("authType", "agent")
    if auth == "psmp":
        gw = resolve(conn.get("psmpHost"), variables).strip()
        if not gw:
            raise ValueError("passerelle PSMP manquante")
        gw_port = _int(resolve(conn.get("psmpPort"), variables))
        target = f"{host}:{port}" if port != 22 else host
        tech = resolve(conn.get("psmpTechnicalAccount"), variables).strip()
        login = resolve(conn.get("psmpUserLogin"), variables).strip() or psmp_default_login
        if tech:
            if not login:
                raise ValueError("login PSMP personnel manquant (Paramètres)")
            psm = f"{login}@{tech}@{target}@{gw}"
        else:
            legacy = user or login
            psm = f"{legacy}@{target}@{gw}" if legacy else f"{target}@{gw}"
        argv = [ssh, *extra, "-p", str(gw_port), psm]
        return SshPlan(argv, shlex.join(["ssh", *extra, "-p", str(gw_port), psm]), psm, target, True)
    dest = f"{user}@{host}" if user else host
    argv = [ssh, *extra]
    if auth == "privateKey" and conn.get("privateKeyPath"):
        argv += ["-i", os.path.expanduser(resolve(conn["privateKeyPath"], variables))]
    if port != 22:
        argv += ["-p", str(port)]
    argv.append(dest)
    return SshPlan(argv, shlex.join(["ssh"] + argv[1:]), "", host, False)


_ASCII_FIX = {"œ": "oe", "Œ": "OE", "æ": "ae", "Æ": "AE", "ß": "ss", "’": "'", "‘": "'", "«": '"', "»": '"',
              "“": '"', "”": '"', "–": "-", "—": "-", "…": "...", "€": "EUR"}


def clean_reason(text, ascii_only=False, max_len=0):
    """Raison PSM prête à envoyer -> (texte, problème). Problème non vide = on n'envoie rien.

    Une seule ligne, sans caractère de contrôle ni espace en trop, accents sous leur forme normale,
    jamais vide, jamais de ${VARIABLE} non remplacée."""
    t = unicodedata.normalize("NFC", text or "")
    t = re.sub(r"\s+", " ", t)                                     # retours à la ligne, tabulations, espaces insécables
    t = "".join(ch for ch in t if not unicodedata.category(ch).startswith("C"))
    t = re.sub(r" {2,}", " ", t).strip()
    if ascii_only:
        t = re.sub(r"«\s*", '"', re.sub(r"\s*»", '"', t))
        t = "".join(_ASCII_FIX.get(ch, ch) for ch in t)
        t = "".join(ch for ch in unicodedata.normalize("NFKD", t) if not unicodedata.combining(ch))
        t = unicodedata.normalize("NFC", t)
        bad = sorted({ch for ch in t if not ch.isascii()})
        if bad:
            return t, "caractère impossible à écrire sans accent : " + " ".join(bad)
    if not t:
        return "", "la raison est vide"
    if re.search(r"\$\{[^}]*\}", t):
        return t, "une variable n'a pas été remplacée : " + re.search(r"\$\{[^}]*\}", t).group(0)
    if max_len and len(t) > int(max_len):
        return t, f"trop longue ({len(t)} caractères, {int(max_len)} au maximum) : elle serait coupée"
    return t, ""


def reason_choices(settings):
    """Raisons prédéfinies (nom exact, description)."""
    out = []
    for item in (settings or {}).get("reasonChoices") or []:
        if isinstance(item, (list, tuple)) and item and isinstance(item[0], str) and item[0].strip():
            out.append((item[0].strip(), str(item[1]) if len(item) > 1 else ""))
    return out or list(PSM_REASONS)


def canon_reason(text, choices=PSM_REASONS):
    """Si le texte correspond à une raison prédéfinie (casse ou espaces près), renvoie son orthographe exacte."""
    key = re.sub(r"\s+", " ", unicodedata.normalize("NFC", text or "")).strip().casefold()
    for name, _desc in choices:
        if key and key == re.sub(r"\s+", " ", name).strip().casefold():
            return name
    return clean_reason(text)[0]


def pick_reason(raw, settings):
    """Raison à envoyer -> (texte, problème) : prédéfinie à l'identique, sinon texte nettoyé et contrôlé."""
    exact = canon_reason(raw, reason_choices(settings))
    return clean_reason(exact, settings.get("reasonAscii", False), settings.get("reasonMaxLen", 0))


@dataclass
class AutoRule:
    regex: object
    response: str = ""
    once: bool = True
    label: str = ""
    kind: str = "reply"          # reply : tape la réponse ; notify : te prévient seulement
    connection_phase: bool = True
    fired: bool = False


def build_rules(conn, variables, reason, settings):
    """Règles d'une connexion : raison PSM (tapée), code RSA (on te prévient), règles perso (texte en clair)."""
    rules = []
    if conn.get("authType") == "psmp":
        try:
            rules.append(AutoRule(re.compile(settings.get("reasonPattern") or REASON_PATTERN), reason or "",
                                  True, "raison PSM", "reply" if reason else "notify"))
        except re.error:
            rules.append(AutoRule(re.compile(REASON_PATTERN), reason or "", True, "raison PSM",
                                  "reply" if reason else "notify"))
    try:
        code = re.compile(settings.get("codePattern") or CODE_PATTERN)
    except re.error:
        code = re.compile(CODE_PATTERN)
    rules.append(AutoRule(code, "", False, "code", "notify"))
    for r in conn.get("autoResponses", []) or []:
        pat = r.get("pattern", "")
        if not pat or r.get("secret"):
            continue
        try:
            rx = re.compile(pat if r.get("regex") else re.escape(pat), re.IGNORECASE)
        except re.error:
            continue
        rules.append(AutoRule(rx, resolve(r.get("response", ""), variables), r.get("once", True), pat, "reply",
                              False))
    return rules


# ======================================================================================
# Émulateur VT (xterm-256color)
# ======================================================================================

DEFAULT = -1
BOLD, DIM, ITALIC, UNDERLINE, BLINK, REVERSE, HIDDEN, STRIKE = 1, 2, 4, 8, 16, 32, 64, 128
TRUECOLOR = 1 << 24
DEFAULT_ATTR = (DEFAULT, DEFAULT, 0)
DEC_GRAPHICS = str.maketrans({
    "`": "◆", "a": "▒", "b": "␉", "c": "␌", "d": "␍", "e": "␊", "f": "°", "g": "±", "h": "␤", "i": "␋",
    "j": "┘", "k": "┐", "l": "┌", "m": "└", "n": "┼", "o": "⎺", "p": "⎻", "q": "─", "r": "⎼", "s": "⎽",
    "t": "├", "u": "┤", "v": "┴", "w": "┬", "x": "│", "y": "≤", "z": "≥", "{": "π", "|": "≠", "}": "£",
    "~": "·",
})
_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_CSI = re.compile(r"\x1b\[([\x30-\x3f]*)([\x20-\x2f]*)([\x40-\x7e])")
_CSI_PARTIAL = re.compile(r"\x1b\[[\x30-\x3f]*[\x20-\x2f]*\Z")
_ANSI_STRIP = re.compile(r"\x1b\[[\x30-\x3f]*[\x20-\x2f]*[\x40-\x7e]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|"
                         r"\x1b[@-Z\\-_()*+#%][0-9A-Za-z]?")


def strip_ansi(s):
    return _ANSI_STRIP.sub("", s)


@lru_cache(maxsize=8192)
def char_width(c):
    o = ord(c)
    if o < 0x300:
        return 1
    if unicodedata.combining(c) or unicodedata.category(c) in ("Mn", "Me", "Cf"):
        return 0
    return 2 if unicodedata.east_asian_width(c) in ("W", "F") else 1


class Line:
    __slots__ = ("chars", "attrs", "wrapped")

    def __init__(self, cols, attr=DEFAULT_ATTR):
        self.chars = [" "] * cols
        self.attrs = [attr] * cols
        self.wrapped = False

    def resize(self, cols):
        n = len(self.chars)
        if cols > n:
            self.chars.extend([" "] * (cols - n))
            self.attrs.extend([DEFAULT_ATTR] * (cols - n))
        elif cols < n:
            del self.chars[cols:]
            del self.attrs[cols:]

    def text(self, start=0, end=None):
        return "".join(self.chars[start:end]).rstrip()


def _ints(s):
    out = []
    for p in s.split(";") if s else []:
        head = p.split(":", 1)[0]
        out.append(int(head) if head.isdigit() else 0)
    return out


class Screen:
    def __init__(self, cols=80, rows=24, scrollback=10000):
        self.cols, self.rows = max(2, cols), max(1, rows)
        self.history = deque(maxlen=max(100, scrollback))
        self.history_total = 0          # lignes passées dans l'historique depuis le début
        self.history_resets = 0
        self.write_back = lambda s: None
        self.on_title = lambda t: None
        self.on_bell = lambda: None
        self.on_cwd = lambda p: None
        self.color_query = None
        self.title = ""
        self._pending = ""
        self._attr_cache = {DEFAULT_ATTR: DEFAULT_ATTR}
        self.reset()

    def reset(self):
        self.main = [Line(self.cols) for _ in range(self.rows)]
        self.alt = None
        self.lines = self.main
        self.alt_active = False
        self.cx = self.cy = 0
        self.wrap_pending = False
        self.attr = DEFAULT_ATTR
        self.top, self.bottom = 0, self.rows - 1
        self.autowrap = True
        self.origin = False
        self.insert_mode = False
        self.app_cursor = False
        self.app_keypad = False
        self.bracketed_paste = False
        self.cursor_visible = True
        self.reverse_video = False
        self.lnm = False
        self.mouse_mode = 0
        self.mouse_sgr = False
        self.focus_events = False
        self.cursor_style = 0
        self.g = ["B", "B"]
        self.gl = 0
        self.saved = None
        self.tabs = set(range(8, self.cols, 8))
        self.last_char = " "
        self.changed = True

    def _intern(self, t):
        return self._attr_cache.setdefault(t, t)

    def _blank_attr(self):
        bg = self.attr[1]
        return DEFAULT_ATTR if bg == DEFAULT else self._intern((DEFAULT, bg, 0))

    def _new_line(self):
        return Line(self.cols, self._blank_attr())

    # ---- défilement
    def scroll_up(self, n=1, top=None, bottom=None, to_history=True):
        top = self.top if top is None else top
        bottom = self.bottom if bottom is None else bottom
        n = min(n, bottom - top + 1)
        if n <= 0:
            return
        removed = self.lines[top:top + n]
        del self.lines[top:top + n]
        self.lines[bottom - n + 1:bottom - n + 1] = [self._new_line() for _ in range(n)]
        if to_history and top == 0 and not self.alt_active:
            self.history.extend(removed)
            self.history_total += n
        self.changed = True

    def scroll_down(self, n=1, top=None, bottom=None):
        top = self.top if top is None else top
        bottom = self.bottom if bottom is None else bottom
        n = min(n, bottom - top + 1)
        if n <= 0:
            return
        del self.lines[bottom - n + 1:bottom + 1]
        self.lines[top:top] = [self._new_line() for _ in range(n)]
        self.changed = True

    def index(self):
        if self.cy == self.bottom:
            self.scroll_up(1)
        elif self.cy < self.rows - 1:
            self.cy += 1

    def reverse_index(self):
        if self.cy == self.top:
            self.scroll_down(1)
        elif self.cy > 0:
            self.cy -= 1

    def linefeed(self):
        self.wrap_pending = False
        self.index()
        if self.lnm:
            self.cx = 0

    # ---- texte
    def _wrap(self):
        self.wrap_pending = False
        self.lines[self.cy].wrapped = True
        self.cx = 0
        self.index()

    def put_text(self, s):
        if not s:
            return
        if self.g[self.gl] == "0":
            s = s.translate(DEC_GRAPHICS)
        self.last_char = s[-1]
        self.changed = True
        i, n, cols, attr = 0, len(s), self.cols, self.attr
        while i < n:
            if self.wrap_pending and self.autowrap:
                self._wrap()
            line = self.lines[self.cy]
            chars, attrs = line.chars, line.attrs
            x = self.cx
            chunk = s[i:i + cols - x]
            if chunk.isascii() and not self.insert_mode:
                k = len(chunk)
                if x > 0 and chars[x] == "":
                    chars[x - 1] = " "
                chars[x:x + k] = chunk
                attrs[x:x + k] = [attr] * k
                if x + k < cols and chars[x + k] == "":
                    chars[x + k] = " "
                i += k
                if x + k >= cols:
                    self.cx = cols - 1
                    self.wrap_pending = self.autowrap
                    if not self.autowrap and i < n:
                        chars[cols - 1] = s[n - 1]
                        i = n
                else:
                    self.cx = x + k
                continue
            c = s[i]
            i += 1
            w = char_width(c)
            if w == 0:
                px = self.cx if self.wrap_pending else self.cx - 1
                if px >= 0:
                    if chars[px] == "" and px > 0:
                        px -= 1
                    chars[px] += c
                continue
            if w == 2 and self.cx >= cols - 1:
                if not self.autowrap:
                    continue
                chars[cols - 1] = " "
                self._wrap()
                line = self.lines[self.cy]
                chars, attrs = line.chars, line.attrs
            x = self.cx
            if self.insert_mode:
                chars[x:x] = [" "] * w
                attrs[x:x] = [self._blank_attr()] * w
                del chars[cols:]
                del attrs[cols:]
            if chars[x] == "" and x > 0:
                chars[x - 1] = " "
            chars[x] = c
            attrs[x] = attr
            if w == 2:
                chars[x + 1] = ""
                attrs[x + 1] = attr
            elif x + 1 < cols and chars[x + 1] == "":
                chars[x + 1] = " "
            x += w
            if x >= cols:
                self.cx = cols - 1
                self.wrap_pending = self.autowrap
            else:
                self.cx = x

    # ---- analyse du flux
    def feed(self, data):
        if self._pending:
            data = self._pending + data
            self._pending = ""
        i, n = 0, len(data)
        ctrl = _CTRL.search
        while i < n:
            m = ctrl(data, i)
            if m is None:
                self.put_text(data[i:])
                break
            j = m.start()
            if j > i:
                self.put_text(data[i:j])
            c = data[j]
            if c != "\x1b":
                self.control(c)
                i = j + 1
                continue
            if j + 1 >= n:
                self._pending = data[j:]
                break
            c2 = data[j + 1]
            if c2 == "[":
                mm = _CSI.match(data, j)
                if mm:
                    self.csi(mm.group(1), mm.group(2), mm.group(3))
                    i = mm.end()
                    continue
                if _CSI_PARTIAL.match(data, j):
                    if n - j < 512:
                        self._pending = data[j:]
                    break
                i = j + 2
                continue
            if c2 in "]P_^X":
                end, tlen = self._find_st(data, j + 2)
                if end < 0:
                    if n - j < 65536:
                        self._pending = data[j:]
                    break
                if c2 == "]":
                    self.osc(data[j + 2:end])
                i = end + tlen
                continue
            if c2 in "()*+-./#% ":
                if j + 2 >= n:
                    self._pending = data[j:]
                    break
                if c2 in "()*+":
                    self.g["()*+".index(c2) & 1] = data[j + 2]
                elif c2 == "#" and data[j + 2] == "8":
                    for line in self.lines:
                        line.chars[:] = ["E"] * self.cols
                        line.attrs[:] = [DEFAULT_ATTR] * self.cols
                    self.changed = True
                i = j + 3
                continue
            self.esc(c2)
            i = j + 2

    @staticmethod
    def _find_st(data, start):
        bel = data.find("\x07", start)
        st = data.find("\x1b\\", start)
        if bel < 0 and st < 0:
            return -1, 0
        if st < 0 or (0 <= bel < st):
            return bel, 1
        return st, 2

    def control(self, c):
        self.changed = True
        if c == "\r":
            self.cx = 0
            self.wrap_pending = False
        elif c in "\n\x0b\x0c":
            self.linefeed()
        elif c == "\x08":
            if self.wrap_pending:
                self.wrap_pending = False
            elif self.cx > 0:
                self.cx -= 1
        elif c == "\t":
            self.wrap_pending = False
            nxt = [t for t in self.tabs if t > self.cx]
            self.cx = min(min(nxt) if nxt else self.cols - 1, self.cols - 1)
        elif c == "\x07":
            self.on_bell()
        elif c == "\x0e":
            self.gl = 1
        elif c == "\x0f":
            self.gl = 0

    def esc(self, c):
        self.changed = True
        if c == "7":
            self.save_cursor()
        elif c == "8":
            self.restore_cursor()
        elif c == "D":
            self.wrap_pending = False
            self.index()
        elif c == "E":
            self.cx = 0
            self.linefeed()
        elif c == "M":
            self.wrap_pending = False
            self.reverse_index()
        elif c == "H":
            self.tabs.add(self.cx)
        elif c == "c":
            self.reset()
        elif c == "=":
            self.app_keypad = True
        elif c == ">":
            self.app_keypad = False

    def save_cursor(self):
        self.saved = (self.cx, self.cy, self.attr, self.origin, self.wrap_pending, list(self.g), self.gl)

    def restore_cursor(self):
        if self.saved is None:
            self.cx = self.cy = 0
            self.attr = DEFAULT_ATTR
            return
        self.cx, self.cy, self.attr, self.origin, self.wrap_pending, g, self.gl = self.saved
        self.g = list(g)
        self.cx = min(self.cx, self.cols - 1)
        self.cy = min(self.cy, self.rows - 1)

    def _set_alt(self, on, save):
        if on == self.alt_active:
            return
        if on:
            if save:
                self.save_cursor()
            self.alt = [Line(self.cols) for _ in range(self.rows)]
            self.lines = self.alt
            self.alt_active = True
        else:
            self.lines = self.main
            self.alt = None
            self.alt_active = False
            if save:
                self.restore_cursor()
        self.changed = True

    def csi(self, params, inter, final):
        self.changed = True
        private = ""
        if params and params[0] in "?><=":
            private, params = params[0], params[1:]
        if final == "m" and not private and not inter:
            self.sgr(params.split(";") if params else [])
            return
        nums = _ints(params)

        def p(i=0, d=1):
            v = nums[i] if i < len(nums) else 0
            return v if v else d

        rows, cols = self.rows, self.cols
        if inter:
            if inter == " " and final == "q":
                self.cursor_style = p(0, 0)
            elif inter == "!" and final == "p":
                self._soft_reset()
            return
        if private == "?":
            if final in "hl":
                self._dec_modes(nums, final == "h")
            elif final == "n" and p(0, 0) == 6:
                self.write_back(f"\x1b[?{self.cy + 1};{self.cx + 1}R")
            return
        if private == ">":
            if final == "c":
                self.write_back("\x1b[>0;10;1c")
            return
        if private:
            return
        if final not in "mnctr":
            self.wrap_pending = False
        if final in "Hf":
            r, c = p(0) - 1, p(1) - 1
            if self.origin:
                r = min(r + self.top, self.bottom)
            self.cy = max(0, min(rows - 1, r))
            self.cx = max(0, min(cols - 1, c))
        elif final == "K":
            self.erase_line(p(0, 0))
        elif final == "J":
            self.erase_display(p(0, 0))
        elif final == "A":
            lim = self.top if self.cy >= self.top else 0
            self.cy = max(lim, self.cy - p())
        elif final in "Be":
            lim = self.bottom if self.cy <= self.bottom else rows - 1
            self.cy = min(lim, self.cy + p())
        elif final in "Ca":
            self.cx = min(cols - 1, self.cx + p())
        elif final == "D":
            self.cx = max(0, self.cx - p())
        elif final == "E":
            lim = self.bottom if self.cy <= self.bottom else rows - 1
            self.cy, self.cx = min(lim, self.cy + p()), 0
        elif final == "F":
            lim = self.top if self.cy >= self.top else 0
            self.cy, self.cx = max(lim, self.cy - p()), 0
        elif final in "G`":
            self.cx = max(0, min(cols - 1, p() - 1))
        elif final == "d":
            r = p() - 1 + (self.top if self.origin else 0)
            self.cy = max(0, min(rows - 1, r))
        elif final == "X":
            n = min(p(), cols - self.cx)
            line = self.lines[self.cy]
            line.chars[self.cx:self.cx + n] = [" "] * n
            line.attrs[self.cx:self.cx + n] = [self._blank_attr()] * n
        elif final == "@":
            n = min(p(), cols - self.cx)
            line = self.lines[self.cy]
            line.chars[self.cx:self.cx] = [" "] * n
            line.attrs[self.cx:self.cx] = [self._blank_attr()] * n
            del line.chars[cols:]
            del line.attrs[cols:]
        elif final == "P":
            n = min(p(), cols - self.cx)
            line = self.lines[self.cy]
            del line.chars[self.cx:self.cx + n]
            del line.attrs[self.cx:self.cx + n]
            line.chars.extend([" "] * n)
            line.attrs.extend([self._blank_attr()] * n)
        elif final == "L":
            if self.top <= self.cy <= self.bottom:
                self.scroll_down(p(), self.cy, self.bottom)
                self.cx = 0
        elif final == "M":
            if self.top <= self.cy <= self.bottom:
                self.scroll_up(p(), self.cy, self.bottom, to_history=False)
                self.cx = 0
        elif final == "S":
            self.scroll_up(p(), to_history=False)
        elif final == "T":
            self.scroll_down(p())
        elif final == "r":
            t, b = p(0) - 1, min(p(1, rows), rows) - 1
            if t < b:
                self.top, self.bottom = t, b
                self.cx = 0
                self.cy = self.top if self.origin else 0
        elif final == "b":
            self.put_text(self.last_char * min(p(), 65535))
        elif final == "c":
            if p(0, 0) == 0:
                self.write_back("\x1b[?62;22c")
        elif final == "n":
            v = p(0, 0)
            if v == 5:
                self.write_back("\x1b[0n")
            elif v == 6:
                r = self.cy - (self.top if self.origin else 0)
                self.write_back(f"\x1b[{r + 1};{self.cx + 1}R")
        elif final in "hl":
            on = final == "h"
            for v in nums:
                if v == 4:
                    self.insert_mode = on
                elif v == 20:
                    self.lnm = on
        elif final == "g":
            v = p(0, 0)
            if v == 0:
                self.tabs.discard(self.cx)
            elif v == 3:
                self.tabs.clear()
        elif final == "I":
            for _ in range(p()):
                self.control("\t")
        elif final == "Z":
            for _ in range(p()):
                prv = [t for t in self.tabs if t < self.cx]
                self.cx = max(prv) if prv else 0
        elif final == "s":
            if not params:
                self.save_cursor()
        elif final == "u":
            self.restore_cursor()
        elif final == "t":
            if p(0, 0) == 18:
                self.write_back(f"\x1b[8;{rows};{cols}t")

    def _soft_reset(self):
        self.attr = DEFAULT_ATTR
        self.insert_mode = self.origin = self.app_cursor = False
        self.autowrap = self.cursor_visible = True
        self.top, self.bottom = 0, self.rows - 1
        self.g, self.gl = ["B", "B"], 0

    def _dec_modes(self, nums, on):
        for v in nums:
            if v == 1:
                self.app_cursor = on
            elif v == 5:
                self.reverse_video = on
            elif v == 6:
                self.origin = on
                self.cx, self.cy = 0, (self.top if on else 0)
            elif v == 7:
                self.autowrap = on
            elif v == 25:
                self.cursor_visible = on
            elif v in (47, 1047):
                self._set_alt(on, save=False)
            elif v == 1048:
                self.save_cursor() if on else self.restore_cursor()
            elif v == 1049:
                self._set_alt(on, save=True)
            elif v == 2004:
                self.bracketed_paste = on
            elif v in (9, 1000, 1002, 1003):
                self.mouse_mode = v if on else 0
            elif v == 1006:
                self.mouse_sgr = on
            elif v == 1004:
                self.focus_events = on

    def erase_line(self, mode):
        line = self.lines[self.cy]
        blank = self._blank_attr()
        a, b = {0: (self.cx, self.cols), 1: (0, self.cx + 1)}.get(mode, (0, self.cols))
        line.chars[a:b] = [" "] * (b - a)
        line.attrs[a:b] = [blank] * (b - a)
        if mode != 1:
            line.wrapped = False

    def erase_display(self, mode):
        if mode == 3:
            self.history.clear()
            self.history_resets += 1
            return
        if mode == 0:
            self.erase_line(0)
            rng = range(self.cy + 1, self.rows)
        elif mode == 1:
            self.erase_line(1)
            rng = range(0, self.cy)
        else:
            rng = range(self.rows)
        for r in rng:
            self.lines[r] = self._new_line()

    def sgr(self, parts):
        fg, bg, fl = self.attr
        if not parts:
            parts = ["0"]
        i, n = 0, len(parts)
        while i < n:
            part = parts[i]
            if ":" in part:
                sub = [int(x) if x.isdigit() else 0 for x in part.split(":")]
                code = sub[0]
                if code in (38, 48) and len(sub) >= 2:
                    col = None
                    if sub[1] == 5 and len(sub) >= 3:
                        col = sub[2] & 255
                    elif sub[1] == 2 and len(sub) >= 5:
                        r, g, b = sub[-3:]
                        col = TRUECOLOR | ((r & 255) << 16) | ((g & 255) << 8) | (b & 255)
                    if col is not None:
                        if code == 38:
                            fg = col
                        else:
                            bg = col
                elif code == 4:
                    fl = (fl | UNDERLINE) if (len(sub) < 2 or sub[1]) else (fl & ~UNDERLINE)
                i += 1
                continue
            code = int(part) if part.isdigit() else 0
            if code == 0:
                fg = bg = DEFAULT
                fl = 0
            elif code == 1:
                fl |= BOLD
            elif code == 2:
                fl |= DIM
            elif code == 3:
                fl |= ITALIC
            elif code in (4, 21):
                fl |= UNDERLINE
            elif code in (5, 6):
                fl |= BLINK
            elif code == 7:
                fl |= REVERSE
            elif code == 8:
                fl |= HIDDEN
            elif code == 9:
                fl |= STRIKE
            elif code == 22:
                fl &= ~(BOLD | DIM)
            elif code == 23:
                fl &= ~ITALIC
            elif code == 24:
                fl &= ~UNDERLINE
            elif code == 25:
                fl &= ~BLINK
            elif code == 27:
                fl &= ~REVERSE
            elif code == 28:
                fl &= ~HIDDEN
            elif code == 29:
                fl &= ~STRIKE
            elif 30 <= code <= 37:
                fg = code - 30
            elif code == 39:
                fg = DEFAULT
            elif 40 <= code <= 47:
                bg = code - 40
            elif code == 49:
                bg = DEFAULT
            elif 90 <= code <= 97:
                fg = code - 90 + 8
            elif 100 <= code <= 107:
                bg = code - 100 + 8
            elif code in (38, 48):
                col = None
                if i + 2 < n and parts[i + 1] == "5":
                    col = int(parts[i + 2] or 0) & 255
                    i += 2
                elif i + 4 < n and parts[i + 1] == "2":
                    r, g, b = (int(x or 0) & 255 for x in parts[i + 2:i + 5])
                    col = TRUECOLOR | (r << 16) | (g << 8) | b
                    i += 4
                if col is not None:
                    if code == 38:
                        fg = col
                    else:
                        bg = col
            i += 1
        self.attr = self._intern((fg, bg, fl))

    def osc(self, s):
        code, _, rest = s.partition(";")
        if code in ("0", "2"):
            self.title = rest
            self.on_title(rest)
        elif code == "7":
            self.on_cwd(re.sub(r"^file://[^/]*", "", rest))
        elif code in ("10", "11", "12") and rest == "?" and self.color_query:
            kind = {"10": "fg", "11": "bg", "12": "cursor"}[code]
            self.write_back(f"\x1b]{code};{_xcolor(self.color_query(kind))}\x1b\\")
        elif code == "4" and self.color_query:
            idx, _, q = rest.partition(";")
            if q == "?" and idx.isdigit():
                self.write_back(f"\x1b]4;{idx};{_xcolor(self.color_query(int(idx)))}\x1b\\")

    def resize(self, cols, rows):
        cols, rows = max(2, cols), max(1, rows)
        if cols == self.cols and rows == self.rows:
            return
        for buf in (self.main, self.alt):
            if buf is not None:
                for line in buf:
                    line.resize(cols)
        if rows < self.rows:
            diff = self.rows - rows
            for buf in (self.main, self.alt):
                if buf is None:
                    continue
                active = buf is self.lines
                below = (self.rows - 1 - self.cy) if active else diff
                from_bottom = min(diff, max(0, below))
                if from_bottom:
                    del buf[len(buf) - from_bottom:]
                from_top = diff - from_bottom
                if from_top:
                    removed = buf[:from_top]
                    del buf[:from_top]
                    if buf is self.main:
                        self.history.extend(removed)
                        self.history_total += from_top
                    if active:
                        self.cy -= from_top
        elif rows > self.rows:
            for buf in (self.main, self.alt):
                if buf is not None:
                    buf.extend(Line(cols) for _ in range(rows - self.rows))
        self.cols, self.rows = cols, rows
        self.top, self.bottom = 0, rows - 1
        self.tabs = set(range(8, cols, 8))
        self.cx = max(0, min(cols - 1, self.cx))
        self.cy = max(0, min(rows - 1, self.cy))
        self.wrap_pending = False
        self.changed = True

    # ---- lecture
    def first_abs(self):
        """Numéro absolu de la plus ancienne ligne encore en mémoire."""
        return self.history_total - len(self.history)

    def line_at(self, abs_row):
        """Ligne au numéro absolu (historique puis écran), ou None."""
        k = abs_row - self.first_abs()
        if 0 <= k < len(self.history):
            return self.history[k]
        r = abs_row - self.history_total
        if 0 <= r < self.rows:
            return self.lines[r]
        return None

    def text_from(self, abs_row, col):
        """Texte affiché entre une position (ligne absolue, colonne) et le curseur."""
        end_abs = self.history_total + self.cy
        end_col = self.cols if self.wrap_pending else self.cx
        out = []
        for r in range(abs_row, end_abs + 1):
            line = self.line_at(r)
            if line is None:
                continue
            a = col if r == abs_row else 0
            b = end_col if r == end_abs else self.cols
            part = "".join(line.chars[a:b])
            if r < end_abs and not line.wrapped:
                part = part.rstrip() + "\n"
            out.append(part)
        return "".join(out)

    def prompt_text(self, max_rows=8):
        """Ce qui est écrit avant le curseur sur la ligne en cours (pour les réponses automatiques).
        Une invite trop longue pour la fenêtre est coupée sur plusieurs lignes : on la recolle."""
        line = self.lines[self.cy]
        end = self.cols if self.wrap_pending else self.cx
        parts = ["".join(line.chars[:end])]
        r = self.history_total + self.cy - 1
        while len(parts) < max_rows:
            prev = self.line_at(r)
            if prev is None or not prev.wrapped:
                break
            parts.append("".join(prev.chars[:self.cols]))
            r -= 1
        return "".join(reversed(parts))

    def display_text(self):
        return "\n".join(line.text() for line in self.lines)


def _xcolor(hexcol):
    h = hexcol.lstrip("#")
    if len(h) != 6:
        h = "000000"
    return f"rgb:{h[0:2]}{h[0:2]}/{h[2:4]}{h[2:4]}/{h[4:6]}{h[4:6]}"


# ======================================================================================
# Pseudo-terminal (shell local ou ssh)
# ======================================================================================

TIOCSCTTY = getattr(termios, "TIOCSCTTY", 0x20007461 if IS_MAC else 0x540E)


def _set_size(fd, cols, rows):
    try:
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    except OSError:
        pass


def child_env(extra=None):
    env = dict(os.environ)
    env.update({"TERM": "xterm-256color", "COLORTERM": "truecolor", "TERM_PROGRAM": "TerminalPro",
                "TERM_PROGRAM_VERSION": VERSION})
    if "LANG" not in env and "LC_ALL" not in env:
        env["LANG"] = "fr_FR.UTF-8" if IS_MAC else "C.UTF-8"
    for k in ("QT_QPA_PLATFORM_PLUGIN_PATH", "QT_PLUGIN_PATH", "PYTHONPATH", "PYTHONHOME"):
        env.pop(k, None)
    env.update(extra or {})
    return env


class Pty:
    """Lance un programme autorisé (shell ou ssh) dans un pseudo-terminal. Lecture/écriture non bloquantes."""

    def __init__(self, argv, cols, rows, cwd=None, env=None):
        if not executable_autorise(argv[0]):
            raise PermissionError(f"programme non autorisé : {argv[0]}")
        env = child_env(env)
        master, slave = os.openpty()
        _set_size(slave, cols, rows)
        try:
            cwd = cwd if cwd and os.path.isdir(cwd) else os.path.expanduser("~")
        except OSError:
            cwd = "/"
        import warnings
        with warnings.catch_warnings():         # Python prévient qu'il y a des fils : l'enfant ne fait qu'un exec
            warnings.simplefilter("ignore", DeprecationWarning)
            pid = os.fork()
        if pid == 0:                            # enfant : uniquement des appels système, puis exec
            try:
                os.close(master)
                os.setsid()
                fcntl.ioctl(slave, TIOCSCTTY, 0)
                for fd in (0, 1, 2):
                    os.dup2(slave, fd)
                if slave > 2:
                    os.close(slave)
                for sig in (signal.SIGPIPE, signal.SIGXFSZ, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM,
                            signal.SIGHUP, signal.SIGCHLD):
                    signal.signal(sig, signal.SIG_DFL)
                try:
                    os.chdir(cwd)
                except OSError:
                    pass
                os.execve(argv[0], argv, env)
            except BaseException as exc:  # noqa: BLE001
                try:
                    os.write(2, f"\r\nImpossible de lancer {argv[0]} : {exc}\r\n".encode("utf-8", "replace"))
                except OSError:
                    pass
            finally:
                os._exit(127)
        os.close(slave)
        self.pid, self.fd = pid, master
        os.set_blocking(master, False)
        self.out = bytearray()
        self.exit_code = None

    def read(self):
        """Octets disponibles ; b"" à la fin (programme terminé) ; None s'il n'y a rien pour l'instant."""
        try:
            data = os.read(self.fd, 65536)
        except BlockingIOError:
            return None
        except OSError:
            return b""
        return data

    def write(self, data):
        if self.fd < 0:
            return
        self.out += data
        self.flush()

    def flush(self):
        """Écrit ce qui peut l'être ; True si tout est parti."""
        while self.out and self.fd >= 0:
            try:
                n = os.write(self.fd, self.out[:4096])
            except BlockingIOError:
                return False
            except OSError:
                self.out.clear()
                return True
            del self.out[:n]
        return True

    def resize(self, cols, rows):
        if self.fd >= 0:
            _set_size(self.fd, cols, rows)

    def tty_modes(self):
        """(écho, mode ligne, touche « effacer la ligne ») du terminal du programme, ou None si illisible.
        Écho coupé + mode ligne = saisie masquée, comme un mot de passe (c'est ce que regardent iTerm et
        Terminal pour afficher la clé). ssh repasse en mode brut une fois connecté."""
        if self.fd < 0:
            return None
        try:
            attrs = termios.tcgetattr(self.fd)
        except (termios.error, OSError):
            return None
        lflag, kill = attrs[3], attrs[6][termios.VKILL]
        if not isinstance(kill, bytes) or kill in (b"\x00", b"\xff"):
            kill = b""
        return bool(lflag & termios.ECHO), bool(lflag & termios.ICANON), kill

    def poll(self):
        if self.exit_code is not None:
            return self.exit_code
        try:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
        except ChildProcessError:
            self.exit_code = 0
            return 0
        if pid == 0:
            return None
        self.exit_code = os.waitstatus_to_exitcode(status)
        return self.exit_code

    def close(self):
        if self.fd >= 0:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = -1

    def kill(self):
        if self.poll() is None:
            for sig in (signal.SIGHUP, signal.SIGTERM):
                try:
                    os.killpg(self.pid, sig)
                except OSError:
                    try:
                        os.kill(self.pid, sig)
                    except OSError:
                        break
        self.close()


@dataclass
class LaunchSpec:
    name: str
    argv: list
    icon: str = "terminal"
    cwd: str = ""
    kind: str = "shell"                  # shell | ssh
    node: dict = None
    reason: str = ""
    banner: str = ""
    extra: dict = field(default_factory=dict)


def detect_profiles():
    """Ton shell de connexion d'abord, puis zsh / bash / fish s'ils existent."""
    out, seen = [], set()
    shells = shells_disponibles()
    login = shells[0] if shells else "/bin/sh"
    for sh in [login] + [s for s in shells if os.path.basename(s) in ("zsh", "bash", "fish")]:
        base = os.path.basename(sh)
        if base in seen:
            continue
        seen.add(base)
        out.append(LaunchSpec(base, [sh, "-l"], "terminal", os.path.expanduser("~")))
    return out


# ======================================================================================
# Elasticsearch (https uniquement, certificat vérifié, adresse autorisée)
# ======================================================================================

class EsError(Exception):
    pass


def es_address(db):
    from urllib.parse import urlsplit
    u = urlsplit((db.get("url") or "").strip())
    if u.scheme != "https" or not u.hostname:
        raise EsError("adresse invalide : il faut une adresse https://… (les connexions non chiffrées "
                      "sont refusées)")
    return u.hostname, u.port or 443, u.path.rstrip("/")


def es_request(db, secret, method, path, body=None, timeout=15):
    host, port, base = es_address(db)
    if (_norm_host(host), int(port)) not in _RESEAU["hotes"]:
        raise EsError(f"{host}:{port} n'est pas une adresse autorisée — enregistre la base d'abord")
    import http.client
    import ssl
    try:
        ctx = ssl.create_default_context(cafile=db.get("caFile") or None)
    except (OSError, ssl.SSLError) as exc:
        raise EsError(f"certificat de l'entreprise illisible : {exc}") from None
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    auth = db.get("authType", "none")
    if auth == "apiKey" and secret:
        headers["Authorization"] = f"ApiKey {secret}"
    elif auth == "basic" and db.get("basicAuthUsername"):
        import base64
        tok = base64.b64encode(f"{db['basicAuthUsername']}:{secret or ''}".encode()).decode()
        headers["Authorization"] = f"Basic {tok}"
    payload = json.dumps(body).encode("utf-8") if body is not None else None
    try:
        resoudre_autorise(host, port)
        conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=timeout)
        try:
            conn.request(method, base + "/" + path.lstrip("/"), body=payload, headers=headers)
            resp = conn.getresponse()
            raw = resp.read().decode("utf-8", "replace")
            status = resp.status
        finally:
            conn.close()
    except ssl.SSLCertVerificationError as exc:
        raise EsError(f"certificat refusé ({exc.verify_message}). Indique le certificat de ton entreprise "
                      "(.pem) dans la configuration de la base.") from None
    except PermissionError as exc:
        raise EsError(str(exc)) from None
    except OSError as exc:
        raise EsError(f"connexion impossible : {exc}") from None
    if status >= 400:
        raise EsError(f"HTTP {status} : {raw[:400]}")
    try:
        js = json.loads(raw) if raw else {}
    except ValueError:
        raise EsError(f"réponse illisible : {raw[:200]}") from None
    if isinstance(js, dict) and js.get("error"):
        raise EsError(json.dumps(js["error"])[:400])
    return js


def get_values(source, path):
    cur = [source]
    for part in path.split("."):
        nxt = []
        for c in cur:
            if isinstance(c, list):
                if part.isdigit():
                    if int(part) < len(c):
                        nxt.append(c[int(part)])
                    continue
                nxt.extend(e[part] for e in c if isinstance(e, dict) and part in e)
            elif isinstance(c, dict) and part in c:
                nxt.append(c[part])
        cur = nxt
        if not cur:
            return []
    out = []
    for c in cur:
        out.extend(c if isinstance(c, list) else [c])
    return [str(v) for v in out if v is not None and v != "" and not isinstance(v, dict)]


def hit_value(hit, path):
    if not path:
        return ""
    if path in ("_id", "_index"):
        return str(hit.get(path, ""))
    vals = get_values(hit.get("_source", {}), path)
    return vals[0] if vals else ""


def hit_values(hit, path):
    if path in ("_id", "_index"):
        return [hit_value(hit, path)]
    return get_values(hit.get("_source", {}), path)


_ES_ESCAPE = re.compile(r'([+\-=&|!(){}\[\]^"~?:\\/<>])')


def build_query(text, db, alive_only):
    terms = [t for t in text.split() if t]
    if terms:
        q = " AND ".join("*" + _ES_ESCAPE.sub(r"\\\1", t) + "*" for t in terms)
        base = {"query_string": {"query": q, "analyze_wildcard": True}}
    else:
        base = {"match_all": {}}
    fm = db["fieldMapping"]
    if alive_only and fm.get("statusField"):
        val = fm.get("statusAliveValue", "alive")
        return {"bool": {"must": [base], "filter": [{"bool": {"should": [
            {"term": {fm["statusField"]: val}}, {"term": {fm["statusField"] + ".keyword": val}}],
            "minimum_should_match": 1}}]}}
    return base


def es_search(db, secret, text, alive_only=True, size=50):
    js = es_request(db, secret, "POST", f"{db['index']}/_search",
                    {"query": build_query(text, db, alive_only), "size": size})
    return js.get("hits", {}).get("hits", [])


def process_hit(hit, db):
    fm = db["fieldMapping"]
    host = hit_value(hit, fm.get("hostnameField") or "_id") or str(hit.get("_id", ""))
    status = hit_value(hit, fm.get("statusField", ""))
    tags = []
    for f in fm.get("tagFields", []):
        tags.extend(hit_values(hit, f))
    details = []
    for f in fm.get("detailFields", []):
        v = ", ".join(hit_values(hit, f))
        if v:
            details.append((f.split(".")[-1], v))
    title = next((v for v in (hit_value(hit, p) for p in fm.get("displayNameFields") or []) if v), "") or host
    subtitle = " · ".join(v for v in (hit_value(hit, f) for f in fm.get("subtitleFields", [])) if v)
    return {"id": str(hit.get("_id", "")), "hostname": host, "displayName": title,
            "subtitle": subtitle or host, "status": status,
            "isAlive": (status.lower() == (fm.get("statusAliveValue") or "alive").lower())
            if fm.get("statusField") else None,
            "node": hit_value(hit, fm.get("nodeField", "")), "os": hit_value(hit, fm.get("osField", "")),
            "tags": [t for t in tags if t], "details": details, "dbName": db["name"]}


def unique_nodes(db, secret):
    fld = db["fieldMapping"].get("nodeField")
    if not fld:
        return []
    for f in (fld + ".keyword", fld):
        try:
            js = es_request(db, secret, "POST", f"{db['index']}/_search",
                            {"size": 0, "aggs": {"nodes": {"terms": {"field": f, "size": 1000}}}})
        except EsError:
            continue
        found = [b["key"] for b in js.get("aggregations", {}).get("nodes", {}).get("buckets", []) if b.get("key")]
        if found:
            return sorted(set(map(str, found)))
    return []


def es_test(db, secret):
    js = es_request(db, secret, "GET", f"{db['index']}/_count")
    return f"OK — {js.get('count', '?')} documents dans « {db['index']} »"


def _flatten_mapping(props, prefix=""):
    for name, spec in (props or {}).items():
        if "properties" in spec:
            yield from _flatten_mapping(spec["properties"], f"{prefix}{name}.")
        else:
            yield f"{prefix}{name}", spec.get("type", "object")


def _flatten_source(obj, prefix=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _flatten_source(v, f"{prefix}{k}.")
    elif isinstance(obj, list):
        if obj and isinstance(obj[0], dict):
            yield from _flatten_source(obj[0], prefix)
        else:
            yield prefix[:-1], "array"
    else:
        yield prefix[:-1], type(obj).__name__


def discover_fields(db, secret, sample_size=25):
    types = {}
    try:
        js = es_request(db, secret, "GET", f"{db['index']}/_mapping")
        for idx in js.values():
            mappings = idx.get("mappings", {})
            props = mappings.get("properties")
            if props is None:
                props = next((t["properties"] for t in mappings.values() if isinstance(t, dict)
                              and "properties" in t), {})
            for path, typ in _flatten_mapping(props):
                types.setdefault(path, typ)
    except EsError:
        pass
    samples = es_request(db, secret, "POST", f"{db['index']}/_search",
                         {"size": sample_size, "query": {"match_all": {}}}).get("hits", {}).get("hits", [])
    for h in samples:
        for path, typ in _flatten_source(h.get("_source", {})):
            if path:
                types.setdefault(path, typ)
    fields = [{"path": "_id", "type": "id", "sample": str(samples[0]["_id"]) if samples else ""}]
    for path in sorted(types):
        sample = next((v for v in (hit_value(h, path) for h in samples) if v), "")
        fields.append({"path": path, "type": types[path], "sample": sample})
    return fields, samples


def node_account(db, node, mappings):
    if node and mappings.get(node):
        return mappings[node]
    t = db.get("psmpUsernameTemplate") or "${node}"
    return t.replace("${node.lower}", node.lower()).replace("${node.upper}", node.upper()).replace("${node}", node)


def connection_from_hit(hit, db, mappings, psmp_login):
    base = {"type": "connection", "name": hit["displayName"], "description": f"[ES:{db['name']}] {hit['hostname']}",
            "host": hit["hostname"], "port": int(db.get("defaultSshPort") or 22), "variables": [],
            "autoResponses": []}
    if db.get("psmpGatewayHost"):
        tech = node_account(db, hit.get("node", ""), mappings)
        base.update({"username": tech, "authType": "psmp", "psmpHost": db["psmpGatewayHost"],
                     "psmpPort": int(db.get("psmpGatewayPort") or 22), "psmpUserLogin": psmp_login,
                     "psmpTechnicalAccount": tech, "psmpReason": db.get("defaultPsmpReason") or ""})
    else:
        base.update({"username": db.get("defaultUsername", ""), "authType": "agent"})
    return base


# ======================================================================================
# Import (WinTerm, extension VS Code « SSH Manager ») — lecture seule
# ======================================================================================

def _support_dirs():
    if IS_MAC:
        yield os.path.expanduser("~/Library/Application Support")
    else:
        yield os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
        yield os.environ.get("APPDATA") or ""


def winterm_configs():
    out = []
    for base in _support_dirs():
        for name in ("WinTerm", "winterm", "MacInDows", "macindows"):
            p = os.path.join(base, name, "config.json")
            if base and os.path.isfile(p) and p not in out:
                out.append(p)
    return out


def _clean_node(src):
    node = {k: v for k, v in src.items() if k not in ("children", "parentId", "_password")}
    if node.get("type") == "connection":
        node["autoResponses"] = [{k: v for k, v in r.items() if k != "response" or not r.get("secret")}
                                 for r in node.get("autoResponses", []) or [] if not r.get("secret")]
    return node


def _import_tree(store, nodes, nid, parent_id):
    src = nodes.get(nid)
    if not src or nid in store.nodes:
        return 0
    node = _clean_node(src)
    node["id"] = nid
    store.add(node, parent_id)
    return 1 + sum(_import_tree(store, nodes, c, nid) for c in src.get("children", []) or [])


def import_data(config, store, ssh_data=None, dbs=None, mappings=None, psmp_login=""):
    """Fusionne sans rien écraser : ce qui existe déjà est gardé."""
    n_nodes = n_dbs = n_map = 0
    if ssh_data:
        nodes = ssh_data.get("nodes", {})
        for rid in ssh_data.get("rootIds", []):
            n_nodes += _import_tree(store, nodes, rid, None)
    existing = {d["name"] for d in config.data["es"]["databases"]}
    for d in dbs or []:
        if d.get("name") and d["name"] not in existing:
            config.data["es"]["databases"].append(normalize_db(d))
            existing.add(d["name"])
            n_dbs += 1
    for k, v in (mappings or {}).items():
        if k not in config.data["psmpNodeMappings"]:
            config.data["psmpNodeMappings"][k] = v
            n_map += 1
    if psmp_login and not config.settings.get("psmpUserLogin"):
        config.settings["psmpUserLogin"] = psmp_login
    return n_nodes, n_dbs, n_map


def import_winterm(config, store, path):
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return import_data(config, store, data.get("ssh"), (data.get("es") or {}).get("databases"),
                       data.get("psmpNodeMappings"), (data.get("settings") or {}).get("psmpUserLogin", ""))


def _load_jsonc(path):
    with open(path, "r", encoding="utf-8") as fh:
        txt = fh.read()
    out, i, n, in_str = [], 0, len(txt), False
    while i < n:
        c = txt[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(txt[i + 1])
                i += 1
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
            out.append(c)
        elif txt.startswith("//", i):
            j = txt.find("\n", i)
            i = n if j < 0 else j
            continue
        elif txt.startswith("/*", i):
            j = txt.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        else:
            out.append(c)
        i += 1
    return json.loads(re.sub(r",(\s*[}\]])", r"\1", "".join(out)) or "{}")


def import_vscode(config, store):
    import sqlite3
    totals, found = [0, 0, 0], False
    for base in _support_dirs():
        for name in ("Code", "Code - Insiders", "VSCodium", "Cursor"):
            udir = os.path.join(base, name, "User")
            if not base or not os.path.isdir(udir):
                continue
            db_path = os.path.join(udir, "globalStorage", "state.vscdb")
            if os.path.isfile(db_path):
                try:
                    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
                    rows = con.execute("SELECT value FROM ItemTable WHERE key = ?", ("local.ssh-manager",)).fetchall()
                    con.close()
                except sqlite3.Error:
                    rows = []
                for (value,) in rows:
                    found = True
                    state = json.loads(value)
                    res = import_data(config, store, state.get("sshManager.data"), None,
                                      state.get("sshManager.es.nodeMapping"))
                    totals = [a + b for a, b in zip(totals, res)]
            sp = os.path.join(udir, "settings.json")
            if os.path.isfile(sp):
                try:
                    st = _load_jsonc(sp)
                except (ValueError, OSError):
                    st = {}
                if st.get("sshManager.elasticsearch.databases") or st.get("sshManager.psmpUserLogin"):
                    found = True
                res = import_data(config, store, None, st.get("sshManager.elasticsearch.databases"), None,
                                  st.get("sshManager.psmpUserLogin", ""))
                totals = [a + b for a, b in zip(totals, res)]
    return found, tuple(totals)


# ======================================================================================
# Qt (uniquement QtCore, QtGui et QtWidgets)
# ======================================================================================

from PySide6.QtCore import (QEvent, QObject, QPoint, QPointF, QRect, QRectF, QSize,  # noqa: E402
                            QSocketNotifier, Qt, QTimer, Signal)
from PySide6.QtGui import (QAction, QColor, QFont, QFontDatabase, QFontMetricsF,  # noqa: E402
                           QGuiApplication, QIcon, QKeySequence, QPainter, QPainterPath, QPalette, QPen,
                           QPixmap, QPolygonF)
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QButtonGroup, QCheckBox, QComboBox,  # noqa: E402
                               QDialog, QDialogButtonBox, QFileDialog, QFormLayout, QFrame, QGridLayout,
                               QHBoxLayout, QInputDialog, QLabel, QLineEdit, QListWidget,
                               QListWidgetItem, QMainWindow, QMenu, QMessageBox, QPlainTextEdit, QPushButton,
                               QRadioButton, QScrollArea, QScrollBar, QSpinBox, QSplitter,
                               QStackedWidget, QTabBar, QTabWidget, QToolButton, QTreeWidget,
                               QTreeWidgetItem, QVBoxLayout, QWidget)

# ---- interface sombre façon Windows Terminal --------------------------------------------

UI = {
    "tabbar": "#202020", "tab_hover": "#2A2A2A", "tab_active": "#2C2C2C", "text": "#FFFFFF",
    "text_dim": "#A8A8A8", "text_disabled": "#6D6D6D", "panel": "#272727", "panel_alt": "#2F2F2F",
    "input": "#1C1C1C", "border": "#3C3C3C", "hover": "#3A3A3A", "accent": "#4CC2FF", "accent_dark": "#0078D4",
    "danger": "#FF99A4", "success": "#6CCB5F", "warning": "#FCE100", "menu": "#2C2C2C",
}

SCHEMES = {
    "Campbell": {"background": "#0C0C0C", "foreground": "#CCCCCC", "cursor": "#FFFFFF", "selection": "#FFFFFF",
                 "colors": ["#0C0C0C", "#C50F1F", "#13A10E", "#C19C00", "#0037DA", "#881798", "#3A96DD",
                            "#CCCCCC", "#767676", "#E74856", "#16C60C", "#F9F1A5", "#3B78FF", "#B4009E",
                            "#61D6D6", "#F2F2F2"]},
    "Campbell PowerShell": {"background": "#012456", "foreground": "#CCCCCC", "cursor": "#FFFFFF",
                            "selection": "#FFFFFF",
                            "colors": ["#0C0C0C", "#C50F1F", "#13A10E", "#C19C00", "#0037DA", "#881798",
                                       "#3A96DD", "#CCCCCC", "#767676", "#E74856", "#16C60C", "#F9F1A5",
                                       "#3B78FF", "#B4009E", "#61D6D6", "#F2F2F2"]},
    "One Half Dark": {"background": "#282C34", "foreground": "#DCDFE4", "cursor": "#FFFFFF", "selection": "#FFFFFF",
                      "colors": ["#282C34", "#E06C75", "#98C379", "#E5C07B", "#61AFEF", "#C678DD", "#56B6C2",
                                 "#DCDFE4", "#5A6374", "#E06C75", "#98C379", "#E5C07B", "#61AFEF", "#C678DD",
                                 "#56B6C2", "#DCDFE4"]},
    "One Half Light": {"background": "#FAFAFA", "foreground": "#383A42", "cursor": "#4F525D",
                       "selection": "#4F525D",
                       "colors": ["#383A42", "#E45649", "#50A14F", "#C18401", "#0184BC", "#A626A4", "#0997B3",
                                  "#FAFAFA", "#4F525D", "#DF6C75", "#98C379", "#E4C07A", "#61AFEF", "#C577DD",
                                  "#56B5C1", "#FFFFFF"]},
    "Tango Dark": {"background": "#000000", "foreground": "#D3D7CF", "cursor": "#FFFFFF", "selection": "#FFFFFF",
                   "colors": ["#000000", "#CC0000", "#4E9A06", "#C4A000", "#3465A4", "#75507B", "#06989A",
                              "#D3D7CF", "#555753", "#EF2929", "#8AE234", "#FCE94F", "#729FCF", "#AD7FA8",
                              "#34E2E2", "#EEEEEC"]},
    "Solarized Dark": {"background": "#002B36", "foreground": "#839496", "cursor": "#FFFFFF", "selection": "#FFFFFF",
                       "colors": ["#002B36", "#DC322F", "#859900", "#B58900", "#268BD2", "#D33682", "#2AA198",
                                  "#EEE8D5", "#073642", "#CB4B16", "#586E75", "#657B83", "#839496", "#6C71C4",
                                  "#93A1A1", "#FDF6E3"]},
    "Vintage": {"background": "#000000", "foreground": "#C0C0C0", "cursor": "#FFFFFF", "selection": "#FFFFFF",
                "colors": ["#000000", "#800000", "#008000", "#808000", "#000080", "#800080", "#008080", "#C0C0C0",
                           "#808080", "#FF0000", "#00FF00", "#FFFF00", "#0000FF", "#FF00FF", "#00FFFF",
                           "#FFFFFF"]},
}


def build_palette(scheme):
    pal = [QColor(c) for c in scheme["colors"]]
    levels = [0, 95, 135, 175, 215, 255]
    for r in range(6):
        for g in range(6):
            for b in range(6):
                pal.append(QColor(levels[r], levels[g], levels[b]))
    pal += [QColor(8 + i * 10, 8 + i * 10, 8 + i * 10) for i in range(24)]
    return pal


def blend(c1, c2, t):
    a, b = QColor(c1), QColor(c2)
    return QColor(round(a.red() + (b.red() - a.red()) * t), round(a.green() + (b.green() - a.green()) * t),
                  round(a.blue() + (b.blue() - a.blue()) * t))


def mono_font(family="", size=13):
    families = set(QFontDatabase.families())
    cands = ([family] if family else []) + (["SF Mono", "Menlo", "Monaco"] if IS_MAC else
                                            ["Cascadia Mono", "Consolas", "DejaVu Sans Mono", "Liberation Mono"])
    for fam in cands:
        if fam in families:
            font = QFont(fam)
            break
    else:
        font = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
    font.setStyleHint(QFont.StyleHint.Monospace)
    font.setFixedPitch(True)
    font.setPointSizeF(float(size))
    font.setKerning(False)
    return font


# ---- glyphes (dessinés, aucune image externe) --------------------------------------------

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


def glyph_icon(name, color="#FFFFFF"):
    icon = QIcon()
    for px in (16, 20, 24, 32, 48, 64, 128, 256):
        pm = QPixmap(px, px)
        pm.fill(Qt.GlobalColor.transparent)
        p = QPainter(pm)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.scale(px / 16.0, px / 16.0)
        _GLYPHS[name](p, QColor(color))
        p.end()
        icon.addPixmap(pm)
    return icon


@_glyph("terminal")
def _(p, c):
    _pen(p, c, 1.3)
    p.drawRoundedRect(QRectF(1.5, 2.5, 13, 11), 2, 2)
    p.drawPolyline(QPolygonF([QPointF(4.5, 6), QPointF(7, 8), QPointF(4.5, 10)]))
    p.drawLine(QPointF(8.5, 10.5), QPointF(11.5, 10.5))


@_glyph("app")
def _(p, c):
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#1B1B1B"))
    p.drawRoundedRect(QRectF(0.8, 1.6, 14.4, 12.8), 2.6, 2.6)
    p.setBrush(QColor("#2E2E2E"))
    p.drawRoundedRect(QRectF(0.8, 1.6, 14.4, 3.4), 2.6, 2.6)
    p.drawRect(QRectF(0.8, 3.6, 14.4, 1.4))
    p.setBrush(QColor("#4CC2FF"))
    p.drawEllipse(QPointF(3, 3.3), 0.7, 0.7)
    _pen(p, "#4CC2FF", 1.5)
    p.drawPolyline(QPolygonF([QPointF(3.6, 7.2), QPointF(6.2, 9.4), QPointF(3.6, 11.6)]))
    _pen(p, "#FFFFFF", 1.5)
    p.drawLine(QPointF(7.6, 11.8), QPointF(11.8, 11.8))


@_glyph("ssh")
def _(p, c):
    _pen(p, c, 1.3)
    p.drawEllipse(QPointF(5, 8), 3, 3)
    p.drawLine(QPointF(8, 8), QPointF(14.5, 8))
    p.drawLine(QPointF(12.5, 8), QPointF(12.5, 10.5))
    p.drawLine(QPointF(14.5, 8), QPointF(14.5, 10.5))


@_glyph("key")
def _(p, c):
    _GLYPHS["ssh"](p, QColor("#FCE100"))


@_glyph("add")
def _(p, c):
    _pen(p, c, 1.3)
    p.drawLine(QPointF(8, 3), QPointF(8, 13))
    p.drawLine(QPointF(3, 8), QPointF(13, 8))


@_glyph("chevron")
def _(p, c):
    _pen(p, c, 1.3)
    p.drawPolyline(QPolygonF([QPointF(4, 6), QPointF(8, 10), QPointF(12, 6)]))


@_glyph("sidebar")
def _(p, c):
    _pen(p, c, 1.2)
    p.drawRoundedRect(QRectF(1.5, 2.5, 13, 11), 1.5, 1.5)
    p.drawLine(QPointF(6, 2.5), QPointF(6, 13.5))
    for y in (5.5, 8, 10.5):
        p.drawLine(QPointF(3, y), QPointF(4.5, y))


@_glyph("folder")
def _(p, c):
    _pen(p, c, 1.2)
    path = QPainterPath()
    path.moveTo(1.5, 4)
    path.lineTo(6, 4)
    path.lineTo(7.5, 5.5)
    path.lineTo(14.5, 5.5)
    path.lineTo(14.5, 13)
    path.lineTo(1.5, 13)
    path.closeSubpath()
    p.drawPath(path)


@_glyph("search")
def _(p, c):
    _pen(p, c, 1.4)
    p.drawEllipse(QPointF(6.5, 6.5), 4.3, 4.3)
    p.drawLine(QPointF(9.8, 9.8), QPointF(14.3, 14.3))


@_glyph("settings")
def _(p, c):
    _pen(p, c, 1.2)
    p.drawEllipse(QPointF(8, 8), 2.2, 2.2)
    import math
    for k in range(8):
        a = k * math.pi / 4
        p.drawLine(QPointF(8 + 4.2 * math.cos(a), 8 + 4.2 * math.sin(a)),
                   QPointF(8 + 6.2 * math.cos(a), 8 + 6.2 * math.sin(a)))
    p.drawEllipse(QPointF(8, 8), 4.2, 4.2)


@_glyph("plug")
def _(p, c):
    _pen(p, c, 1.3)
    p.drawLine(QPointF(2, 5), QPointF(12, 5))
    p.drawPolyline(QPolygonF([QPointF(10, 3), QPointF(12.5, 5), QPointF(10, 7)]))
    p.drawLine(QPointF(14, 11), QPointF(4, 11))
    p.drawPolyline(QPolygonF([QPointF(6, 9), QPointF(3.5, 11), QPointF(6, 13)]))


# ======================================================================================
# Session : un programme (shell ou ssh) branché sur un écran VT
# ======================================================================================

class Session(QObject):
    output = Signal()
    title_changed = Signal(str)
    exited = Signal(int)
    notify = Signal(str, str)            # (genre, message) : "code", "reason", "info"

    def __init__(self, spec, settings, scrollback=10000):
        super().__init__()
        self.spec = spec
        self.settings = settings
        self.screen = Screen(80, 24, scrollback)
        self.screen.write_back = self.write
        self.screen.on_title = self._on_title
        self.screen.on_bell = lambda: QApplication.beep()
        self.title = spec.name
        self.pty = None
        self.rn = self.wn = None
        self.started = False
        self.running = False
        self.exit_code = None
        self.rules = []
        self.started_at = 0.0
        self._phase_until = 0.0
        self._last_notice = None
        self._decoder = None
        self._reap = QTimer(self)
        self._reap.setInterval(40)
        self._reap.timeout.connect(self._check_exit)
        self._reason = None                  # envoi de la raison en cours (vérifié lettre par lettre)
        self._last_output = 0.0
        self._reason_timer = QTimer(self)
        self._reason_timer.setInterval(50)
        self._reason_timer.timeout.connect(self._reason_tick)
        if spec.banner:
            self.screen.feed(spec.banner)

    # ---- cycle de vie
    def start(self, cols, rows):
        import codecs
        self.screen.resize(cols, rows)
        self._decoder = codecs.getincrementaldecoder("utf-8")("replace")
        self.exit_code = None
        self.rules = list(self.spec.extra["rules"]()) if self.spec.extra.get("rules") else []
        self.started_at = time.monotonic()
        self._phase_until = 0.0
        self._last_notice = None
        self.started = True
        try:
            self.pty = Pty(self.spec.argv, cols, rows, self.spec.cwd, self.spec.extra.get("env"))
        except Exception as exc:  # noqa: BLE001
            self.screen.feed(f"\x1b[91m[Erreur] {exc}\x1b[0m\r\n")
            self.running = False
            self.exit_code = -1
            self.output.emit()
            QTimer.singleShot(0, lambda: self.exited.emit(-1))
            return
        self.running = True
        self.rn = QSocketNotifier(self.pty.fd, QSocketNotifier.Type.Read, self)
        self.rn.activated.connect(self._on_read)
        self.wn = QSocketNotifier(self.pty.fd, QSocketNotifier.Type.Write, self)
        self.wn.setEnabled(False)
        self.wn.activated.connect(self._on_write)

    def restart(self):
        self.screen.feed("\r\n")
        self.start(self.screen.cols, self.screen.rows)
        self.output.emit()

    def close(self):
        self._stop_notifiers()
        if self.pty is not None:
            self.pty.kill()
            pty = self.pty
            QTimer.singleShot(1500, lambda: pty.poll())      # ramasse le processus terminé
        self.running = False

    def _stop_notifiers(self):
        for n in (self.rn, self.wn):
            if n is not None:
                n.setEnabled(False)
                n.deleteLater()
        self.rn = self.wn = None

    # ---- entrées / sorties
    def _on_read(self, *_args):
        budget = 262144
        changed = False
        while budget > 0 and self.pty is not None:
            data = self.pty.read()
            if data is None:
                break
            if data == b"":
                self._stop_notifiers()
                self._reap.start()
                break
            budget -= len(data)
            text = self._decoder.decode(data)
            if text:
                self.screen.feed(text)
                changed = True
                self._last_output = time.monotonic()
        if changed:
            self._check_rules()
            self.output.emit()

    def _check_exit(self):
        if self.pty is None:
            self._reap.stop()
            return
        code = self.pty.poll()
        if code is None:
            return
        self._reap.stop()
        tail = self._decoder.decode(b"", final=True) if self._decoder else ""
        if tail:
            self.screen.feed(tail)
        self.pty.close()
        self.running = False
        self.exit_code = code
        self.output.emit()
        self.exited.emit(code)

    def write(self, data):
        if self.pty is None or not self.running:
            return
        self.pty.write(data.encode("utf-8") if isinstance(data, str) else data)
        if self.pty.out and self.wn is not None:
            self.wn.setEnabled(True)

    def _on_write(self, *_args):
        if self.pty is None or self.pty.flush():
            if self.wn is not None:
                self.wn.setEnabled(False)

    def paste(self, text):
        text = text.replace("\r\n", "\r").replace("\n", "\r")
        if self.screen.bracketed_paste:
            text = "\x1b[200~" + text.replace("\x1b[201~", "") + "\x1b[201~"
        self.write(text)

    def resize(self, cols, rows):
        if cols == self.screen.cols and rows == self.screen.rows:
            return
        self.screen.resize(cols, rows)
        if self.pty is not None and self.running:
            self.pty.resize(cols, rows)

    # ---- réponses automatiques
    def _check_rules(self):
        if not self.rules:
            return
        prompt = self.screen.prompt_text()
        if not prompt.strip():
            return
        window = float(self.settings.get("autoWindow", 180) or 180)
        now = time.monotonic()
        modes = self.pty.tty_modes() if self.pty is not None else None
        # ssh reste en mode ligne pendant toute l'authentification (clé de la passerelle, PIN, raison),
        # même si tu mets dix minutes à vérifier une empreinte ; il passe en mode brut une fois connecté.
        in_auth = modes is not None and modes[1]
        in_phase = in_auth or now < max(self.started_at + window, self._phase_until)
        key = (self.screen.history_total + self.screen.cy, prompt)
        for rule in self.rules:
            if (rule.once and rule.fired) or (rule.connection_phase and not in_phase):
                continue
            if not rule.regex.search(prompt):
                continue
            if rule.kind == "notify":
                self._phase_until = now + window       # tu cherches ton jeton : on attend la raison plus longtemps
                if key != self._last_notice:
                    self._last_notice = key
                    if rule.label == "raison PSM":
                        self.notify.emit("reason", "Le serveur demande la raison PSM : tape-la.")
                    else:
                        self.notify.emit("code", "Tape ton PIN + code RSA")
                break
            rule.fired = True
            if rule.label == "raison PSM":
                self._start_reason(rule)
                break
            resp = rule.response
            QTimer.singleShot(150, lambda r=resp: self.write(r + "\r"))
            self.notify.emit("info", f"Réponse automatique envoyée ({rule.label})")
            break

    # ---- raison PSM : envoi vérifié
    def _start_reason(self, rule):
        """1) attendre que le serveur ait fini d'écrire ; 2) taper la raison SANS valider ;
        3) relire ce que le serveur affiche ; 4) Entrée seulement si c'est exactement la raison."""
        text, problem = clean_reason(rule.response, self.settings.get("reasonAscii", False),
                                     self.settings.get("reasonMaxLen", 0))
        if problem:
            self.notify.emit("error", f"Raison non envoyée ({problem}) : tape-la toi-même.")
            return
        self._reason = {"rule": rule, "text": text, "stage": "quiet", "deadline": time.monotonic() + 6.0}
        self._reason_timer.start()

    def _end_reason(self, kind=None, message=""):
        self._reason = None
        self._reason_timer.stop()
        if kind:
            self.notify.emit(kind, message)

    def user_typed(self):
        """Tu as tapé quelque chose : l'envoi automatique s'arrête net (rien n'est validé à ta place)."""
        if self._reason is not None:
            sent = self._reason["stage"] == "echo"
            self._end_reason("warn", "Envoi automatique de la raison interrompu : tu as la main."
                             + (" Vérifie la ligne avant d'appuyer sur Entrée." if sent else ""))

    def _reason_tick(self):
        job = self._reason
        if job is None or not self.running:
            self._end_reason()
            return
        now = time.monotonic()
        s = self.screen
        target = job["text"]
        if job["stage"] == "quiet":
            if now - self._last_output < 0.3:
                if now > job["deadline"]:
                    job["rule"].fired = False
                    self._end_reason("error", "Le serveur écrit sans arrêt : raison non envoyée, tape-la toi-même.")
                return
            if not job["rule"].regex.search(s.prompt_text()):
                job["rule"].fired = False                 # la question a disparu : rien n'a été tapé
                self._end_reason()
                return
            modes = self.pty.tty_modes() if self.pty is not None else None
            if modes is not None and not modes[0] and modes[1]:
                # La passerelle masque la saisie, comme pour un mot de passe : rien ne s'affichera jamais.
                # On efface d'abord la ligne (au cas où), puis la raison exacte et Entrée d'un seul envoi.
                self.write(modes[2] + target.encode("utf-8") + b"\r")
                self._end_reason("reason", f"Raison PSM envoyée : « {target} » (saisie masquée par la passerelle, "
                                           "comme un mot de passe)")
                return
            job["start"] = (s.history_total + s.cy, s.cols if s.wrap_pending else s.cx)
            job["stage"] = "echo"
            job["deadline"] = now + 4.0
            self.write(target)                        # sans Entrée
            return
        shown = s.text_from(*job["start"])
        if shown == target:
            self.write("\r")
            self._end_reason("reason", f"Raison PSM envoyée et vérifiée : « {target} »")
        elif len(shown) > len(target) or (shown and not target.startswith(shown)):
            self._end_reason("error", f"Le serveur affiche « {shown[:70]} » au lieu de la raison : rien n'a été "
                                      "validé. Corrige la ligne puis appuie sur Entrée.")
        elif now > job["deadline"]:
            if not shown:
                modes = self.pty.tty_modes() if self.pty is not None else None
                if modes is not None and modes[1] and modes[2]:
                    self.write(modes[2])                        # ligne vidée : rien de caché ne reste
                    self._end_reason("warn", "Le serveur n'affiche pas la raison : rien n'a été validé et la "
                                             "ligne a été vidée. Tape la raison toi-même puis Entrée.")
                else:
                    self._end_reason("warn", "Raison tapée, mais le serveur ne l'affiche pas : impossible de la "
                                             "vérifier. Appuie sur Entrée si tu es sûr, sinon efface-la.")
            else:
                self._end_reason("error", f"Raison incomplète à l'écran (« {shown} ») : rien n'a été validé. "
                                          "Corrige la ligne puis appuie sur Entrée.")

    def _on_title(self, t):
        self.title = t or self.spec.name
        self.title_changed.emit(self.title)


# ======================================================================================
# Vue terminal
# ======================================================================================

_CURSOR_KEYS = {Qt.Key.Key_Up: "A", Qt.Key.Key_Down: "B", Qt.Key.Key_Right: "C", Qt.Key.Key_Left: "D",
                Qt.Key.Key_Home: "H", Qt.Key.Key_End: "F"}
_TILDE_KEYS = {Qt.Key.Key_Insert: 2, Qt.Key.Key_Delete: 3, Qt.Key.Key_PageUp: 5, Qt.Key.Key_PageDown: 6,
               Qt.Key.Key_F5: 15, Qt.Key.Key_F6: 17, Qt.Key.Key_F7: 18, Qt.Key.Key_F8: 19, Qt.Key.Key_F9: 20,
               Qt.Key.Key_F10: 21, Qt.Key.Key_F11: 23, Qt.Key.Key_F12: 24}
_SS3_KEYS = {Qt.Key.Key_F1: "P", Qt.Key.Key_F2: "Q", Qt.Key.Key_F3: "R", Qt.Key.Key_F4: "S"}
_CTRL_SPECIAL = {Qt.Key.Key_Space: "\x00", Qt.Key.Key_At: "\x00", Qt.Key.Key_2: "\x00",
                 Qt.Key.Key_BracketLeft: "\x1b", Qt.Key.Key_Backslash: "\x1c", Qt.Key.Key_BracketRight: "\x1d",
                 Qt.Key.Key_AsciiCircum: "\x1e", Qt.Key.Key_6: "\x1e", Qt.Key.Key_Underscore: "\x1f",
                 Qt.Key.Key_Minus: "\x1f", Qt.Key.Key_Slash: "\x1f", Qt.Key.Key_Question: "\x7f"}
# Sur Mac, Qt appelle « Control » la touche Cmd et « Meta » la vraie touche Ctrl.
TERM_CTRL = Qt.KeyboardModifier.MetaModifier if IS_MAC else Qt.KeyboardModifier.ControlModifier
APP_MOD = Qt.KeyboardModifier.ControlModifier          # Cmd sur Mac


def key_mods(ev, option_as_meta=False):
    m = ev.modifiers()
    shift = bool(m & Qt.KeyboardModifier.ShiftModifier)
    ctrl = bool(m & TERM_CTRL)
    alt = bool(m & Qt.KeyboardModifier.AltModifier)
    cmd = IS_MAC and bool(m & Qt.KeyboardModifier.ControlModifier)
    meta = alt and (not IS_MAC or option_as_meta)       # Option sur Mac = caractères spéciaux (| { } [ ] ~)
    return shift, ctrl, alt, cmd, meta


def encode_key(ev, screen, option_as_meta=False):
    key, text = ev.key(), ev.text()
    shift, ctrl, alt, cmd, meta = key_mods(ev, option_as_meta)
    if cmd:
        return None
    mod = 1 + (1 if shift else 0) + (2 if meta else 0) + (4 if ctrl else 0)
    if key in _CURSOR_KEYS:
        c = _CURSOR_KEYS[key]
        if mod > 1:
            return f"\x1b[1;{mod}{c}"
        return ("\x1bO" if screen.app_cursor else "\x1b[") + c
    if key in _TILDE_KEYS:
        n = _TILDE_KEYS[key]
        return f"\x1b[{n};{mod}~" if mod > 1 else f"\x1b[{n}~"
    if key in _SS3_KEYS:
        c = _SS3_KEYS[key]
        return f"\x1b[1;{mod}{c}" if mod > 1 else "\x1bO" + c
    if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
        return "\x1b\r" if meta else "\r"
    if key == Qt.Key.Key_Backspace:
        return ("\x1b" if meta else "") + ("\x08" if ctrl else "\x7f")
    if key == Qt.Key.Key_Backtab or (key == Qt.Key.Key_Tab and shift):
        return "\x1b[Z"
    if key == Qt.Key.Key_Tab:
        return "\t"
    if key == Qt.Key.Key_Escape:
        return "\x1b"
    if ctrl:
        if Qt.Key.Key_A <= key <= Qt.Key.Key_Z:
            return ("\x1b" if meta else "") + chr(key - Qt.Key.Key_A + 1)
        if key in _CTRL_SPECIAL:
            return _CTRL_SPECIAL[key]
        if text and len(text) == 1 and ord(text) < 32:
            return text
    if text:
        if text == "\x7f":
            return "\x7f"
        if meta and not ctrl:
            return "\x1b" + text
        return text
    return None


class TerminalView(QWidget):
    PAD = 6
    focused_view = Signal(object)
    context_menu = Signal(object, QPoint)
    close_requested = Signal(object)

    def __init__(self, session, app):
        super().__init__()
        self.session = session
        self.app = app
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setAttribute(Qt.WidgetAttribute.WA_InputMethodEnabled, True)
        self.setAttribute(Qt.WidgetAttribute.WA_OpaquePaintEvent, True)
        self.setCursor(Qt.CursorShape.IBeamCursor)
        self.setMouseTracking(True)
        self.setMinimumSize(120, 60)
        self.sb = QScrollBar(Qt.Orientation.Vertical, self)
        self.sb.setObjectName("termscroll")
        self.sb.valueChanged.connect(self._on_scroll)
        self.follow = True
        self.top_abs = 0
        self.sel_anchor = self.sel_head = None
        self._sel_mode = "char"
        self._press_pos = None
        self._last_click = (0.0, 0)
        self._mouse_btn = None
        self._wheel_acc = 0.0
        self._blink_on = True
        self.blink = QTimer(self)
        self.blink.setInterval(530)
        self.blink.timeout.connect(self._toggle_blink)
        self._resize_timer = QTimer(self)
        self._resize_timer.setSingleShot(True)
        self._resize_timer.setInterval(30)
        self._resize_timer.timeout.connect(self._apply_size)
        self.toast = QLabel(self)
        self.toast.setObjectName("toast")
        self.toast.setWordWrap(False)
        self.toast.hide()
        self._toast_timer = QTimer(self)
        self._toast_timer.setSingleShot(True)
        self._toast_timer.timeout.connect(self.toast.hide)
        self._style_cache = {}
        self.highlight = False
        self.apply_appearance()
        session.output.connect(self._on_output)
        session.notify.connect(self.show_notice)
        session.exited.connect(self._on_exit)

    # ---- apparence
    def apply_appearance(self):
        st = self.app.config.settings
        self.scheme = SCHEMES.get(st.get("colorScheme"), SCHEMES["Campbell"])
        self.palette_ = build_palette(self.scheme)
        self.bg = QColor(self.scheme["background"])
        self.fg = QColor(self.scheme["foreground"])
        self.cursor_color = QColor(self.scheme["cursor"])
        self.sel_color = blend(self.scheme["background"], self.scheme["selection"], 0.32)
        base = mono_font(st.get("fontFamily", ""), st.get("fontSize", 13))
        self.fonts = {}
        for key, (bold, italic) in {"n": (False, False), "b": (True, False), "i": (False, True),
                                    "bi": (True, True)}.items():
            f = QFont(base)
            f.setBold(bold)
            f.setItalic(italic)
            self.fonts[key] = f
        fm = QFontMetricsF(base)
        self.cw = max(1.0, fm.horizontalAdvance("M"))
        self.ch = max(1, int(fm.lineSpacing() + 0.999))
        self.ascent = fm.ascent()
        self._style_cache = {}
        self.update()
        self._resize_timer.start()

    def _color(self, c, bold=False):
        if c & TRUECOLOR:
            return QColor((c >> 16) & 255, (c >> 8) & 255, c & 255)
        if bold and c < 8:
            c += 8
        return self.palette_[c & 255]

    def _style(self, attr):
        st = self._style_cache.get(attr)
        if st is not None:
            return st
        fgc, bgc, fl = attr
        fg = QColor(self.fg) if fgc == DEFAULT else self._color(fgc, bool(fl & BOLD))
        bg = None if bgc == DEFAULT else self._color(bgc)
        if fl & REVERSE:
            fg, bg = (bg or QColor(self.bg)), fg
        if fl & DIM:
            fg = blend(fg, bg or self.bg, 0.45)
        if fl & HIDDEN:
            fg = bg or QColor(self.bg)
        bold, italic = bool(fl & BOLD), bool(fl & ITALIC)
        font = self.fonts["bi" if bold and italic else "b" if bold else "i" if italic else "n"]
        st = (fg, bg, font, bool(fl & UNDERLINE), bool(fl & STRIKE))
        self._style_cache[attr] = st
        return st

    # ---- géométrie
    def grid_size(self):
        w = self.width() - self.sb.width() - 2 * self.PAD
        h = self.height() - 2 * self.PAD
        return max(10, int(w // self.cw)), max(2, int(h // self.ch))

    def resizeEvent(self, ev):
        sw = 10
        self.sb.setGeometry(self.width() - sw, 0, sw, self.height())
        self._place_toast()
        self._resize_timer.start()
        super().resizeEvent(ev)

    def _apply_size(self):
        if self.width() < 40:
            return
        cols, rows = self.grid_size()
        if not self.session.started:
            self.session.start(cols, rows)
        else:
            self.session.resize(cols, rows)
        self._sync_scroll()
        self.update()

    # ---- défilement
    def _bounds(self):
        s = self.session.screen
        if s.alt_active:
            return s.history_total, s.history_total
        return s.first_abs(), s.history_total

    def _sync_scroll(self):
        lo, hi = self._bounds()
        if self.follow:
            self.top_abs = hi
        self.top_abs = max(lo, min(hi, self.top_abs))
        self.sb.blockSignals(True)
        self.sb.setRange(lo, hi)
        self.sb.setPageStep(self.session.screen.rows)
        self.sb.setValue(self.top_abs)
        self.sb.blockSignals(False)
        self.sb.setVisible(hi > lo)

    def _on_scroll(self, value):
        lo, hi = self._bounds()
        self.top_abs = value
        self.follow = value >= hi
        self.update()

    def scroll_lines(self, n):
        lo, hi = self._bounds()
        self.top_abs = max(lo, min(hi, self.top_abs + n))
        self.follow = self.top_abs >= hi
        self._sync_scroll()
        self.update()

    def scroll_to_bottom(self):
        self.follow = True
        self._sync_scroll()
        self.update()

    def _on_output(self):
        s = self.session.screen
        if s.history_resets != getattr(self, "_resets", 0):
            self._resets = s.history_resets
            self.sel_anchor = self.sel_head = None
        self._sync_scroll()
        self._blink_on = True
        self.update()

    # ---- dessin
    def paintEvent(self, ev):
        s = self.session.screen
        p = QPainter(self)
        p.fillRect(self.rect(), self.bg)
        cw, ch, pad = self.cw, self.ch, self.PAD
        rows = s.rows
        sel = self._selection_range()
        for vr in range(rows):
            abs_row = self.top_abs + vr
            line = s.line_at(abs_row)
            if line is None:
                continue
            y = pad + vr * ch
            chars, attrs = line.chars, line.attrs
            n = min(len(chars), s.cols)
            # fonds
            i = 0
            while i < n:
                a = attrs[i]
                j = i + 1
                while j < n and attrs[j] is a:
                    j += 1
                bg = self._style(a)[1]
                if bg is not None:
                    p.fillRect(QRectF(pad + i * cw, y, (j - i) * cw + 0.5, ch), bg)
                i = j
            if sel:
                c0, c1 = self._sel_cols(sel, abs_row, n)
                if c1 > c0:
                    p.fillRect(QRectF(pad + c0 * cw, y, (c1 - c0) * cw, ch), self.sel_color)
            # texte
            base = y + self.ascent + (ch - QFontMetricsF(self.fonts["n"]).lineSpacing()) / 2
            i = 0
            while i < n:
                a = attrs[i]
                fg, _bg, font, underline, strike = self._style(a)
                j = i
                run = []
                while j < n and attrs[j] is a and (chars[j].isascii() and len(chars[j]) == 1):
                    run.append(chars[j])
                    j += 1
                if run:
                    txt = "".join(run)
                    if txt.strip():
                        p.setFont(font)
                        p.setPen(fg)
                        p.drawText(QPointF(pad + i * cw, base), txt)
                    if underline or strike:
                        self._decorate(p, fg, pad + i * cw, y, (j - i) * cw, underline, strike)
                    i = j
                    continue
                c = chars[i]
                if c:
                    p.setFont(font)
                    p.setPen(fg)
                    p.drawText(QPointF(pad + i * cw, base), c)
                    if underline or strike:
                        self._decorate(p, fg, pad + i * cw, y, cw * (2 if i + 1 < n and chars[i + 1] == "" else 1),
                                       underline, strike)
                i += 1
        self._paint_cursor(p, s)
        if self.highlight:
            p.setPen(QPen(QColor(UI["accent"]), 1))
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawRect(self.rect().adjusted(0, 0, -1, -1))
        p.end()

    def _decorate(self, p, color, x, y, w, underline, strike):
        p.setPen(QPen(color, 1))
        if underline:
            p.drawLine(QPointF(x, y + self.ch - 2), QPointF(x + w, y + self.ch - 2))
        if strike:
            p.drawLine(QPointF(x, y + self.ch / 2), QPointF(x + w, y + self.ch / 2))

    def _paint_cursor(self, p, s):
        if not s.cursor_visible or not self.session.running:
            return
        vr = s.history_total + s.cy - self.top_abs
        if not (0 <= vr < s.rows):
            return
        focused = self.hasFocus()
        if focused and self.app.config.settings.get("cursorBlink", True) and not self._blink_on:
            return
        x = self.PAD + s.cx * self.cw
        y = self.PAD + vr * self.ch
        line = s.lines[s.cy]
        wide = s.cx + 1 < s.cols and line.chars[s.cx + 1] == ""
        w = self.cw * (2 if wide else 1)
        shape = self.app.config.settings.get("cursorShape", "bar")
        if s.cursor_style in (1, 2):
            shape = "block"
        elif s.cursor_style in (3, 4):
            shape = "underscore"
        elif s.cursor_style in (5, 6):
            shape = "bar"
        color = self.cursor_color if focused else blend(self.cursor_color, self.bg, 0.45)
        if not focused:
            p.setPen(QPen(color, 1))
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawRect(QRectF(x + 0.5, y + 0.5, w - 1, self.ch - 1))
        elif shape == "block":
            p.fillRect(QRectF(x, y, w, self.ch), color)
            ch = line.chars[s.cx]
            if ch.strip():
                p.setFont(self._style(line.attrs[s.cx])[2])
                p.setPen(self.bg)
                p.drawText(QPointF(x, y + self.ascent), ch)
        elif shape == "underscore":
            p.fillRect(QRectF(x, y + self.ch - 2, w, 2), color)
        else:
            p.fillRect(QRectF(x, y, 2, self.ch), color)

    def _toggle_blink(self):
        self._blink_on = not self._blink_on
        s = self.session.screen
        vr = s.history_total + s.cy - self.top_abs
        self.update(QRect(0, int(self.PAD + vr * self.ch) - 1, self.width(), self.ch + 2))

    # ---- focus
    def focusInEvent(self, ev):
        self._blink_on = True
        self.blink.start()
        if self.session.screen.focus_events:
            self.session.write("\x1b[I")
        self.focused_view.emit(self)
        if self.toast.isVisible() and self.toast.property("kind") == "focus":
            self.toast.hide()
        self.update()
        super().focusInEvent(ev)

    def focusOutEvent(self, ev):
        self.blink.stop()
        if self.session.screen.focus_events:
            self.session.write("\x1b[O")
        self.update()
        super().focusOutEvent(ev)

    # ---- clavier
    @staticmethod
    def is_terminal_key(ev):
        """Vrai si la touche doit aller au programme (et non déclencher un raccourci de la fenêtre)."""
        m = ev.modifiers()
        if IS_MAC:
            if m & Qt.KeyboardModifier.MetaModifier and ev.key() in (Qt.Key.Key_Tab, Qt.Key.Key_Backtab):
                return False                            # Ctrl+Tab = onglet suivant
            return not (m & APP_MOD)                    # Cmd+… = raccourcis de l'application
        ctrl, shift = bool(m & APP_MOD), bool(m & Qt.KeyboardModifier.ShiftModifier)
        alt = bool(m & Qt.KeyboardModifier.AltModifier)
        if ctrl and shift and not alt:
            return False                                # Ctrl+Maj+… = raccourcis (façon Windows Terminal)
        if ctrl and not alt and ev.key() in (Qt.Key.Key_Tab, Qt.Key.Key_Backtab, Qt.Key.Key_Plus, Qt.Key.Key_Minus,
                                            Qt.Key.Key_Equal, Qt.Key.Key_0, Qt.Key.Key_Comma):
            return False
        if alt and not ctrl and ev.key() in (Qt.Key.Key_Left, Qt.Key.Key_Right, Qt.Key.Key_Up, Qt.Key.Key_Down,
                                             Qt.Key.Key_Plus, Qt.Key.Key_Minus, Qt.Key.Key_Underscore,
                                             Qt.Key.Key_Equal, Qt.Key.Key_D):
            return False
        return True

    def event(self, ev):
        if ev.type() == QEvent.Type.ShortcutOverride and self.is_terminal_key(ev):
            ev.accept()
            return True
        return super().event(ev)

    def focusNextPrevChild(self, _next):
        return False                                    # Tab appartient au shell

    def keyPressEvent(self, ev):
        s = self.session
        shift, ctrl, alt, cmd, meta = key_mods(ev, self.app.config.settings.get("optionAsMeta", False))
        if not IS_MAC and ctrl and not shift and ev.key() == Qt.Key.Key_C and self.has_selection():
            self.copy()
            return
        if not IS_MAC and ctrl and not shift and ev.key() == Qt.Key.Key_V:
            self.paste()
            return
        if shift and not ctrl and ev.key() in (Qt.Key.Key_PageUp, Qt.Key.Key_PageDown):
            self.scroll_lines((-1 if ev.key() == Qt.Key.Key_PageUp else 1) * max(1, s.screen.rows - 1))
            return
        if not s.running:
            if ev.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter) and s.started:
                s.restart()
                self.update()
            elif ctrl and ev.key() == Qt.Key.Key_D:
                self.close_requested.emit(self)
            return
        data = encode_key(ev, s.screen, self.app.config.settings.get("optionAsMeta", False))
        if data:
            self.clear_selection()
            if self.toast.isVisible() and self.toast.property("kind") in ("code", "focus", "error", "warn"):
                self.toast.hide()
            s.user_typed()
            s.write(data)
            self.scroll_to_bottom()
            self._blink_on = True
        else:
            super().keyPressEvent(ev)

    def inputMethodEvent(self, ev):
        txt = ev.commitString()
        if txt and self.session.running:
            self.clear_selection()
            self.session.user_typed()
            self.session.write(txt)
            self.scroll_to_bottom()
        ev.accept()

    def inputMethodQuery(self, query):
        if query == Qt.InputMethodQuery.ImEnabled:
            return True
        if query == Qt.InputMethodQuery.ImCursorRectangle:
            s = self.session.screen
            vr = s.history_total + s.cy - self.top_abs
            return QRect(int(self.PAD + s.cx * self.cw), int(self.PAD + vr * self.ch), int(self.cw), self.ch)
        return super().inputMethodQuery(query)

    # ---- souris
    def cell_at(self, pos):
        col = int((pos.x() - self.PAD) // self.cw)
        vr = int((pos.y() - self.PAD) // self.ch)
        s = self.session.screen
        col = max(0, min(s.cols - 1, col))
        vr = max(0, min(s.rows - 1, vr))
        return self.top_abs + vr, col, vr

    def _mouse_report(self, ev, kind):
        """Transmet la souris aux programmes qui la demandent (vim, htop…). Maj = sélection locale."""
        s = self.session.screen
        if not s.mouse_mode or not self.session.running or ev.modifiers() & Qt.KeyboardModifier.ShiftModifier:
            return False
        if s.alt_active is False and not self.follow:
            return False
        _abs, col, vr = self.cell_at(ev.position().toPoint())
        if kind == "move":
            if s.mouse_mode == 1003 or (s.mouse_mode == 1002 and self._mouse_btn is not None):
                code = (self._mouse_btn if self._mouse_btn is not None else 3) + 32
            else:
                return True
        else:
            btn = {Qt.MouseButton.LeftButton: 0, Qt.MouseButton.MiddleButton: 1,
                   Qt.MouseButton.RightButton: 2}.get(ev.button(), 0)
            if kind == "press":
                self._mouse_btn = btn
                code = btn
            else:
                self._mouse_btn = None
                code = btn if s.mouse_sgr else 3
        m = ev.modifiers()
        code += (4 if m & Qt.KeyboardModifier.ShiftModifier else 0) + (16 if m & TERM_CTRL else 0)
        self._send_mouse(code, col, vr, kind == "release")
        return True

    def _send_mouse(self, code, col, row, release=False):
        s = self.session.screen
        if s.mouse_sgr:
            self.session.write(f"\x1b[<{code};{col + 1};{row + 1}{'m' if release else 'M'}")
        elif col < 223 and row < 223:
            self.session.write("\x1b[M" + chr(32 + code) + chr(33 + col) + chr(33 + row))

    def mousePressEvent(self, ev):
        self.setFocus()
        if ev.button() == Qt.MouseButton.RightButton:
            self.context_menu.emit(self, ev.globalPosition().toPoint())
            return
        if self._mouse_report(ev, "press"):
            return
        if ev.button() != Qt.MouseButton.LeftButton:
            return
        abs_row, col, _vr = self.cell_at(ev.position().toPoint())
        now = time.monotonic()
        clicks = self._last_click[1] + 1 if now - self._last_click[0] < 0.4 else 1
        self._last_click = (now, clicks)
        if ev.modifiers() & Qt.KeyboardModifier.ShiftModifier and self.sel_anchor is not None:
            self.sel_head = (abs_row, col)
        elif clicks == 2:
            self._select_word(abs_row, col)
        elif clicks >= 3:
            self._select_line(abs_row)
        else:
            self._sel_mode = "char"
            self.sel_anchor = self.sel_head = (abs_row, col)
            self._press_pos = ev.position().toPoint()
        self.update()

    def mouseDoubleClickEvent(self, ev):
        self.mousePressEvent(ev)

    def mouseMoveEvent(self, ev):
        if self._mouse_report(ev, "move"):
            return
        if not (ev.buttons() & Qt.MouseButton.LeftButton) or self.sel_anchor is None:
            return
        pos = ev.position().toPoint()
        if pos.y() < 0:
            self.scroll_lines(-1)
        elif pos.y() > self.height():
            self.scroll_lines(1)
        abs_row, col, _vr = self.cell_at(pos)
        x_col = (pos.x() - self.PAD) / self.cw
        if self._sel_mode == "char" and x_col - int(x_col) > 0.5:
            col = min(self.session.screen.cols, col + 1)
        self.sel_head = (abs_row, col)
        self.update()

    def mouseReleaseEvent(self, ev):
        if self._mouse_report(ev, "release"):
            return
        if self.sel_anchor == self.sel_head and self._sel_mode == "char":
            self.sel_anchor = self.sel_head = None
            self.update()
        elif self.has_selection() and self.app.config.settings.get("copyOnSelect"):
            self.copy(clear=False)

    def wheelEvent(self, ev):
        s = self.session.screen
        if ev.modifiers() & APP_MOD:
            self.app.zoom(1 if ev.angleDelta().y() > 0 else -1)
            return
        dy = ev.pixelDelta().y() / self.ch if not ev.pixelDelta().isNull() else ev.angleDelta().y() / 40
        self._wheel_acc += dy
        steps = int(self._wheel_acc)
        if not steps:
            return
        self._wheel_acc -= steps
        if s.mouse_mode and self.session.running:
            _abs, col, vr = self.cell_at(ev.position().toPoint())
            for _ in range(min(abs(steps), 10)):
                self._send_mouse(64 if steps > 0 else 65, col, vr)
            return
        if s.alt_active and self.session.running:
            key = ("\x1bOA" if s.app_cursor else "\x1b[A") if steps > 0 else ("\x1bOB" if s.app_cursor else "\x1b[B")
            self.session.write(key * min(abs(steps), 10))
            return
        self.scroll_lines(-steps)

    # ---- sélection
    def _selection_range(self):
        if self.sel_anchor is None or self.sel_head is None or self.sel_anchor == self.sel_head:
            return None
        a, b = sorted([self.sel_anchor, self.sel_head])
        return a, b

    @staticmethod
    def _sel_cols(sel, abs_row, n):
        (r0, c0), (r1, c1) = sel
        if abs_row < r0 or abs_row > r1:
            return 0, 0
        start = c0 if abs_row == r0 else 0
        end = c1 if abs_row == r1 else n
        return start, min(end, n)

    def has_selection(self):
        return self._selection_range() is not None

    def clear_selection(self):
        if self.sel_anchor is not None:
            self.sel_anchor = self.sel_head = None
            self.update()

    def _select_word(self, abs_row, col):
        line = self.session.screen.line_at(abs_row)
        if line is None:
            return
        chars = line.chars
        word = re.compile(r"[\w.\-/~:@%+=#,]")
        if not word.match(chars[col] or " "):
            self.sel_anchor, self.sel_head = (abs_row, col), (abs_row, col + 1)
            return
        a = col
        while a > 0 and word.match(chars[a - 1] or " "):
            a -= 1
        b = col
        while b < len(chars) and word.match(chars[b] or " "):
            b += 1
        self.sel_anchor, self.sel_head = (abs_row, a), (abs_row, b)
        self._sel_mode = "word"

    def _select_line(self, abs_row):
        self.sel_anchor, self.sel_head = (abs_row, 0), (abs_row, self.session.screen.cols)
        self._sel_mode = "line"

    def select_all(self):
        s = self.session.screen
        self.sel_anchor, self.sel_head = (s.first_abs(), 0), (s.history_total + s.rows - 1, s.cols)
        self.update()

    def selected_text(self):
        sel = self._selection_range()
        if not sel:
            return ""
        s = self.session.screen
        (r0, _c0), (r1, _c1) = sel
        out = []
        for r in range(r0, r1 + 1):
            line = s.line_at(r)
            if line is None:
                continue
            a, b = self._sel_cols(sel, r, len(line.chars))
            txt = "".join(line.chars[a:b])
            if r < r1 and line.wrapped and b >= len(line.chars):
                out.append(txt)
            else:
                out.append(txt.rstrip() + ("\n" if r < r1 else ""))
        return "".join(out)

    def copy(self, clear=True):
        txt = self.selected_text()
        if txt:
            QGuiApplication.clipboard().setText(txt)
            if clear:
                self.clear_selection()
        return bool(txt)

    def paste(self):
        txt = QGuiApplication.clipboard().text()
        if not txt or not self.session.running:
            return
        if "\n" in txt.rstrip("\n") and self.app.config.settings.get("warnPaste", True):
            n = txt.rstrip("\n").count("\n") + 1
            if not confirm(self.window(), "Coller plusieurs lignes",
                           f"Tu vas coller {n} lignes : chacune sera exécutée comme une commande.\n\n"
                           + txt[:400] + ("…" if len(txt) > 400 else ""), ok="Coller"):
                return
        self.session.user_typed()
        self.session.paste(txt)
        self.scroll_to_bottom()

    def clear_buffer(self):
        s = self.session.screen
        s.history.clear()
        s.history_resets += 1
        self.sel_anchor = self.sel_head = None
        self.scroll_to_bottom()

    # ---- recherche dans l'historique
    def find(self, text, backwards=True, case=False):
        """Cherche à partir de la sélection actuelle ; sélectionne et montre le résultat."""
        if not text:
            return False
        s = self.session.screen
        needle = text if case else text.lower()
        first, last = s.first_abs(), s.history_total + s.rows - 1
        if self.sel_anchor is not None:
            start = min(self.sel_anchor, self.sel_head)[0] - (1 if backwards else -1)
        else:
            start = last if backwards else first
        rng = range(start, first - 1, -1) if backwards else range(start, last + 1)
        for r in rng:
            line = s.line_at(r)
            if line is None:
                continue
            hay = "".join(c if c else "" for c in line.chars)
            hay = hay if case else hay.lower()
            k = hay.rfind(needle) if backwards else hay.find(needle)
            if k >= 0:
                self.sel_anchor, self.sel_head = (r, k), (r, k + len(text))
                lo, hi = self._bounds()
                if not (self.top_abs <= r < self.top_abs + s.rows):
                    self.top_abs = max(lo, min(hi, r - s.rows // 2))
                    self.follow = self.top_abs >= hi
                    self._sync_scroll()
                self.update()
                return True
        return False

    # ---- notifications dans le volet
    def show_notice(self, kind, message):
        self.toast.setText({"code": "🔑  ", "reason": "✓  ", "error": "⚠  ", "warn": "⚠  "}.get(kind, "") + message)
        self.toast.setProperty("kind", kind)
        self.toast.setStyleSheet({"error": "QLabel#toast { border-color: #E74856; }",
                                  "warn": "QLabel#toast { border-color: #FCE100; }"}.get(kind, ""))
        self.toast.adjustSize()
        self._place_toast()
        self.toast.show()
        self.toast.raise_()
        if kind in ("code", "error", "warn"):
            self._toast_timer.stop()          # reste affiché jusqu'à ce que tu tapes
            win = self.window()
            if not win.isActiveWindow():
                QApplication.alert(win, 0)    # le Dock rebondit
            if self.isVisible():
                self.setFocus()
        else:
            self._toast_timer.start(5000)
        self.app.on_notice(self, kind)

    def _place_toast(self):
        if not self.toast.isVisible() and not self.toast.text():
            return
        self.toast.adjustSize()
        w, h = self.toast.width(), self.toast.height()
        self.toast.move(max(8, (self.width() - self.sb.width() - w) // 2), self.height() - h - 14)

    def _on_exit(self, code):
        self.update()

    def show_exit_message(self, code):
        self.session.screen.feed(
            f"\r\n\x1b[90m[processus terminé, code {code}] Entrée pour relancer, "
            f"{'Cmd+W' if IS_MAC else 'Ctrl+Maj+W'} pour fermer.\x1b[0m")
        self._on_output()


# ======================================================================================
# Petits outils d'interface
# ======================================================================================

SESSION_SECRETS = {}          # clé API / mot de passe Elasticsearch : en mémoire seulement, jamais sur disque


class _Relay(QObject):
    done = Signal(object, object)


_JOBS = set()


def run_async(fn, callback):
    """Exécute fn() dans un fil à part (réseau Elasticsearch) et rappelle callback(résultat, erreur) ici."""
    import threading
    relay = _Relay()
    _JOBS.add(relay)

    def finish(res, err):
        _JOBS.discard(relay)
        callback(res, err)
    relay.done.connect(finish, Qt.ConnectionType.QueuedConnection)

    def work():
        try:
            res, err = fn(), None
        except EsError as exc:
            res, err = None, str(exc)
        except Exception as exc:  # noqa: BLE001
            res, err = None, f"{type(exc).__name__} : {exc}"
        relay.done.emit(res, err)
    threading.Thread(target=work, daemon=True).start()


def es_secret(parent, db, ask=True):
    """Clé API / mot de passe de la base : demandé une fois par lancement, gardé en mémoire uniquement."""
    auth = db.get("authType", "none")
    if auth == "none":
        return ""
    slug = db_slug(db.get("name"))
    if slug in SESSION_SECRETS:
        return SESSION_SECRETS[slug]
    if not ask:
        return None
    label = "Clé API (encodée base64)" if auth == "apiKey" else f"Mot de passe de {db.get('basicAuthUsername')}"
    text, ok = QInputDialog.getText(parent, f"Elasticsearch — {db.get('name')}",
                                    label + "\n(gardé en mémoire jusqu'à la fermeture, jamais enregistré)",
                                    QLineEdit.EchoMode.Password)
    if not ok:
        return None
    SESSION_SECRETS[slug] = text
    return text


def form(parent=None):
    lay = QFormLayout(parent)
    lay.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)
    lay.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)
    return lay


def hint(text):
    lab = QLabel(text)
    lab.setObjectName("hint")
    lab.setWordWrap(True)
    return lab


def confirm(parent, title, text, ok="Oui"):
    box = QMessageBox(QMessageBox.Icon.Question, title, text, QMessageBox.StandardButton.Cancel, parent)
    yes = box.addButton(ok, QMessageBox.ButtonRole.AcceptRole)
    box.setDefaultButton(QMessageBox.StandardButton.Cancel)
    box.exec()
    return box.clickedButton() is yes


def copy_text(text):
    QGuiApplication.clipboard().setText(text or "")


class KeyValueEditor(QWidget):
    def __init__(self, items=None, key_label="Nom", value_label="Valeur"):
        super().__init__()
        self.rows = []
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        head = QHBoxLayout()
        for txt, stretch in ((key_label, 1), (value_label, 2)):
            lab = QLabel(txt)
            lab.setObjectName("hint")
            head.addWidget(lab, stretch)
        head.addSpacing(28)
        lay.addLayout(head)
        self.box = QVBoxLayout()
        lay.addLayout(self.box)
        add = QPushButton("+ Ajouter")
        add.clicked.connect(lambda: self.add_row("", ""))
        lay.addWidget(add, 0, Qt.AlignmentFlag.AlignLeft)
        for it in items or []:
            self.add_row(it.get("key", ""), it.get("value", ""))

    def add_row(self, k, v):
        row = QWidget()
        h = QHBoxLayout(row)
        h.setContentsMargins(0, 0, 0, 0)
        ke, ve = QLineEdit(k), QLineEdit(v)
        rm = QToolButton()
        rm.setText("✕")
        rec = (row, ke, ve)
        rm.clicked.connect(lambda: (row.deleteLater(), self.rows.remove(rec)))
        h.addWidget(ke, 1)
        h.addWidget(ve, 2)
        h.addWidget(rm)
        self.box.addWidget(row)
        self.rows.append(rec)
        if not k:
            ke.setFocus()

    def get(self):
        return [{"key": k.text().strip(), "value": v.text()} for _, k, v in self.rows if k.text().strip()]


# ======================================================================================
# Dialogues
# ======================================================================================

class ReasonCombo(QComboBox):
    """Champ « raison » : choisir dans la liste évite toute faute de frappe ; texte libre possible."""
    textChanged = Signal(str)

    def __init__(self, value, choices, placeholder=""):
        super().__init__()
        self.setEditable(True)
        self.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self.addItems([n for n, _d in choices])
        self.setCurrentText(value or "")
        self.lineEdit().setPlaceholderText(placeholder)
        self.editTextChanged.connect(self.textChanged)

    def text(self):
        return self.currentText()

    def setText(self, value):
        self.setCurrentText(value)


class ReasonDialog(QDialog):
    """Raison PSM, comme sur le portail : une raison prédéfinie (sans faute possible) ou une autre."""

    def __init__(self, parent, target, history, default="", ascii_only=False, max_len=0, choices=None, now=None):
        super().__init__(parent)
        self.ascii_only, self.max_len = ascii_only, max_len
        self.choices = list(choices or PSM_REASONS)
        self.now = now or datetime.datetime.now()
        self.setWindowTitle("Raison de la connexion")
        self.setMinimumWidth(620)
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel(f"Connexion PSMP vers <b>{target}</b>"))
        lay.addWidget(hint("Tapée quand la passerelle la demande (après ton PIN + code RSA), puis relue à l'écran : "
                           "Entrée n'est envoyée que si le texte affiché est exactement celui-ci."))
        lay.addWidget(QLabel("<b>Choisis une raison</b>"))
        box = QFrame()
        box.setObjectName("card")
        bl = QVBoxLayout(box)
        bl.setSpacing(2)
        self.group = QButtonGroup(self)
        self.radios = {}
        for name, desc in self.choices:
            rb = QRadioButton(name.replace("&", "&&"))
            f = rb.font()
            f.setBold(True)
            rb.setFont(f)
            self.group.addButton(rb)
            self.radios[name] = rb
            bl.addWidget(rb)
            if desc:
                d = hint(desc)
                d.setContentsMargins(24, 0, 0, 6)
                bl.addWidget(d)
            rb.toggled.connect(lambda on, n=name: on and self._radio_chosen())
        lay.addWidget(box)
        lay.addWidget(QLabel("<b>Ou saisis une autre raison</b>"))
        self.free = QComboBox()
        self.free.setEditable(True)
        self.free.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        names = {n.casefold() for n, _d in self.choices}
        custom = []
        for h in history:
            clean, problem = clean_reason(h, ascii_only, max_len)
            if clean and not problem and clean.casefold() not in names and clean not in custom:
                custom.append(clean)
        self.free.addItems(custom)
        self.free.setCurrentText("")
        self.free.lineEdit().setPlaceholderText("Ta raison")
        self.free.editTextChanged.connect(self._free_typed)
        lay.addWidget(self.free)
        self.preview = QLabel("")
        self.preview.setWordWrap(True)
        self.preview.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        lay.addWidget(self.preview)
        self.warning = QLabel("")
        self.warning.setWordWrap(True)
        lay.addWidget(self.warning)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.ok = bb.button(QDialogButtonBox.StandardButton.Ok)
        self.ok.setText("Se connecter")
        bb.button(QDialogButtonBox.StandardButton.Cancel).setText("Annuler")
        bb.accepted.connect(self._accept)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)
        exact = canon_reason(default, self.choices) if default else ""
        if exact in self.radios:
            self.radios[exact].setChecked(True)
        elif default and default.strip():
            self.free.setCurrentText(default)
        else:
            rb = self.radios.get(DEFAULT_PSM_REASON) or next(iter(self.radios.values()), None)
            if rb is not None:
                rb.setChecked(True)
        self._check()

    def _uncheck_all(self):
        self.group.setExclusive(False)
        for rb in self.radios.values():
            rb.setChecked(False)
        self.group.setExclusive(True)

    def _radio_chosen(self):
        self.free.blockSignals(True)
        self.free.setCurrentText("")
        self.free.blockSignals(False)
        self._check()

    def _free_typed(self, text):
        if text.strip():
            self._uncheck_all()
        self._check()

    def selected(self):
        return next((n for n, rb in self.radios.items() if rb.isChecked()), "")

    def _value(self):
        name = self.selected()
        if name:
            return clean_reason(name, self.ascii_only, self.max_len)
        return clean_reason(canon_reason(self.free.currentText(), self.choices), self.ascii_only, self.max_len)

    def _check(self, *_a):
        clean, problem = self._value()
        if not self.selected() and not self.free.currentText().strip():
            problem = "choisis une raison ou saisis-en une"
        self.ok.setEnabled(not problem)
        if problem:
            self.preview.setText(f"<span style='color:#FF99A4'>⚠ {problem[:1].upper() + problem[1:]}</span>")
        else:
            esc = clean.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            self.preview.setText(f"Sera envoyé ({len(clean)} caractères) : « <b>{esc}</b> »")
        notes = []
        raw = self.free.currentText()
        if not problem and not self.selected() and clean in self.radios:
            notes.append("reconnue comme raison prédéfinie : orthographe exacte utilisée")
        elif not problem and not self.selected() and clean != raw.strip():
            notes.append("espaces en trop, retours à la ligne ou caractères invisibles retirés")
        if not problem and not clean.isascii():
            notes.append("contient des accents : vérifie à la 1re connexion qu'ils sont bien enregistrés côté "
                         "CyberArk (sinon coche « Raison sans accents » dans Paramètres › PSMP)")
        if clean == "Morning checks" and self.now.hour >= 11:
            notes.append(f"« Morning checks » est prévue pour le matin, avant 11 h (il est {self.now:%H:%M})")
        self.warning.setText("<span style='color:#FCE100'>" + "<br>".join(notes) + "</span>" if notes else "")

    def _accept(self):
        if self.ok.isEnabled():
            self.accept()

    def reason(self):
        return self._value()[0]


class CategoryDialog(QDialog):
    def __init__(self, parent, app, node=None, parent_id=None):
        super().__init__(parent)
        node = node or {}
        self.setWindowTitle("Modifier la catégorie" if node else "Nouvelle catégorie")
        self.setMinimumWidth(560)
        lay = QVBoxLayout(self)
        f = form()
        self.name = QLineEdit(node.get("name", ""))
        self.desc = QLineEdit(node.get("description", ""))
        f.addRow("Nom", self.name)
        f.addRow("Description", self.desc)
        lay.addLayout(f)
        pid = node.get("parentId") if node else parent_id
        inh = inherited_variables(app.store, pid)
        if inh:
            lay.addWidget(QLabel("<b>Variables héritées</b>"))
            for k, v, src in inh:
                lay.addWidget(hint(f"${{{k}}} = {v}    ← {src}"))
        lay.addWidget(QLabel("<b>Variables</b> (utilisables avec ${NOM} dans les connexions de la catégorie)"))
        self.vars = KeyValueEditor(node.get("variables", []))
        lay.addWidget(self.vars)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self._ok)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)

    def _ok(self):
        if not self.name.text().strip():
            QMessageBox.warning(self, "Nom requis", "Indique un nom de catégorie.")
            return
        self.accept()

    def result_node(self):
        return {"type": "category", "name": self.name.text().strip(), "description": self.desc.text().strip(),
                "variables": self.vars.get()}


class AutoResponseEditor(QWidget):
    def __init__(self, rules):
        super().__init__()
        self.rows = []
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        self.box = QVBoxLayout()
        lay.addLayout(self.box)
        add = QPushButton("+ Ajouter une réponse")
        add.clicked.connect(lambda: self.add_row({}))
        lay.addWidget(add, 0, Qt.AlignmentFlag.AlignLeft)
        for r in rules or []:
            if not r.get("secret"):
                self.add_row(r)

    def add_row(self, r):
        w = QFrame()
        w.setObjectName("card")
        g = QGridLayout(w)
        pat = QLineEdit(r.get("pattern", ""))
        pat.setPlaceholderText("Quand la ligne affichée se termine par…")
        resp = QLineEdit(r.get("response", ""))
        resp.setPlaceholderText("…taper (texte en clair, jamais un mot de passe)")
        rx = QCheckBox("Expression régulière")
        rx.setChecked(bool(r.get("regex")))
        once = QCheckBox("Une seule fois")
        once.setChecked(r.get("once", True))
        rm = QToolButton()
        rm.setText("✕")
        rec = {"w": w, "id": r.get("id") or new_id(), "pattern": pat, "response": resp, "regex": rx, "once": once}
        rm.clicked.connect(lambda: (w.deleteLater(), self.rows.remove(rec)))
        g.addWidget(pat, 0, 0, 1, 2)
        g.addWidget(resp, 0, 2, 1, 2)
        g.addWidget(rm, 0, 4)
        g.addWidget(rx, 1, 0)
        g.addWidget(once, 1, 1)
        self.box.addWidget(w)
        self.rows.append(rec)

    def get(self):
        return [{"id": r["id"], "pattern": r["pattern"].text(), "response": r["response"].text(),
                 "regex": r["regex"].isChecked(), "once": r["once"].isChecked()}
                for r in self.rows if r["pattern"].text()]


class ConnectionDialog(QDialog):
    def __init__(self, parent, app, node=None, parent_id=None, temp=False):
        super().__init__(parent)
        self.app = app
        self.node = node = copy.deepcopy(node or {})
        self.parent_id = node.get("parentId") if node.get("id") else parent_id
        self.setWindowTitle("Modifier la connexion" if node.get("id") else "Nouvelle connexion")
        self.resize(700, 640)
        lay = QVBoxLayout(self)
        tabs = QTabWidget()
        lay.addWidget(tabs, 1)
        self.e = {}

        def entry(f, key, label, default="", tip=None):
            w = QLineEdit(str(node.get(key, default) if node.get(key) is not None else default))
            w.textChanged.connect(self.update_preview)
            self.e[key] = w
            f.addRow(label, w)
            if tip:
                f.addRow("", hint(tip))
            return w

        g = QWidget()
        fg = form(g)
        entry(fg, "name", "Nom")
        entry(fg, "description", "Description")
        entry(fg, "host", "Hôte cible", tip="Variables ${NOM} acceptées")
        entry(fg, "port", "Port", 22)
        entry(fg, "username", "Utilisateur")
        entry(fg, "extraArgs", "Options ssh", tip="Facultatif, ex. : -o ServerAliveInterval=30")
        tabs.addTab(g, "Général")

        a = QWidget()
        al = QVBoxLayout(a)
        self.auth = QComboBox()
        for key, label in AUTH_TYPES:
            self.auth.addItem(label, key)
        idx = max(0, self.auth.findData(node.get("authType", "agent")))
        self.auth.setCurrentIndex(idx)
        self.auth.currentIndexChanged.connect(self._auth_changed)
        row = QHBoxLayout()
        row.addWidget(QLabel("Type"))
        row.addWidget(self.auth, 1)
        al.addLayout(row)
        self.auth_pages = QStackedWidget()
        al.addWidget(self.auth_pages)
        al.addStretch(1)
        pa = QWidget()
        QVBoxLayout(pa).addWidget(hint("Utilise ton agent SSH et ta configuration ~/.ssh/config."))
        pk = QWidget()
        fk = form(pk)
        kr = QHBoxLayout()
        self.e["privateKeyPath"] = ke = QLineEdit(node.get("privateKeyPath", ""))
        ke.textChanged.connect(self.update_preview)
        browse = QPushButton("Parcourir…")
        browse.clicked.connect(self._browse_key)
        kr.addWidget(ke, 1)
        kr.addWidget(browse)
        fk.addRow("Clé privée", kr)
        fk.addRow("", hint("Seul le chemin est noté : la clé reste où elle est."))
        pp = QWidget()
        QVBoxLayout(pp).addWidget(hint("ssh te demandera ton mot de passe : tu le tapes toi-même, "
                                       "rien n'est enregistré."))
        ps = QWidget()
        fs = form(ps)
        entry(fs, "psmpHost", "Passerelle PSMP")
        entry(fs, "psmpPort", "Port passerelle", 22)
        entry(fs, "psmpUserLogin", "Login personnel",
              tip=f"Vide = celui des paramètres ({app.config.settings.get('psmpUserLogin') or 'non défini'})")
        entry(fs, "psmpTechnicalAccount", "Compte technique")
        choices = reason_choices(app.config.settings)
        self.e["psmpReason"] = rc = ReasonCombo(node.get("psmpReason", ""), choices, "vide = raison par défaut")
        rc.textChanged.connect(self.update_preview)
        fs.addRow("Raison PSM", rc)
        fs.addRow("", hint("Choisis-la dans la liste pour éviter toute faute. Tapée automatiquement quand la "
                           "passerelle la demande (après ton PIN + code RSA)."))
        self._choices = choices
        for page in (pa, pk, pp, ps):
            self.auth_pages.addWidget(page)
        tabs.addTab(a, "Authentification")

        v = QWidget()
        vl = QVBoxLayout(v)
        inh = inherited_variables(app.store, self.parent_id)
        if inh:
            vl.addWidget(QLabel("<b>Variables héritées</b>"))
            for k, val, src in inh:
                vl.addWidget(hint(f"${{{k}}} = {val}    ← {src}"))
        vl.addWidget(QLabel("<b>Variables locales</b> (prioritaires)"))
        self.vars = KeyValueEditor(node.get("variables", []))
        vl.addWidget(self.vars)
        vl.addStretch(1)
        tabs.addTab(v, "Variables")

        r = QWidget()
        rl = QVBoxLayout(r)
        rl.addWidget(hint("Le terminal regarde la ligne où attend le curseur et tape la réponse quand elle "
                          "correspond. La raison PSM est déjà gérée : ajoute ici d'autres questions simples. "
                          "Pas de mot de passe ici."))
        self.rules = AutoResponseEditor(node.get("autoResponses", []))
        rl.addWidget(self.rules)
        rl.addStretch(1)
        tabs.addTab(r, "Réponses automatiques")

        pv = QGridLayout()
        self.preview = QLineEdit()
        self.preview.setReadOnly(True)
        self.psm = QLineEdit()
        self.psm.setReadOnly(True)
        for w in (self.preview, self.psm):
            w.setFont(mono_font("", 12))
        c1, c2 = QPushButton("Copier"), QPushButton("Copier")
        c1.clicked.connect(lambda: copy_text(self.preview.text()))
        c2.clicked.connect(lambda: copy_text(self.psm.text()))
        pv.addWidget(QLabel("Commande"), 0, 0)
        pv.addWidget(self.preview, 0, 1)
        pv.addWidget(c1, 0, 2)
        pv.addWidget(QLabel("Chaîne PSM"), 1, 0)
        pv.addWidget(self.psm, 1, 1)
        pv.addWidget(c2, 1, 2)
        lay.addLayout(pv)
        bb = QDialogButtonBox()
        if temp:
            bb.addButton("Se connecter", QDialogButtonBox.ButtonRole.AcceptRole)
        else:
            bb.addButton(QDialogButtonBox.StandardButton.Save)
        bb.addButton(QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self._ok)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)
        self._auth_changed()

    def _browse_key(self):
        path, _ = QFileDialog.getOpenFileName(self, "Clé privée SSH", os.path.expanduser("~/.ssh"))
        if path:
            self.e["privateKeyPath"].setText(path)

    def auth_type(self):
        return self.auth.currentData() or "agent"

    def _auth_changed(self, *_a):
        self.auth_pages.setCurrentIndex([k for k, _l in AUTH_TYPES].index(self.auth_type()))
        self.update_preview()

    def values(self):
        d = {k: w.text().strip() for k, w in self.e.items()}
        for k in ("port", "psmpPort"):
            d[k] = _int(d.get(k))
        d.update({"authType": self.auth_type(), "type": "connection", "variables": self.vars.get(),
                  "autoResponses": self.rules.get()})
        if d.get("psmpReason") and "${" not in d["psmpReason"]:
            d["psmpReason"] = canon_reason(d["psmpReason"], self._choices)
        return d

    def update_preview(self, *_a):
        d = self.values()
        d["id"], d["parentId"] = self.node.get("id"), self.parent_id
        variables = {k: v for k, v, _s in inherited_variables(self.app.store, self.parent_id)}
        variables.update({it["key"]: it["value"] for it in d["variables"]})
        try:
            plan = build_plan(d, variables, self.app.config.settings.get("psmpUserLogin", ""))
            cmd, psm = plan.display, plan.psm_string or "—"
        except Exception as exc:  # noqa: BLE001
            cmd, psm = f"Incomplet : {exc}", "—"
        self.preview.setText(cmd)
        self.psm.setText(psm)

    def _ok(self):
        d = self.values()
        if not d["host"]:
            QMessageBox.warning(self, "Hôte requis", "Indique l'hôte cible.")
            return
        if not d["name"]:
            self.e["name"].setText(d["host"])
        self.accept()

    def result_node(self):
        return self.values()


class EsDatabaseDialog(QDialog):
    def __init__(self, parent, app, db=None):
        super().__init__(parent)
        self.app = app
        self.orig_name = (db or {}).get("name")
        self.db = normalize_db(db or {})
        db = self.db
        self.setWindowTitle("Base Elasticsearch")
        self.resize(720, 640)
        lay = QVBoxLayout(self)
        tabs = QTabWidget()
        lay.addWidget(tabs, 1)
        self.e = {}

        def entry(f, key, label, tip=None):
            w = QLineEdit(str(db.get(key, "")))
            self.e[key] = w
            f.addRow(label, w)
            if tip:
                f.addRow("", hint(tip))
            return w

        c = QWidget()
        fc = form(c)
        entry(fc, "name", "Nom")
        entry(fc, "url", "Adresse", "https:// obligatoire, ex. https://es.entreprise.local:9200 — seule cette "
                                    "adresse sera autorisée à sortir.")
        entry(fc, "index", "Index", "Motifs acceptés : servers-*")
        ar = QHBoxLayout()
        self.auth_btns = {}
        for val, lbl in (("none", "Aucune"), ("apiKey", "Clé API"), ("basic", "Utilisateur + mot de passe")):
            b = QRadioButton(lbl)
            b.setChecked(db.get("authType") == val)
            b.toggled.connect(self._auth_changed)
            self.auth_btns[val] = b
            ar.addWidget(b)
        ar.addStretch(1)
        fc.addRow("Authentification", ar)
        self.user = QLineEdit(db.get("basicAuthUsername", ""))
        self.user_label = QLabel("Utilisateur")
        fc.addRow(self.user_label, self.user)
        fc.addRow("", hint("La clé ou le mot de passe te sera demandé à la première recherche, gardé en mémoire "
                           "jusqu'à la fermeture, jamais enregistré."))
        cr = QHBoxLayout()
        self.e["caFile"] = cae = QLineEdit(db.get("caFile", ""))
        cb = QPushButton("…")
        cb.clicked.connect(self._browse_ca)
        cr.addWidget(cae, 1)
        cr.addWidget(cb)
        fc.addRow("Certificat de l'entreprise", cr)
        fc.addRow("", hint("Fichier .pem de l'autorité de certification interne (export depuis Trousseau "
                           "d'accès). Le certificat du serveur est toujours vérifié."))
        tr = QHBoxLayout()
        test = QPushButton("Tester la connexion")
        test.clicked.connect(self._test)
        self.test_lbl = QLabel("")
        self.test_lbl.setWordWrap(True)
        tr.addWidget(test)
        tr.addWidget(self.test_lbl, 1)
        fc.addRow("", tr)
        tabs.addTab(c, "Connexion")

        p = QWidget()
        fp = form(p)
        entry(fp, "psmpGatewayHost", "Passerelle PSMP", "Vide = connexion ssh directe")
        entry(fp, "psmpGatewayPort", "Port passerelle")
        entry(fp, "psmpUsernameTemplate", "Compte technique", "Modèle : ${node}, ${node.lower}, ${node.upper} "
                                                              "(si le nœud n'est pas dans la table des nœuds)")
        self.e["defaultPsmpReason"] = ReasonCombo(db.get("defaultPsmpReason", ""),
                                                  reason_choices(app.config.settings), "vide = raison par défaut")
        fp.addRow("Raison PSM par défaut", self.e["defaultPsmpReason"])
        entry(fp, "defaultSshPort", "Port ssh cible")
        entry(fp, "defaultUsername", "Utilisateur (sans PSMP)")
        entry(fp, "favoriteCategoryName", "Catégorie des favoris")
        tabs.addTab(p, "SSH / PSMP")

        d = QWidget()
        dl = QHBoxLayout(d)
        left = QVBoxLayout()
        fm = db["fieldMapping"]
        fd = QFormLayout()
        self.map = {}
        for key, label, multi in (("displayNameFields", "Titre", True), ("subtitleFields", "Sous-titre", True),
                                  ("hostnameField", "Hôte de connexion", False), ("statusField", "Statut", False),
                                  ("statusAliveValue", "Valeur « vivant »", False), ("osField", "Système", False),
                                  ("nodeField", "Nœud PSMP", False), ("tagFields", "Étiquettes", True),
                                  ("detailFields", "Détails", True)):
            val = fm.get(key)
            w = QLineEdit(", ".join(val) if isinstance(val, list) else str(val or ""))
            w.setProperty("multi", multi)
            w.installEventFilter(self)
            self.map[key] = w
            fd.addRow(label, w)
        left.addLayout(fd)
        left.addWidget(hint("Plusieurs champs : sépare-les par des virgules (le 1er non vide sert de titre). "
                            "Double-clique un champ à droite pour l'ajouter dans la case sélectionnée."))
        left.addStretch(1)
        dl.addLayout(left, 3)
        right = QVBoxLayout()
        load = QPushButton("Charger les champs de l'index")
        load.clicked.connect(self._load_fields)
        right.addWidget(load)
        self.fields = QListWidget()
        self.fields.itemDoubleClicked.connect(self._add_field)
        right.addWidget(self.fields, 1)
        dl.addLayout(right, 2)
        self._last_map = self.map["displayNameFields"]
        tabs.addTab(d, "Affichage des résultats")
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self._ok)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)
        self._auth_changed()

    def eventFilter(self, obj, ev):
        if ev.type() == QEvent.Type.FocusIn and obj in self.map.values():
            self._last_map = obj
        return super().eventFilter(obj, ev)

    def _auth_changed(self, *_a):
        basic = self.auth_btns["basic"].isChecked()
        self.user.setVisible(basic)
        self.user_label.setVisible(basic)

    def _browse_ca(self):
        path, _ = QFileDialog.getOpenFileName(self, "Certificat de l'entreprise", os.path.expanduser("~"),
                                              "Certificats (*.pem *.crt *.cer);;Tous (*)")
        if path:
            self.e["caFile"].setText(path)

    def current_db(self):
        d = dict(self.db)
        for k, w in self.e.items():
            d[k] = w.text().strip()
        if d.get("defaultPsmpReason"):
            d["defaultPsmpReason"] = canon_reason(d["defaultPsmpReason"], reason_choices(self.app.config.settings))
        d["authType"] = next((k for k, b in self.auth_btns.items() if b.isChecked()), "none")
        d["basicAuthUsername"] = self.user.text().strip()
        fm = dict(d["fieldMapping"])
        for key, w in self.map.items():
            txt = w.text().strip()
            fm[key] = [x.strip() for x in txt.split(",") if x.strip()] if w.property("multi") else txt
        fm["hostnameField"] = fm["hostnameField"] or "_id"
        fm["statusAliveValue"] = fm["statusAliveValue"] or "alive"
        d["fieldMapping"] = fm
        return normalize_db(d)

    def _authorize(self, d):
        try:
            host, port, _p = es_address(d)
        except EsError as exc:
            self.test_lbl.setText(str(exc))
            return False
        autoriser_hote(host, port)
        return True

    def _test(self):
        d = self.current_db()
        if not self._authorize(d):
            return
        secret = es_secret(self, d)
        if secret is None:
            return
        self.test_lbl.setText("Test en cours…")
        run_async(lambda: es_test(d, secret),
                  lambda res, err: self.test_lbl.setText(res if res else f"Échec : {err}"))

    def _load_fields(self):
        d = self.current_db()
        if not self._authorize(d):
            return
        secret = es_secret(self, d)
        if secret is None:
            return
        self.fields.clear()
        self.fields.addItem("Chargement…")

        def done(res, err):
            self.fields.clear()
            if err:
                self.fields.addItem(f"Erreur : {err[:200]}")
                return
            for f in res[0]:
                it = QListWidgetItem(f"{f['path']}    {f['sample'][:40]}")
                it.setData(Qt.ItemDataRole.UserRole, f["path"])
                it.setToolTip(f"{f['type']} — ex. : {f['sample'][:200]}")
                self.fields.addItem(it)
        run_async(lambda: discover_fields(d, secret), done)

    def _add_field(self, item):
        path = item.data(Qt.ItemDataRole.UserRole)
        w = self._last_map
        if not path or w is None:
            return
        if w.property("multi") and w.text().strip():
            parts = [x.strip() for x in w.text().split(",") if x.strip()]
            if path not in parts:
                w.setText(", ".join(parts + [path]))
        else:
            w.setText(path)

    def _ok(self):
        d = self.current_db()
        if not d["name"] or not d["url"]:
            QMessageBox.warning(self, "Champs requis", "Le nom et l'adresse sont obligatoires.")
            return
        try:
            es_address(d)
        except EsError as exc:
            QMessageBox.warning(self, "Adresse refusée", str(exc))
            return
        others = [x["name"] for x in self.app.config.data["es"]["databases"] if x["name"] != self.orig_name]
        if d["name"] in others:
            QMessageBox.warning(self, "Nom déjà utilisé", "Une autre base porte déjà ce nom.")
            return
        self.accept()


class NodeMappingDialog(QDialog):
    def __init__(self, parent, app, db):
        super().__init__(parent)
        self.app, self.db = app, db
        self.setWindowTitle(f"Nœuds PSMP — {db['name']}")
        self.resize(620, 560)
        lay = QVBoxLayout(self)
        lay.addWidget(hint(f"Associe chaque nœud (champ « {db['fieldMapping'].get('nodeField')} ») à son compte "
                           "technique PSMP."))
        bar = QHBoxLayout()
        scan = QPushButton("Lister les nœuds depuis Elasticsearch")
        scan.clicked.connect(self._scan)
        add = QPushButton("+ Nœud")
        add.clicked.connect(lambda: self._row("", ""))
        self.status = QLabel("")
        bar.addWidget(scan)
        bar.addWidget(add)
        bar.addWidget(self.status, 1)
        lay.addLayout(bar)
        area = QScrollArea()
        area.setWidgetResizable(True)
        inner = QWidget()
        self.box = QVBoxLayout(inner)
        self.box.addStretch(1)
        area.setWidget(inner)
        lay.addWidget(area, 1)
        self.rows = []
        for n, acc in sorted(app.config.data.get("psmpNodeMappings", {}).items()):
            self._row(n, acc)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)

    def _row(self, node, acc):
        w = QWidget()
        h = QHBoxLayout(w)
        h.setContentsMargins(0, 0, 0, 0)
        ne, ae = QLineEdit(node), QLineEdit(acc or (node_account(self.db, node, {}) if node else ""))
        rm = QToolButton()
        rm.setText("✕")
        rec = (w, ne, ae)
        rm.clicked.connect(lambda: (w.deleteLater(), self.rows.remove(rec)))
        h.addWidget(ne, 1)
        h.addWidget(ae, 1)
        h.addWidget(rm)
        self.box.insertWidget(self.box.count() - 1, w)
        self.rows.append(rec)

    def _scan(self):
        secret = es_secret(self, self.db)
        if secret is None:
            return
        self.status.setText("Recherche…")

        def done(nodes, err):
            if err:
                self.status.setText(f"Erreur : {err[:100]}")
                return
            known = {ne.text() for _w, ne, _a in self.rows}
            new = [n for n in nodes if n not in known]
            for n in new:
                self._row(n, "")
            self.status.setText(f"{len(nodes)} nœud(s), {len(new)} nouveau(x)")
        run_async(lambda: unique_nodes(self.db, secret), done)

    def mapping(self):
        return {ne.text().strip(): ae.text().strip() for _w, ne, ae in self.rows if ne.text().strip()}


class SettingsDialog(QDialog):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        s = app.config.settings
        self.setWindowTitle("Paramètres")
        self.resize(680, 620)
        lay = QVBoxLayout(self)
        tabs = QTabWidget()
        lay.addWidget(tabs, 1)

        ap = QWidget()
        fa = form(ap)
        self.font = QComboBox()
        self.font.setEditable(True)
        self.font.addItems(sorted(f for f in QFontDatabase.families() if QFontDatabase.isFixedPitch(f)))
        self.font.setCurrentText(s.get("fontFamily") or mono_font().family())
        fa.addRow("Police", self.font)
        self.size = QSpinBox()
        self.size.setRange(6, 40)
        self.size.setValue(int(s.get("fontSize", 13)))
        fa.addRow("Taille", self.size)
        self.scheme = QComboBox()
        self.scheme.addItems(list(SCHEMES))
        self.scheme.setCurrentText(s.get("colorScheme", "Campbell"))
        fa.addRow("Couleurs", self.scheme)
        self.cursor = QComboBox()
        for key, label in (("bar", "Barre"), ("underscore", "Souligné"), ("block", "Bloc")):
            self.cursor.addItem(label, key)
        self.cursor.setCurrentIndex(max(0, self.cursor.findData(s.get("cursorShape", "bar"))))
        fa.addRow("Curseur", self.cursor)
        self.blink = QCheckBox("Curseur clignotant")
        self.blink.setChecked(s.get("cursorBlink", True))
        fa.addRow("", self.blink)
        tabs.addTab(ap, "Apparence")

        bh = QWidget()
        fb = form(bh)
        self.default = QComboBox()
        for p in app.profiles:
            self.default.addItem(p.name)
        self.default.setCurrentText(s.get("defaultProfile") or (app.profiles[0].name if app.profiles else ""))
        fb.addRow("Shell par défaut", self.default)
        self.close_exit = QComboBox()
        for key, label in (("graceful", "Si tout s'est bien passé (code 0)"), ("always", "Toujours"),
                           ("never", "Jamais")):
            self.close_exit.addItem(label, key)
        self.close_exit.setCurrentIndex(max(0, self.close_exit.findData(s.get("closeOnExit", "graceful"))))
        fb.addRow("Fermer le volet à la fin", self.close_exit)
        self.scrollback = QSpinBox()
        self.scrollback.setRange(1000, 200000)
        self.scrollback.setSingleStep(1000)
        self.scrollback.setValue(int(s.get("scrollback", 10000)))
        fb.addRow("Historique (lignes)", self.scrollback)
        self.cos = QCheckBox("Copier automatiquement la sélection")
        self.cos.setChecked(s.get("copyOnSelect", False))
        self.wp = QCheckBox("Demander avant de coller plusieurs lignes")
        self.wp.setChecked(s.get("warnPaste", True))
        self.cc = QCheckBox("Demander avant de fermer plusieurs onglets")
        self.cc.setChecked(s.get("confirmClose", True))
        self.oam = QCheckBox("Option sert de touche Méta (sinon : caractères spéciaux | { } [ ] ~)")
        self.oam.setChecked(s.get("optionAsMeta", False))
        for w in (self.cos, self.wp, self.cc, self.oam):
            fb.addRow("", w)
        tabs.addTab(bh, "Comportement")

        ps = QWidget()
        fp = form(ps)
        self.login = QLineEdit(s.get("psmpUserLogin", ""))
        fp.addRow("Login PSMP personnel", self.login)
        self.ask = QCheckBox("Demander la raison à chaque connexion PSMP (pré-remplie avec la dernière)")
        self.ask.setChecked(s.get("askReason", True))
        fp.addRow("", self.ask)
        self.reason = ReasonCombo(s.get("defaultReason") or DEFAULT_PSM_REASON, reason_choices(s))
        fp.addRow("Raison par défaut", self.reason)
        self.choices_edit = QPlainTextEdit("\n".join(f"{n} | {d}" for n, d in reason_choices(s)))
        self.choices_edit.setFixedHeight(110)
        self.choices_edit.setFont(mono_font("", 11))
        fp.addRow("Raisons prédéfinies", self.choices_edit)
        fp.addRow("", hint("Une par ligne : « Nom exact | description ». Le nom est envoyé tel quel."))
        self.rpat = QLineEdit(s.get("reasonPattern", REASON_PATTERN))
        self.cpat = QLineEdit(s.get("codePattern", CODE_PATTERN))
        for w in (self.rpat, self.cpat):
            w.setFont(mono_font("", 11))
        fp.addRow("Invite « raison »", self.rpat)
        fp.addRow("Invite « PIN + code »", self.cpat)
        fp.addRow("", hint("Expressions régulières testées sur la ligne où attend le curseur. "
                           "La raison est tapée pour toi ; pour le PIN + code, le terminal te prévient seulement."))
        self.ascii = QCheckBox("Raison sans accents (é → e, œ → oe…) si la passerelle les enregistre mal")
        self.ascii.setChecked(s.get("reasonAscii", False))
        fp.addRow("", self.ascii)
        self.maxlen = QSpinBox()
        self.maxlen.setRange(0, 2000)
        self.maxlen.setSpecialValueText("pas de limite")
        self.maxlen.setSuffix(" caractères")
        self.maxlen.setValue(int(s.get("reasonMaxLen", 0) or 0))
        fp.addRow("Longueur max. de la raison", self.maxlen)
        self.window_s = QSpinBox()
        self.window_s.setRange(20, 3600)
        self.window_s.setSuffix(" s")
        self.window_s.setValue(int(s.get("autoWindow", 180)))
        fp.addRow("Surveiller pendant", self.window_s)
        tabs.addTab(ps, "PSMP")

        info = QWidget()
        il = QVBoxLayout(info)
        il.addWidget(QLabel("<b>Reprendre des connexions existantes</b>"))
        il.addWidget(hint("Rien n'est écrasé : seules les connexions, bases et nœuds absents sont ajoutés. "
                          "Les mots de passe ne sont jamais repris."))
        row = QHBoxLayout()
        b1 = QPushButton("Depuis WinTerm")
        b1.clicked.connect(self._import_winterm)
        b2 = QPushButton("Depuis VS Code (SSH Manager)")
        b2.clicked.connect(self._import_vscode)
        row.addWidget(b1)
        row.addWidget(b2)
        row.addStretch(1)
        il.addLayout(row)
        self.import_lbl = hint("")
        il.addWidget(self.import_lbl)
        il.addSpacing(12)
        il.addWidget(QLabel("<b>Sécurité</b>"))
        problems = controle_reseau()
        state = "actif ✓" if _VERROU["actif"] and not problems else ("actif" if _VERROU["actif"] else "inactif (test)")
        il.addWidget(hint(f"Verrou : {state}\nProgrammes autorisés : "
                          + ", ".join(sorted(os.path.basename(p) for p in _EXEC_AUTORISES))
                          + "\nAdresses réseau autorisées : " + (", ".join(hotes_autorises()) or "aucune")
                          + f"\nConfiguration : {app.config.path}"))
        il.addStretch(1)
        tabs.addTab(info, "Import et sécurité")
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self._ok)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)

    def parsed_choices(self):
        out = []
        for line in self.choices_edit.toPlainText().splitlines():
            name, _sep, desc = line.partition("|")
            name = clean_reason(name)[0]
            if name and name.casefold() not in {n.casefold() for n, _d in out}:
                out.append([name, desc.strip()])
        return out

    def _ok(self):
        if not self.parsed_choices():
            QMessageBox.warning(self, "Raisons", "Il faut au moins une raison prédéfinie.")
            return
        for w, label in ((self.rpat, "raison"), (self.cpat, "PIN + code")):
            try:
                re.compile(w.text())
            except re.error as exc:
                QMessageBox.warning(self, "Expression invalide", f"Invite « {label} » : {exc}")
                return
        self.accept()

    def _import_winterm(self):
        files = winterm_configs()
        if not files:
            path, _ = QFileDialog.getOpenFileName(self, "config.json de WinTerm", os.path.expanduser("~"),
                                                  "JSON (*.json)")
            if not path:
                return
            files = [path]
        total = [0, 0, 0]
        for f in files:
            try:
                total = [a + b for a, b in zip(total, import_winterm(self.app.config, self.app.store, f))]
            except (OSError, ValueError) as exc:
                self.import_lbl.setText(f"Lecture impossible de {f} : {exc}")
                return
        self.app.save()
        self.app.refresh_sidebar()
        self.import_lbl.setText(f"WinTerm : {total[0]} élément(s), {total[1]} base(s), {total[2]} nœud(s) ajoutés.")

    def _import_vscode(self):
        try:
            found, total = import_vscode(self.app.config, self.app.store)
        except Exception as exc:  # noqa: BLE001
            self.import_lbl.setText(f"Import impossible : {exc}")
            return
        self.app.save()
        self.app.refresh_sidebar()
        self.import_lbl.setText(f"VS Code : {total[0]} élément(s), {total[1]} base(s), {total[2]} nœud(s) "
                                "ajoutés." if found else "Aucune donnée SSH Manager trouvée dans VS Code.")

    def values(self):
        return {"fontFamily": self.font.currentText().strip(), "fontSize": self.size.value(),
                "colorScheme": self.scheme.currentText(), "cursorShape": self.cursor.currentData(),
                "cursorBlink": self.blink.isChecked(), "defaultProfile": self.default.currentText(),
                "closeOnExit": self.close_exit.currentData(), "scrollback": self.scrollback.value(),
                "copyOnSelect": self.cos.isChecked(), "warnPaste": self.wp.isChecked(),
                "confirmClose": self.cc.isChecked(), "optionAsMeta": self.oam.isChecked(),
                "psmpUserLogin": self.login.text().strip(), "askReason": self.ask.isChecked(),
                "defaultReason": canon_reason(self.reason.text(), [tuple(c) for c in self.parsed_choices()]),
                "reasonChoices": self.parsed_choices(), "reasonPattern": self.rpat.text(),
                "codePattern": self.cpat.text(), "autoWindow": self.window_s.value(),
                "reasonAscii": self.ascii.isChecked(), "reasonMaxLen": self.maxlen.value()}


# ======================================================================================
# Barre latérale : connexions + recherche Elasticsearch
# ======================================================================================

class ConnTree(QTreeWidget):
    moved = Signal(str, object, object)       # id, nouveau parent, position

    def __init__(self):
        super().__init__()
        self.setHeaderHidden(True)
        self.setDragDropMode(QAbstractItemView.DragDropMode.InternalMove)
        self.setDefaultDropAction(Qt.DropAction.MoveAction)
        self.setIndentation(16)

    def dropEvent(self, ev):
        src = self.currentItem()
        target = self.itemAt(ev.position().toPoint())
        ev.ignore()
        if src is None:
            return
        sid = src.data(0, Qt.ItemDataRole.UserRole)
        if target is None:
            self.moved.emit(sid, None, None)
            return
        tid = target.data(0, Qt.ItemDataRole.UserRole)
        pos = self.dropIndicatorPosition()
        if target.data(0, Qt.ItemDataRole.UserRole + 1) == "category" and \
                pos == QAbstractItemView.DropIndicatorPosition.OnItem:
            self.moved.emit(sid, tid, None)
            return
        parent = target.parent()
        pid = parent.data(0, Qt.ItemDataRole.UserRole) if parent else None
        idx = (parent.indexOfChild(target) if parent else self.indexOfTopLevelItem(target))
        if pos == QAbstractItemView.DropIndicatorPosition.BelowItem:
            idx += 1
        self.moved.emit(sid, pid, idx)


AUTH_GLYPH = {"psmp": "◈", "password": "●", "privateKey": "◆", "agent": "▸"}


class ConnectionsPanel(QWidget):
    def __init__(self, app):
        super().__init__()
        self.app = app
        lay = QVBoxLayout(self)
        lay.setContentsMargins(8, 6, 4, 4)
        bar = QHBoxLayout()
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("Filtrer…")
        self.filter.setClearButtonEnabled(True)
        self.filter.textChanged.connect(self.refresh)
        bar.addWidget(self.filter, 1)
        for icon, tip, fn in (("add", "Nouvelle connexion", lambda: self.new_connection()),
                              ("folder", "Nouvelle catégorie", lambda: self.new_category()),
                              ("plug", "Connexion rapide (non enregistrée)", self.quick_connect)):
            b = QToolButton()
            b.setIcon(glyph_icon(icon, UI["text"]))
            b.setToolTip(tip)
            b.clicked.connect(fn)
            bar.addWidget(b)
        lay.addLayout(bar)
        self.tree = ConnTree()
        self.tree.itemActivated.connect(self._activate)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._menu)
        self.tree.moved.connect(self._moved)
        lay.addWidget(self.tree, 1)
        self.empty = hint("Aucune connexion.\nClique sur + pour en créer une, ou reprends celles de WinTerm "
                          "(Paramètres › Import).")
        self.empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(self.empty)
        self.refresh()

    def refresh(self, *_a):
        t = self.tree
        opened = set()
        for i in range(t.topLevelItemCount()):
            self._collect_open(t.topLevelItem(i), opened)
        sel = self.selected()
        t.clear()
        store = self.app.store
        q = self.filter.text().strip().lower()
        if q:
            for n in sorted(store.all_connections(), key=lambda n: n.get("name", "").lower()):
                if any(q in str(n.get(k, "")).lower() for k in ("name", "host", "description", "psmpTechnicalAccount")):
                    t.addTopLevelItem(self._item(n))
        else:
            def add(parent, nodes):
                for n in nodes:
                    item = self._item(n)
                    if parent is None:
                        t.addTopLevelItem(item)
                    else:
                        parent.addChild(item)
                    if n.get("type") == "category":
                        add(item, store.children(n["id"]))
                        item.setExpanded(n["id"] in opened or not opened)
            add(None, store.children(None))
        if sel:
            self._select(sel["id"])
        self.empty.setVisible(not store.nodes)

    def _collect_open(self, item, out):
        if item.isExpanded():
            out.add(item.data(0, Qt.ItemDataRole.UserRole))
        for i in range(item.childCount()):
            self._collect_open(item.child(i), out)

    def _item(self, n):
        cat = n.get("type") == "category"
        text = n.get("name", "") if cat else f"{AUTH_GLYPH.get(n.get('authType'), '›')}  {n.get('name') or n.get('host')}"
        item = QTreeWidgetItem([text])
        item.setData(0, Qt.ItemDataRole.UserRole, n["id"])
        item.setData(0, Qt.ItemDataRole.UserRole + 1, n.get("type"))
        if cat:
            f = item.font(0)
            f.setBold(True)
            item.setFont(0, f)
            item.setIcon(0, glyph_icon("folder", UI["text_dim"]))
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsDropEnabled)
        else:
            item.setToolTip(0, n.get("description") or n.get("host", ""))
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsDropEnabled)
        return item

    def _select(self, nid):
        def walk(item):
            if item.data(0, Qt.ItemDataRole.UserRole) == nid:
                self.tree.setCurrentItem(item)
                return True
            return any(walk(item.child(i)) for i in range(item.childCount()))
        for i in range(self.tree.topLevelItemCount()):
            if walk(self.tree.topLevelItem(i)):
                return

    def selected(self):
        item = self.tree.currentItem()
        return self.app.store.get(item.data(0, Qt.ItemDataRole.UserRole)) if item else None

    def _target_parent(self):
        n = self.selected()
        if not n:
            return None
        return n["id"] if n.get("type") == "category" else n.get("parentId")

    def _activate(self, item, _col=0):
        n = self.app.store.get(item.data(0, Qt.ItemDataRole.UserRole))
        if n and n.get("type") == "connection":
            self.app.connect(n)

    def _moved(self, sid, pid, idx):
        if sid in self.app.store.nodes and self.app.store.move(sid, pid, idx):
            self.app.save()
        self.refresh()
        self._select(sid)

    def new_connection(self, parent_id="__sel__"):
        pid = self._target_parent() if parent_id == "__sel__" else parent_id
        dlg = ConnectionDialog(self, self.app, None, pid)
        if dlg.exec():
            self.app.store.add(dlg.result_node(), pid)
            self.app.save()
            self.refresh()

    def new_category(self, parent_id="__sel__"):
        pid = self._target_parent() if parent_id == "__sel__" else parent_id
        dlg = CategoryDialog(self, self.app, None, pid)
        if dlg.exec():
            self.app.store.add(dlg.result_node(), pid)
            self.app.save()
            self.refresh()

    def quick_connect(self):
        dlg = ConnectionDialog(self, self.app, {"name": "Connexion rapide"}, None, temp=True)
        if dlg.exec():
            self.app.connect(dlg.result_node())

    def edit_selected(self):
        n = self.selected()
        if not n:
            return
        dlg = (CategoryDialog if n.get("type") == "category" else ConnectionDialog)(self, self.app, n)
        if dlg.exec():
            self.app.store.update(n["id"], dlg.result_node())
            self.app.save()
            self.refresh()

    def duplicate_selected(self):
        n = self.selected()
        if n and n.get("type") == "connection":
            c = copy.deepcopy(n)
            c.pop("id", None)
            c["name"] = c.get("name", "") + " (copie)"
            self.app.store.add(c, n.get("parentId"))
            self.app.save()
            self.refresh()

    def delete_selected(self):
        n = self.selected()
        if not n:
            return
        what = "la catégorie et tout son contenu" if n.get("type") == "category" else "la connexion"
        if confirm(self, "Supprimer", f"Supprimer {what} « {n.get('name')} » ?\n"
                                      "(une copie de la configuration est gardée)", ok="Supprimer"):
            self.app.store.delete(n["id"])
            self.app.save()
            self.refresh()

    def _menu(self, pos):
        item = self.tree.itemAt(pos)
        if item:
            self.tree.setCurrentItem(item)
        n = self.selected() if item else None
        m = QMenu(self)
        if n and n.get("type") == "connection":
            plan = self.app.plan_for(n)
            m.addAction("Se connecter (nouvel onglet)", lambda: self.app.connect(n))
            m.addAction("Se connecter dans un volet à droite", lambda: self.app.connect(n, "right"))
            m.addAction("Se connecter dans un volet en bas", lambda: self.app.connect(n, "down"))
            m.addSeparator()
            m.addAction("Copier la commande ssh", lambda: copy_text(plan.display if plan else ""))
            a = m.addAction("Copier la chaîne PSM", lambda: copy_text(plan.psm_string if plan else ""))
            a.setEnabled(bool(plan and plan.psm_string))
            m.addSeparator()
            m.addAction("Modifier…", self.edit_selected)
            m.addAction("Dupliquer", self.duplicate_selected)
            m.addAction("Supprimer…", self.delete_selected)
        elif n:
            m.addAction("Nouvelle connexion ici…", lambda: self.new_connection(n["id"]))
            m.addAction("Nouvelle sous-catégorie…", lambda: self.new_category(n["id"]))
            m.addAction("Ouvrir toutes les connexions", lambda: [self.app.connect(c) for c in
                                                                self.app.store.children(n["id"])
                                                                if c.get("type") == "connection"])
            m.addSeparator()
            m.addAction("Modifier…", self.edit_selected)
            m.addAction("Supprimer…", self.delete_selected)
        else:
            m.addAction("Nouvelle connexion…", lambda: self.new_connection(None))
            m.addAction("Nouvelle catégorie…", lambda: self.new_category(None))
        m.exec(self.tree.viewport().mapToGlobal(pos))


class HitCard(QFrame):
    activated = Signal(object)
    menu = Signal(object, QPoint)

    def __init__(self, hit, favorited=False):
        super().__init__()
        self.hit = hit
        self.setObjectName("card")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(10, 7, 10, 7)
        lay.setSpacing(2)
        r1 = QHBoxLayout()
        alive = hit.get("isAlive")
        dot = QLabel("●")
        dot.setStyleSheet(f"color: {UI['success'] if alive else ('#E74856' if alive is False else '#767676')};")
        r1.addWidget(dot)
        title = QLabel(("★ " if favorited else "") + (hit.get("displayName") or "—"))
        title.setObjectName("cardtitle")
        r1.addWidget(title, 1)
        if hit.get("os"):
            low = hit["os"].lower()
            col = next((c for k, c in (("windows", "#3B78FF"), ("linux", "#B07A00"), ("aix", "#13A10E"),
                                       ("solaris", "#C50F1F")) if k in low), "#5A5A5A")
            badge = QLabel(hit["os"][:14])
            badge.setStyleSheet(f"background: {col}; color: white; border-radius: 3px; padding: 0 5px;")
            r1.addWidget(badge)
        lay.addLayout(r1)
        if hit.get("subtitle") and hit["subtitle"] != hit.get("displayName"):
            sub = QLabel(hit["subtitle"])
            sub.setObjectName("hint")
            sub.setFont(mono_font("", 11))
            lay.addWidget(sub)
        if hit.get("tags"):
            tags = QLabel("  ".join(f"[{t}]" for t in hit["tags"][:6]))
            tags.setObjectName("hint")
            lay.addWidget(tags)
        if hit.get("node"):
            node = QLabel("◈ " + hit["node"])
            node.setStyleSheet(f"color: {UI['accent']};")
            lay.addWidget(node)
        for k, v in hit.get("details") or []:
            lab = QLabel(f"{k} : {v}")
            lab.setObjectName("hint")
            lab.setWordWrap(True)
            lay.addWidget(lab)

    def mouseDoubleClickEvent(self, ev):
        self.activated.emit(self.hit)

    def mousePressEvent(self, ev):
        if ev.button() == Qt.MouseButton.RightButton:
            self.menu.emit(self.hit, ev.globalPosition().toPoint())


class SearchPanel(QWidget):
    def __init__(self, app):
        super().__init__()
        self.app = app
        self._gen = 0
        lay = QVBoxLayout(self)
        lay.setContentsMargins(8, 6, 4, 4)
        r1 = QHBoxLayout()
        self.db_box = QComboBox()
        self.db_box.activated.connect(self._db_changed)
        r1.addWidget(self.db_box, 1)
        for icon, tip, fn in (("settings", "Configurer la base", self.edit_db), ("add", "Ajouter une base",
                                                                              lambda: self._edit(None)),
                              ("chevron", "Plus…", self._db_menu)):
            b = QToolButton()
            b.setIcon(glyph_icon(icon, UI["text"]))
            b.setToolTip(tip)
            b.clicked.connect(fn)
            r1.addWidget(b)
        lay.addLayout(r1)
        r2 = QHBoxLayout()
        self.query = QLineEdit()
        self.query.setPlaceholderText("Rechercher un serveur…")
        self.query.setClearButtonEnabled(True)
        self.query.textChanged.connect(lambda _t: self.timer.start())
        self.query.returnPressed.connect(self.run_search)
        self.alive = QCheckBox("Vivants")
        self.alive.setChecked(True)
        self.alive.toggled.connect(lambda _c: self.run_search())
        r2.addWidget(self.query, 1)
        r2.addWidget(self.alive)
        lay.addLayout(r2)
        self.status = hint("")
        lay.addWidget(self.status)
        self.area = QScrollArea()
        self.area.setWidgetResizable(True)
        self.inner = QWidget()
        self.list = QVBoxLayout(self.inner)
        self.list.setContentsMargins(0, 0, 4, 0)
        self.list.addStretch(1)
        self.area.setWidget(self.inner)
        lay.addWidget(self.area, 1)
        self.timer = QTimer(self)
        self.timer.setSingleShot(True)
        self.timer.setInterval(350)
        self.timer.timeout.connect(self.run_search)
        self.hits = []
        self.refresh_dbs()

    @property
    def dbs(self):
        return self.app.config.data["es"]["databases"]

    def current_db(self):
        if not self.dbs:
            return None
        i = min(int(self.app.config.data["es"].get("selected", 0) or 0), len(self.dbs) - 1)
        return self.dbs[max(0, i)]

    def refresh_dbs(self):
        self.db_box.clear()
        self.db_box.addItems([d["name"] for d in self.dbs])
        db = self.current_db()
        if db:
            self.db_box.setCurrentText(db["name"])
        else:
            self.status.setText("Aucune base : clique sur + pour en ajouter une.")

    def _db_changed(self, i):
        self.app.config.data["es"]["selected"] = i
        self.app.save()
        self.run_search()

    def edit_db(self):
        self._edit(self.current_db())

    def _edit(self, db):
        dlg = EsDatabaseDialog(self, self.app, db)
        if not dlg.exec():
            return
        new = dlg.current_db()
        dbs = self.dbs
        if dlg.orig_name:
            idx = next(i for i, d in enumerate(dbs) if d["name"] == dlg.orig_name)
            dbs[idx] = new
        else:
            dbs.append(new)
            idx = len(dbs) - 1
        self.app.config.data["es"]["selected"] = idx
        self.app.authorize_dbs()
        self.app.save()
        self.refresh_dbs()
        self.run_search()

    def _db_menu(self):
        db = self.current_db()
        m = QMenu(self)
        a1 = m.addAction("Nœuds PSMP…", self.node_mapping)
        m.addSeparator()
        a2 = m.addAction("Supprimer cette base…", self.delete_db)
        for a in (a1, a2):
            a.setEnabled(bool(db))
        m.exec(self.cursor().pos())

    def node_mapping(self):
        db = self.current_db()
        dlg = NodeMappingDialog(self, self.app, db)
        if dlg.exec():
            self.app.config.data["psmpNodeMappings"] = dlg.mapping()
            self.app.save()

    def delete_db(self):
        db = self.current_db()
        if db and confirm(self, "Supprimer", f"Supprimer la base « {db['name']} » ?", ok="Supprimer"):
            self.dbs.remove(db)
            self.app.config.data["es"]["selected"] = 0
            self.app.save()
            self.refresh_dbs()
            self._clear()

    def on_show(self):
        self.query.setFocus()
        if not self.hits and self.current_db():
            self.run_search()

    def _clear(self):
        while self.list.count() > 1:
            w = self.list.takeAt(0).widget()
            if w:
                w.deleteLater()

    def run_search(self):
        db = self.current_db()
        if not db:
            return
        secret = es_secret(self, db)
        if secret is None:
            self.status.setText("Recherche annulée (identifiant non fourni).")
            return
        self._gen += 1
        gen = self._gen
        q, alive = self.query.text(), self.alive.isChecked()
        self.status.setText("Recherche…")
        run_async(lambda: [process_hit(h, db) for h in es_search(db, secret, q, alive)],
                  lambda res, err: self._show(gen, db, res, err))

    def _show(self, gen, db, hits, err):
        if gen != self._gen:
            return
        self._clear()
        if err:
            self.status.setText("Erreur : " + err[:300])
            if "401" in err or "403" in err:
                SESSION_SECRETS.pop(db_slug(db.get("name")), None)
            return
        self.hits = hits
        self.status.setText(f"{len(hits)} résultat(s)" + (" (50 max)" if len(hits) >= 50 else ""))
        cat = self.app.store.find_root_category(db.get("favoriteCategoryName"))
        favs = {c.get("host") for c in self.app.store.children(cat["id"])} if cat else set()
        for h in hits:
            card = HitCard(h, h["hostname"] in favs)
            card.activated.connect(lambda hit: self.connect(hit))
            card.menu.connect(self._card_menu)
            self.list.insertWidget(self.list.count() - 1, card)

    def _conn(self, h):
        db = next((d for d in self.dbs if d["name"] == h["dbName"]), self.current_db())
        return connection_from_hit(h, db, self.app.config.data.get("psmpNodeMappings", {}),
                                   self.app.config.settings.get("psmpUserLogin", "")), db

    def connect(self, h, where="tab"):
        node, _db = self._conn(h)
        self.app.connect(node, where)

    def _card_menu(self, h, pos):
        node, db = self._conn(h)
        plan = self.app.plan_for(node)
        m = QMenu(self)
        m.addAction("Se connecter (nouvel onglet)", lambda: self.app.connect(node))
        m.addAction("Se connecter dans un volet à droite", lambda: self.app.connect(node, "right"))
        m.addAction("Se connecter dans un volet en bas", lambda: self.app.connect(node, "down"))
        m.addAction("Modifier puis se connecter…", lambda: self._edit_connect(node))
        m.addSeparator()
        m.addAction("Ajouter aux favoris", lambda: self._favorite(node, db))
        a = m.addAction("Copier la chaîne PSM", lambda: copy_text(plan.psm_string if plan else ""))
        a.setEnabled(bool(plan and plan.psm_string))
        m.addAction("Copier la commande ssh", lambda: copy_text(plan.display if plan else ""))
        m.addAction("Copier l'hôte", lambda: copy_text(h["hostname"]))
        m.exec(pos)

    def _edit_connect(self, node):
        dlg = ConnectionDialog(self, self.app, node, None, temp=True)
        if dlg.exec():
            self.app.connect(dlg.result_node())

    def _favorite(self, node, db):
        store = self.app.store
        name = db.get("favoriteCategoryName") or "★ Elasticsearch"
        cat = store.find_root_category(name) or store.add({"type": "category", "name": name, "variables": []}, None)
        store.add(dict(node), cat["id"])
        self.app.save()
        self.app.refresh_sidebar()
        self.status.setText(f"« {node['name']} » ajouté aux favoris.")


class VersionLabel(QLabel):
    """Numéro de version en bas du panneau ; un clic ouvre « À propos »."""

    def __init__(self, app):
        super().__init__(f"{APP_NAME} {VERSION}")
        self.app = app
        self.setObjectName("hint")
        self.setContentsMargins(10, 2, 10, 4)
        self.setToolTip(version_details() + " — cliquer pour « À propos »")
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def mousePressEvent(self, ev):
        if ev.button() == Qt.MouseButton.LeftButton:
            self.app.show_about()


class Sidebar(QWidget):
    def __init__(self, app):
        super().__init__()
        self.setObjectName("sidebar")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 4, 0, 0)
        self.bar = QTabBar()
        self.bar.setObjectName("sidetabs")
        self.bar.addTab("Connexions")
        self.bar.addTab("Elasticsearch")
        self.bar.setDrawBase(False)
        self.bar.currentChanged.connect(self.show_page)
        lay.addWidget(self.bar)
        self.stack = QStackedWidget()
        self.conn = ConnectionsPanel(app)
        self.es = SearchPanel(app)
        self.stack.addWidget(self.conn)
        self.stack.addWidget(self.es)
        lay.addWidget(self.stack, 1)
        self.version = VersionLabel(app)
        lay.addWidget(self.version)

    def show_page(self, i):
        self.bar.setCurrentIndex(i)
        self.stack.setCurrentIndex(i)
        if i == 1:
            self.es.on_show()
        else:
            self.conn.filter.setFocus()

    def refresh(self):
        self.conn.refresh()
        self.es.refresh_dbs()


# ======================================================================================
# Thème de la fenêtre (sombre, façon Windows Terminal)
# ======================================================================================

def _theme_image(name, painter_fn, size=28):
    path = os.path.join(data_dir("theme"), name)
    if not os.path.isfile(path):
        pm = QPixmap(size, size)
        pm.fill(Qt.GlobalColor.transparent)
        p = QPainter(pm)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter_fn(p)
        p.end()
        pm.save(path, "PNG")
    return path.replace("\\", "/")


def _draw_check(p):
    _pen(p, "#000000", 3.2)
    p.drawPolyline(QPolygonF([QPointF(6, 14.5), QPointF(11.5, 20), QPointF(22, 8.5)]))


def _draw_close(color):
    def fn(p):
        _pen(p, color, 2.2)
        p.drawLine(QPointF(9, 9), QPointF(19, 19))
        p.drawLine(QPointF(19, 9), QPointF(9, 19))
    return fn


def app_css():
    c = UI
    check = _theme_image("coche.png", _draw_check)
    close = _theme_image("fermer.png", _draw_close("#A8A8A8"))
    close_h = _theme_image("fermer-survol.png", _draw_close("#FFFFFF"))
    return f"""
QWidget {{ background: {c['panel']}; color: {c['text']}; }}
QMainWindow, QWidget#central {{ background: {c['tabbar']}; }}
QWidget#tabstrip {{ background: {c['tabbar']}; }}
QTabBar#tabs {{ background: {c['tabbar']}; }}
QTabBar#tabs::tab {{ background: transparent; color: {c['text_dim']}; padding: 7px 8px 7px 12px; margin: 5px 1px 0 0;
    border-top-left-radius: 8px; border-top-right-radius: 8px; min-width: 110px; max-width: 230px; }}
QTabBar#tabs::tab:selected {{ background: {c['tab_active']}; color: {c['text']}; }}
QTabBar#tabs::tab:hover:!selected {{ background: {c['tab_hover']}; color: {c['text']}; }}
QTabBar::close-button {{ image: url("{close}"); subcontrol-position: right; margin: 2px; border-radius: 4px; }}
QTabBar::close-button:hover {{ image: url("{close_h}"); background: {c['hover']}; }}
QTabBar QToolButton {{ background: {c['tabbar']}; border: none; }}
QToolButton#stripbtn {{ background: transparent; border: none; border-radius: 5px; padding: 5px; margin-top: 4px; }}
QToolButton#stripbtn:hover, QToolButton#stripbtn:checked {{ background: {c['tab_hover']}; }}
QWidget#sidebar, QWidget#sidebar QWidget {{ background: {c['tabbar']}; }}
QTabBar#sidetabs::tab {{ background: transparent; color: {c['text_dim']}; padding: 6px 12px; border: none;
    border-bottom: 2px solid transparent; font-weight: bold; }}
QTabBar#sidetabs::tab:selected {{ color: {c['text']}; border-bottom: 2px solid {c['accent']}; }}
QFrame#card, QWidget#sidebar QFrame#card {{ background: {c['panel']}; border: 1px solid {c['border']}; border-radius: 6px; }}
QFrame#card:hover {{ border-color: {c['accent']}; }}
QFrame#card QLabel {{ background: transparent; }}
QLabel#cardtitle {{ font-weight: bold; }}
QLabel#hint {{ color: {c['text_dim']}; background: transparent; }}
QLabel#toast {{ background: rgba(32,32,32,235); color: {c['text']}; border: 1px solid {c['accent']}; border-radius: 8px;
    padding: 8px 14px; font-weight: bold; }}
QLineEdit, QComboBox, QSpinBox, QPlainTextEdit {{ background: {c['input']}; color: {c['text']}; border: 1px solid {c['border']};
    border-radius: 4px; padding: 4px 6px; selection-background-color: {c['accent_dark']}; }}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus {{ border-color: {c['accent']}; }}
QComboBox QAbstractItemView {{ background: {c['menu']}; color: {c['text']}; selection-background-color: {c['accent_dark']}; }}
QPushButton {{ background: {c['panel_alt']}; color: {c['text']}; border: 1px solid {c['border']}; border-radius: 4px;
    padding: 5px 12px; }}
QPushButton:hover {{ background: {c['hover']}; }}
QPushButton:default {{ background: {c['accent_dark']}; border-color: {c['accent_dark']}; }}
QToolButton {{ background: transparent; border: none; border-radius: 4px; padding: 3px; color: {c['text']}; }}
QToolButton:hover {{ background: {c['hover']}; }}
QTreeWidget, QListWidget {{ background: {c['tabbar']}; color: {c['text']}; border: none; outline: 0; }}
QTreeWidget::item, QListWidget::item {{ padding: 3px 2px; border-radius: 4px; }}
QTreeWidget::item:selected, QListWidget::item:selected {{ background: {c['hover']}; color: {c['text']}; }}
QTreeWidget::item:hover, QListWidget::item:hover {{ background: {c['tab_hover']}; }}
QMenu {{ background: {c['menu']}; color: {c['text']}; border: 1px solid {c['border']}; border-radius: 8px; padding: 4px; }}
QMenu::item {{ padding: 6px 26px 6px 22px; border-radius: 4px; }}
QMenu::item:selected {{ background: {c['hover']}; }}
QMenu::item:disabled {{ color: {c['text_disabled']}; }}
QMenu::separator {{ height: 1px; background: {c['border']}; margin: 4px 8px; }}
QTabWidget::pane {{ border: none; border-top: 1px solid {c['border']}; }}
QTabWidget > QTabBar::tab {{ background: transparent; color: {c['text_dim']}; padding: 6px 12px; border: none;
    border-bottom: 2px solid transparent; }}
QTabWidget > QTabBar::tab:selected {{ color: {c['text']}; border-bottom: 2px solid {c['accent']}; }}
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 0; }}
QScrollBar::handle:vertical {{ background: #5A5A5A; border-radius: 3px; min-height: 30px; margin: 2px 3px; }}
QScrollBar::handle:vertical:hover {{ background: #8A8A8A; margin: 1px 2px; }}
QScrollBar::add-line, QScrollBar::sub-line, QScrollBar::add-page, QScrollBar::sub-page {{ background: none; height: 0; }}
QScrollBar:horizontal {{ height: 0; }}
QSplitter::handle {{ background: {c['tabbar']}; }}
QSplitter::handle:hover {{ background: {c['hover']}; }}
QScrollArea {{ border: none; }}
QGroupBox {{ border: 1px solid {c['border']}; border-radius: 6px; margin-top: 10px; padding-top: 6px; }}
QCheckBox, QRadioButton {{ background: transparent; }}
QCheckBox::indicator {{ width: 14px; height: 14px; border: 1px solid #9A9A9A; border-radius: 4px; background: {c['input']}; }}
QCheckBox::indicator:hover {{ border-color: #CFCFCF; }}
QCheckBox::indicator:checked {{ background: {c['accent']}; border-color: {c['accent']}; image: url("{check}"); }}
QRadioButton::indicator {{ width: 14px; height: 14px; border: 1px solid #9A9A9A; border-radius: 8px; background: {c['input']}; }}
QRadioButton::indicator:checked {{ border: 4px solid {c['accent']}; width: 8px; height: 8px; background: #000000; }}
QToolTip {{ background: {c['menu']}; color: {c['text']}; border: 1px solid {c['border']}; padding: 4px; }}
QWidget#findbar {{ background: {c['menu']}; border: 1px solid {c['border']}; border-radius: 6px; }}
"""


def sc(mac, other):
    keys = mac if IS_MAC else other
    if isinstance(keys, str):
        keys = [keys]
    return [QKeySequence(k) for k in keys if k]


# ======================================================================================
# Onglet : un ou plusieurs volets (fractionnés)
# ======================================================================================

class FindBar(QWidget):
    def __init__(self, page):
        super().__init__(page)
        self.page = page
        self.setObjectName("findbar")
        h = QHBoxLayout(self)
        h.setContentsMargins(6, 4, 4, 4)
        self.edit = QLineEdit()
        self.edit.setPlaceholderText("Rechercher dans l'historique")
        self.edit.setMinimumWidth(220)
        self.edit.returnPressed.connect(lambda: self.go(True))
        up, down, close = QToolButton(), QToolButton(), QToolButton()
        up.setText("↑")
        down.setText("↓")
        close.setText("✕")
        up.clicked.connect(lambda: self.go(True))
        down.clicked.connect(lambda: self.go(False))
        close.clicked.connect(self.close_bar)
        self.info = QLabel("")
        self.info.setObjectName("hint")
        for w in (self.edit, self.info, up, down, close):
            h.addWidget(w)
        self.hide()

    def keyPressEvent(self, ev):
        if ev.key() == Qt.Key.Key_Escape:
            self.close_bar()
            return
        super().keyPressEvent(ev)

    def open(self):
        self.adjustSize()
        self.move(self.page.width() - self.width() - 24, 8)
        self.show()
        self.raise_()
        self.edit.setFocus()
        self.edit.selectAll()

    def go(self, backwards):
        view = self.page.active
        if view is not None:
            found = view.find(self.edit.text(), backwards)
            self.info.setText("" if found else "introuvable")

    def close_bar(self):
        self.hide()
        if self.page.active is not None:
            self.page.active.setFocus()


class TabPage(QWidget):
    changed = Signal(object)

    def __init__(self, win, spec):
        super().__init__()
        self.win = win
        self.custom_title = None
        self.lay = QVBoxLayout(self)
        self.lay.setContentsMargins(0, 0, 0, 0)
        view = win.make_view(spec, self)
        self.root = view
        self.lay.addWidget(view)
        self.active = view
        self.findbar = FindBar(self)

    def resizeEvent(self, ev):
        if self.findbar.isVisible():
            self.findbar.move(self.width() - self.findbar.width() - 24, 8)
        super().resizeEvent(ev)

    def views(self, w=None):
        w = w or self.root
        if isinstance(w, TerminalView):
            return [w]
        out = []
        if isinstance(w, QSplitter):
            for i in range(w.count()):
                out += self.views(w.widget(i))
        return out

    def set_active(self, view):
        self.active = view
        multi = len(self.views()) > 1
        for v in self.views():
            hl = multi and v is view
            if v.highlight != hl:
                v.highlight = hl
                v.update()
        self.changed.emit(self)

    def split(self, view, orient, spec):
        view = view or self.active
        new = self.win.make_view(spec, self)
        parent = view.parentWidget()
        sp = QSplitter(orient)
        sp.setHandleWidth(3)
        sp.setChildrenCollapsible(False)
        if isinstance(parent, QSplitter):
            idx = parent.indexOf(view)
            sizes = parent.sizes()
            parent.insertWidget(idx, sp)
            sp.addWidget(view)
            sp.addWidget(new)
            parent.setSizes(sizes)
        else:
            self.lay.removeWidget(view)
            sp.addWidget(view)
            sp.addWidget(new)
            self.lay.addWidget(sp)
            self.root = sp
        total = sp.width() if orient == Qt.Orientation.Horizontal else sp.height()
        sp.setSizes([max(1, total // 2)] * 2)
        new.setFocus()
        self.set_active(new)
        return new

    def close_view(self, view):
        view.session.close()
        views = self.views()
        if view is self.root:
            self.win.remove_page(self)
            return
        parent = view.parentWidget()
        view.setParent(None)
        view.deleteLater()
        if isinstance(parent, QSplitter) and parent.count() == 1:
            remaining = parent.widget(0)
            grand = parent.parentWidget()
            if parent is self.root:
                self.lay.removeWidget(parent)
                self.lay.addWidget(remaining)
                self.root = remaining
            elif isinstance(grand, QSplitter):
                idx = grand.indexOf(parent)
                sizes = grand.sizes()
                grand.insertWidget(idx, remaining)
                grand.setSizes(sizes)
            parent.setParent(None)
            parent.deleteLater()
        rest = [v for v in views if v is not view]
        if rest:
            target = self.active if self.active in rest else rest[0]
            target.setFocus()
            self.set_active(target)

    def move_focus(self, direction):
        cur = self.active
        if cur is None:
            return
        r = QRect(cur.mapTo(self, QPoint(0, 0)), cur.size())
        best, best_d = None, None
        for v in self.views():
            if v is cur:
                continue
            o = QRect(v.mapTo(self, QPoint(0, 0)), v.size())
            if direction == "left":
                ok, d = o.right() < r.left() and o.bottom() > r.top() and o.top() < r.bottom(), r.left() - o.right()
            elif direction == "right":
                ok, d = o.left() > r.right() and o.bottom() > r.top() and o.top() < r.bottom(), o.left() - r.right()
            elif direction == "up":
                ok, d = o.bottom() < r.top() and o.right() > r.left() and o.left() < r.right(), r.top() - o.bottom()
            else:
                ok, d = o.top() > r.bottom() and o.right() > r.left() and o.left() < r.right(), o.top() - r.bottom()
            if ok and (best_d is None or d < best_d):
                best, best_d = v, d
        if best is not None:
            best.setFocus()

    def title(self):
        if self.custom_title:
            return self.custom_title
        return self.active.session.title if self.active is not None else ""


# ======================================================================================
# Fenêtre principale
# ======================================================================================

class MainWindow(QMainWindow):
    def __init__(self, cwd=None):
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.setWindowIcon(glyph_icon("app"))
        self.config = Config()
        self.store = SshStore(self.config.data["ssh"])
        self.profiles = detect_profiles()
        self.authorize_dbs()
        self.pages = []
        self._closing = False
        central = QWidget()
        central.setObjectName("central")
        v = QVBoxLayout(central)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)
        strip = QWidget()
        strip.setObjectName("tabstrip")
        h = QHBoxLayout(strip)
        h.setContentsMargins(8, 0, 8, 0)
        h.setSpacing(2)
        self.side_btn = QToolButton()
        self.side_btn.setObjectName("stripbtn")
        self.side_btn.setIcon(glyph_icon("sidebar", UI["text"]))
        self.side_btn.setCheckable(True)
        self.side_btn.setToolTip("Connexions SSH et recherche")
        self.side_btn.clicked.connect(lambda: self.toggle_sidebar())
        h.addWidget(self.side_btn)
        self.tabbar = QTabBar()
        self.tabbar.setObjectName("tabs")
        self.tabbar.setMovable(True)
        self.tabbar.setTabsClosable(True)
        self.tabbar.setExpanding(False)
        self.tabbar.setDocumentMode(True)
        self.tabbar.setDrawBase(False)
        self.tabbar.setElideMode(Qt.TextElideMode.ElideRight)
        self.tabbar.setUsesScrollButtons(True)
        self.tabbar.setIconSize(QSize(14, 14))
        self.tabbar.currentChanged.connect(self._tab_changed)
        self.tabbar.tabCloseRequested.connect(lambda i: self.close_page(self.page_at(i)))
        self.tabbar.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tabbar.customContextMenuRequested.connect(self._tab_menu)
        h.addWidget(self.tabbar, 0, Qt.AlignmentFlag.AlignBottom)
        self.new_btn = QToolButton()
        self.new_btn.setObjectName("stripbtn")
        self.new_btn.setIcon(glyph_icon("add", UI["text"]))
        self.new_btn.setToolTip("Nouvel onglet")
        self.new_btn.clicked.connect(lambda: self.new_tab())
        self.menu_btn = QToolButton()
        self.menu_btn.setObjectName("stripbtn")
        self.menu_btn.setIcon(glyph_icon("chevron", UI["text"]))
        self.menu_btn.setToolTip("Profils, connexions, paramètres")
        self.menu_btn.clicked.connect(self._new_tab_menu)
        h.addWidget(self.new_btn)
        h.addWidget(self.menu_btn)
        h.addStretch(1)
        v.addWidget(strip)
        self.body = QSplitter(Qt.Orientation.Horizontal)
        self.body.setHandleWidth(4)
        self.body.setChildrenCollapsible(False)
        self.sidebar = Sidebar(self)
        self.stack = QStackedWidget()
        self.body.addWidget(self.sidebar)
        self.body.addWidget(self.stack)
        self.body.setStretchFactor(1, 1)
        v.addWidget(self.body, 1)
        self.setCentralWidget(central)
        self._build_actions()
        st = self.config.settings
        self.sidebar.setVisible(bool(st.get("sidebarVisible")))
        self.side_btn.setChecked(bool(st.get("sidebarVisible")))
        self.body.setSizes([int(st.get("sidebarWidth", 330)), 900])
        geo = st.get("geometry")
        if geo:
            from PySide6.QtCore import QByteArray
            self.restoreGeometry(QByteArray.fromBase64(geo.encode()))
        else:
            self.resize(1100, 680)
        self.new_tab(cwd=cwd)

    # ---- sécurité réseau
    def authorize_dbs(self):
        for db in self.config.data["es"]["databases"]:
            try:
                host, port, _p = es_address(db)
            except EsError:
                continue
            autoriser_hote(host, port)

    # ---- actions et raccourcis
    def _act(self, text, fn, keys=(), menu=None):
        a = QAction(text, self)
        if keys:
            a.setShortcuts(keys)
            a.setShortcutContext(Qt.ShortcutContext.WindowShortcut)
        a.triggered.connect(lambda _c=False: fn())
        self.addAction(a)
        if menu is not None:
            menu.addAction(a)
        return a

    def _build_actions(self):
        mb = self.menuBar()
        mb.setNativeMenuBar(True)
        if not IS_MAC:
            mb.hide()
        A = self._act
        f = mb.addMenu("Fichier")
        self.a = a = {}
        a["new"] = A("Nouvel onglet", self.new_tab, sc("Ctrl+T", "Ctrl+Shift+T"), f)
        a["dup"] = A("Dupliquer l'onglet", self.duplicate_tab, sc("Ctrl+Shift+T", "Ctrl+Shift+D"), f)
        a["right"] = A("Fractionner à droite", lambda: self.split("right"), sc("Ctrl+D", ["Alt+Shift++", "Alt+Shift+="]), f)
        a["down"] = A("Fractionner en bas", lambda: self.split("down"), sc("Ctrl+Shift+D", ["Alt+Shift+-", "Alt+Shift+_"]), f)
        f.addSeparator()
        a["quick"] = A("Connexion SSH rapide…", lambda: self.sidebar.conn.quick_connect(),
                       sc("Ctrl+Shift+O", "Ctrl+Shift+O"), f)
        f.addSeparator()
        a["close"] = A("Fermer le volet", self.close_active, sc("Ctrl+W", "Ctrl+Shift+W"), f)
        e = mb.addMenu("Édition")
        a["copy"] = A("Copier", lambda: self._view_do("copy"), sc("Ctrl+C", "Ctrl+Shift+C"), e)
        a["paste"] = A("Coller", lambda: self._view_do("paste"), sc("Ctrl+V", "Ctrl+Shift+V"), e)
        a["all"] = A("Tout sélectionner", lambda: self._view_do("select_all"), sc("Ctrl+A", "Ctrl+Shift+A"), e)
        e.addSeparator()
        a["find"] = A("Rechercher…", self.find, sc("Ctrl+F", "Ctrl+Shift+F"), e)
        a["clear"] = A("Effacer l'historique", lambda: self._view_do("clear_buffer"), sc("Ctrl+K", "Ctrl+Shift+K"), e)
        e.addSeparator()
        a["settings"] = A("Paramètres…", self.open_settings, sc("Ctrl+,", "Ctrl+,"), e)
        a["settings"].setMenuRole(QAction.MenuRole.PreferencesRole)
        vw = mb.addMenu("Affichage")
        a["side"] = A("Connexions SSH", self.toggle_sidebar, sc("Ctrl+B", "Ctrl+Shift+B"), vw)
        a["es"] = A("Recherche Elasticsearch", self.show_es, sc("Ctrl+E", "Ctrl+Shift+E"), vw)
        vw.addSeparator()
        a["zin"] = A("Agrandir le texte", lambda: self.zoom(1), sc(["Ctrl+=", "Ctrl++"], ["Ctrl+=", "Ctrl++"]), vw)
        a["zout"] = A("Réduire le texte", lambda: self.zoom(-1), sc("Ctrl+-", "Ctrl+-"), vw)
        a["z0"] = A("Taille normale", lambda: self.zoom(0), sc("Ctrl+0", "Ctrl+0"), vw)
        vw.addSeparator()
        a["full"] = A("Plein écran", self.toggle_fullscreen, sc("Ctrl+Meta+F", "F11"), vw)
        w = mb.addMenu("Fenêtre")
        a["next"] = A("Onglet suivant", lambda: self.next_tab(1),
                      sc(["Ctrl+Shift+]", "Meta+Tab", "Ctrl+Shift+Right"], ["Ctrl+Tab", "Ctrl+PgDown"]), w)
        a["prev"] = A("Onglet précédent", lambda: self.next_tab(-1),
                      sc(["Ctrl+Shift+[", "Meta+Shift+Tab", "Meta+Shift+Backtab", "Ctrl+Shift+Left"],
                         ["Ctrl+Shift+Tab", "Ctrl+Shift+Backtab", "Ctrl+PgUp"]), w)
        w.addSeparator()
        for d, label, mk, ok in (("left", "Volet de gauche", "Ctrl+Alt+Left", "Alt+Left"),
                                 ("right", "Volet de droite", "Ctrl+Alt+Right", "Alt+Right"),
                                 ("up", "Volet du haut", "Ctrl+Alt+Up", "Alt+Up"),
                                 ("down", "Volet du bas", "Ctrl+Alt+Down", "Alt+Down")):
            A(label, lambda dd=d: self.focus_pane(dd), sc(mk, ok), w)
        w.addSeparator()
        azerty = "&é\"'(§è!ç"
        for n in range(1, 10):
            A(f"Onglet {n}", lambda k=n: self.goto_tab(k),
              sc([f"Ctrl+{n}", f"Ctrl+{azerty[n - 1]}"], f"Ctrl+Alt+{n}"), w if n == 1 else None)
        hm = mb.addMenu("Aide")
        A("Raccourcis clavier", self.show_shortcuts, (), hm)
        A(f"À propos de {APP_NAME}", self.show_about, (), hm).setMenuRole(QAction.MenuRole.AboutRole)

    def _view_do(self, method):
        v = self.active_view()
        if v is not None:
            getattr(v, method)()

    # ---- pages et vues
    def make_view(self, spec, page):
        session = Session(spec, self.config.settings, int(self.config.settings.get("scrollback", 10000)))
        session.screen.color_query = lambda kind, s=session: self._color_query(kind)
        view = TerminalView(session, self)
        view.page = page
        view.focused_view.connect(lambda v: v.page.set_active(v))
        view.context_menu.connect(self._terminal_menu)
        view.close_requested.connect(self.close_view)
        session.title_changed.connect(lambda _t, p=page: self._refresh_tab(p))
        session.exited.connect(lambda code, vv=view: self.on_session_exit(vv, code))
        return view

    def _color_query(self, kind):
        sch = SCHEMES.get(self.config.settings.get("colorScheme"), SCHEMES["Campbell"])
        if kind in ("fg", "bg", "cursor"):
            return sch[{"fg": "foreground", "bg": "background", "cursor": "cursor"}[kind]]
        return build_palette(sch)[int(kind) & 255].name()

    def page_at(self, i):
        return self.tabbar.tabData(i) if 0 <= i < self.tabbar.count() else None

    def index_of(self, page):
        for i in range(self.tabbar.count()):
            if self.tabbar.tabData(i) is page:
                return i
        return -1

    def active_page(self):
        return self.page_at(self.tabbar.currentIndex())

    def active_view(self):
        p = self.active_page()
        return p.active if p is not None else None

    def default_profile(self):
        name = self.config.settings.get("defaultProfile")
        for p in self.profiles:
            if p.name == name:
                return p
        if self.profiles:
            return self.profiles[0]
        return LaunchSpec("sh", ["/bin/sh", "-l"])

    def new_tab(self, spec=None, cwd=None):
        spec = copy.copy(spec or self.default_profile())
        if cwd:
            spec.cwd = cwd
        page = TabPage(self, spec)
        page.changed.connect(self._refresh_tab)
        self.pages.append(page)
        self.stack.addWidget(page)
        i = self.tabbar.addTab(glyph_icon(spec.icon if spec.icon in _GLYPHS else "terminal", UI["text_dim"]),
                               spec.name)
        self.tabbar.setTabData(i, page)
        self.tabbar.setCurrentIndex(i)
        self._tab_changed(i)
        return page

    def _tab_changed(self, i):
        page = self.page_at(i)
        if page is None:
            return
        self.stack.setCurrentWidget(page)
        self._refresh_tab(page)
        if page.active is not None:
            QTimer.singleShot(0, page.active.setFocus)

    def _refresh_tab(self, page):
        i = self.index_of(page)
        if i < 0:
            return
        title = page.title() or APP_NAME
        self.tabbar.setTabText(i, title)
        self.tabbar.setTabToolTip(i, title)
        if page is self.active_page():
            self.setWindowTitle(title)
        if page.active is not None and page.active.hasFocus():
            kind = page.active.session.spec.icon
            self.tabbar.setTabIcon(i, glyph_icon(kind if kind in _GLYPHS else "terminal", UI["text_dim"]))

    def remove_page(self, page):
        i = self.index_of(page)
        if i < 0:
            return
        for v in page.views():
            v.session.close()
        self.tabbar.removeTab(i)
        self.stack.removeWidget(page)
        self.pages.remove(page)
        page.deleteLater()
        if not self.pages and not self._closing:
            self.close()

    def close_page(self, page):
        if page is None:
            return
        running = [v for v in page.views() if v.session.running and v.session.spec.kind == "ssh"]
        if running and self.config.settings.get("confirmClose", True) and \
                not confirm(self, "Fermer l'onglet", "Une connexion ssh est ouverte dans cet onglet. La fermer ?",
                            ok="Fermer"):
            return
        self.remove_page(page)

    def close_view(self, view):
        if view.page is not None:
            view.page.close_view(view)

    def close_active(self):
        v = self.active_view()
        if v is not None:
            self.close_view(v)

    def duplicate_tab(self):
        v = self.active_view()
        if v is not None:
            self.new_tab(v.session.spec)

    def split(self, where="right", spec=None):
        page = self.active_page()
        if page is None:
            return
        spec = spec or (page.active.session.spec if page.active is not None else self.default_profile())
        page.split(page.active, Qt.Orientation.Horizontal if where == "right" else Qt.Orientation.Vertical, spec)

    def focus_pane(self, direction):
        page = self.active_page()
        if page is not None:
            page.move_focus(direction)

    def next_tab(self, d):
        n = self.tabbar.count()
        if n:
            self.tabbar.setCurrentIndex((self.tabbar.currentIndex() + d) % n)

    def goto_tab(self, k):
        n = self.tabbar.count()
        if n:
            self.tabbar.setCurrentIndex(n - 1 if k == 9 else min(k - 1, n - 1))

    def on_session_exit(self, view, code):
        mode = self.config.settings.get("closeOnExit", "graceful")
        if code == -1 or mode == "never" or (mode == "graceful" and code != 0):
            view.show_exit_message(code)
        else:
            self.close_view(view)

    def on_notice(self, view, kind):
        if kind != "code":
            return
        page = view.page
        i = self.index_of(page)
        if i >= 0 and (page is not self.active_page() or not self.isActiveWindow()):
            self.tabbar.setTabIcon(i, glyph_icon("key"))

    # ---- connexions ssh
    def plan_for(self, node):
        try:
            return build_plan(node, effective_variables(self.store, node),
                              self.config.settings.get("psmpUserLogin", ""))
        except Exception:  # noqa: BLE001
            return None

    def connect(self, node, where="tab"):
        variables = effective_variables(self.store, node)
        st = self.config.settings
        try:
            plan = build_plan(node, variables, st.get("psmpUserLogin", ""))
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, "Connexion impossible", str(exc))
            return
        if not executable_autorise(plan.argv[0]):
            QMessageBox.warning(self, "Connexion impossible", f"ssh introuvable ({plan.argv[0]}).")
            return
        reason = ""
        if plan.psmp:
            raw = resolve(node.get("psmpReason"), variables).strip() or st.get("defaultReason") or DEFAULT_PSM_REASON
            reason, problem = pick_reason(raw, st)
            if st.get("askReason", True) or problem:          # jamais de raison vide ou douteuse
                dlg = ReasonDialog(self, plan.target, self.config.data.get("reasons", []),
                                   reason if not problem else raw, st.get("reasonAscii", False),
                                   st.get("reasonMaxLen", 0), reason_choices(st))
                if not dlg.exec():
                    return
                reason = dlg.reason()
            if not reason:
                return
            self.config.add_reason(reason)
            self.save()
        lines = [f"→ {plan.display}"]
        if plan.psmp:
            lines.append("→ PIN + code RSA : à toi de les taper quand ils sont demandés")
            lines.append(f"→ raison PSM tapée automatiquement (vérifiée à l'écran si la passerelle l'affiche) : « {reason} »")
        banner = "\x1b[90m" + "\r\n".join(lines) + "\x1b[0m\r\n"
        settings = st
        spec = LaunchSpec(node.get("name") or plan.target, plan.argv, "ssh", os.path.expanduser("~"), "ssh",
                          node, reason, banner,
                          {"rules": lambda: build_rules(node, variables, reason, settings)})
        if where == "tab" or not self.pages:
            self.new_tab(spec)
        else:
            self.split(where, spec)

    # ---- barre latérale
    def toggle_sidebar(self, show=None):
        vis = (not self.sidebar.isVisible()) if show is None else show
        if not vis and self.sidebar.isVisible():
            self.config.settings["sidebarWidth"] = self.body.sizes()[0]
        self.sidebar.setVisible(vis)
        self.side_btn.setChecked(vis)
        self.config.settings["sidebarVisible"] = vis
        if vis:
            self.sidebar.show_page(self.sidebar.stack.currentIndex())
        elif self.active_view() is not None:
            self.active_view().setFocus()

    def show_es(self):
        self.toggle_sidebar(True)
        self.sidebar.show_page(1)

    def refresh_sidebar(self):
        self.sidebar.refresh()

    # ---- menus
    def _new_tab_menu(self):
        m = QMenu(self)
        for p in self.profiles:
            m.addAction(glyph_icon("terminal", UI["text"]), p.name, lambda pp=p: self.new_tab(pp))
        m.addSeparator()
        m.addAction(glyph_icon("plug", UI["text"]), "Connexion SSH rapide…", self.sidebar.conn.quick_connect)
        m.addAction(glyph_icon("sidebar", UI["text"]), "Connexions SSH", lambda: self.toggle_sidebar(True))
        m.addAction(glyph_icon("search", UI["text"]), "Recherche Elasticsearch", self.show_es)
        m.addSeparator()
        m.addAction(glyph_icon("settings", UI["text"]), "Paramètres", self.open_settings)
        m.addAction("Raccourcis clavier", self.show_shortcuts)
        m.addAction(f"À propos de {APP_NAME} ({VERSION})", self.show_about)
        m.exec(self.menu_btn.mapToGlobal(QPoint(0, self.menu_btn.height())))

    def _tab_menu(self, pos):
        i = self.tabbar.tabAt(pos)
        page = self.page_at(i)
        if page is None:
            return
        self.tabbar.setCurrentIndex(i)
        m = QMenu(self)
        m.addAction("Dupliquer l'onglet", self.duplicate_tab)
        m.addAction("Fractionner à droite", lambda: self.split("right"))
        m.addAction("Fractionner en bas", lambda: self.split("down"))
        m.addAction("Renommer l'onglet…", lambda: self._rename(page))
        m.addSeparator()
        a = m.addAction("Fermer les autres onglets", lambda: [self.close_page(p) for p in list(self.pages)
                                                               if p is not page])
        a.setEnabled(len(self.pages) > 1)
        m.addAction("Fermer l'onglet", lambda: self.close_page(page))
        m.exec(self.tabbar.mapToGlobal(pos))

    def _terminal_menu(self, view, pos):
        m = QMenu(self)
        a = m.addAction("Copier", view.copy)
        a.setEnabled(view.has_selection())
        m.addAction("Coller", view.paste)
        m.addAction("Tout sélectionner", view.select_all)
        m.addAction("Rechercher…", self.find)
        m.addSeparator()
        m.addAction("Fractionner à droite", lambda: self.split("right"))
        m.addAction("Fractionner en bas", lambda: self.split("down"))
        m.addAction("Nouvel onglet", self.new_tab)
        node = view.session.spec.node
        if node:
            plan = self.plan_for(node)
            m.addSeparator()
            m.addAction("Copier la commande ssh", lambda: copy_text(plan.display if plan else ""))
            b = m.addAction("Copier la chaîne PSM", lambda: copy_text(plan.psm_string if plan else ""))
            b.setEnabled(bool(plan and plan.psm_string))
        m.addSeparator()
        m.addAction("Effacer l'historique", view.clear_buffer)
        m.addAction("Fermer le volet", lambda: self.close_view(view))
        m.exec(pos)

    def _rename(self, page):
        name, ok = QInputDialog.getText(self, "Renommer l'onglet", "Titre (vide = automatique) :",
                                        text=page.custom_title or page.title())
        if ok:
            page.custom_title = name.strip() or None
            self._refresh_tab(page)

    def find(self):
        page = self.active_page()
        if page is not None:
            page.findbar.open()

    # ---- réglages
    def open_settings(self):
        dlg = SettingsDialog(self, self)
        if not dlg.exec():
            return
        self.config.settings.update(dlg.values())
        self.save()
        self.apply_appearance()

    def apply_appearance(self):
        for page in self.pages:
            for v in page.views():
                v.apply_appearance()

    def zoom(self, delta):
        st = self.config.settings
        st["fontSize"] = (13 if IS_MAC else 11) if delta == 0 else max(6, min(40, int(st.get("fontSize", 13)) + delta))
        self.apply_appearance()

    def toggle_fullscreen(self):
        self.showNormal() if self.isFullScreen() else self.showFullScreen()

    def save(self):
        try:
            self.config.save()
        except OSError as exc:
            QMessageBox.warning(self, APP_NAME, f"Enregistrement impossible : {exc}")

    def show_shortcuts(self):
        if IS_MAC:
            txt = ("⌘T nouvel onglet · ⌘W fermer le volet · ⌘D fractionner à droite · ⇧⌘D en bas\n"
                   "⌥⌘←↑→↓ changer de volet · ⌘1…9 aller à l'onglet · ⌃Tab / ⇧⌘→ onglet suivant\n"
                   "⌘C / ⌘V copier / coller · ⌘F rechercher · ⌘K effacer · ⌘B connexions · ⌘E Elasticsearch\n"
                   "⌘, paramètres · ⌘+ / ⌘- / ⌘0 taille du texte · ⇧⌘O connexion rapide\n"
                   "Maj+clic : sélectionner dans vim/htop · Maj+Page↑/↓ : remonter l'historique")
        else:
            txt = ("Ctrl+Maj+T nouvel onglet · Ctrl+Maj+W fermer le volet · Ctrl+Maj+D dupliquer\n"
                   "Alt+Maj++ fractionner à droite · Alt+Maj+- en bas · Alt+←↑→↓ changer de volet\n"
                   "Ctrl+Tab onglet suivant · Ctrl+Alt+1…9 aller à l'onglet\n"
                   "Ctrl+C (avec sélection) / Ctrl+V · Ctrl+Maj+F rechercher · Ctrl+Maj+K effacer\n"
                   "Ctrl+Maj+B connexions · Ctrl+Maj+E Elasticsearch · Ctrl+, paramètres · F11 plein écran")
        QMessageBox.information(self, "Raccourcis clavier", txt)

    def show_about(self):
        problems = controle_reseau()
        state = "actif ✓" if _VERROU["actif"] and not problems else ("actif" if _VERROU["actif"] else "inactif")
        import PySide6
        QMessageBox.about(self, APP_NAME, f"<b>{APP_NAME}</b> — version {VERSION} du {VERSION_DATE}<br>"
                                          f"Terminal à onglets façon Windows Terminal.<br>"
                                          f"Python {sys.version.split()[0]} · PySide6 {PySide6.__version__}"
                                          f"<br><br>Verrou anti-exfiltration : {state}<br>"
                                          f"Programmes autorisés : "
                                          f"{', '.join(sorted(os.path.basename(p) for p in _EXEC_AUTORISES))}<br>"
                                          f"Adresses réseau autorisées : {', '.join(hotes_autorises()) or 'aucune'}"
                                          f"<br>Aucun mot de passe n'est enregistré.")

    # ---- fermeture
    def closeEvent(self, ev):
        running = [v for p in self.pages for v in p.views() if v.session.running]
        if (len(self.pages) > 1 or any(v.session.spec.kind == "ssh" for v in running)) and running \
                and self.config.settings.get("confirmClose", True) and not self._closing:
            if not confirm(self, "Fermer", f"{len(self.pages)} onglet(s), {len(running)} programme(s) en cours. "
                                           "Tout fermer ?", ok="Tout fermer"):
                ev.ignore()
                return
        self._closing = True
        st = self.config.settings
        if not self.isFullScreen():
            st["geometry"] = bytes(self.saveGeometry().toBase64()).decode()
        if self.sidebar.isVisible():
            st["sidebarWidth"] = self.body.sizes()[0]
        for p in list(self.pages):
            for v in p.views():
                v.session.close()
        self.save()
        ev.accept()


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
    if not (sys.platform == "darwin" or sys.platform.startswith("linux")):
        raise SystemExit(f"{APP_NAME} fonctionne sur Mac (et Linux).")
    os.environ.setdefault("QT_MAC_WANTS_LAYER", "1")
    autoriser_executable(ssh_path())
    for sh in shells_disponibles():
        autoriser_executable(sh)
    installer_verrou()
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    cwd = os.path.abspath(os.path.expanduser(args[0])) if args and os.path.isdir(os.path.expanduser(args[0])) else None
    app = QApplication(sys.argv[:1])
    from PySide6.QtCore import QLibraryInfo, QTranslator
    tr = QTranslator(app)
    if tr.load("qtbase_fr", QLibraryInfo.path(QLibraryInfo.LibraryPath.TranslationsPath)):
        app.installTranslator(tr)               # boutons standard en français (Annuler, Enregistrer…)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(VERSION)
    app.setOrganizationName(ORG_NAME)
    app.setStyle("Fusion")
    pal = QPalette()
    for role, col in ((QPalette.ColorRole.Window, UI["panel"]), (QPalette.ColorRole.WindowText, UI["text"]),
                      (QPalette.ColorRole.Base, UI["input"]), (QPalette.ColorRole.AlternateBase, UI["panel_alt"]),
                      (QPalette.ColorRole.Text, UI["text"]), (QPalette.ColorRole.Button, UI["panel_alt"]),
                      (QPalette.ColorRole.ButtonText, UI["text"]), (QPalette.ColorRole.Highlight, UI["accent_dark"]),
                      (QPalette.ColorRole.HighlightedText, "#FFFFFF"), (QPalette.ColorRole.ToolTipBase, UI["menu"]),
                      (QPalette.ColorRole.ToolTipText, UI["text"]), (QPalette.ColorRole.PlaceholderText, "#8A8A8A")):
        pal.setColor(role, QColor(col))
    app.setPalette(pal)
    app.setStyleSheet(app_css())
    app.setWindowIcon(glyph_icon("app"))
    win = MainWindow(cwd)
    win.show()
    problems = controle_reseau()
    if problems:
        QMessageBox.critical(win, APP_NAME, "Le verrou a détecté un module interdit :\n" + "\n".join(problems))
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
