#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PaaS Explorer — explorateur des clusters IBM Cloud Kubernetes Service et Red Hat OpenShift,
façon Explorateur de fichiers Windows 11, pour le Mac du travail.

* Même environnement que les autres outils : PySide6-Essentials + bibliothèque standard.
* Reprend les fonctions de consultation du PaaSExplorer d'origine (comptes, clusters, namespaces, pods, logs,
  YAML, charts Helm, topologie, vue d'ensemble, mode démo), avec favoris et recherche de namespaces.
* Verrou anti-exfiltration (« audit hook » Python, impossible à retirer une fois posé) :
  - le programme ne lance aucun autre programme ;
  - il ne se connecte qu'aux adresses d'IBM Cloud (*.cloud.ibm.com), aux points d'accès que tu
    déclares, et aux domaines que tu ajoutes toi-même dans les paramètres ;
  - certificats toujours vérifiés (ceux du Mac, plus le certificat de l'entreprise si besoin) ;
  - codes à usage unique, jetons et clés restent en mémoire : rien n'est jamais enregistré.
* Connexion comme « oc login -u passcode » : adresse du serveur + namespace(s) + code à usage unique pris sur
  https://iam.cloud.ibm.com/identity/passcode (pas besoin de clé API, ni du droit de lister les clusters).
* Lecture seule, toujours : rien ne se modifie depuis l'outil (il n'envoie que des requêtes GET au cluster).
  Pour modifier (mettre à l'échelle, redémarrer, supprimer, éditer, terminal dans un pod), le bouton
  « Console » ouvre la bonne page de la console web OpenShift, ou du portail IBM Cloud.

Lancement :  ~/mac/explorer/venv/bin/python ~/mac/explorer/paasexplorer.py
"""

import base64
import datetime
import datetime as _dt
import gzip
import hashlib
import io
import json
import math
import os
import queue
import random
import re
import shutil
import socket
import ssl
import sys
import threading
import time
import unicodedata
import zipfile
from collections import deque
from urllib.parse import parse_qs, urlencode, urlsplit

APP_NAME = "PaaS Explorer"
ORG_NAME = "explorateur-maison"
VERSION = "2.2"          # à augmenter à chaque modification (1.0.0 = version d'origine en Tkinter)
VERSION_DATE = "27/11/2026"
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


EMPREINTE = "8287b425d4c64a19"          # remplie à la livraison : sert à voir si le fichier a été abîmé en le copiant
REPERES = "6591:79074cc7,fcf2d424,e3b11202,8a4b6ac7,74c78319,201c05c9,c8a64e1a,3366eabd,a203750f,7e293d51,68470a7b,f44b2244,7454bf52,1b58719a,2d3d0c6f,a745e6e9,92838458,5fb38e6a,064d6bd5,4f9a2d2d,1e7d3ef1,360c00cd,eb102ef8,eb31b83a,52ffbdb9,2d03deae,795d1aa2"            # remplis à la livraison : nombre de lignes et empreinte de chaque tranche de 250 lignes


def _texte_compare(path):
    """Texte du script tel qu'on le compare. Les différences sans effet sur le programme sont gommées :
    fins de ligne Windows, BOM, accents décomposés, espaces en fin de ligne, lignes vides en fin de fichier
    (ce que font souvent un copier-coller ou un éditeur web comme celui de git)."""
    try:
        with open(path, "rb") as fh:
            text = fh.read().decode("utf-8", "replace")
    except OSError:
        return None
    text = unicodedata.normalize("NFC", text.lstrip("\ufeff").replace("\r\n", "\n").replace("\r", "\n"))
    text = "\n".join(line.rstrip(" \t") for line in text.split("\n")).rstrip("\n") + "\n"
    text = re.sub(r'^EMPREINTE = "[0-9a-f]*"', 'EMPREINTE = ""', text, count=1, flags=re.M)
    return re.sub(r'^REPERES = "[0-9a-f:,]*"', 'REPERES = ""', text, count=1, flags=re.M)


def empreinte_fichier(path):
    """Empreinte d'un script (voir _texte_compare) ; None si illisible."""
    text = _texte_compare(path)
    return None if text is None else hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def reperes_fichier(path, tranche=250):
    """« 7442:ab12cd34,… » : nombre de lignes puis une empreinte courte par tranche de lignes."""
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


# ======================================================================================
# Verrou anti-exfiltration (version PaaS : aucun programme lancé, réseau limité à IBM Cloud)
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
    "os.system", "os.spawn", "os.startfile", "os.posix_spawn", "os.posix_spawnp", "os.exec", "os.fork",
    "os.forkpty", "pty.spawn", "subprocess.Popen", "webbrowser.open", "urllib.Request", "socket.bind",
    "socket.sendto", "socket.sendmsg", "socket.gethostbyname", "socket.gethostbyname_ex",
    "socket.gethostbyaddr", "socket.getnameinfo", "socket.sethostname", "ctypes.dlopen", "ctypes.dlsym",
    "ctypes.cdata",
})
_LIBS_FORBIDDEN = ("QtNetwork", "Qt6Network", "QtWebEngine", "Qt6WebEngine", "QtWebSockets", "Qt6WebSockets",
                   "QtHttpServer", "qpdf", "QtPdf", "Qt6Pdf")
_VERROU = {"actif": False}
_RESEAU = {"hotes": set(), "ips": set()}  # (hôte, port) autorisés, puis (ip, port) résolues pour eux


def module_interdit(name):
    if not isinstance(name, str):
        return False
    parts = name.split(".")
    if parts[0] in _BLOCKED_MODULES or ".".join(parts[:2]) in _BLOCKED_MODULES:
        return True
    return parts[0] == "PySide6" and len(parts) > 1 and parts[1] in _QT_NET


def _norm_host(host):
    if isinstance(host, bytes):
        host = host.decode("idna", "replace")
    return str(host or "").strip().lower().rstrip(".").strip("[]")


def autoriser_hote(host, port):
    """Ouvre une adresse précise (hôte, port). Appelé uniquement par NET, après contrôle du domaine."""
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


def certificats_du_mac():
    """Certificats racine du Mac (Apple + ceux installés par l'entreprise dans le trousseau Système).
    Lus UNE fois au démarrage, avant la pose du verrou (après, plus aucun programme ne peut être lancé)."""
    if not IS_MAC:
        return ""
    import subprocess
    keychains = [k for k in ("/System/Library/Keychains/SystemRootCertificates.keychain",
                             "/Library/Keychains/System.keychain") if os.path.exists(k)]
    try:
        out = subprocess.run(["/usr/bin/security", "find-certificate", "-a", "-p"] + keychains,
                             capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return ""
    return out.stdout if out.returncode == 0 else ""


# ======================================================================================
# Stockage (dossier privé du compte, copies de sécurité avant chaque écriture)
# ======================================================================================

def data_dir(*parts):
    if IS_MAC:
        base = os.path.expanduser("~/Library/Application Support/" + APP_NAME)
    else:
        base = os.path.join(os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share"), "paas-explorer")
    path = os.path.join(base, *parts)
    os.makedirs(path, mode=0o700, exist_ok=True)
    return path


IAM_DEFAULT = "https://iam.cloud.ibm.com"
CS_DEFAULT = "https://containers.cloud.ibm.com"
DEFAULT_DOMAINS = ("cloud.ibm.com",)
DEFAULT_SETTINGS = {
    "showSystemNamespaces": False, "detailsPane": True, "logTail": 500, "navWidth": 290,
    "windowGeometry": "", "useMacCerts": True, "caFile": "", "proxy": "auto", "extraDomains": [],
}


class Config:
    def __init__(self, folder=None):
        self.dir = folder or data_dir()
        self.path = os.path.join(self.dir, "config.json")
        self.data = {"version": 1, "settings": dict(DEFAULT_SETTINGS), "accounts": [], "clusterPrefs": {},
                     "favorites": [], "nsCache": {}}
        self.imported = False
        if os.path.isfile(self.path):
            self.load()
        elif folder is None:
            self.imported = self.import_original()

    def load(self):
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
        self.data["accounts"] = [clean_account(a) for a in self.data.get("accounts", []) if isinstance(a, dict)]

    def import_original(self):
        """Premier lancement : reprend la liste des comptes du PaaSExplorer d'origine (jamais les clés)."""
        old = (os.path.expanduser("~/Library/Application Support/PaaSExplorer/config.json") if IS_MAC else
               os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"),
                            "paasexplorer", "config.json"))
        try:
            with open(old, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
        except (OSError, ValueError):
            return False
        accs = [clean_account(a) for a in loaded.get("accounts", []) if isinstance(a, dict) and a.get("name")]
        if not accs:
            return False
        self.data["accounts"] = accs
        st = loaded.get("settings") or {}
        for key in ("showSystemNamespaces", "detailsPane", "logTail", "navWidth"):
            if key in st:
                self.data["settings"][key] = st[key]
        self.save()
        return True

    def save(self):
        if os.path.isfile(self.path):          # copie de sécurité avant d'écraser
            folder = data_dir("copies") if self.dir == data_dir() else os.path.join(self.dir, "copies")
            os.makedirs(folder, mode=0o700, exist_ok=True)
            stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
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

    @property
    def accounts(self):
        return self.data["accounts"]

    def cluster_pref(self, cid):
        return self.data["clusterPrefs"].setdefault(cid, {})


NS_RE = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")


def clean_account(a):
    """Ce qu'on garde d'une connexion sur disque : jamais de code, de clé ni de jeton, jamais d'option qui coupe
    les certificats. Deux sortes : « cluster » (serveur + namespaces) et « ibm » (compte IBM Cloud)."""
    name = str(a.get("name", "")).strip()
    iam = str(a.get("iamUrl") or IAM_DEFAULT).strip().rstrip("/")
    if a.get("kind") == "cluster" or a.get("server"):
        nss = a.get("namespaces") or []
        if isinstance(nss, str):
            nss = re.split(r"[\s,;]+", nss)
        nss = [n.strip().lower() for n in nss if n and NS_RE.match(n.strip().lower())]
        console = str(a.get("console") or "").strip().rstrip("/")
        out = {"name": name, "kind": "cluster", "server": str(a.get("server", "")).strip().rstrip("/"),
               "namespaces": list(dict.fromkeys(nss)), "iamUrl": iam}
        if console.startswith("https://"):
            out["console"] = console
        return out
    return {"name": name, "kind": "ibm", "iamUrl": iam,
            "csUrl": str(a.get("csUrl") or CS_DEFAULT).strip().rstrip("/")}


SESSION_SECRETS = {}     # nom du compte -> clé API : en mémoire seulement, jamais sur disque


# ======================================================================================
# Réseau : destinations contrôlées, certificats toujours vérifiés, sans urllib.request
# ======================================================================================

class NetError(Exception):
    pass


class CloudError(Exception):
    def __init__(self, message, status=None, body=""):
        super().__init__(message)
        self.status = status
        self.body = body


class KubeError(Exception):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


def _host_matches(host, domain):
    host, domain = _norm_host(host), _norm_host(domain).lstrip("*.").lstrip(".")
    return bool(domain) and (host == domain or host.endswith("." + domain))


class Network:
    """Toutes les connexions du programme passent par ici."""

    def __init__(self):
        self.declared = set()          # hôtes déclarés à la main (points d'accès d'un compte)
        self.extra = []                # domaines ajoutés dans les paramètres
        self.mac_pem = ""
        self.use_mac = True
        self.ca_file = ""
        self.proxy = "auto"
        self._ctx = {}
        self._lock = threading.Lock()

    def configure(self, settings, mac_pem=None):
        if mac_pem is not None:
            self.mac_pem = mac_pem
        self.use_mac = bool(settings.get("useMacCerts", True))
        self.ca_file = (settings.get("caFile") or "").strip()
        self.proxy = (settings.get("proxy") or "auto").strip() or "auto"
        self.extra = [d.strip().lower().lstrip("*.").lstrip(".") for d in settings.get("extraDomains") or []
                      if d and d.strip()]
        with self._lock:
            self._ctx.clear()

    def domains(self):
        return list(DEFAULT_DOMAINS) + [d for d in self.extra if d not in DEFAULT_DOMAINS]

    def declare(self, url):
        u = urlsplit(url or "")
        if u.scheme == "https" and u.hostname:
            self.declared.add(_norm_host(u.hostname))

    def permitted(self, host):
        host = _norm_host(host)
        return host in self.declared or any(_host_matches(host, d) for d in self.domains())

    def refusal(self, host):
        return (f"{host} n'est pas une destination autorisée. Seules les adresses d'IBM Cloud "
                f"({', '.join('*.' + d for d in self.domains())}) et les points d'accès de tes comptes sont "
                "permis : ajoute le domaine dans Paramètres › Réseau si c'est voulu.")

    # ---- certificats
    def context(self, extra_ca=None):
        key = hashlib.sha256((extra_ca or "").encode()).hexdigest()
        with self._lock:
            ctx = self._ctx.get(key)
        if ctx is not None:
            return ctx
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        if self.use_mac and self.mac_pem:
            for pem in re.findall(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", self.mac_pem, re.S):
                try:                       # un par un : un certificat illisible n'empêche pas les autres
                    ctx.load_verify_locations(cadata=pem)
                except (ssl.SSLError, ValueError):
                    pass
        if self.ca_file:
            try:
                ctx.load_verify_locations(cafile=os.path.expanduser(self.ca_file))
            except (OSError, ssl.SSLError) as exc:
                raise NetError(f"certificat de l'entreprise illisible ({self.ca_file}) : {exc}") from None
        if extra_ca:
            try:
                ctx.load_verify_locations(cadata=extra_ca)
            except (ssl.SSLError, ValueError):
                pass
        with self._lock:
            self._ctx[key] = ctx
        return ctx

    # ---- proxy (variables d'environnement, réglage du Mac, ou adresse donnée dans les paramètres)
    def _proxy_url(self, host):
        mode = self.proxy
        if mode == "none":
            return None
        bypass = []
        if mode == "auto":
            url = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or ""
            bypass = [b.strip() for b in (os.environ.get("NO_PROXY") or os.environ.get("no_proxy") or "").split(",")]
            if not url and IS_MAC:
                try:
                    import _scproxy
                    url = _scproxy._get_proxies().get("https", "")
                    bypass += list((_scproxy._get_proxy_settings() or {}).get("exceptions", []))
                except Exception:  # noqa: BLE001
                    url = ""
        else:
            url = mode
        if not url:
            return None
        h = _norm_host(host)
        for b in bypass:
            b = _norm_host(b)
            if b == "*" or (b and (h == b.lstrip("*.").lstrip(".") or h.endswith("." + b.lstrip("*.").lstrip(".")))):
                return None
        return url if "://" in url else "http://" + url

    # ---- connexions
    def _connect(self, host, port, timeout):
        autoriser_hote(host, port)
        infos = resoudre_autorise(host, port)
        last = None
        for family, kind, proto, _canon, addr in infos:
            sock = socket.socket(family, kind, proto)
            sock.settimeout(timeout)
            try:
                sock.connect(addr)
                return sock
            except OSError as exc:
                last = exc
                sock.close()
        raise last or OSError(f"aucune adresse pour {host}")

    def tcp(self, host, port, timeout=30):
        if not self.permitted(host):
            raise NetError(self.refusal(host))
        proxy = self._proxy_url(host)
        try:
            if not proxy:
                return self._connect(host, port, timeout)
            p = urlsplit(proxy)
            if not p.hostname:
                raise NetError(f"adresse de proxy illisible : {proxy}")
            sock = self._connect(p.hostname, p.port or 8080, timeout)
            req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
            if p.username:
                from urllib.parse import unquote
                cred = base64.b64encode(f"{unquote(p.username)}:{unquote(p.password or '')}".encode()).decode()
                req += f"Proxy-Authorization: Basic {cred}\r\n"
            sock.sendall((req + "\r\n").encode())
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                head += chunk
                if len(head) > 65536:
                    break
            status = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            if " 200" not in status:
                sock.close()
                raise NetError(f"le proxy {p.hostname} refuse la connexion à {host} : {status or 'pas de réponse'}")
            return sock
        except PermissionError as exc:
            raise NetError(str(exc)) from None
        except socket.timeout:
            raise NetError(f"{host} ne répond pas (délai dépassé)") from None
        except OSError as exc:
            hint = "" if proxy else (" — si ton réseau passe par un proxy, indique-le dans Paramètres › Réseau")
            raise NetError(f"connexion impossible à {host} : {exc}{hint}") from None

    def tls(self, host, port, ctx, timeout=30):
        sock = self.tcp(host, port, timeout)
        try:
            return ctx.wrap_socket(sock, server_hostname=host)
        except ssl.SSLCertVerificationError as exc:
            sock.close()
            raise NetError(f"certificat de {host} refusé ({exc.verify_message}). Si un proxy d'entreprise "
                           "intercepte les connexions, indique son certificat racine (.pem) dans "
                           "Paramètres › Réseau.") from None
        except (ssl.SSLError, OSError) as exc:
            sock.close()
            raise NetError(f"échec TLS avec {host} : {exc}") from None

    def request(self, method, url, headers=None, body=None, ctx=None, timeout=30, stream=False):
        """(statut, en-têtes en minuscules, corps) ; avec stream=True : (statut, en-têtes, connexion, réponse)."""
        import http.client
        u = urlsplit(url)
        if u.scheme != "https" or not u.hostname:
            raise NetError(f"adresse refusée (https obligatoire) : {url}")
        host, port = u.hostname, u.port or 443
        path = (u.path or "/") + ("?" + u.query if u.query else "")
        net = self
        context = ctx or self.context()

        class _Https(http.client.HTTPSConnection):
            def connect(self):
                self.sock = net.tls(host, port, context, self.timeout)

        if isinstance(body, dict):
            body = urlencode(body).encode()
        elif isinstance(body, str):
            body = body.encode("utf-8")
        conn = _Https(host, port, context=context, timeout=timeout)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            resp = conn.getresponse()
            hdrs = {k.lower(): v for k, v in resp.getheaders()}
            if stream:
                return resp.status, hdrs, conn, resp
            data = resp.read()
            conn.close()
            return resp.status, hdrs, data
        except NetError:
            conn.close()
            raise
        except socket.timeout:
            conn.close()
            raise NetError(f"{host} ne répond pas (délai dépassé)") from None
        except (OSError, http.client.HTTPException) as exc:
            conn.close()
            raise NetError(f"erreur réseau avec {host} : {exc}") from None


NET = Network()


def _short(body):
    txt = body.decode("utf-8", "replace") if isinstance(body, bytes) else str(body)
    try:
        js = json.loads(txt)
        for k in ("errorMessage", "description", "message", "error_description", "error"):
            if isinstance(js, dict) and js.get(k):
                return str(js[k])[:300]
    except ValueError:
        pass
    return txt[:300]


def jwt_exp(token):
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return float(json.loads(base64.urlsafe_b64decode(payload)).get("exp", 0))
    except Exception:  # noqa: BLE001
        return 0.0


# ======================================================================================
# IBM Cloud (IAM + API Containers)
# ======================================================================================

IAM_CLI_BASIC = base64.b64encode(b"bx:bx").decode()      # client de la CLI IBM Cloud (ibmcloud login --sso)
IAM_KUBE_BASIC = base64.b64encode(b"kube:kube").decode()
PASSCODE_GRANT = "urn:ibm:params:oauth:grant-type:passcode"
APIKEY_GRANT = "urn:ibm:params:oauth:grant-type:apikey"


def passcode_url(iam_url=None):
    """Page IBM où l'on obtient un code à usage unique (la même que « ibmcloud login --sso »)."""
    return f"{(iam_url or IAM_DEFAULT).rstrip('/')}/identity/passcode"


def is_api_key(code):
    """Une clé API IBM fait 44 caractères ; un code à usage unique, une dizaine."""
    return len((code or "").strip()) >= 30 and not code.strip().startswith("sha256~")


def _http(method, url, headers, data=None, timeout=30, ctx=None, ok_redirect=False):
    try:
        status, hdrs, body = NET.request(method, url, headers, data, ctx=ctx, timeout=timeout)
    except NetError as exc:
        raise CloudError(str(exc)) from None
    if status >= 400 or (status >= 300 and not ok_redirect):
        raise CloudError(f"HTTP {status} sur {urlsplit(url).hostname} : {_short(body)}", status,
                         body.decode("utf-8", "replace"))
    return status, hdrs, body


def iam_token(iam_url, form, basic=None):
    headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
    if basic:
        headers["Authorization"] = "Basic " + basic
    try:
        _, _, body = _http("POST", f"{iam_url.rstrip('/')}/identity/token", headers, form)
    except CloudError as exc:
        if form.get("grant_type") == PASSCODE_GRANT and exc.status in (400, 401):
            raise CloudError("Code à usage unique refusé par IBM Cloud : il est faux, déjà utilisé ou expiré. "
                             "Prends-en un nouveau.", exc.status) from None
        raise
    try:
        return json.loads(body)
    except ValueError:
        raise CloudError(f"réponse IAM illisible : {_short(body)}") from None


def openshift_login(server, ca_pem, user, password):
    """Comme « oc login -u <user> -p <password> --server=<server> » (user = passcode ou apikey) :
    renvoie (jeton OAuth OpenShift, expiration)."""
    ctx = NET.context(ca_pem)
    _, _, body = _http("GET", f"{server.rstrip('/')}/.well-known/oauth-authorization-server",
                       {"Accept": "application/json"}, ctx=ctx)
    try:
        auth_ep = json.loads(body)["authorization_endpoint"]
    except (ValueError, KeyError, TypeError):
        raise CloudError("Serveur de connexion OpenShift introuvable sur ce cluster.") from None
    u = urlsplit(auth_ep)
    if u.scheme != "https" or not NET.permitted(u.hostname or ""):
        raise CloudError(NET.refusal(u.hostname or auth_ep))
    url = auth_ep + "?" + urlencode({"client_id": "openshift-challenging-client", "response_type": "token"})
    basic = base64.b64encode(f"{user}:{password}".encode()).decode()
    try:
        status, headers, _ = _http("GET", url, {"Authorization": "Basic " + basic, "X-CSRF-Token": "a"},
                                   ctx=ctx, ok_redirect=True)
    except CloudError as exc:
        if exc.status == 401:
            what = "Code à usage unique refusé" if user == "passcode" else "Clé API refusée"
            raise CloudError(f"{what} par OpenShift : faux, déjà utilisé ou expiré. Prends-en un nouveau.",
                             401) from None
        raise
    frag = parse_qs(urlsplit(headers.get("location", "")).fragment)
    if "access_token" not in frag:
        raise CloudError(f"Connexion OpenShift refusée (HTTP {status}). Vérifie tes droits sur le cluster.")
    try:
        life = int(frag.get("expires_in", ["86400"])[0])
    except ValueError:
        life = 86400
    return frag["access_token"][0], time.time() + life


def openshift_token_from(server, ca_pem, code):
    """Code à usage unique, jeton OpenShift collé (sha256~…) ou clé API → (jeton, expiration)."""
    code = (code or "").strip()
    if code.startswith("sha256~"):
        return code, time.time() + 86400
    return openshift_login(server, ca_pem, "apikey" if is_api_key(code) else "passcode", code)


def _check_server(server):
    u = urlsplit(server or "")
    if u.scheme != "https" or not u.hostname:
        raise CloudError(f"Adresse de serveur invalide (https obligatoire) : {server}")
    if not NET.permitted(u.hostname):
        raise CloudError(NET.refusal(u.hostname))


class IbmAccount:
    """Un compte IBM Cloud, ouvert par code à usage unique (comme « ibmcloud login --sso ») ou par clé API."""
    demo = False
    kind = "ibm"

    def __init__(self, name, apikey=None, passcode=None, iam_url=IAM_DEFAULT, cs_url=CS_DEFAULT):
        self.name = name
        self.apikey = apikey or None
        self._passcode = passcode or None
        self._refresh = None
        self.iam_url = (iam_url or IAM_DEFAULT).rstrip("/")
        self.cs_url = (cs_url or CS_DEFAULT).rstrip("/")
        NET.declare(self.iam_url)
        NET.declare(self.cs_url)
        self._access = (None, 0.0)
        self._id_token = (None, 0.0)
        self._oc_tokens = {}
        self._ca_cache = {}
        self._lock = threading.Lock()
        self._auth_lock = threading.Lock()

    # ---- IAM
    def access_token(self, force=False):
        with self._auth_lock:                   # un seul échange à la fois : les autres attendent son jeton
            return self._access_token(force)

    def _access_token(self, force):
        with self._lock:
            tok, exp = self._access
            if tok and not force and time.time() < exp - 120:
                return tok
            code, self._passcode = self._passcode, None        # un code ne sert qu'une fois
            refresh = self._refresh
        if self.apikey:
            js = iam_token(self.iam_url, {"grant_type": APIKEY_GRANT, "apikey": self.apikey})
        elif refresh:
            try:
                js = iam_token(self.iam_url, {"grant_type": "refresh_token", "refresh_token": refresh},
                               basic=IAM_CLI_BASIC)
            except CloudError:
                raise CloudError("Session IBM Cloud expirée : clic droit sur le compte › Se reconnecter, "
                                 "avec un nouveau code.", 401) from None
        elif code:
            js = iam_token(self.iam_url, {"grant_type": PASSCODE_GRANT, "passcode": code}, basic=IAM_CLI_BASIC)
        else:
            raise CloudError("Session IBM Cloud fermée : un nouveau code à usage unique est nécessaire.", 401)
        tok = js["access_token"]
        with self._lock:
            self._access = (tok, float(js.get("expiration") or time.time() + 3000))
            self._refresh = js.get("refresh_token") or self._refresh
        return tok

    def kube_id_token(self, force=False):
        """Jeton OIDC accepté par l'API Kubernetes des clusters IKS (avec une clé API seulement)."""
        if not self.apikey:
            raise CloudError("Cluster Kubernetes (IKS) : la connexion par code à usage unique n'est pas prise en "
                             "charge ; il faut une clé API pour ce type de cluster.")
        with self._lock:
            tok, exp = self._id_token
            if tok and not force and time.time() < exp - 120:
                return tok
        js = iam_token(self.iam_url, {"grant_type": APIKEY_GRANT, "apikey": self.apikey,
                                      "response_type": "cloud_iam id_token"}, basic=IAM_KUBE_BASIC)
        tok = js.get("id_token") or js["access_token"]
        with self._lock:
            self._id_token = (tok, jwt_exp(tok) or time.time() + 3000)
        return tok

    # ---- clusters
    def _cs_get(self, path, params=None, raw=False):
        url = f"{self.cs_url}{path}" + ("?" + urlencode(params) if params else "")
        headers = {"Authorization": "Bearer " + self.access_token(), "Accept": "application/json"}
        _, _, body = _http("GET", url, headers, timeout=60)
        if raw:
            return body
        try:
            return json.loads(body or b"null")
        except ValueError:
            raise CloudError(f"réponse illisible de l'API Containers : {_short(body)}") from None

    def list_clusters(self):
        try:
            data = self._cs_get("/global/v2/getClusters") or []
        except CloudError as exc:
            if exc.status == 403:
                raise CloudError("IBM Cloud refuse de lister les clusters de ce compte (HTTP 403 : droits "
                                 "insuffisants). Ajoute le cluster à la main avec le bouton « Connexion » "
                                 "(adresse du serveur + namespace).", 403) from None
            raise
        out = []
        for c in data:
            ctype = (c.get("type") or "").lower()
            if ctype not in ("kubernetes", "openshift"):
                ctype = "openshift" if "openshift" in (c.get("masterKubeVersion") or "").lower() else "kubernetes"
            se = c.get("serviceEndpoints") or {}
            out.append({
                "id": c.get("id"), "name": c.get("name"), "type": ctype,
                "region": c.get("region", ""), "state": c.get("state", ""),
                "version": c.get("masterKubeVersion", ""), "provider": c.get("provider", ""),
                "resourceGroup": c.get("resourceGroupName", ""), "workers": c.get("workerCount", ""),
                "public": se.get("publicServiceEndpointURL") or c.get("masterURL") or "",
                "private": se.get("privateServiceEndpointURL") or "",
                "ingress": (c.get("ingress") or {}).get("hostname", ""),
            })
        return sorted(out, key=lambda x: (x["type"], x["name"] or ""))

    def cluster_ca(self, cluster_id):
        """Autorité de certification du cluster (et synchronisation du RBAC IAM, comme « ibmcloud ks cluster config »)."""
        if cluster_id in self._ca_cache:
            return self._ca_cache[cluster_id]
        ca = None
        try:
            body = self._cs_get("/global/v2/applyRBACAndGetKubeconfig", {"cluster": cluster_id}, raw=True)
            ca = _ca_from_kubeconfig(body.decode("utf-8", "replace"))
        except (CloudError, ValueError):
            pass
        if not ca:
            try:
                body = self._cs_get(f"/global/v1/clusters/{cluster_id}/config", raw=True)
                with zipfile.ZipFile(io.BytesIO(body)) as z:
                    for n in z.namelist():
                        if n.endswith(".pem") and "key" not in n.lower():
                            ca = z.read(n).decode()
                            break
            except (CloudError, zipfile.BadZipFile, ValueError, KeyError):
                pass
        self._ca_cache[cluster_id] = ca
        return ca

    @staticmethod
    def server_of(cluster, private=False):
        return (cluster["private"] if private and cluster.get("private") else cluster["public"]) or cluster["private"]

    def needs_code(self, cluster, private=False):
        """OpenShift ouvert par code : chaque connexion au cluster demande un nouveau code (comme oc login)."""
        if cluster["type"] != "openshift" or self.apikey:
            return False
        cached = self._oc_tokens.get(self.server_of(cluster, private))
        return not cached or time.time() > cached[1] - 60

    def invalidate(self, cluster):
        for srv in (cluster.get("public"), cluster.get("private")):
            self._oc_tokens.pop(srv, None)

    # ---- client Kubernetes
    def connect(self, cluster, private=False, code=None):
        server = self.server_of(cluster, private)
        if not server:
            raise CloudError("Ce cluster n'expose aucun point d'accès (public ou privé).")
        _check_server(server)
        ca = self.cluster_ca(cluster["id"])
        if cluster["type"] == "openshift" and code:
            self._oc_tokens[server] = openshift_token_from(server, ca, code)

        def token(force=False):
            return self.cluster_token(cluster, server, ca, force)
        token(False)   # authentification immédiate : remonte l'erreur au plus tôt
        kube = KubeClient(server, token, ca, cluster["type"])
        kube.whoami()
        return kube

    # ---- jeton pour le cluster
    def cluster_token(self, cluster, server, ca_pem=None, force=False):
        if cluster["type"] != "openshift":
            return self.kube_id_token(force)
        cached = self._oc_tokens.get(server)
        if cached and not (force and self.apikey) and time.time() < cached[1] - 60:
            return cached[0]
        if not self.apikey:
            raise CloudError("Session OpenShift expirée : reconnecte-toi avec un nouveau code à usage unique.", 401)
        tok, exp = openshift_login(server, ca_pem, "apikey", self.apikey)
        self._oc_tokens[server] = (tok, exp)
        return tok


class DirectAccount:
    """Connexion directe à un cluster OpenShift : adresse du serveur + namespaces, ouverte par code à usage
    unique (comme « oc login -u passcode -p <code> --server=<serveur> »). Aucun appel à l'API IBM Cloud."""
    demo = False
    kind = "cluster"
    CID = "cluster"

    def __init__(self, meta):
        self.update(meta)
        self._token = (None, 0.0)

    def update(self, meta):
        self.name = meta["name"]
        self.server = meta["server"].rstrip("/")
        self.namespaces = list(meta.get("namespaces") or [])
        self.iam_url = meta.get("iamUrl") or IAM_DEFAULT
        NET.declare(self.server)
        NET.declare(self.iam_url)

    def cluster(self):
        host = urlsplit(self.server).hostname or self.server
        return {"id": self.CID, "name": self.name, "type": "openshift", "region": "", "state": "",
                "version": "", "provider": "", "resourceGroup": "", "workers": "", "public": self.server,
                "private": "", "ingress": "", "host": host}

    def list_clusters(self):
        return [self.cluster()]

    def needs_code(self, cluster=None, private=False):
        tok, exp = self._token
        return not tok or time.time() > exp - 60

    def invalidate(self, cluster=None):
        self._token = (None, 0.0)

    def connect(self, cluster=None, private=False, code=None):
        _check_server(self.server)
        if code:
            self._token = openshift_token_from(self.server, None, code)
        elif self.needs_code():
            raise CloudError("Un code à usage unique est nécessaire pour se connecter.", 401)
        kube = KubeClient(self.server, lambda force=False: self._token[0], None, "openshift")
        try:
            kube.whoami()
        except KubeError as exc:
            if exc.status == 401:
                self.invalidate()
                raise CloudError("Le cluster refuse ce jeton (HTTP 401) : prends un nouveau code.", 401) from None
            raise
        return kube


PORTAL = "https://cloud.ibm.com"
# Ressources que la console OpenShift connaît sous leur nom court dans ses adresses
CONSOLE_PLURALS = {"pods", "services", "configmaps", "secrets", "persistentvolumeclaims", "serviceaccounts",
                   "events", "deployments", "statefulsets", "daemonsets", "replicasets", "jobs", "cronjobs",
                   "routes", "deploymentconfigs", "buildconfigs", "builds", "imagestreams", "ingresses",
                   "horizontalpodautoscalers", "networkpolicies", "roles", "rolebindings", "nodes",
                   "persistentvolumes", "storageclasses", "namespaces", "projects"}


def console_ref(res):
    """Nom de la ressource dans les adresses de la console : « deployments » ou « groupe~version~Kind »."""
    if res.get("name") in CONSOLE_PLURALS:
        return res["name"]
    return f"{res.get('group') or 'core'}~{res.get('version', 'v1')}~{res.get('kind', '')}"


def console_link(base, view="cluster", ns=None, res=None, name=None, page=""):
    """Adresse d'une page de la console web OpenShift (là où se font les modifications)."""
    base = (base or "").rstrip("/")
    if not base:
        return ""
    if view == "topology" and ns:
        return f"{base}/topology/ns/{ns}"
    if view == "helm" and ns:
        return f"{base}/helm-releases/ns/{ns}" + (f"/release/{name}" if name else "")
    if res is not None:
        ref = console_ref(res)
        url = f"{base}/k8s/ns/{ns}/{ref}" if ns and res.get("namespaced", True) else f"{base}/k8s/cluster/{ref}"
        return url + (f"/{name}" if name else "") + (f"/{page}" if name and page else "")
    if ns:
        return f"{base}/k8s/cluster/projects/{ns}"
    return base


def portal_link(cluster=None):
    """Page du cluster dans le portail IBM Cloud (ou la liste des clusters si on ne connaît pas son identifiant)."""
    cid = (cluster or {}).get("id")
    kind = "openshift" if (cluster or {}).get("type", "openshift") == "openshift" else "kubernetes"
    if cid and cid != "cluster" and re.match(r"^[A-Za-z0-9-]+$", cid):
        return f"{PORTAL}/kubernetes/clusters/{cid}/overview?platformType={kind}"
    return f"{PORTAL}/kubernetes/clusters?platformType={kind}"


def _ca_from_kubeconfig(text):
    m = re.search(r'certificate-authority-data:\s*"?([A-Za-z0-9+/=]+)', text)
    if m:
        try:
            return base64.b64decode(m.group(1)).decode()
        except Exception:  # noqa: BLE001
            return None
    return None


# ======================================================================================
# Client Kubernetes
# ======================================================================================

class KubeClient:
    demo = False

    def __init__(self, server, token_fn, ca_pem=None, flavor="kubernetes"):
        self.server = server.rstrip("/")
        self.token_fn = token_fn          # token_fn(force: bool) -> str
        self.ca_pem = ca_pem
        self.flavor = flavor
        self.user = ""
        self.console = ""                 # adresse de la console web (trouvée à la connexion)
        self._discovery = None
        self._lock = threading.Lock()

    def _token(self, force):
        try:
            return self.token_fn(force)
        except CloudError as exc:
            raise KubeError(str(exc), exc.status) from None

    def whoami(self):
        """Nom de l'utilisateur connecté (OpenShift) ; vérifie au passage que le jeton est accepté."""
        try:
            self.user = self.request("GET", "/apis/user.openshift.io/v1/users/~", timeout=15).get(
                "metadata", {}).get("name", "")
        except KubeError as exc:
            if exc.status in (401,):
                raise
            self.version()
        return self.user

    def namespaces(self, declared=()):
        """Namespaces visibles : la liste complète si on a le droit, sinon les projets OpenShift accessibles
        (comme « oc projects »), plus ceux indiqués à la main. Renvoie (noms, origine)."""
        names, how = [], "déclarés"
        try:
            names = [n["metadata"]["name"] for n in self.list(CATALOG_BY_KEY["namespaces"])]
            how = "tous"
        except KubeError as exc:
            if exc.status == 401:
                raise
            try:
                js = self.request("GET", "/apis/project.openshift.io/v1/projects", timeout=30)
                names = [p["metadata"]["name"] for p in js.get("items", [])]
                how = "projets"
            except KubeError as exc2:
                if exc2.status == 401:
                    raise
        return sorted(set(names) | {d for d in declared if d}), how

    @property
    def ctx(self):
        return NET.context(self.ca_pem)

    def _url(self, path, params=None):
        url = self.server + path
        if params:
            url += "?" + urlencode({k: v for k, v in params.items() if v is not None}, doseq=True)
        return url

    def _headers(self, force=False, ctype=None, has_body=False):
        h = {"Authorization": "Bearer " + self._token(force), "Accept": "application/json, */*"}
        if has_body:
            h["Content-Type"] = ctype or "application/json"
        return h

    def _raw(self, method, path, params=None, body=None, ctype="application/json", timeout=30):
        if method != "GET" or body is not None:          # outil en lecture seule : aucune requête qui modifie
            raise KubeError("Lecture seule : les modifications se font dans la console OpenShift.", 405)
        data = None
        url = self._url(path, params)
        for force in (False, True):
            try:
                status, _, raw = NET.request(method, url, self._headers(force, ctype, data is not None), data,
                                             ctx=self.ctx, timeout=timeout)
            except NetError as exc:
                raise KubeError(f"Cluster injoignable : {exc}") from None
            if status == 401 and not force:
                continue
            break
        if status >= 400:
            txt = raw.decode("utf-8", "replace")
            try:
                msg = json.loads(txt).get("message") or txt
            except (ValueError, AttributeError):
                msg = txt
            if status == 401:
                msg = "session expirée ou jeton refusé : reconnecte-toi avec un nouveau code"
            raise KubeError(f"HTTP {status} : {msg[:400]}", status)
        return raw

    def request(self, method, path, params=None, body=None, ctype="application/json", timeout=30):
        raw = self._raw(method, path, params, body, ctype, timeout)
        try:
            return json.loads(raw) if raw else {}
        except ValueError:
            raise KubeError(f"réponse illisible : {raw[:200]!r}") from None

    def text(self, path, params=None, timeout=60):
        return self._raw("GET", path, params, timeout=timeout).decode("utf-8", "replace")

    # ---- découverte
    def discovery(self):
        with self._lock:
            if self._discovery is not None:
                return self._discovery
        out = []
        out += _resources("", "v1", self.request("GET", "/api/v1"))
        for g in self.request("GET", "/apis").get("groups", []):
            pv = (g.get("preferredVersion") or {}).get("groupVersion")
            if not pv:
                continue
            try:
                out += _resources(g["name"], pv.split("/")[-1], self.request("GET", f"/apis/{pv}", timeout=15))
            except KubeError:
                continue
        with self._lock:
            self._discovery = out
        return out

    def has(self, group, plural):
        try:
            return any(r["group"] == group and r["name"] == plural for r in self.discovery())
        except KubeError:
            return False

    # ---- lecture / écriture
    @staticmethod
    def path(res, ns=None, name=None, sub=None):
        base = "/api/v1" if not res["group"] else f"/apis/{res['group']}/{res['version']}"
        if res.get("namespaced", True) and ns:
            base += f"/namespaces/{ns}"
        base += f"/{res['name']}"
        if name:
            base += f"/{name}"
        if sub:
            base += f"/{sub}"
        return base

    def list(self, res, ns=None, selector=None):
        js = self.request("GET", self.path(res, ns), {"labelSelector": selector, "limit": 2000}, timeout=60)
        items = js.get("items", [])
        kind = js.get("kind", "")
        kind = kind[:-4] if kind.endswith("List") else kind
        for it in items:
            it.setdefault("kind", kind or res.get("kind", ""))
            it.setdefault("apiVersion", (res["group"] + "/" if res["group"] else "") + res["version"])
        return items

    def get(self, res, ns, name):
        return self.request("GET", self.path(res, ns, name))

    # ---- logs
    def logs(self, ns, pod, container=None, tail=500, timestamps=False, previous=False):
        return self.text(f"/api/v1/namespaces/{ns}/pods/{pod}/log",
                         {"container": container, "tailLines": tail or None,
                          "timestamps": "true" if timestamps else None, "previous": "true" if previous else None})

    def logs_follow(self, ns, pod, container, tail, timestamps, stop, on_line):
        params = {"container": container, "follow": "true", "tailLines": tail or None,
                  "timestamps": "true" if timestamps else None}
        url = self._url(f"/api/v1/namespaces/{ns}/pods/{pod}/log", params)
        try:
            status, _, conn, resp = NET.request("GET", url, self._headers(), ctx=self.ctx, timeout=3600, stream=True)
        except NetError as exc:
            raise KubeError(f"Cluster injoignable : {exc}") from None
        if status >= 400:
            msg = resp.read(2000).decode("utf-8", "replace")
            conn.close()
            raise KubeError(f"HTTP {status} : {_short(msg)}", status)

        def watcher():                 # « Arrêter » ferme la connexion, ce qui débloque la lecture
            stop.wait()
            try:
                conn.sock.shutdown(socket.SHUT_RDWR)
            except Exception:  # noqa: BLE001
                pass
        threading.Thread(target=watcher, daemon=True).start()
        try:
            while not stop.is_set():
                raw = resp.readline()
                if not raw:
                    break
                on_line(raw.decode("utf-8", "replace"))
        except (OSError, ValueError):
            pass
        finally:
            conn.close()

    # ---- métriques
    def pod_metrics(self, ns):
        try:
            js = self.request("GET", f"/apis/metrics.k8s.io/v1beta1/namespaces/{ns}/pods", timeout=15)
        except KubeError:
            return None
        out = {}
        for it in js.get("items", []):
            cpu = mem = 0.0
            for c in it.get("containers", []):
                cpu += cpu_millis(c.get("usage", {}).get("cpu", "0"))
                mem += mem_bytes(c.get("usage", {}).get("memory", "0"))
            out[it["metadata"]["name"]] = (cpu, mem)
        return out

    def version(self):
        try:
            return self.request("GET", "/version", timeout=10).get("gitVersion", "")
        except KubeError:
            return ""

    def find_console(self, fallback=""):
        """Adresse de la console web OpenShift, comme « oc whoami --show-console » (ConfigMap console-public,
        lisible par tout utilisateur connecté). À défaut : <serveur>/console, qui redirige vers la console."""
        try:
            js = self.request("GET", "/api/v1/namespaces/openshift-config-managed/configmaps/console-public",
                              timeout=15)
            url = ((js.get("data") or {}).get("consoleURL") or "").rstrip("/")
            if url.startswith("https://"):
                return url
        except KubeError:
            pass
        return fallback or (self.server + "/console" if self.flavor == "openshift" else "")


# ======================================================================================
# Ressources, catalogue, Helm, YAML, topologie (logique reprise telle quelle de l'original)
# ======================================================================================

def _resources(group, version, js):
    out = []
    for r in js.get('resources', []):
        if '/' in r['name']:
            continue
        out.append({'group': group, 'version': version, 'name': r['name'], 'kind': r.get('kind', ''),
                    'namespaced': r.get('namespaced', False), 'verbs': r.get('verbs', []),
                    'short': r.get('shortNames', [])})
    return out


# ============================================================ quantités
_SUFFIX = {'Ki': 2 ** 10, 'Mi': 2 ** 20, 'Gi': 2 ** 30, 'Ti': 2 ** 40, 'K': 1e3, 'k': 1e3, 'M': 1e6, 'G': 1e9,
           'T': 1e12, 'E': 1e18, 'Ei': 2 ** 60, 'P': 1e15, 'Pi': 2 ** 50}


def cpu_millis(q) -> float:
    q = str(q or '0')
    try:
        if q.endswith('n'):
            return float(q[:-1]) / 1e6
        if q.endswith('u'):
            return float(q[:-1]) / 1e3
        if q.endswith('m'):
            return float(q[:-1])
        return float(q) * 1000
    except ValueError:
        return 0.0


def mem_bytes(q) -> float:
    q = str(q or '0')
    m = re.match(r'^([0-9.eE+-]+)([A-Za-z]*)$', q)
    if not m:
        return 0.0
    try:
        return float(m.group(1)) * _SUFFIX.get(m.group(2), 1)
    except ValueError:
        return 0.0


def human_bytes(n):
    for unit in ('o', 'Kio', 'Mio', 'Gio', 'Tio'):
        if abs(n) < 1024 or unit == 'Tio':
            return f'{n:.0f} {unit}' if unit == 'o' else f'{n:.1f} {unit}'
        n /= 1024


def parse_time(ts):
    if not ts:
        return None
    try:
        return _dt.datetime.strptime(ts[:19], '%Y-%m-%dT%H:%M:%S').replace(tzinfo=_dt.timezone.utc)
    except ValueError:
        return None


def age(ts) -> str:
    t = parse_time(ts) if isinstance(ts, str) else ts
    if not t:
        return ''
    s = int((_dt.datetime.now(_dt.timezone.utc) - t).total_seconds())
    if s < 120:
        return f'{max(s, 0)}s'
    if s < 7200:
        return f'{s // 60}m'
    if s < 172800:
        return f'{s // 3600}h'
    return f'{s // 86400}j'


def age_seconds(ts):
    t = parse_time(ts)
    return (_dt.datetime.now(_dt.timezone.utc) - t).total_seconds() if t else 0


def fmt_time(ts):
    t = parse_time(ts)
    return t.astimezone().strftime('%d/%m/%Y %H:%M:%S') if t else ''


# ============================================================ catalogue
def _m(o):
    return o.get('metadata', {})


def _labels_str(d):
    return ', '.join(f'{k}={v}' for k, v in (d or {}).items())


def pod_status(p):
    """(texte, niveau) — niveau : ok | warn | err | off."""
    st = p.get('status', {})
    if _m(p).get('deletionTimestamp'):
        return 'Terminating', 'warn'
    reason = st.get('reason')
    phase = st.get('phase', 'Unknown')
    for cs in st.get('initContainerStatuses', []) or []:
        w = (cs.get('state') or {}).get('waiting')
        if w and w.get('reason'):
            return f"Init:{w['reason']}", 'err' if 'Err' in w['reason'] or 'Back' in w['reason'] else 'warn'
    for cs in st.get('containerStatuses', []) or []:
        state = cs.get('state') or {}
        if state.get('waiting', {}).get('reason'):
            r = state['waiting']['reason']
            return r, 'err' if r in ('CrashLoopBackOff', 'ErrImagePull', 'ImagePullBackOff', 'CreateContainerConfigError',
                                     'InvalidImageName', 'RunContainerError') else 'warn'
        if state.get('terminated', {}).get('reason') and phase != 'Succeeded':
            return state['terminated']['reason'], 'err'
    if reason:
        return reason, 'warn'
    level = {'Running': 'ok', 'Succeeded': 'off', 'Pending': 'warn', 'Failed': 'err'}.get(phase, 'warn')
    if phase == 'Running':
        css = st.get('containerStatuses', []) or []
        if css and not all(c.get('ready') for c in css):
            return 'Running (non prêt)', 'warn'
    return phase, level


def pod_ready(p):
    css = p.get('status', {}).get('containerStatuses', []) or []
    total = len(p.get('spec', {}).get('containers', [])) or len(css)
    return f'{sum(1 for c in css if c.get("ready"))}/{total}'


def pod_restarts(p):
    return sum(c.get('restartCount', 0) for c in p.get('status', {}).get('containerStatuses', []) or [])


def _workload_level(ready, want):
    if want == 0:
        return 'off'
    return 'ok' if ready >= want else ('err' if ready == 0 else 'warn')


def _deploy_cols(o):
    s, sp = o.get('status', {}), o.get('spec', {})
    want, ready = sp.get('replicas', 0), s.get('readyReplicas', 0)
    imgs = ', '.join(c.get('image', '').split('/')[-1] for c in sp.get('template', {}).get('spec', {}).get('containers', []))
    return [f'{ready}/{want}', s.get('updatedReplicas', 0), s.get('availableReplicas', 0), imgs], _workload_level(ready, want)


def _sts_cols(o):
    s, sp = o.get('status', {}), o.get('spec', {})
    want, ready = sp.get('replicas', 0), s.get('readyReplicas', 0)
    return [f'{ready}/{want}', sp.get('serviceName', '')], _workload_level(ready, want)


def _ds_cols(o):
    s = o.get('status', {})
    want, ready = s.get('desiredNumberScheduled', 0), s.get('numberReady', 0)
    return [want, s.get('currentNumberScheduled', 0), ready, s.get('numberAvailable', 0)], _workload_level(ready, want)


def _rs_cols(o):
    s, sp = o.get('status', {}), o.get('spec', {})
    want, ready = sp.get('replicas', 0), s.get('readyReplicas', 0)
    owner = ', '.join(r.get('name', '') for r in _m(o).get('ownerReferences', []))
    return [want, s.get('replicas', 0), ready, owner], _workload_level(ready, want)


def _pod_cols(o):
    txt, lvl = pod_status(o)
    return [pod_ready(o), txt, pod_restarts(o), o.get('spec', {}).get('nodeName', ''),
            o.get('status', {}).get('podIP', '')], lvl


def _svc_cols(o):
    sp = o.get('spec', {})
    ports = ', '.join(f"{p.get('port')}{'→' + str(p.get('targetPort')) if p.get('targetPort') not in (None, p.get('port')) else ''}"
                      f"/{p.get('protocol', 'TCP')}" for p in sp.get('ports', []) or [])
    ext = ', '.join(i.get('ip') or i.get('hostname', '') for i in
                    (o.get('status', {}).get('loadBalancer', {}).get('ingress') or []))
    return [sp.get('type', ''), sp.get('clusterIP', ''), ext, ports], 'ok'


def _ing_cols(o):
    rules = o.get('spec', {}).get('rules', []) or []
    hosts = ', '.join(r.get('host', '*') for r in rules)
    addr = ', '.join(i.get('ip') or i.get('hostname', '') for i in
                     (o.get('status', {}).get('loadBalancer', {}).get('ingress') or []))
    return [o.get('spec', {}).get('ingressClassName', ''), hosts, addr], 'ok'


def _route_cols(o):
    sp = o.get('spec', {})
    tls = (sp.get('tls') or {}).get('termination', '')
    return [sp.get('host', ''), sp.get('path', ''), (sp.get('to') or {}).get('name', ''), tls or '—'], 'ok'


def _cm_cols(o):
    return [len(o.get('data', {}) or {}) + len(o.get('binaryData', {}) or {})], 'ok'


def _secret_cols(o):
    return [o.get('type', ''), len(o.get('data', {}) or {})], 'ok'


def _pvc_cols(o):
    s, sp = o.get('status', {}), o.get('spec', {})
    phase = s.get('phase', '')
    return [phase, sp.get('volumeName', ''), (s.get('capacity') or {}).get('storage', ''),
            ', '.join(sp.get('accessModes', []) or []), sp.get('storageClassName', '')], \
        'ok' if phase == 'Bound' else 'warn'


def _job_cols(o):
    s, sp = o.get('status', {}), o.get('spec', {})
    comp = f"{s.get('succeeded', 0)}/{sp.get('completions', 1)}"
    lvl = 'err' if s.get('failed') else ('off' if s.get('succeeded') else 'warn')
    dur = ''
    if s.get('startTime') and s.get('completionTime'):
        dur = f"{int((parse_time(s['completionTime']) - parse_time(s['startTime'])).total_seconds())}s"
    return [comp, dur], lvl


def _cron_cols(o):
    sp, s = o.get('spec', {}), o.get('status', {})
    return [sp.get('schedule', ''), 'Oui' if sp.get('suspend') else 'Non', len(s.get('active', []) or []),
            age(s.get('lastScheduleTime')) if s.get('lastScheduleTime') else ''], 'off' if sp.get('suspend') else 'ok'


def _hpa_cols(o):
    sp, s = o.get('spec', {}), o.get('status', {})
    ref = (sp.get('scaleTargetRef') or {})
    return [f"{ref.get('kind', '')}/{ref.get('name', '')}", sp.get('minReplicas', 1), sp.get('maxReplicas', ''),
            s.get('currentReplicas', '')], 'ok'


def _event_cols(o):
    inv = o.get('involvedObject', {}) or o.get('regarding', {})
    t = o.get('type', 'Normal')
    return [t, o.get('reason', ''), f"{inv.get('kind', '')}/{inv.get('name', '')}",
            (o.get('message') or o.get('note') or '').replace('\n', ' '), o.get('count', 1)], \
        'warn' if t == 'Warning' else 'ok'


def _node_cols(o):
    s = o.get('status', {})
    ready = next((c for c in s.get('conditions', []) if c.get('type') == 'Ready'), {})
    ok = ready.get('status') == 'True'
    roles = ', '.join(k.split('/')[-1] for k in _m(o).get('labels', {}) if k.startswith('node-role.kubernetes.io/')) or 'worker'
    cap = s.get('capacity', {})
    zone = _m(o).get('labels', {}).get('topology.kubernetes.io/zone', '')
    return ['Ready' if ok else 'NotReady', roles, s.get('nodeInfo', {}).get('kubeletVersion', ''),
            f"{cpu_millis(cap.get('cpu', '0')) / 1000:.0f}", human_bytes(mem_bytes(cap.get('memory', '0'))), zone], \
        'ok' if ok else 'err'


def _ns_cols(o):
    ph = o.get('status', {}).get('phase', '')
    return [ph, _labels_str(_m(o).get('labels'))[:80]], 'ok' if ph == 'Active' else 'warn'


def _pv_cols(o):
    sp, s = o.get('spec', {}), o.get('status', {})
    claim = sp.get('claimRef') or {}
    return [(sp.get('capacity') or {}).get('storage', ''), s.get('phase', ''),
            f"{claim.get('namespace', '')}/{claim.get('name', '')}" if claim else '', sp.get('storageClassName', '')], 'ok'


def _sc_cols(o):
    return [o.get('provisioner', ''), o.get('reclaimPolicy', ''),
            'Oui' if _m(o).get('annotations', {}).get('storageclass.kubernetes.io/is-default-class') == 'true' else ''], 'ok'


def _dc_cols(o):
    s, sp = o.get('status', {}), o.get('spec', {})
    want, ready = sp.get('replicas', 0), s.get('readyReplicas', 0)
    return [f'{ready}/{want}', s.get('latestVersion', '')], _workload_level(ready, want)


def _role_cols(o):
    return [len(o.get('rules', []) or [])], 'ok'


def _rb_cols(o):
    ref = o.get('roleRef', {})
    subj = ', '.join(f"{s.get('kind', '')[:2]}:{s.get('name', '')}" for s in o.get('subjects', []) or [])
    return [f"{ref.get('kind', '')}/{ref.get('name', '')}", subj[:120]], 'ok'


def _np_cols(o):
    sp = o.get('spec', {})
    sel = _labels_str((sp.get('podSelector') or {}).get('matchLabels')) or '(tous les pods)'
    return [sel, ', '.join(sp.get('policyTypes', []) or [])], 'ok'


def _sa_cols(o):
    return [len(o.get('secrets', []) or [])], 'ok'


def R(key, label, group, version, plural, kind, cols=None, headers=None, namespaced=True, icon='doc'):
    return {'key': key, 'label': label, 'group': group, 'version': version, 'name': plural, 'kind': kind,
            'namespaced': namespaced, 'cols': cols, 'headers': headers or [], 'icon': icon}


CATALOG = [
    R('pods', 'Pods', '', 'v1', 'pods', 'Pod', _pod_cols, ['Prêt', 'Statut', 'Redémarrages', 'Nœud', 'IP'], icon='pod'),
    R('deployments', 'Deployments', 'apps', 'v1', 'deployments', 'Deployment', _deploy_cols,
      ['Prêt', 'À jour', 'Disponibles', 'Images'], icon='deploy'),
    R('deploymentconfigs', 'DeploymentConfigs', 'apps.openshift.io', 'v1', 'deploymentconfigs', 'DeploymentConfig',
      _dc_cols, ['Prêt', 'Version'], icon='deploy'),
    R('statefulsets', 'StatefulSets', 'apps', 'v1', 'statefulsets', 'StatefulSet', _sts_cols, ['Prêt', 'Service'],
      icon='deploy'),
    R('daemonsets', 'DaemonSets', 'apps', 'v1', 'daemonsets', 'DaemonSet', _ds_cols,
      ['Désirés', 'Actuels', 'Prêts', 'Disponibles'], icon='deploy'),
    R('replicasets', 'ReplicaSets', 'apps', 'v1', 'replicasets', 'ReplicaSet', _rs_cols,
      ['Désirés', 'Actuels', 'Prêts', 'Propriétaire'], icon='deploy'),
    R('jobs', 'Jobs', 'batch', 'v1', 'jobs', 'Job', _job_cols, ['Complétions', 'Durée'], icon='job'),
    R('cronjobs', 'CronJobs', 'batch', 'v1', 'cronjobs', 'CronJob', _cron_cols,
      ['Planification', 'Suspendu', 'Actifs', 'Dernière exécution'], icon='job'),
    R('services', 'Services', '', 'v1', 'services', 'Service', _svc_cols,
      ['Type', 'Cluster IP', 'IP externe', 'Ports'], icon='net'),
    R('ingresses', 'Ingress', 'networking.k8s.io', 'v1', 'ingresses', 'Ingress', _ing_cols,
      ['Classe', 'Hôtes', 'Adresse'], icon='net'),
    R('routes', 'Routes', 'route.openshift.io', 'v1', 'routes', 'Route', _route_cols,
      ['Hôte', 'Chemin', 'Service', 'TLS'], icon='net'),
    R('networkpolicies', 'NetworkPolicies', 'networking.k8s.io', 'v1', 'networkpolicies', 'NetworkPolicy', _np_cols,
      ['Pods ciblés', 'Types'], icon='net'),
    R('configmaps', 'ConfigMaps', '', 'v1', 'configmaps', 'ConfigMap', _cm_cols, ['Clés'], icon='config'),
    R('secrets', 'Secrets', '', 'v1', 'secrets', 'Secret', _secret_cols, ['Type', 'Clés'], icon='secret'),
    R('hpa', 'HorizontalPodAutoscalers', 'autoscaling', 'v2', 'horizontalpodautoscalers', 'HorizontalPodAutoscaler',
      _hpa_cols, ['Cible', 'Min', 'Max', 'Réplicas'], icon='config'),
    R('pvc', 'PersistentVolumeClaims', '', 'v1', 'persistentvolumeclaims', 'PersistentVolumeClaim', _pvc_cols,
      ['Statut', 'Volume', 'Capacité', 'Accès', 'Classe'], icon='disk'),
    R('serviceaccounts', 'ServiceAccounts', '', 'v1', 'serviceaccounts', 'ServiceAccount', _sa_cols, ['Secrets'],
      icon='user'),
    R('roles', 'Roles', 'rbac.authorization.k8s.io', 'v1', 'roles', 'Role', _role_cols, ['Règles'], icon='user'),
    R('rolebindings', 'RoleBindings', 'rbac.authorization.k8s.io', 'v1', 'rolebindings', 'RoleBinding', _rb_cols,
      ['Rôle', 'Sujets'], icon='user'),
    R('events', 'Événements', '', 'v1', 'events', 'Event', _event_cols, ['Type', 'Raison', 'Objet', 'Message', 'Nb'],
      icon='event'),
    # ressources du cluster
    R('nodes', 'Nœuds', '', 'v1', 'nodes', 'Node', _node_cols, ['Statut', 'Rôles', 'Version', 'CPU', 'Mémoire', 'Zone'],
      namespaced=False, icon='node'),
    R('namespaces', 'Namespaces', '', 'v1', 'namespaces', 'Namespace', _ns_cols, ['Statut', 'Labels'],
      namespaced=False, icon='folder'),
    R('persistentvolumes', 'PersistentVolumes', '', 'v1', 'persistentvolumes', 'PersistentVolume', _pv_cols,
      ['Capacité', 'Statut', 'Réclamé par', 'Classe'], namespaced=False, icon='disk'),
    R('storageclasses', 'StorageClasses', 'storage.k8s.io', 'v1', 'storageclasses', 'StorageClass', _sc_cols,
      ['Provisionneur', 'Récupération', 'Défaut'], namespaced=False, icon='disk'),
]
CATALOG_BY_KEY = {r['key']: r for r in CATALOG}

NAV_GROUPS = [
    ('Charges de travail', 'workload', ['pods', 'deployments', 'deploymentconfigs', 'statefulsets', 'daemonsets',
                                        'replicasets', 'jobs', 'cronjobs']),
    ('Réseau', 'net', ['services', 'routes', 'ingresses', 'networkpolicies']),
    ('Configuration', 'config', ['configmaps', 'secrets', 'hpa']),
    ('Stockage', 'disk', ['pvc']),
    ('Accès', 'user', ['serviceaccounts', 'roles', 'rolebindings']),
]
OPENSHIFT_ONLY = {'routes', 'deploymentconfigs'}
CLUSTER_KEYS = ['nodes', 'namespaces', 'persistentvolumes', 'storageclasses']


def generic_resource(d):
    """Ressource issue de la découverte (CRD, etc.) -> entrée de catalogue générique."""
    return R(f"{d['group']}/{d['name']}", d['kind'], d['group'], d['version'], d['name'], d['kind'],
             namespaced=d['namespaced'])


def row_for(res, obj):
    """(colonnes, niveau) pour une ligne de liste — Nom et Âge ajoutés par la vue."""
    if res.get('cols'):
        try:
            cols, lvl = res['cols'](obj)
            return [str(c) for c in cols], lvl
        except Exception:
            pass
    return [], 'ok'


# ================================================================== Helm
def helm_releases(secrets: list) -> list:
    """Décode les releases Helm 3 (secrets type helm.sh/release.v1). Une entrée par release (dernière révision)."""
    revs = []
    for s in secrets:
        if s.get('type') != 'helm.sh/release.v1':
            continue
        raw = (s.get('data') or {}).get('release')
        if not raw:
            continue
        try:
            rel = helm_decode(raw)
        except Exception:
            continue
        revs.append(rel)
    by_name = {}
    for r in revs:
        by_name.setdefault(r.get('name'), []).append(r)
    out = []
    for name, lst in by_name.items():
        lst.sort(key=lambda r: r.get('version', 0))
        latest = lst[-1]
        latest['_history'] = lst
        out.append(latest)
    return sorted(out, key=lambda r: r.get('name', ''))


def helm_decode(secret_b64: str) -> dict:
    data = base64.b64decode(base64.b64decode(secret_b64))
    if data[:3] == b'\x1f\x8b\x08':
        data = gzip.decompress(data)
    return json.loads(data)


def helm_encode(release: dict) -> str:
    """Inverse de helm_decode (utilisé par le mode démo)."""
    inner = base64.b64encode(gzip.compress(json.dumps(release).encode()))
    return base64.b64encode(inner).decode()


def deep_merge(a, b):
    out = dict(a or {})
    for k, v in (b or {}).items():
        out[k] = deep_merge(out.get(k), v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


# ================================================================== YAML
_PLAIN = re.compile(r'^[A-Za-z0-9_./@:+-][A-Za-z0-9_ ./@:+=,()-]*$')
_RESERVED = {'true', 'false', 'yes', 'no', 'on', 'off', 'null', '~', 'y', 'n', ''}


def _scalar(v):
    if v is None:
        return 'null'
    if isinstance(v, bool):
        return 'true' if v else 'false'
    if isinstance(v, (int, float)):
        return str(v)
    s = str(v)
    if (_PLAIN.match(s) and s.lower() not in _RESERVED and not re.match(r'^[0-9.+-]+$', s)
            and not s.endswith(':') and ': ' not in s and ' #' not in s):
        return s
    return json.dumps(s, ensure_ascii=False)


def to_yaml(obj, indent=0) -> str:
    pad = '  ' * indent
    lines = []
    if isinstance(obj, dict):
        if not obj:
            return pad + '{}'
        for k, v in obj.items():
            key = _scalar(k)
            if isinstance(v, (dict, list)) and v:
                lines.append(f'{pad}{key}:')
                lines.append(to_yaml(v, indent + (1 if isinstance(v, dict) else 0)))
            elif isinstance(v, str) and '\n' in v:
                lines.append(f'{pad}{key}: |' + ('-' if not v.endswith('\n') else ''))
                lines.extend(f'{pad}  {ln}' for ln in v.rstrip('\n').split('\n'))
            else:
                lines.append(f'{pad}{key}: {_scalar(v) if not isinstance(v, (dict, list)) else ("{}" if isinstance(v, dict) else "[]")}')
    elif isinstance(obj, list):
        if not obj:
            return pad + '[]'
        for v in obj:
            if isinstance(v, dict) and v:
                sub = to_yaml(v, indent + 1).split('\n')
                lines.append(f'{pad}- {sub[0].lstrip()}')
                lines.extend(sub[1:])
            elif isinstance(v, list) and v:
                lines.append(f'{pad}-')
                lines.append(to_yaml(v, indent + 1))
            elif isinstance(v, str) and '\n' in v:
                lines.append(f'{pad}- |')
                lines.extend(f'{pad}  {ln}' for ln in v.rstrip('\n').split('\n'))
            else:
                lines.append(f'{pad}- {_scalar(v) if not isinstance(v, (dict, list)) else "{}"}')
    else:
        lines.append(pad + _scalar(obj))
    return '\n'.join(lines)


def clean_for_display(obj, keep_managed=False):
    o = json.loads(json.dumps(obj))
    md = o.get('metadata', {})
    if not keep_managed:
        md.pop('managedFields', None)
    ann = md.get('annotations') or {}
    ann.pop('kubectl.kubernetes.io/last-applied-configuration', None)
    if md.get('annotations') == {}:
        md.pop('annotations')
    return o


# ============================================================= topologie
def _selects(selector: dict, labels: dict) -> bool:
    return bool(selector) and all((labels or {}).get(k) == v for k, v in selector.items())


def build_topology(objs: dict) -> list:
    """objs : {'pods': [...], 'deployments': [...], ...}. Retourne une forêt de nœuds
    {'kind','name','obj','level','children':[...]} pour l'affichage en arbre."""
    def node(kind, o, children=None, note=''):
        st = ''
        lvl = 'ok'
        if kind == 'Pod':
            st, lvl = pod_status(o)
        return {'kind': kind, 'name': _m(o).get('name', ''), 'obj': o, 'status': st, 'level': lvl,
                'note': note, 'children': children or []}

    pods = objs.get('pods', [])
    rs_by_name = {_m(r)['name']: r for r in objs.get('replicasets', [])}
    used_pods = set()

    def pod_children(p):
        out = []
        spec = p.get('spec', {})
        for v in spec.get('volumes', []) or []:
            if v.get('configMap'):
                out.append({'kind': 'ConfigMap', 'name': v['configMap'].get('name', ''), 'obj': None, 'status': '',
                            'level': 'ok', 'note': 'volume', 'children': []})
            elif v.get('secret'):
                out.append({'kind': 'Secret', 'name': v['secret'].get('secretName', ''), 'obj': None, 'status': '',
                            'level': 'ok', 'note': 'volume', 'children': []})
            elif v.get('persistentVolumeClaim'):
                out.append({'kind': 'PersistentVolumeClaim', 'name': v['persistentVolumeClaim'].get('claimName', ''),
                            'obj': None, 'status': '', 'level': 'ok', 'note': 'volume', 'children': []})
        for c in spec.get('containers', []) or []:
            for ef in c.get('envFrom', []) or []:
                ref = ef.get('configMapRef') or ef.get('secretRef')
                if ref:
                    out.append({'kind': 'ConfigMap' if ef.get('configMapRef') else 'Secret', 'name': ref.get('name', ''),
                                'obj': None, 'status': '', 'level': 'ok', 'note': 'envFrom', 'children': []})
        uniq = {}
        for o in out:
            uniq.setdefault((o['kind'], o['name']), o)
        return list(uniq.values())

    def pods_of(owner_kind, owner_name):
        res = []
        for p in pods:
            for ref in _m(p).get('ownerReferences', []) or []:
                if ref.get('kind') == owner_kind and ref.get('name') == owner_name:
                    used_pods.add(_m(p)['name'])
                    res.append(node('Pod', p, pod_children(p)))
        return res

    workloads = []
    for d in objs.get('deployments', []):
        dn = _m(d)['name']
        children = []
        for rs in rs_by_name.values():
            if any(r.get('kind') == 'Deployment' and r.get('name') == dn for r in _m(rs).get('ownerReferences', []) or []):
                pp = pods_of('ReplicaSet', _m(rs)['name'])
                if pp or rs.get('spec', {}).get('replicas'):
                    children.append(node('ReplicaSet', rs, pp))
        workloads.append(node('Deployment', d, children))
    for kind, key in (('StatefulSet', 'statefulsets'), ('DaemonSet', 'daemonsets'), ('Job', 'jobs'),
                      ('DeploymentConfig', 'deploymentconfigs')):
        for w in objs.get(key, []):
            if kind == 'DeploymentConfig':
                rcs = []
                for p in pods:
                    if _m(p).get('labels', {}).get('deploymentconfig') == _m(w)['name']:
                        used_pods.add(_m(p)['name'])
                        rcs.append(node('Pod', p, pod_children(p)))
                workloads.append(node(kind, w, rcs))
            else:
                workloads.append(node(kind, w, pods_of(kind, _m(w)['name'])))
    orphans = [node('Pod', p, pod_children(p)) for p in pods if _m(p)['name'] not in used_pods]

    exposure = []
    svcs = objs.get('services', [])
    svc_nodes = {}
    for s in svcs:
        sel = s.get('spec', {}).get('selector') or {}
        targets = [node('Pod', p) for p in pods if _selects(sel, _m(p).get('labels'))]
        svc_nodes[_m(s)['name']] = node('Service', s, targets, note=s.get('spec', {}).get('type', ''))
    linked = set()
    for r in objs.get('routes', []):
        to = (r.get('spec', {}).get('to') or {}).get('name')
        ch = [svc_nodes[to]] if to in svc_nodes else []
        linked.add(to)
        exposure.append(node('Route', r, ch, note=r.get('spec', {}).get('host', '')))
    for ing in objs.get('ingresses', []):
        ch = []
        for rule in ing.get('spec', {}).get('rules', []) or []:
            for p in (rule.get('http') or {}).get('paths', []) or []:
                name = ((p.get('backend') or {}).get('service') or {}).get('name') or (p.get('backend') or {}).get('serviceName')
                if name in svc_nodes and svc_nodes[name] not in ch:
                    ch.append(svc_nodes[name])
                    linked.add(name)
        hosts = ', '.join(r.get('host', '*') for r in ing.get('spec', {}).get('rules', []) or [])
        exposure.append(node('Ingress', ing, ch, note=hosts))
    for name, sn in svc_nodes.items():
        if name not in linked:
            exposure.append(sn)

    forest = []
    if exposure:
        forest.append({'kind': 'Groupe', 'name': 'Exposition (Routes / Ingress → Services → Pods)', 'obj': None,
                       'status': '', 'level': 'ok', 'note': '', 'children': exposure})
    if workloads:
        forest.append({'kind': 'Groupe', 'name': 'Charges de travail (→ ReplicaSets → Pods → configuration)',
                       'obj': None, 'status': '', 'level': 'ok', 'note': '', 'children': workloads})
    if orphans:
        forest.append({'kind': 'Groupe', 'name': 'Pods sans propriétaire', 'obj': None, 'status': '', 'level': 'ok',
                       'note': '', 'children': orphans})
    return forest


# ======================================================================================
# Mode démonstration (aucune connexion : clusters, pods, logs et shell simulés)
# ======================================================================================

_NOW = _dt.datetime.now(_dt.timezone.utc)


def _ts(minutes_ago):
    return (_NOW - _dt.timedelta(minutes=minutes_ago)).strftime('%Y-%m-%dT%H:%M:%SZ')


def _h(s, n=5):
    return hashlib.md5(s.encode()).hexdigest()[:n]


DEMO_CLUSTERS = [
    {'id': 'c0demo1prod', 'name': 'ocp-prod-paris', 'type': 'openshift', 'region': 'eu-de', 'state': 'normal',
     'version': '4.14.21_openshift', 'provider': 'vpc-gen2', 'resourceGroup': 'production', 'workers': 6,
     'public': 'https://c111-e.eu-de.containers.cloud.ibm.com:31443', 'private': '', 'ingress': 'ocp-prod.demo'},
    {'id': 'c0demo2dev', 'name': 'iks-dev-francfort', 'type': 'kubernetes', 'region': 'eu-de', 'state': 'normal',
     'version': '1.29.4_1532', 'provider': 'vpc-gen2', 'resourceGroup': 'dev', 'workers': 3,
     'public': 'https://c222-e.eu-de.containers.cloud.ibm.com:30211', 'private': '', 'ingress': 'iks-dev.demo'},
    {'id': 'c0demo3rec', 'name': 'ocp-recette', 'type': 'openshift', 'region': 'eu-gb', 'state': 'warning',
     'version': '4.15.8_openshift', 'provider': 'vpc-gen2', 'resourceGroup': 'recette', 'workers': 3,
     'public': 'https://c333-e.eu-gb.containers.cloud.ibm.com:32001', 'private': '', 'ingress': 'ocp-rec.demo'},
]

APPS = {
    'boutique-front': [('front', 2, 'icr.io/boutique/front:1.8.0', 8080), ('cdn-proxy', 1, 'nginx:1.25', 80)],
    'boutique-api': [('api', 3, 'icr.io/boutique/api:3.2.1', 8080), ('panier', 2, 'icr.io/boutique/panier:2.0.4', 8080)],
    'paiement': [('paiement', 2, 'icr.io/finance/paiement:1.0.4', 8443), ('antifraude', 1, 'icr.io/finance/af:0.9.2', 9000)],
    'monitoring': [('grafana', 1, 'grafana/grafana:10.2.3', 3000), ('prometheus-operator', 1, 'quay.io/prometheus-operator:v0.71', 8080),
                   ('alertmanager', 1, 'quay.io/prometheus/alertmanager:v0.26', 9093)],
    'batch-nuit': [('ordonnanceur', 1, 'icr.io/batch/ordo:5.1', 8080)],
}
SYSTEM_NS = {
    'openshift': ['default', 'kube-system', 'kube-public', 'ibm-system', 'openshift-console', 'openshift-ingress',
                  'openshift-monitoring', 'openshift-operators', 'openshift-dns', 'openshift-image-registry'],
    'kubernetes': ['default', 'kube-system', 'kube-public', 'ibm-system', 'ibm-operators', 'calico-system',
                   'tigera-operator'],
}
EXTRA_CRDS = [
    {'group': 'monitoring.coreos.com', 'version': 'v1', 'name': 'servicemonitors', 'kind': 'ServiceMonitor',
     'namespaced': True, 'verbs': ['get', 'list'], 'short': ['smon']},
    {'group': 'monitoring.coreos.com', 'version': 'v1', 'name': 'prometheusrules', 'kind': 'PrometheusRule',
     'namespaced': True, 'verbs': ['get', 'list'], 'short': []},
    {'group': 'cert-manager.io', 'version': 'v1', 'name': 'certificates', 'kind': 'Certificate',
     'namespaced': True, 'verbs': ['get', 'list'], 'short': ['cert']},
]


class DemoAccount:
    demo = True

    def __init__(self):
        self.name = 'Compte de démonstration'
        self._kubes = {}

    def list_clusters(self):
        time.sleep(0.3)
        return [dict(c) for c in DEMO_CLUSTERS]

    def connect(self, cluster, private=False):
        if cluster['id'] not in self._kubes:
            self._kubes[cluster['id']] = DemoKube(cluster)
        return self._kubes[cluster['id']]


class DemoKube:
    demo = True

    def __init__(self, cluster):
        self.cluster = cluster
        self.flavor = cluster['type']
        self.server = cluster['public']
        self.rng = random.Random(cluster['id'])
        self.store = {}          # (plural, ns) -> [objets]
        self._build()

    # ------------------------------------------------------------ données
    def _add(self, plural, ns, obj):
        self.store.setdefault((plural, ns), []).append(obj)

    @staticmethod
    def _meta(name, ns=None, minutes=60 * 24 * 12, labels=None, owner=None, ann=None):
        md = {'name': name, 'uid': _h(f'{ns}/{name}', 8) + '-demo', 'creationTimestamp': _ts(minutes),
              'labels': labels or {}, 'resourceVersion': str(abs(hash(name)) % 900000 + 1000)}
        if ns:
            md['namespace'] = ns
        if owner:
            md['ownerReferences'] = [{'apiVersion': 'apps/v1', 'kind': owner[0], 'name': owner[1], 'controller': True}]
        if ann:
            md['annotations'] = ann
        return md

    def _build(self):
        rng = self.rng
        ocp = self.flavor == 'openshift'
        nodes = []
        for i in range(self.cluster['workers']):
            ip = f'10.{rng.randint(100, 250)}.{rng.randint(0, 64)}.{rng.randint(2, 250)}'
            nodes.append(ip)
            ready = not (self.cluster['state'] == 'warning' and i == 2)
            self._add('nodes', None, {
                'kind': 'Node', 'apiVersion': 'v1',
                'metadata': self._meta(ip, None, 60 * 24 * 40, {
                    'node-role.kubernetes.io/worker': '', 'topology.kubernetes.io/zone': f"{self.cluster['region']}-{i % 3 + 1}",
                    'ibm-cloud.kubernetes.io/worker-pool-name': 'default', 'kubernetes.io/hostname': ip}),
                'status': {'conditions': [{'type': 'Ready', 'status': 'True' if ready else 'Unknown'}],
                           'capacity': {'cpu': '8', 'memory': '32775144Ki', 'pods': '110'},
                           'allocatable': {'cpu': '7910m', 'memory': '29500000Ki'},
                           'nodeInfo': {'kubeletVersion': 'v1.27.13+' + _h(ip, 7) if ocp else 'v1.29.4+IKS',
                                        'osImage': 'Red Hat Enterprise Linux CoreOS' if ocp else 'Ubuntu 20.04.6 LTS',
                                        'containerRuntimeVersion': 'cri-o://1.27.6'},
                           'addresses': [{'type': 'InternalIP', 'address': ip}]}})
        for sc, prov in (('ibmc-vpc-block-10iops-tier', 'vpc.block.csi.ibm.io'), ('ibmc-vpc-block-general-purpose',
                                                                                   'vpc.block.csi.ibm.io'),
                         ('ibmc-vpc-file-dp2', 'vpc.file.csi.ibm.io')):
            self._add('storageclasses', None, {'kind': 'StorageClass', 'apiVersion': 'storage.k8s.io/v1',
                                               'metadata': self._meta(sc, None, 60 * 24 * 40, ann={
                                                   'storageclass.kubernetes.io/is-default-class':
                                                       'true' if 'general' in sc else 'false'}),
                                               'provisioner': prov, 'reclaimPolicy': 'Delete',
                                               'volumeBindingMode': 'WaitForFirstConsumer'})
        all_ns = SYSTEM_NS[self.flavor] + list(APPS)
        for ns in all_ns:
            self._add('namespaces', None, {'kind': 'Namespace', 'apiVersion': 'v1',
                                           'metadata': self._meta(ns, None, 60 * 24 * 30,
                                                                  {'kubernetes.io/metadata.name': ns}),
                                           'status': {'phase': 'Active'}})
            self._add('serviceaccounts', ns, {'kind': 'ServiceAccount', 'apiVersion': 'v1',
                                              'metadata': self._meta('default', ns), 'secrets': []})
            self._add('configmaps', ns, {'kind': 'ConfigMap', 'apiVersion': 'v1',
                                         'metadata': self._meta('kube-root-ca.crt', ns),
                                         'data': {'ca.crt': '-----BEGIN CERTIFICATE-----\nMIIDemo…\n-----END CERTIFICATE-----\n'}})
        for ns, deps in APPS.items():
            self._build_app_ns(ns, deps, nodes, ocp)
        for ns in SYSTEM_NS[self.flavor][1:4]:
            self._build_app_ns(ns, [(f'{ns.split("-")[0]}-agent', 1, 'icr.io/ibm/agent:1.4', 8080)], nodes, ocp,
                               system=True)

    def _build_app_ns(self, ns, deps, nodes, ocp, system=False):
        rng = self.rng
        for name, replicas, image, port in deps:
            labels = {'app': name, 'app.kubernetes.io/name': name, 'app.kubernetes.io/part-of': ns}
            rs_hash = _h(ns + name, 9)
            ready = replicas
            pods_status = []
            for i in range(replicas):
                st = 'Running'
                if ns == 'paiement' and name == 'antifraude':
                    st = 'CrashLoopBackOff'
                if ns == 'batch-nuit' and i == 0 and self.cluster['state'] == 'warning':
                    st = 'Pending'
                pods_status.append(st)
            ready = sum(1 for s in pods_status if s == 'Running')
            tpl = {'metadata': {'labels': labels},
                   'spec': {'containers': [{'name': name, 'image': image, 'ports': [{'containerPort': port}],
                                            'resources': {'requests': {'cpu': f'{rng.choice([50, 100, 250, 500])}m',
                                                                       'memory': f'{rng.choice([128, 256, 512, 1024])}Mi'},
                                                          'limits': {'cpu': '1', 'memory': '1Gi'}},
                                            'envFrom': [{'configMapRef': {'name': f'{name}-config'}}]},
                                           ] + ([{'name': 'log-shipper', 'image': 'fluent/fluent-bit:2.2', 'resources': {}}]
                                                if name in ('api', 'paiement') else []),
                            'volumes': [{'name': 'config', 'configMap': {'name': f'{name}-config'}}] +
                                       ([{'name': 'tls', 'secret': {'secretName': f'{name}-tls'}}] if port == 8443 else [])}}
            self._add('deployments', ns, {
                'kind': 'Deployment', 'apiVersion': 'apps/v1',
                'metadata': self._meta(name, ns, 60 * 24 * rng.randint(3, 60), labels,
                                       ann={'deployment.kubernetes.io/revision': str(rng.randint(1, 9))}),
                'spec': {'replicas': replicas, 'selector': {'matchLabels': {'app': name}}, 'template': tpl,
                         'strategy': {'type': 'RollingUpdate'}},
                'status': {'replicas': replicas, 'readyReplicas': ready, 'updatedReplicas': replicas,
                           'availableReplicas': ready}})
            rs_name = f'{name}-{rs_hash}'
            self._add('replicasets', ns, {
                'kind': 'ReplicaSet', 'apiVersion': 'apps/v1',
                'metadata': self._meta(rs_name, ns, 60 * 24 * 2, labels, owner=('Deployment', name)),
                'spec': {'replicas': replicas, 'selector': {'matchLabels': {'app': name}}, 'template': tpl},
                'status': {'replicas': replicas, 'readyReplicas': ready}})
            for i, st in enumerate(pods_status):
                pod = f'{rs_name}-{_h(rs_name + str(i))}'
                self._add('pods', ns, self._pod(pod, ns, labels, ('ReplicaSet', rs_name), tpl['spec'], st,
                                                rng.choice(nodes)))
            svc_labels = {'app': name}
            self._add('services', ns, {
                'kind': 'Service', 'apiVersion': 'v1', 'metadata': self._meta(name, ns, labels=labels),
                'spec': {'type': 'ClusterIP', 'clusterIP': f'172.21.{rng.randint(0, 255)}.{rng.randint(1, 254)}',
                         'selector': svc_labels, 'ports': [{'name': 'http', 'port': 80 if port != 8443 else 443,
                                                            'targetPort': port, 'protocol': 'TCP'}]}})
            self._add('configmaps', ns, {'kind': 'ConfigMap', 'apiVersion': 'v1',
                                         'metadata': self._meta(f'{name}-config', ns, labels=labels),
                                         'data': {'LOG_LEVEL': 'INFO', 'TZ': 'Europe/Paris',
                                                  'application.yaml': f'server:\n  port: {port}\nfeatures:\n  cache: true\n'}})
            if port == 8443:
                self._add('secrets', ns, {'kind': 'Secret', 'apiVersion': 'v1', 'type': 'kubernetes.io/tls',
                                          'metadata': self._meta(f'{name}-tls', ns),
                                          'data': {'tls.crt': 'TFMwdExTMUNSVWRKVGk=', 'tls.key': 'KioqKg=='}})
            if not system and name in ('front', 'grafana', 'api'):
                host = f"{name}-{ns}.{self.cluster['ingress']}.eu-de.containers.appdomain.cloud"
                if ocp:
                    self._add('routes', ns, {'kind': 'Route', 'apiVersion': 'route.openshift.io/v1',
                                             'metadata': self._meta(name, ns, labels=labels),
                                             'spec': {'host': host, 'path': '/', 'to': {'kind': 'Service', 'name': name},
                                                      'tls': {'termination': 'edge'}}})
                else:
                    self._add('ingresses', ns, {'kind': 'Ingress', 'apiVersion': 'networking.k8s.io/v1',
                                                'metadata': self._meta(name, ns, labels=labels),
                                                'spec': {'ingressClassName': 'public-iks-k8s-nginx', 'rules': [
                                                    {'host': host, 'http': {'paths': [{'path': '/', 'pathType': 'Prefix',
                                                                                       'backend': {'service': {'name': name, 'port': {'number': 80}}}}]}}]},
                                                'status': {'loadBalancer': {'ingress': [{'hostname': 'a1b2c3-eu-de.lb.appdomain.cloud'}]}}})
            if name == 'front':
                self._add('horizontalpodautoscalers', ns, {
                    'kind': 'HorizontalPodAutoscaler', 'apiVersion': 'autoscaling/v2',
                    'metadata': self._meta(name, ns),
                    'spec': {'scaleTargetRef': {'kind': 'Deployment', 'name': name}, 'minReplicas': 2, 'maxReplicas': 8},
                    'status': {'currentReplicas': replicas, 'desiredReplicas': replicas}})
        if system:
            return
        self._add('secrets', ns, {'kind': 'Secret', 'apiVersion': 'v1', 'type': 'Opaque',
                                  'metadata': self._meta(f'{ns}-db-credentials', ns),
                                  'data': {'username': base64.b64encode(b'app').decode(),
                                           'password': base64.b64encode(b'demo-password').decode()}})
        self._add('roles', ns, {'kind': 'Role', 'apiVersion': 'rbac.authorization.k8s.io/v1',
                                'metadata': self._meta('lecture-seule', ns),
                                'rules': [{'apiGroups': [''], 'resources': ['pods', 'pods/log'], 'verbs': ['get', 'list']}]})
        self._add('rolebindings', ns, {'kind': 'RoleBinding', 'apiVersion': 'rbac.authorization.k8s.io/v1',
                                       'metadata': self._meta('equipe-dev-lecture', ns),
                                       'roleRef': {'kind': 'Role', 'name': 'lecture-seule'},
                                       'subjects': [{'kind': 'Group', 'name': f'IAM#equipe-{ns}@demo.fr'}]})
        self._add('networkpolicies', ns, {'kind': 'NetworkPolicy', 'apiVersion': 'networking.k8s.io/v1',
                                          'metadata': self._meta('deny-other-namespaces', ns),
                                          'spec': {'podSelector': {}, 'policyTypes': ['Ingress']}})
        if ns == 'boutique-api':
            labels = {'app': 'redis'}
            for i in range(2):
                self._add('pods', ns, self._pod(f'redis-{i}', ns, labels, ('StatefulSet', 'redis'),
                                                {'containers': [{'name': 'redis', 'image': 'redis:7.2'}],
                                                 'volumes': [{'name': 'data', 'persistentVolumeClaim': {'claimName': f'data-redis-{i}'}}]},
                                                'Running', self.rng.choice(nodes)))
                self._add('persistentvolumeclaims', ns, {
                    'kind': 'PersistentVolumeClaim', 'apiVersion': 'v1', 'metadata': self._meta(f'data-redis-{i}', ns),
                    'spec': {'accessModes': ['ReadWriteOnce'], 'storageClassName': 'ibmc-vpc-block-10iops-tier',
                             'volumeName': f'pvc-{_h(ns + str(i), 12)}', 'resources': {'requests': {'storage': '10Gi'}}},
                    'status': {'phase': 'Bound', 'capacity': {'storage': '10Gi'}}})
                self._add('persistentvolumes', None, {
                    'kind': 'PersistentVolume', 'apiVersion': 'v1', 'metadata': self._meta(f'pvc-{_h(ns + str(i), 12)}'),
                    'spec': {'capacity': {'storage': '10Gi'}, 'storageClassName': 'ibmc-vpc-block-10iops-tier',
                             'claimRef': {'namespace': ns, 'name': f'data-redis-{i}'}}, 'status': {'phase': 'Bound'}})
            self._add('statefulsets', ns, {'kind': 'StatefulSet', 'apiVersion': 'apps/v1',
                                           'metadata': self._meta('redis', ns, labels=labels),
                                           'spec': {'replicas': 2, 'serviceName': 'redis', 'selector': {'matchLabels': labels}},
                                           'status': {'replicas': 2, 'readyReplicas': 2}})
            self._add('services', ns, {'kind': 'Service', 'apiVersion': 'v1', 'metadata': self._meta('redis', ns),
                                       'spec': {'type': 'ClusterIP', 'clusterIP': 'None', 'selector': labels,
                                                'ports': [{'port': 6379, 'protocol': 'TCP'}]}})
        if ns == 'batch-nuit':
            self._add('cronjobs', ns, {'kind': 'CronJob', 'apiVersion': 'batch/v1',
                                       'metadata': self._meta('export-comptable', ns),
                                       'spec': {'schedule': '0 2 * * *', 'suspend': False},
                                       'status': {'lastScheduleTime': _ts(60 * 7)}})
            for d in range(3):
                jn = f'export-comptable-{2890 + d}'
                failed = d == 1
                self._add('jobs', ns, {'kind': 'Job', 'apiVersion': 'batch/v1',
                                       'metadata': self._meta(jn, ns, 60 * (7 + 24 * d), owner=('CronJob', 'export-comptable')),
                                       'spec': {'completions': 1},
                                       'status': {'succeeded': 0 if failed else 1, 'failed': 1 if failed else 0,
                                                  'startTime': _ts(60 * (7 + 24 * d)),
                                                  'completionTime': _ts(60 * (7 + 24 * d) - 4)}})
                self._add('pods', ns, self._pod(f'{jn}-{_h(jn)}', ns, {'job-name': jn}, ('Job', jn),
                                                {'containers': [{'name': 'export', 'image': 'icr.io/batch/export:2.3'}]},
                                                'Error' if failed else 'Completed', self.rng.choice(nodes)))
        self._build_helm(ns)
        self._build_events(ns)
        self.store.setdefault(('servicemonitors', ns), [])
        if ns == 'monitoring':
            for n in ('front', 'api', 'paiement'):
                self._add('servicemonitors', ns, {'kind': 'ServiceMonitor', 'apiVersion': 'monitoring.coreos.com/v1',
                                                  'metadata': self._meta(n, ns), 'spec': {'endpoints': [{'port': 'http'}]}})
        if ns in ('boutique-front', 'paiement'):
            self._add('certificates', ns, {'kind': 'Certificate', 'apiVersion': 'cert-manager.io/v1',
                                           'metadata': self._meta(f'{ns}-cert', ns),
                                           'spec': {'dnsNames': [f'{ns}.demo.fr'], 'issuerRef': {'name': 'letsencrypt'}}})

    def _pod(self, name, ns, labels, owner, spec, state, node):
        rng = self.rng
        minutes = rng.randint(30, 60 * 24 * 9)
        css = []
        for c in spec.get('containers', []):
            cs = {'name': c['name'], 'image': c.get('image', ''), 'restartCount': 0, 'ready': True,
                  'state': {'running': {'startedAt': _ts(minutes)}}}
            if state == 'CrashLoopBackOff' and c is spec['containers'][0]:
                cs.update(ready=False, restartCount=rng.randint(12, 48),
                          state={'waiting': {'reason': 'CrashLoopBackOff',
                                             'message': 'back-off 5m0s restarting failed container'}},
                          lastState={'terminated': {'reason': 'Error', 'exitCode': 1}})
            elif state in ('Completed', 'Error'):
                cs.update(ready=False, state={'terminated': {'reason': state, 'exitCode': 0 if state == 'Completed' else 2}})
            elif state == 'Pending':
                cs = None
            else:
                cs['restartCount'] = rng.choice([0, 0, 0, 1, 2])
            if cs:
                css.append(cs)
        phase = {'Completed': 'Succeeded', 'Error': 'Failed', 'Pending': 'Pending'}.get(state, 'Running')
        status = {'phase': phase, 'podIP': f'172.30.{rng.randint(0, 255)}.{rng.randint(2, 254)}',
                  'hostIP': node, 'startTime': _ts(minutes), 'containerStatuses': css,
                  'conditions': [{'type': 'Ready', 'status': 'True' if state == 'Running' else 'False'}]}
        if state == 'Pending':
            status['conditions'] = [{'type': 'PodScheduled', 'status': 'False', 'reason': 'Unschedulable',
                                     'message': '0/3 nodes are available: 3 Insufficient memory.'}]
            node = ''
        return {'kind': 'Pod', 'apiVersion': 'v1',
                'metadata': self._meta(name, ns, minutes, labels, owner=owner),
                'spec': dict(spec, nodeName=node, serviceAccountName='default', restartPolicy='Always'),
                'status': status}

    def _build_helm(self, ns):
        charts = {
            'boutique-front': [('front', 'boutique-front', ['2.2.0', '2.3.0', '2.3.1'], '1.8.0', 'deployed')],
            'monitoring': [('prometheus', 'kube-prometheus-stack', ['55.5.0', '56.6.2'], 'v0.71.2', 'deployed'),
                           ('grafana', 'grafana', ['7.3.0'], '10.2.3', 'deployed')],
            'paiement': [('paiement', 'paiement', ['1.0.3', '1.0.4'], '1.0.4', 'failed')],
            'boutique-api': [('api', 'boutique-api', ['3.1.0', '3.2.1'], '3.2.1', 'deployed')],
        }.get(ns, [])
        for rel, chart, versions, app_ver, final in charts:
            for rev, ver in enumerate(versions, 1):
                last = rev == len(versions)
                status = final if last else 'superseded'
                defaults = {'replicaCount': 1, 'image': {'repository': f'icr.io/{ns}/{chart}', 'tag': app_ver,
                                                         'pullPolicy': 'IfNotPresent'},
                            'service': {'type': 'ClusterIP', 'port': 80},
                            'resources': {'requests': {'cpu': '100m', 'memory': '128Mi'}},
                            'ingress': {'enabled': False}, 'nodeSelector': {}, 'tolerations': []}
                config = {'replicaCount': 2 + rev % 2, 'image': {'tag': app_ver},
                          'env': {'SPRING_PROFILES_ACTIVE': ns, 'FEATURE_NEW_CHECKOUT': 'true' if rev > 1 else 'false'},
                          'resources': {'limits': {'cpu': '1', 'memory': '1Gi'}}}
                release = {
                    'name': rel, 'namespace': ns, 'version': rev,
                    'info': {'first_deployed': _ts(60 * 24 * 30), 'last_deployed': _ts(60 * 24 * (len(versions) - rev) + 90),
                             'deleted': '', 'description': 'Upgrade complete' if status != 'failed' else
                             'Upgrade "paiement" failed: timed out waiting for the condition', 'status': status,
                             'notes': f'{chart} installé. Accès : kubectl -n {ns} port-forward svc/{rel} 8080:80'},
                    'chart': {'metadata': {'name': chart, 'version': ver, 'appVersion': app_ver, 'apiVersion': 'v2',
                                           'description': f'Chart Helm pour {chart}', 'type': 'application'},
                              'values': defaults},
                    'config': config,
                    'manifest': f'---\n# Source: {chart}/templates/deployment.yaml\napiVersion: apps/v1\nkind: Deployment\n'
                                f'metadata:\n  name: {rel}\n  labels:\n    helm.sh/chart: {chart}-{ver}\nspec:\n'
                                f'  replicas: {config["replicaCount"]}\n---\n# Source: {chart}/templates/service.yaml\n'
                                f'apiVersion: v1\nkind: Service\nmetadata:\n  name: {rel}\nspec:\n  ports:\n  - port: 80\n',
                }
                self._add('secrets', ns, {'kind': 'Secret', 'apiVersion': 'v1', 'type': 'helm.sh/release.v1',
                                          'metadata': self._meta(f'sh.helm.release.v1.{rel}.v{rev}', ns,
                                                                 labels={'owner': 'helm', 'name': rel, 'status': status,
                                                                         'version': str(rev)}),
                                          'data': {'release': helm_encode(release)}})

    def _build_events(self, ns):
        for p in self.store.get(('pods', ns), []):
            name = p['metadata']['name']
            st = (p['status'].get('containerStatuses') or [{}])
            waiting = st[0].get('state', {}).get('waiting', {}) if st else {}
            evs = [('Normal', 'Scheduled', f'Successfully assigned {ns}/{name}', 1),
                   ('Normal', 'Pulled', 'Container image already present on machine', 1)]
            if waiting.get('reason') == 'CrashLoopBackOff':
                evs.append(('Warning', 'BackOff', 'Back-off restarting failed container', 214))
            if p['status']['phase'] == 'Pending':
                evs = [('Warning', 'FailedScheduling', '0/3 nodes are available: 3 Insufficient memory.', 37)]
            for i, (t, reason, msg, count) in enumerate(evs):
                self._add('events', ns, {'kind': 'Event', 'apiVersion': 'v1',
                                         'metadata': self._meta(f'{name}.{_h(reason + name, 12)}', ns, 5 + i * 3),
                                         'type': t, 'reason': reason, 'message': msg, 'count': count,
                                         'involvedObject': {'kind': 'Pod', 'name': name, 'namespace': ns},
                                         'lastTimestamp': _ts(2 + i)})

    # --------------------------------------------------------- interface
    def _lat(self):
        time.sleep(self.rng.uniform(0.05, 0.25))

    def discovery(self):
        out = [{'group': r['group'], 'version': r['version'], 'name': r['name'], 'kind': r['kind'],
                'namespaced': r['namespaced'], 'verbs': ['get', 'list', 'delete'], 'short': []}
               for r in CATALOG if not (self.flavor != 'openshift' and r['group'].endswith('openshift.io'))]
        return out + EXTRA_CRDS

    def has(self, group, plural):
        return any(r['group'] == group and r['name'] == plural for r in self.discovery())

    def list(self, res, ns=None, selector=None):
        self._lat()
        if res['group'].endswith('openshift.io') and self.flavor != 'openshift':
            raise KubeError('HTTP 404 : the server could not find the requested resource', 404)
        if res['namespaced'] and ns is None:
            items = [o for (pl, n), lst in self.store.items() if pl == res['name'] for o in lst]
        else:
            items = list(self.store.get((res['name'], ns if res['namespaced'] else None), []))
        if selector:
            k, _, v = selector.partition('=')
            items = [o for o in items if o['metadata'].get('labels', {}).get(k) == v]
        return [dict(o) for o in items]

    def get(self, res, ns, name):
        for o in self.list(res, ns):
            if o['metadata']['name'] == name:
                return o
        raise KubeError(f'HTTP 404 : {res["name"]} "{name}" not found', 404)

    def version(self):
        return 'v' + self.cluster['version'].split('_')[0]

    def pod_metrics(self, ns):
        out = {}
        for p in self.store.get(('pods', ns), []):
            if p['status']['phase'] != 'Running':
                continue
            seed = int(_h(p['metadata']['name'], 6), 16)
            base_cpu = 20 + seed % 380
            base_mem = (90 + seed % 800) * 2 ** 20
            out[p['metadata']['name']] = (base_cpu * random.uniform(0.85, 1.15), base_mem * random.uniform(0.95, 1.05))
        return out

    # -------------------------------------------------------------- logs
    def log_lines(self, pod, n, start=None):
        rng = random.Random(pod + str(start or ''))
        t = time.time() - n * 7 if start is None else start
        out = []
        crash = 'antifraude' in pod
        for i in range(n):
            ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(t + i * 7))
            if crash and i > n - 12:
                lines = ['ERROR o.s.boot.SpringApplication - Application run failed',
                         'java.lang.IllegalStateException: Impossible de joindre le service de scoring (timeout 5000 ms)',
                         '\tat fr.demo.antifraude.ScoringClient.connect(ScoringClient.java:87)',
                         '\tat fr.demo.antifraude.Application.main(Application.java:21)']
                out.append(f'{ts} {lines[i % len(lines)]}')
                continue
            lvl = rng.choices(['INFO', 'INFO', 'INFO', 'DEBUG', 'WARN', 'ERROR'], [50, 20, 10, 10, 6, 2])[0]
            msg = rng.choice([
                'GET /api/v1/produits 200 12ms', 'POST /api/v1/panier 201 48ms', 'GET /health 200 2ms',
                'Connexion pool HikariCP active=4 idle=6', 'Cache hit ratio 0.93', 'Commande #%d validée' % rng.randint(10000, 99999),
                'Requête lente détectée : SELECT * FROM commandes (812 ms)', 'Token JWT expiré pour utilisateur u%d' % rng.randint(1, 999),
                'Planification du job export-comptable', 'Message consommé depuis la file paiements (offset %d)' % rng.randint(1000, 99999)])
            if lvl == 'ERROR':
                msg = 'Échec appel service stock : HTTP 503 (tentative 2/3)'
            out.append(f'{ts} {lvl:5} [{pod.split("-")[0]}] {msg}')
        return out

    def logs(self, ns, pod, container=None, tail=500, timestamps=False, previous=False):
        self._lat()
        n = min(tail or 1000, 1000)
        return '\n'.join(self.log_lines(pod, n)) + '\n'

    def logs_follow(self, ns, pod, container, tail, timestamps, stop: threading.Event, on_line):
        for ln in self.log_lines(pod, min(tail or 200, 1000)):
            on_line(ln + '\n')
        k = 0
        while not stop.wait(random.uniform(0.4, 1.6)):
            k += 1
            on_line(self.log_lines(pod + str(k), 1, time.time())[0] + '\n')

    user = "démo"

    def whoami(self):
        return self.user

    def namespaces(self, declared=()):
        names = [n['metadata']['name'] for n in self.list(CATALOG_BY_KEY['namespaces'])]
        return sorted(set(names) | {d for d in declared if d}), 'tous'

    console = "https://console-openshift-console.demo.example"

    def find_console(self, fallback=""):
        return self.console


# ======================================================================================
# Qt (uniquement QtCore, QtGui et QtWidgets)
# ======================================================================================

from PySide6.QtCore import (QByteArray, QEvent, QObject, QPoint, QPointF, QRectF, QSize,  # noqa: E402
                            Qt, QTimer, QUrl, Signal)
from PySide6.QtGui import (QAction, QBrush, QColor, QDesktopServices, QFont, QFontDatabase,  # noqa: E402
                           QFontMetricsF, QGuiApplication, QIcon, QKeySequence, QPainter, QPainterPath, QPalette,
                           QPen, QPixmap, QPolygonF, QSyntaxHighlighter, QTextCharFormat, QTextCursor)
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QCheckBox,  # noqa: E402
                               QComboBox, QDialog, QDialogButtonBox, QFileDialog, QFormLayout, QFrame,
                               QGridLayout, QGroupBox, QHBoxLayout, QHeaderView, QInputDialog, QLabel,
                               QLineEdit, QMainWindow, QMenu, QMessageBox, QPlainTextEdit,
                               QPushButton, QScrollArea, QSplitter,
                               QStackedWidget, QTabBar, QTabWidget, QTextEdit, QToolButton, QToolTip, QTreeWidget,
                               QTreeWidgetItem, QVBoxLayout, QWidget)


# ======================================================================================
# Outils communs de l'interface
# ======================================================================================

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


class _Relay(QObject):
    done = Signal(object, object)


class ErrText(str):
    """Message d'erreur passé à l'interface ; garde le code HTTP (401 = session expirée, 403 = refusé)."""
    status = None


def err_text(exc):
    e = ErrText(str(exc))
    e.status = getattr(exc, "status", None)
    return e


_JOBS = set()


def run_async(fn, callback):
    """Exécute fn() dans un fil à part (réseau) et rappelle callback(résultat, erreur) dans l'interface."""
    relay = _Relay()
    _JOBS.add(relay)

    def finish(res, err):
        _JOBS.discard(relay)
        callback(res, err)
    relay.done.connect(finish, Qt.ConnectionType.QueuedConnection)

    def work():
        try:
            res, err = fn(), None
        except (CloudError, KubeError, NetError) as exc:
            res, err = None, err_text(exc)
        except Exception as exc:  # noqa: BLE001
            res, err = None, ErrText(f"{type(exc).__name__} : {exc}")
        relay.done.emit(res, err)
    threading.Thread(target=work, daemon=True).start()


def confirm(parent, title, text, ok="Oui"):
    box = QMessageBox(QMessageBox.Icon.Question, title, text, QMessageBox.StandardButton.Cancel, parent)
    yes = box.addButton(ok, QMessageBox.ButtonRole.AcceptRole)
    box.setDefaultButton(QMessageBox.StandardButton.Cancel)
    box.exec()
    return box.clickedButton() is yes


# ======================================================================================
# Thème clair façon Windows 11 (même palette que l'Explorateur)
# ======================================================================================

C = {
    "strip": "#E9EDF2", "chrome": "#F7F9FC", "body": "#FFFFFF", "border": "#E3E3E3", "line": "#EBEBEB",
    "text": "#1A1A1A", "text2": "#616161", "disabled": "#A3A3A3", "hover": "#EEF4FB", "select": "#CCE4F7",
    "selhover": "#BDDCF5", "navsel": "#E6ECF4", "navhover": "#F1F4F8", "accent": "#005FB8", "menu": "#F9F9F9",
    "danger": "#C42B1C", "page": "#F3F3F3", "err": "#C42B1C", "warn": "#9D5D00", "off": "#8A8A8A",
}
LEVEL_COLOR = {"err": C["err"], "warn": C["warn"], "off": C["off"]}

STYLESHEET = """
QWidget { color: @text; }
QMainWindow, QStackedWidget, QWidget#page { background: @body; }
QFrame#cmdbar { background: @chrome; border-bottom: 1px solid @border; }
QFrame#cmdbar QToolButton { padding: 5px 8px; }
QFrame#cmdsep { background: @border; }
QFrame#addrRow { background: @chrome; }
QToolButton {
    background: transparent; border: 1px solid transparent; border-radius: 4px; padding: 4px; color: @text;
}
QToolButton:hover { background: rgba(0, 0, 0, 0.055); }
QToolButton:pressed { background: rgba(0, 0, 0, 0.09); }
QToolButton:checked { background: rgba(0, 0, 0, 0.07); }
QToolButton:disabled { color: @disabled; }
QFrame#addressBar { background: @body; border: 1px solid @border; border-radius: 4px; }
QFrame#addressBar QToolButton { padding: 2px 5px; border-radius: 3px; border: none; }
QFrame#addressBar QLabel#crumbSep { color: @text2; padding: 0 1px; }
QLineEdit#searchBox {
    background: @body; border: 1px solid @border; border-bottom: 1px solid #C9C9C9;
    border-radius: 4px; padding: 0 6px; min-height: 28px;
}
QLineEdit#searchBox:focus { border-bottom: 2px solid @accent; }
QLineEdit, QComboBox, QSpinBox {
    background: @body; border: 1px solid #D4D4D4; border-bottom: 1px solid #ABABAB;
    border-radius: 4px; padding: 3px 6px; selection-background-color: @accent; selection-color: white;
}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus { border-bottom: 2px solid @accent; }
QComboBox::drop-down { border: none; width: 20px; }
QComboBox::down-arrow { image: url(@img_chevdown); width: 10px; height: 10px; }
QComboBox QAbstractItemView { background: @menu; border: 1px solid #D9D9D9; selection-background-color: @select; }
QTreeView, QTreeWidget, QListWidget {
    background: @body; border: none; outline: 0; selection-background-color: @select; selection-color: @text;
}
QTreeWidget#list::item, QTreeWidget#topo::item { height: 28px; border: none; padding-left: 2px; }
QTreeWidget#list::item:hover, QTreeWidget#topo::item:hover { background: @hover; }
QTreeWidget#list::item:selected, QTreeWidget#topo::item:selected { background: @select; color: @text; }
QTreeWidget#list::item:selected:hover, QTreeWidget#topo::item:selected:hover { background: @selhover; }
QTreeWidget#nav { background: @body; border: none; }
QWidget#navPane { background: @body; border-right: 1px solid @line; }
QLineEdit#navSearch {
    background: @chrome; border: 1px solid @border; border-radius: 4px; padding: 0 6px; min-height: 26px;
}
QLineEdit#navSearch:focus { background: @body; border-bottom: 2px solid @accent; }
QTreeWidget#nav::item { height: 28px; border-radius: 4px; padding-left: 2px; }
QTreeWidget#nav::item:hover { background: @navhover; }
QTreeWidget#nav::item:selected { background: @navsel; color: @text; }
QTreeView::branch { background: transparent; }
QTreeView::branch:has-children:closed { image: url(@img_chevright); }
QTreeView::branch:has-children:open { image: url(@img_chevdown); }
QHeaderView { background: @body; border: none; }
QHeaderView::section {
    background: @body; color: @text2; border: none; border-right: 1px solid @line; padding: 0 8px; height: 30px;
}
QHeaderView::section:hover { background: #F5F5F5; color: @text; }
QHeaderView::down-arrow { image: url(@img_chevup); subcontrol-position: top center; width: 9px; height: 7px; top: 1px; }
QHeaderView::up-arrow { image: url(@img_chevdown); subcontrol-position: top center; width: 9px; height: 7px; top: 1px; }
QSplitter::handle { background: @line; }
QSplitter::handle:horizontal { width: 1px; }
QTabWidget#main::pane { border: none; border-top: 1px solid @border; background: @body; }
QTabWidget#main > QTabBar { background: @strip; }
QTabWidget#main > QTabBar::tab {
    background: transparent; color: @text; border: none; margin-top: 4px; margin-right: 2px;
    padding: 0 6px 0 10px; height: 30px; min-width: 110px; max-width: 280px;
    border-top-left-radius: 8px; border-top-right-radius: 8px;
}
QTabWidget#main > QTabBar::tab:hover:!selected { background: rgba(255, 255, 255, 0.55); }
QTabWidget#main > QTabBar::tab:selected { background: @body; }
QTabBar::close-button { image: url(@img_close); subcontrol-position: right; border-radius: 4px; margin: 2px; }
QTabBar::close-button:hover { background: rgba(0, 0, 0, 0.07); }
QTabWidget#pivot::pane { border: none; border-top: 1px solid @border; }
QTabWidget#pivot > QTabBar::tab {
    background: transparent; border: none; padding: 6px 12px; margin-right: 4px; color: @text2;
    border-bottom: 2px solid transparent;
}
QTabWidget#pivot > QTabBar::tab:selected { color: @text; border-bottom: 2px solid @accent; }
QTabWidget#pivot > QTabBar::tab:hover { color: @text; }
QFrame#toolrow { background: @chrome; border-bottom: 1px solid @border; }
QPlainTextEdit#code { background: @body; border: none; selection-background-color: #ADD6FF; selection-color: @text; }
QPlainTextEdit#console { background: #0C0C0C; color: #CCCCCC; border: none; selection-background-color: #264F78;
    selection-color: #FFFFFF; }
QWidget#details, QScrollArea#details { background: @chrome; border: none; border-left: 1px solid @line; }
QLabel#detTitle { font-size: 17px; font-weight: 600; }
QLabel#detKind, QLabel#propKey, QLabel#hint { color: @text2; }
QLabel#h1 { font-size: 22px; font-weight: 600; }
QLabel#h2 { font-size: 17px; font-weight: 600; }
QLabel#sub { color: @text2; }
QLabel#failed { color: @danger; }
QStatusBar { background: @body; color: @text; border-top: 1px solid @line; }
QStatusBar::item { border: none; }
QStatusBar QLabel { color: @text2; padding: 0 6px; }
QLabel#badgeDemo { background: #C239B3; color: white; border-radius: 3px; padding: 1px 8px; font-weight: 600; }
QLabel#badgeRO { background: #E6ECF4; color: #34495E; border-radius: 3px; padding: 1px 8px; }
QMenu { background: @menu; border: 1px solid #D9D9D9; border-radius: 8px; padding: 4px; }
QMenu::item { padding: 6px 32px 6px 10px; border-radius: 4px; margin: 1px 0; color: @text; }
QMenu::item:selected { background: rgba(0, 0, 0, 0.055); color: @text; }
QMenu::item:disabled { color: @disabled; }
QMenu::icon { padding-left: 8px; }
QMenu::separator { height: 1px; background: #E5E5E5; margin: 4px 6px; }
QMenu::right-arrow { image: url(@img_chevright); width: 10px; height: 10px; right: 8px; }
QMenu::indicator { width: 14px; height: 14px; padding-left: 6px; }
QMenu::indicator:non-exclusive:checked { image: url(@img_check); }
QMenu::indicator:exclusive:checked { image: url(@img_dot); }
QScrollBar:vertical { background: transparent; width: 12px; margin: 2px 1px; }
QScrollBar:horizontal { background: transparent; height: 12px; margin: 1px 2px; }
QScrollBar::handle:vertical { background: #C2C2C2; min-height: 32px; border-radius: 3px; margin: 0 3px; }
QScrollBar::handle:horizontal { background: #C2C2C2; min-width: 32px; border-radius: 3px; margin: 3px 0; }
QScrollBar::handle:hover { background: #8C8C8C; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }
QToolTip { background: @menu; color: @text; border: 1px solid #D9D9D9; padding: 4px 6px; border-radius: 4px; }
QDialog, QMessageBox, QInputDialog { background: @menu; }
QGroupBox { border: 1px solid @border; border-radius: 6px; margin-top: 14px; padding: 10px 8px 8px 8px; }
QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 4px; color: @text2; }
QPushButton {
    background: @body; border: 1px solid #D4D4D4; border-bottom-color: #BDBDBD;
    border-radius: 4px; padding: 5px 16px; min-width: 64px; color: @text;
}
QPushButton:hover { background: #F6F6F6; }
QPushButton:pressed { background: #EDEDED; }
QPushButton:default { background: @accent; color: white; border: 1px solid #0054A3; }
QPushButton:default:hover { background: #1A6FC2; }
QPushButton:disabled { color: @disabled; }
QPushButton#small { padding: 2px 8px; min-width: 0; }
QCheckBox::indicator, QRadioButton::indicator { width: 15px; height: 15px; }
"""


def ui_font(px=13, bold=False):
    f = QFont(QApplication.font())
    f.setPixelSize(px)
    if bold:
        f.setWeight(QFont.Weight.DemiBold)
    return f


# ======================================================================================
# Icônes : traits (barre de commandes, menus) et couleurs (objets Kubernetes, comme l'original)
# ======================================================================================

_DRAW = {}


def _icon(name):
    def deco(fn):
        _DRAW[name] = fn
        return fn
    return deco


def _pen(p, color, width=1.2):
    pen = QPen(QColor(color), width)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    p.setPen(pen)
    p.setBrush(Qt.BrushStyle.NoBrush)


def _poly(p, *pts):
    p.drawPolyline(QPolygonF([QPointF(x, y) for x, y in pts]))


def _line(p, x1, y1, x2, y2):
    p.drawLine(QPointF(x1, y1), QPointF(x2, y2))


@_icon("back")
def _(p, c):
    _pen(p, c, 1.3); _line(p, 13, 8, 3, 8); _poly(p, (7.5, 3.5), (3, 8), (7.5, 12.5))


@_icon("forward")
def _(p, c):
    _pen(p, c, 1.3); _line(p, 3, 8, 13, 8); _poly(p, (8.5, 3.5), (13, 8), (8.5, 12.5))


@_icon("up")
def _(p, c):
    _pen(p, c, 1.3); _line(p, 8, 13.5, 8, 2.5); _poly(p, (3.5, 7), (8, 2.5), (12.5, 7))


@_icon("refresh")
def _(p, c):
    _pen(p, c, 1.3)
    p.drawArc(QRectF(2.5, 2.5, 11, 11), 50 * 16, 290 * 16)
    _poly(p, (12.6, 1.6), (12.0, 4.9), (8.8, 4.3))


@_icon("restart")
def _(p, c):
    _pen(p, c, 1.3)
    p.drawArc(QRectF(2.5, 2.5, 11, 11), 100 * 16, 250 * 16)
    _poly(p, (3.6, 1.8), (5.2, 4.8), (2.0, 5.6))
    p.setPen(Qt.PenStyle.NoPen); p.setBrush(QColor(c))
    p.drawPolygon(QPolygonF([QPointF(7.0, 5.6), QPointF(10.6, 8.0), QPointF(7.0, 10.4)]))


@_icon("search")
def _(p, c):
    _pen(p, c, 1.3); p.drawEllipse(QRectF(2.2, 2.2, 8.4, 8.4)); _line(p, 9.4, 9.4, 13.8, 13.8)


@_icon("plus")
def _(p, c):
    _pen(p, c, 1.3); _line(p, 8, 2.5, 8, 13.5); _line(p, 2.5, 8, 13.5, 8)


@_icon("delete")
def _(p, c):
    _pen(p, c, 1.2)
    _line(p, 2.4, 4.0, 13.6, 4.0); _poly(p, (6.0, 4.0), (6.4, 2.2), (9.6, 2.2), (10.0, 4.0))
    path = QPainterPath(); path.moveTo(3.8, 4.0); path.lineTo(4.7, 13.0)
    path.quadTo(4.8, 14.2, 6.0, 14.2); path.lineTo(10.0, 14.2); path.quadTo(11.2, 14.2, 11.3, 13.0)
    path.lineTo(12.2, 4.0); p.drawPath(path)
    _line(p, 6.8, 6.6, 6.8, 11.6); _line(p, 9.2, 6.6, 9.2, 11.6)


@_icon("terminal")
def _(p, c):
    _pen(p, c, 1.2); p.drawRoundedRect(QRectF(1.6, 2.6, 12.8, 10.8), 1.6, 1.6)
    _poly(p, (4.2, 6.2), (6.4, 8.0), (4.2, 9.8)); _line(p, 7.6, 10.2, 11.0, 10.2)


@_icon("logs")
def _(p, c):
    _pen(p, c, 1.2); p.drawRoundedRect(QRectF(2.0, 1.6, 12.0, 12.8), 1.6, 1.6)
    for y, w in ((5.0, 7.0), (8.0, 5.0), (11.0, 6.0)):
        _line(p, 4.6, y, 4.6 + w, y)


@_icon("yaml")
def _(p, c):
    _pen(p, c, 1.3)
    _poly(p, (5.4, 4.4), (2.2, 8.0), (5.4, 11.6))
    _poly(p, (10.6, 4.4), (13.8, 8.0), (10.6, 11.6))
    _line(p, 9.1, 3.2, 6.9, 12.8)


@_icon("scale")
def _(p, c):
    _pen(p, c, 1.2)
    p.drawRoundedRect(QRectF(1.8, 5.2, 5.6, 5.6), 1.0, 1.0)
    p.drawRoundedRect(QRectF(9.4, 2.2, 4.8, 4.8), 1.0, 1.0)
    p.drawRoundedRect(QRectF(9.4, 9.0, 4.8, 4.8), 1.0, 1.0)
    _line(p, 7.4, 8.0, 9.4, 4.6); _line(p, 7.4, 8.0, 9.4, 11.4)


@_icon("lock")
def _(p, c):
    _pen(p, c, 1.2); p.drawRoundedRect(QRectF(3.0, 7.0, 10.0, 7.4), 1.4, 1.4)
    p.drawArc(QRectF(5.0, 2.0, 6.0, 9.0), 0, 180 * 16)
    p.setPen(Qt.PenStyle.NoPen); p.setBrush(QColor(c)); p.drawEllipse(QPointF(8, 10.6), 1.0, 1.0)


@_icon("unlock")
def _(p, c):
    _pen(p, c, 1.2); p.drawRoundedRect(QRectF(3.0, 7.0, 10.0, 7.4), 1.4, 1.4)
    p.drawArc(QRectF(7.6, 1.6, 6.0, 9.0), 20 * 16, 160 * 16)
    p.setPen(Qt.PenStyle.NoPen); p.setBrush(QColor(c)); p.drawEllipse(QPointF(8, 10.6), 1.0, 1.0)


@_icon("copy")
def _(p, c):
    _pen(p, c, 1.2)
    p.drawRoundedRect(QRectF(5.2, 5.0, 8.3, 9.2), 1.6, 1.6)
    _poly(p, (2.5, 10.8), (2.5, 3.6), (3.6, 2.4), (9.6, 2.4))


@_icon("save")
def _(p, c):
    _pen(p, c, 1.2)
    _poly(p, (2.2, 2.2), (11.2, 2.2), (13.8, 4.8), (13.8, 13.8), (2.2, 13.8), (2.2, 2.2))
    p.drawRect(QRectF(5.0, 2.2, 5.4, 3.6)); p.drawRect(QRectF(4.4, 9.0, 7.2, 4.8))


@_icon("settings")
def _(p, c):
    _pen(p, c, 1.2)
    p.drawEllipse(QPointF(8, 8), 2.3, 2.3)
    pts = []
    for i in range(16):
        a = i * math.pi / 8
        r = 6.2 if i % 2 == 0 else 4.9
        pts.append(QPointF(8 + r * math.cos(a), 8 + r * math.sin(a)))
    p.drawPolygon(QPolygonF(pts))


@_icon("external")
def _(p, c):
    _pen(p, c, 1.2)
    _poly(p, (7.0, 3.0), (3.0, 3.0), (3.0, 13.0), (13.0, 13.0), (13.0, 9.0))
    _line(p, 7.5, 8.5, 13.5, 2.5); _poly(p, (9.5, 2.5), (13.5, 2.5), (13.5, 6.5))


def _star(p, c, filled):
    pts = []
    for i in range(10):
        a = -math.pi / 2 + i * math.pi / 5
        r = 6.4 if i % 2 == 0 else 2.7
        pts.append(QPointF(8 + r * math.cos(a), 8.4 + r * math.sin(a)))
    _pen(p, c, 1.1)
    if filled:
        p.setBrush(QColor(c))
    p.drawPolygon(QPolygonF(pts))


@_icon("star")
def _(p, c):
    _star(p, c, False)


@_icon("starfill")
def _(p, c):
    _star(p, "#E8A200" if c == C["text"] else c, True)


@_icon("pane")
def _(p, c):
    _pen(p, c, 1.2); p.drawRoundedRect(QRectF(1.6, 2.4, 12.8, 11.2), 1.6, 1.6); _line(p, 10.4, 2.4, 10.4, 13.6)


@_icon("chevdown")
def _(p, c):
    _pen(p, c, 1.3); _poly(p, (3.5, 6), (8, 10.5), (12.5, 6))


@_icon("chevup")
def _(p, c):
    _pen(p, c, 1.3); _poly(p, (3.5, 10), (8, 5.5), (12.5, 10))


@_icon("chevright")
def _(p, c):
    _pen(p, c, 1.3); _poly(p, (6, 3.5), (10.5, 8), (6, 12.5))


@_icon("close")
def _(p, c):
    _pen(p, c, 1.2); _line(p, 4.5, 4.5, 11.5, 11.5); _line(p, 11.5, 4.5, 4.5, 11.5)


@_icon("check")
def _(p, c):
    _pen(p, c, 1.4); _poly(p, (3.2, 8.4), (6.4, 11.6), (12.8, 4.6))


@_icon("dot")
def _(p, c):
    p.setPen(Qt.PenStyle.NoPen); p.setBrush(QColor(c)); p.drawEllipse(QPointF(8, 8), 2.6, 2.6)


class Glyphs:
    """Icônes au trait, dessinées (aucun fichier externe)."""
    _cache = {}

    @classmethod
    def pixmap(cls, name, px, color=None):
        pm = QPixmap(px, px)
        pm.fill(Qt.GlobalColor.transparent)
        p = QPainter(pm)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.scale(px / 16.0, px / 16.0)
        _DRAW[name](p, color or C["text"])
        p.end()
        return pm

    @classmethod
    def get(cls, name, color=None):
        key = (name, color)
        icon = cls._cache.get(key)
        if icon is None:
            icon = QIcon()
            for px in (16, 32):
                icon.addPixmap(cls.pixmap(name, px, color or C["text"]), QIcon.Mode.Normal)
                icon.addPixmap(cls.pixmap(name, px, C["disabled"]), QIcon.Mode.Disabled)
            cls._cache[key] = icon
        return icon


# Formes en coordonnées 16×16 (reprises du PaaSExplorer d'origine) :
# ('r', x0, y0, x1, y1, couleur) | ('c', cx, cy, r, couleur) | ('o', cx, cy, r, épaisseur, couleur)  (anneau)
_W = "#ffffff"
SHAPES = {
    "account": [("c", 5.5, 9.5, 3.3, "#2b88d8"), ("c", 9.5, 7.5, 4.2, "#2b88d8"), ("c", 12.6, 10.3, 2.7, "#2b88d8"),
                ("r", 2.4, 9.5, 15, 13, "#2b88d8")],
    "kubernetes": [("c", 8, 8, 7.4, "#326ce5"), ("o", 8, 8, 4.1, 1.4, _W), ("c", 8, 8, 1.3, _W),
                   ("r", 7.3, 1.6, 8.7, 4.3, _W), ("r", 7.3, 11.7, 8.7, 14.4, _W),
                   ("r", 1.6, 7.3, 4.3, 8.7, _W), ("r", 11.7, 7.3, 14.4, 8.7, _W)],
    "openshift": [("c", 8, 8, 7.4, "#ee0000"), ("o", 8, 8, 4.4, 1.9, _W), ("r", 3, 7.2, 13, 8.8, "#ee0000")],
    "folder": [("r", 1, 3, 7, 5.5, "#dba32b"), ("r", 1, 4.5, 15, 13.5, "#f5c242"), ("r", 1, 6, 15, 13.5, "#fad66b")],
    "folder_sys": [("r", 1, 3, 7, 5.5, "#8f9aa6"), ("r", 1, 4.5, 15, 13.5, "#b2bcc6"),
                   ("r", 1, 6, 15, 13.5, "#cbd3db")],
    "clusterres": [("r", 1, 3, 7, 5.5, "#4f6bed"), ("r", 1, 4.5, 15, 13.5, "#7088f2"),
                   ("r", 1, 6, 15, 13.5, "#93a6f7")],
    "pod": [("r", 2.5, 3.5, 13.5, 13.5, "#178a4a"), ("r", 2.5, 3.5, 13.5, 6.2, "#3fbf74"),
            ("r", 7.4, 6.2, 8.6, 13.5, "#3fbf74")],
    "deploy": [("r", 5, 1.5, 15, 8.5, "#8e7cf0"), ("r", 3, 4.5, 13, 11.5, "#6a4ce2"), ("r", 1, 7.5, 11, 14.5, "#4b31c2")],
    "net": [("c", 8, 8, 7, "#0f7b9a"), ("o", 8, 8, 4.2, 1.1, _W), ("r", 1.5, 7.4, 14.5, 8.6, _W),
            ("r", 7.4, 1.5, 8.6, 14.5, _W)],
    "config": [("r", 2.5, 1, 13.5, 15, "#7a7a7a"), ("r", 3.5, 2, 12.5, 14, _W), ("r", 5, 4.5, 11, 5.5, "#2b88d8"),
               ("r", 5, 7.5, 11, 8.5, "#7a7a7a"), ("r", 5, 10.5, 9.5, 11.5, "#7a7a7a")],
    "secret": [("o", 8, 6, 3.6, 1.5, "#9d7400"), ("r", 3, 7, 13, 14.5, "#e0a800"), ("r", 7.3, 9, 8.7, 12.5, "#7a5a00")],
    "disk": [("r", 2.5, 3.5, 13.5, 12.5, "#6b7c8f"), ("r", 2.5, 3.5, 13.5, 5.5, "#93a3b5"),
             ("c", 11.3, 10.3, 1, "#3fbf74")],
    "user": [("c", 8, 5, 3, "#5a6b7d"), ("c", 8, 14.5, 6, "#5a6b7d")],
    "event": [("c", 8, 8, 7.2, "#f2a600"), ("r", 7.1, 3.5, 8.9, 9.5, _W), ("r", 7.1, 11, 8.9, 12.8, _W)],
    "job": [("c", 8, 8, 7.2, "#257de0"), ("o", 8, 8, 5.2, 0.9, _W), ("r", 7.4, 4, 8.6, 8.6, _W),
            ("r", 7.4, 7.4, 11.5, 8.6, _W)],
    "node": [("r", 1.5, 2, 14.5, 7, "#4f5d6b"), ("r", 1.5, 9, 14.5, 14, "#4f5d6b"), ("c", 12, 4.5, 1, "#3fbf74"),
             ("c", 12, 11.5, 1, "#3fbf74"), ("r", 3.5, 4, 8, 5, "#93a3b5"), ("r", 3.5, 11, 8, 12, "#93a3b5")],
    "overview": [("r", 1, 1, 15, 15, "#e8eef7"), ("r", 3, 9, 5.5, 13, "#257de0"), ("r", 6.8, 5, 9.3, 13, "#f47230"),
                 ("r", 10.6, 3, 13.1, 13, "#00b894")],
    "helm": [("c", 8, 8, 7.2, "#0f1689"), ("o", 8, 8, 3.8, 1.3, _W), ("r", 7.4, 1, 8.6, 15, _W),
             ("r", 1, 7.4, 15, 8.6, _W), ("c", 8, 8, 1.6, "#0f1689")],
    "topology": [("c", 8, 3.2, 2.4, "#6a4ce2"), ("c", 3.2, 12.5, 2.4, "#257de0"), ("c", 12.8, 12.5, 2.4, "#00b894"),
                 ("r", 7.4, 5, 8.6, 8.5, "#8a8a8a"), ("r", 3, 8, 13, 9.2, "#8a8a8a"),
                 ("r", 2.6, 8, 3.8, 10.5, "#8a8a8a"), ("r", 12.2, 8, 13.4, 10.5, "#8a8a8a")],
    "all": [("r", 1.5, 1.5, 7, 7, "#257de0"), ("r", 9, 1.5, 14.5, 7, "#00b894"), ("r", 1.5, 9, 7, 14.5, "#f47230"),
            ("r", 9, 9, 14.5, 14.5, "#6a4ce2")],
    "doc": [("r", 2.5, 1, 13.5, 15, "#8a8a8a"), ("r", 3.5, 2, 12.5, 14, _W), ("r", 5, 5, 11, 6, "#b0b0b0"),
            ("r", 5, 8, 11, 9, "#b0b0b0")],
    "terminal": [("r", 1, 2, 15, 14, "#1e1e1e"), ("r", 3, 5, 5, 6.5, _W), ("r", 4.5, 6.5, 6.5, 8, _W),
                 ("r", 3, 8, 5, 9.5, _W), ("r", 7, 10, 12, 11.3, _W)],
    "logs": [("r", 1, 1, 15, 15, "#2b2b2b"), ("r", 3, 3.5, 13, 4.7, "#3fbf74"), ("r", 3, 6.5, 11, 7.7, _W),
             ("r", 3, 9.5, 13, 10.7, "#f2a600"), ("r", 3, 12.5, 9, 13.7, _W)],
    "yaml": [("r", 2.5, 1, 13.5, 15, "#8a8a8a"), ("r", 3.5, 2, 12.5, 14, _W), ("r", 5, 4.5, 8, 5.5, "#c42b1c"),
             ("r", 6.5, 7.5, 11, 8.5, "#2b88d8"), ("r", 6.5, 10.5, 10, 11.5, "#2b88d8")],
    "welcome": [("c", 8, 8, 7.4, "#2b88d8"), ("r", 7.2, 3.5, 8.8, 5, _W), ("r", 7.2, 6.5, 8.8, 12.5, _W)],
    "fav": [("p", [(8 + (7.0 if i % 2 == 0 else 3.0) * math.cos(-math.pi / 2 + i * math.pi / 5),
                    8.6 + (7.0 if i % 2 == 0 else 3.0) * math.sin(-math.pi / 2 + i * math.pi / 5))
                   for i in range(10)], "#f2a600")],
    "ok": [("c", 8, 8, 4.2, "#0aac23")],
    "warn": [("c", 8, 8, 4.2, "#e8a200")],
    "err": [("c", 8, 8, 4.2, "#dc3c3d")],
    "off": [("c", 8, 8, 4.2, "#a6a6a6")],
}


class Icons:
    """Icônes en couleur des objets (comptes, clusters, pods…)."""
    _cache = {}

    @staticmethod
    def pixmap(name, px):
        pm = QPixmap(px, px)
        pm.fill(Qt.GlobalColor.transparent)
        p = QPainter(pm)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.scale(px / 16.0, px / 16.0)
        for s in SHAPES.get(name) or SHAPES["doc"]:
            kind, color = s[0], s[-1]
            if kind == "o":
                pen = QPen(QColor(color), s[4])
                p.setPen(pen)
                p.setBrush(Qt.BrushStyle.NoBrush)
                p.drawEllipse(QPointF(s[1], s[2]), s[3], s[3])
                continue
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QColor(color))
            if kind == "p":
                p.drawPolygon(QPolygonF([QPointF(x, y) for x, y in s[1]]))
            elif kind == "r":
                p.drawRect(QRectF(s[1], s[2], s[3] - s[1], s[4] - s[2]))
            elif kind == "c":
                p.drawEllipse(QPointF(s[1], s[2]), s[3], s[3])
        p.end()
        return pm

    @classmethod
    def get(cls, name):
        name = name if name in SHAPES else "doc"
        icon = cls._cache.get(name)
        if icon is None:
            icon = QIcon()
            for px in (16, 20, 24, 32, 48, 64, 128, 256):
                icon.addPixmap(cls.pixmap(name, px))
            cls._cache[name] = icon
        return icon


def apply_theme(app):
    import atexit
    import tempfile
    app.setStyle("Fusion")
    pal = QPalette()
    for role, value in ((QPalette.ColorRole.Window, C["body"]), (QPalette.ColorRole.Base, C["body"]),
                        (QPalette.ColorRole.AlternateBase, "#FAFAFA"), (QPalette.ColorRole.Text, C["text"]),
                        (QPalette.ColorRole.WindowText, C["text"]), (QPalette.ColorRole.Button, C["body"]),
                        (QPalette.ColorRole.ButtonText, C["text"]), (QPalette.ColorRole.Highlight, C["select"]),
                        (QPalette.ColorRole.HighlightedText, C["text"]), (QPalette.ColorRole.ToolTipBase, C["menu"]),
                        (QPalette.ColorRole.ToolTipText, C["text"]), (QPalette.ColorRole.PlaceholderText, "#767676"),
                        (QPalette.ColorRole.Link, C["accent"])):
        pal.setColor(role, QColor(value))
    for role in (QPalette.ColorRole.Text, QPalette.ColorRole.WindowText, QPalette.ColorRole.ButtonText):
        pal.setColor(QPalette.ColorGroup.Disabled, role, QColor(C["disabled"]))
    app.setPalette(pal)
    font = app.font()
    font.setPixelSize(13)
    app.setFont(font)
    img_dir = tempfile.mkdtemp(prefix="paas-explorer-theme-")
    atexit.register(shutil.rmtree, img_dir, True)
    images = {}
    for name, color in (("close", C["text"]), ("chevdown", C["text2"]), ("chevup", C["text2"]),
                        ("chevright", C["text2"]), ("check", C["text"]), ("dot", C["text"])):
        base = os.path.join(img_dir, name)
        Glyphs.pixmap(name, 16, color).save(base + ".png", "PNG")
        Glyphs.pixmap(name, 32, color).save(base + "@2x.png", "PNG")
        images["img_" + name] = (base + ".png").replace("\\", "/")
    css = STYLESHEET
    for key in sorted(images, key=len, reverse=True):
        css = css.replace("@" + key, images[key])
    for key in sorted(C, key=len, reverse=True):
        css = css.replace("@" + key, C[key])
    app.setStyleSheet(css)


def style_menu(menu):
    """Menus aux coins arrondis, comme Windows 11."""
    menu.setWindowFlags(menu.windowFlags() | Qt.WindowType.FramelessWindowHint)
    menu.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
    for action in menu.actions():
        sub = action.menu()
        if sub is not None and sub is not menu:
            style_menu(sub)
    return menu


def popup(menu, global_pos):
    style_menu(menu)
    menu.exec(global_pos)
    menu.deleteLater()


def copy_text(text):
    QGuiApplication.clipboard().setText(text or "")


def drop_layout_items(layout):
    """Vide une mise en page : les widgets sont cachés tout de suite, puis libérés."""
    while layout.count():
        it = layout.takeAt(0)
        w = it.widget()
        if w is not None:
            w.hide()
            w.deleteLater()
        elif it.layout() is not None:
            drop_layout_items(it.layout())


def tool_row():
    """Bandeau d'outils en haut d'un onglet (YAML, logs…)."""
    bar = QFrame()
    bar.setObjectName("toolrow")
    lay = QHBoxLayout(bar)
    lay.setContentsMargins(8, 5, 8, 5)
    lay.setSpacing(6)
    return bar, lay


def tool_button(text, icon=None, slot=None, tip=""):
    b = QToolButton()
    b.setText(text)
    if icon:
        b.setIcon(Glyphs.get(icon))
        b.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon if text
                             else Qt.ToolButtonStyle.ToolButtonIconOnly)
    if tip:
        b.setToolTip(tip)
    if slot:
        b.clicked.connect(lambda _c=False: slot())
    return b


def save_text_dialog(parent, default_name, text):
    path, _flt = QFileDialog.getSaveFileName(parent, "Enregistrer sous", os.path.join(os.path.expanduser("~"),
                                                                                       default_name))
    if not path:
        return None
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


# ======================================================================================
# Vue « Détails » (liste triable et filtrable, icônes d'état)
# ======================================================================================

def _num(v):
    m = re.match(r"^(\d+)(?:/(\d+))?$", str(v))
    return int(m.group(1)) if m else str(v)


def object_rows(res, items):
    rows = []
    for o in items:
        md = o.get("metadata", {})
        extra, level = row_for(res, o)
        ts = md.get("creationTimestamp")
        if res["key"] == "events":
            ts = o.get("lastTimestamp") or o.get("eventTime") or ts
        values = [md.get("name", "")] + extra + [age(ts)]
        sort = [md.get("name", "")] + [_num(v) for v in extra] + [age_seconds(ts)]
        ns = md.get("namespace", "")
        rows.append({"id": f"{ns}/{md.get('name', '')}/{md.get('uid', '')}", "values": values, "sort": sort,
                     "icon": level if res["key"] in ("pods", "nodes") or level in ("err", "warn")
                     else res.get("icon", "doc"),
                     "level": level, "obj": o, "res": res})
    return rows


class ListView(QWidget):
    """Liste façon Explorateur : colonnes triables, filtre, icônes d'état."""
    selection_changed = Signal()
    activated = Signal()
    menu_requested = Signal(QPoint)
    counts_changed = Signal()

    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        self.tree = QTreeWidget()
        self.tree.setObjectName("list")
        self.tree.setRootIsDecorated(False)
        self.tree.setUniformRowHeights(True)
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.tree.setIconSize(QSize(16, 16))
        self.tree.setAllColumnsShowFocus(True)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(lambda pos: self.menu_requested.emit(
            self.tree.viewport().mapToGlobal(pos)))
        self.tree.itemSelectionChanged.connect(self._on_sel)
        self.tree.itemDoubleClicked.connect(lambda *_a: self.activated.emit())
        enter = QAction(self.tree)
        enter.setShortcuts([QKeySequence(Qt.Key.Key_Return), QKeySequence(Qt.Key.Key_Enter)])
        enter.setShortcutContext(Qt.ShortcutContext.WidgetShortcut)
        enter.triggered.connect(lambda: self.activated.emit())
        self.tree.addAction(enter)
        hdr = self.tree.header()
        hdr.setSectionsClickable(True)
        hdr.setSortIndicatorShown(True)
        hdr.setHighlightSections(False)
        hdr.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        hdr.sectionClicked.connect(self.sort_by)
        lay.addWidget(self.tree)
        self.empty = QLabel("", self.tree.viewport())
        self.empty.setObjectName("hint")
        self.empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty.hide()
        self.rows, self.by_id, self.items = [], {}, {}
        self.columns = []
        self.sort_col, self.sort_rev = 0, False
        self.filter_text = ""
        self._filling = False

    def configure_columns(self, columns):
        """columns : [(titre, largeur, ancre)] — la 1re colonne porte l'icône et le nom."""
        if [c[0] for c in columns] == [c[0] for c in self.columns]:
            return
        self.columns = columns
        self.sort_col, self.sort_rev = 0, False
        self.tree.clear()
        self.tree.setColumnCount(len(columns))
        self.tree.setHeaderLabels([c[0] for c in columns])
        hdr = self.tree.header()
        hdr.setStretchLastSection(True)
        for i, (_t, w, anchor) in enumerate(columns):
            hdr.setSectionResizeMode(i, QHeaderView.ResizeMode.Interactive)
            self.tree.setColumnWidth(i, w)
            if anchor == "e":
                self.tree.headerItem().setTextAlignment(i, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

    def set_rows(self, rows, empty_text="Ce dossier est vide."):
        """rows : [{'id','values':[...], 'icon', 'level', 'obj', 'sort':[...]}]"""
        self.rows = rows
        self.by_id = {r["id"]: r for r in rows}
        self.empty.setText(empty_text)
        self._refill()

    def _key(self, r):
        vals = r.get("sort") or r["values"]
        v = vals[self.sort_col] if self.sort_col < len(vals) else ""
        return (0, v, "") if isinstance(v, (int, float)) else (1, 0, str(v).lower())

    def _refill(self):
        sel = {r["id"] for r in self.selected()}
        q = self.filter_text.lower()
        rows = [r for r in self.rows if not q or any(q in str(v).lower() for v in r["values"])]
        rows.sort(key=self._key, reverse=self.sort_rev)
        self._filling = True
        self.tree.setUpdatesEnabled(False)
        try:
            self.tree.clear()
            self.items = {}
            right = [i for i, c in enumerate(self.columns) if c[2] == "e"]
            for r in rows:
                it = QTreeWidgetItem([str(v) for v in r["values"]])
                it.setIcon(0, Icons.get(r.get("icon") or "doc"))
                it.setData(0, Qt.ItemDataRole.UserRole, r["id"])
                color = LEVEL_COLOR.get(r.get("level") or "ok")
                for i in range(len(r["values"])):
                    if color:
                        it.setForeground(i, QBrush(QColor(color)))
                    if i in right:
                        it.setTextAlignment(i, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                self.items[r["id"]] = it
                self.tree.addTopLevelItem(it)
            for rid in sel:
                if rid in self.items:
                    self.items[rid].setSelected(True)
        finally:
            self.tree.setUpdatesEnabled(True)
            self._filling = False
        self.tree.header().setSortIndicator(self.sort_col, Qt.SortOrder.DescendingOrder if self.sort_rev
                                            else Qt.SortOrder.AscendingOrder)
        self.empty.setVisible(not rows)
        if not rows:
            self.empty.setGeometry(0, 40, self.tree.viewport().width(), 60)
        self.counts_changed.emit()
        self.selection_changed.emit()

    def resizeEvent(self, ev):
        super().resizeEvent(ev)
        self.empty.setGeometry(0, 40, self.tree.viewport().width(), 60)

    def update_row(self, row):
        it = self.items.get(row["id"])
        if it is None:
            return
        color = LEVEL_COLOR.get(row.get("level") or "ok")
        for i, v in enumerate(row["values"]):
            it.setText(i, str(v))
            it.setForeground(i, QBrush(QColor(color or C["text"])))

    def _on_sel(self):
        if not self._filling:
            self.selection_changed.emit()
            self.counts_changed.emit()

    def sort_by(self, i):
        if self.sort_col == i:
            self.sort_rev = not self.sort_rev
        else:
            self.sort_col, self.sort_rev = i, False
        self._refill()

    def set_filter(self, text):
        self.filter_text = text
        self._refill()

    def selected(self):
        out = []
        for it in self.tree.selectedItems():
            r = self.by_id.get(it.data(0, Qt.ItemDataRole.UserRole))
            if r:
                out.append(r)
        return out

    def select_id(self, rid):
        it = self.items.get(rid)
        if it is not None:
            self.tree.clearSelection()
            it.setSelected(True)
            self.tree.setCurrentItem(it)

    def visible_count(self):
        return self.tree.topLevelItemCount()


# ======================================================================================
# Vue d'ensemble d'un namespace (tableau de bord dessiné, infobulles au survol)
# ======================================================================================

VIZ = {
    "surface": "#ffffff", "ink": "#191919", "ink2": "#666666", "grid": "#e7e7e7", "border": "#e5e5e5",
    "series": ["#257de0", "#f47230", "#00b894", "#f2a600", "#ee7fac", "#008a17", "#6a4ce2", "#ec4647"],
    "good": "#0aac23", "warning": "#fbb315", "serious": "#f18a59", "critical": "#dc3c3d", "neutral": "#a6a6a6",
}
STATUS_LABELS = [("good", "En cours"), ("warning", "En attente"), ("critical", "En erreur"), ("neutral", "Terminés")]


class _Draw:
    """Petite surface de dessin : dessine si un QPainter est fourni, sinon ne fait que mesurer
    (la même fonction sert à calculer la hauteur puis à peindre)."""

    def __init__(self, p, fonts):
        self.p = p
        self.fonts = fonts
        self.hits = []
        self._fm = {}

    def measure(self, font, text):
        fm = self._fm.get(font)
        if fm is None:
            fm = self._fm[font] = QFontMetricsF(self.fonts[font])
        return fm.horizontalAdvance(str(text))

    def rect(self, x0, y0, x1, y1, fill, outline=None, radius=0):
        if not self.p:
            return
        self.p.setPen(QPen(QColor(outline), 1) if outline else Qt.PenStyle.NoPen)
        self.p.setBrush(QColor(fill) if fill else Qt.BrushStyle.NoBrush)
        r = QRectF(x0, y0, max(0.5, x1 - x0), max(0.5, y1 - y0))
        if radius:
            self.p.drawRoundedRect(r, radius, radius)
        else:
            self.p.drawRect(r)

    def ellipse(self, x0, y0, x1, y1, fill):
        if self.p:
            self.p.setPen(Qt.PenStyle.NoPen)
            self.p.setBrush(QColor(fill))
            self.p.drawEllipse(QRectF(x0, y0, x1 - x0, y1 - y0))

    def line(self, x0, y0, x1, y1, color):
        if self.p:
            self.p.setPen(QPen(QColor(color), 1))
            self.p.drawLine(QPointF(x0, y0), QPointF(x1, y1))

    def text(self, x, y, text, color, font, anchor="nw"):
        if not self.p:
            return
        f = self.fonts[font]
        fm = QFontMetricsF(f)
        w, h = fm.horizontalAdvance(str(text)), fm.height()
        if anchor in ("w", "e", "center"):
            y -= h / 2
        if anchor == "e":
            x -= w
        elif anchor == "center":
            x -= w / 2
        self.p.setFont(f)
        self.p.setPen(QColor(color))
        self.p.drawText(QPointF(x, y + fm.ascent()), str(text))

    def hit(self, x0, y0, x1, y1, tip, action=None):
        self.hits.append((QRectF(x0, y0, x1 - x0, y1 - y0), tip, action))


def bar_end(d, x0, y0, x1, y1, color, r=4):
    """Barre horizontale à extrémité arrondie (ancrée à gauche)."""
    if x1 - x0 < 2 * r:
        d.rect(x0, y0, max(x1, x0 + 1), y1, color)
        return
    d.rect(x0, y0, x1 - r, y1, color)
    d.rect(x1 - 2 * r, y0, x1, y1, color, radius=r)


def card(d, x, y, w, h, title, subtitle=""):
    d.rect(x, y, x + w, y + h, VIZ["surface"], VIZ["border"], radius=6)
    d.text(x + 16, y + 14, title, VIZ["ink"], "title")
    if subtitle:
        d.text(x + 16, y + 38, subtitle, VIZ["ink2"], "small")


def stat_tile(d, x, y, w, h, label, value, sub="", level=None):
    d.rect(x, y, x + w, y + h, VIZ["surface"], VIZ["border"], radius=6)
    d.text(x + 16, y + 12, label, VIZ["ink2"], "small")
    d.text(x + 16, y + 30, str(value), VIZ["ink"], "hero")
    if sub:
        if level:
            d.ellipse(x + 16, y + h - 24, x + 26, y + h - 14, VIZ[level])
        d.text(x + (32 if level else 16), y + h - 19, sub, VIZ["ink2"], "small", "w")


def hbar_chart(d, x, y, w, items, fmt=str, color=None, label_w=None, bar_h=14, gap=10, unit=""):
    """items : [(libellé, valeur, info_infobulle)] — une seule série, triée par l'appelant."""
    color = color or VIZ["series"][0]
    if not items:
        d.text(x, y + 6, "Aucune donnée", VIZ["ink2"], "small")
        return y + 30
    label_w = label_w or min(220, max(d.measure("small", lbl) for lbl, _, _ in items) + 12)
    plot_w = max(40, w - label_w - 70)
    vmax = max(v for _, v, _ in items) or 1
    cy = y
    for lbl, v, info in items:
        short = lbl if len(lbl) <= 34 else lbl[:32] + "…"
        d.text(x + label_w - 10, cy + bar_h / 2, short, VIZ["ink2"], "small", "e")
        d.line(x + label_w, cy - gap / 2 + 1, x + label_w, cy + bar_h + gap / 2 - 1, VIZ["grid"])
        bw = plot_w * (v / vmax)
        bar_end(d, x + label_w, cy, x + label_w + max(bw, 2), cy + bar_h, color)
        d.hit(x, cy - gap / 2, x + w, cy + bar_h + gap / 2, info or f"{lbl} : {fmt(v)}{unit}")
        d.text(x + label_w + bw + 8, cy + bar_h / 2, fmt(v) + unit, VIZ["ink"], "small", "w")
        cy += bar_h + gap
    return cy


def status_bar(d, x, y, w, counts, total_label="pods"):
    """Barre segmentée des états (couleurs d'état + libellé dans la légende)."""
    total = sum(counts.values())
    h = 22
    if not total:
        d.text(x, y, f"Aucun {total_label}", VIZ["ink2"], "small")
        return y + 30
    cx = x
    order = [k for k, _ in STATUS_LABELS if counts.get(k)]
    labels = dict(STATUS_LABELS)
    for i, key in enumerate(order):
        n = counts[key]
        seg = w * n / total
        x1 = cx + seg - (2 if i < len(order) - 1 else 0)
        d.rect(cx, y, max(x1, cx + 1), y + h, VIZ[key])
        d.hit(cx, y, max(x1, cx + 1), y + h, f"{labels[key]} : {n} {total_label} ({n * 100 // total} %)")
        if seg > 36:
            d.text(cx + seg / 2, y + h / 2, str(n), "#0b0b0b" if key == "warning" else "#ffffff", "small_bold",
                   "center")
        cx += seg
    ly, lx = y + h + 14, x
    for key in order:
        label = f"{labels[key]} ({counts[key]})"
        d.ellipse(lx, ly - 5, lx + 10, ly + 5, VIZ[key])
        d.text(lx + 15, ly, label, VIZ["ink2"], "small", "w")
        lx += 30 + d.measure("small", label)
    return ly + 18


def progress_rows(d, x, y, w, rows, bar_h=10, gap=16):
    """rows : [(libellé, prêts, voulus)] — barre de complétude + « prêts/voulus » + état."""
    label_w = min(220, max([d.measure("small", r[0]) for r in rows] + [60]) + 12)
    plot_w = max(40, w - label_w - 70)
    cy = y
    for lbl, ready, want in rows:
        level = "neutral" if want == 0 else ("good" if ready >= want else ("critical" if ready == 0 else "warning"))
        d.text(x + label_w - 10, cy + bar_h / 2, lbl, VIZ["ink2"], "small", "e")
        d.rect(x + label_w, cy, x + label_w + plot_w, cy + bar_h, "#f0f0f0", radius=3)
        frac = (ready / want) if want else 0
        if frac > 0:
            bar_end(d, x + label_w, cy, x + label_w + plot_w * min(frac, 1), cy + bar_h, VIZ[level], r=3)
        state = {"good": "opérationnel", "warning": "dégradé", "critical": "indisponible",
                 "neutral": "arrêté (0 réplica)"}[level]
        d.hit(x, cy - 4, x + w, cy + bar_h + 4, f"{lbl} : {ready}/{want} réplicas prêts — {state}")
        d.ellipse(x + label_w + plot_w + 8, cy, x + label_w + plot_w + 8 + bar_h, cy + bar_h, VIZ[level])
        d.text(x + label_w + plot_w + 24, cy + bar_h / 2, f"{ready}/{want}", VIZ["ink"], "small", "w")
        cy += bar_h + gap
    return cy


class _OverviewCanvas(QWidget):
    def __init__(self, owner):
        super().__init__()
        self.owner = owner
        self.setMouseTracking(True)
        self.hits = []
        self.fonts = {"title": ui_font(15, True), "small": ui_font(12), "small_bold": ui_font(12, True),
                      "hero": ui_font(28, True), "h1": ui_font(20, True)}

    def relayout(self):
        d = _Draw(None, self.fonts)
        h = self.owner.draw(d, max(640, self.width()))
        self.hits = d.hits
        self.setMinimumHeight(int(h))
        self.update()

    def resizeEvent(self, ev):
        super().resizeEvent(ev)
        if ev.size().width() != ev.oldSize().width():
            self.relayout()

    def paintEvent(self, ev):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.fillRect(self.rect(), QColor(C["page"]))
        d = _Draw(p, self.fonts)
        self.owner.draw(d, max(640, self.width()))
        self.hits = d.hits
        p.end()

    def _hit(self, pos):
        for rect, tip, action in reversed(self.hits):
            if rect.contains(QPointF(pos)):
                return tip, action
        return None, None

    def mouseMoveEvent(self, ev):
        tip, action = self._hit(ev.position())
        if tip:
            QToolTip.showText(ev.globalPosition().toPoint(), tip, self)
        else:
            QToolTip.hideText()
        self.setCursor(Qt.CursorShape.PointingHandCursor if action else Qt.CursorShape.ArrowCursor)

    def mouseDoubleClickEvent(self, ev):
        _tip, action = self._hit(ev.position())
        if action:
            action()


class OverviewView(QScrollArea):
    """Tableau de bord d'un namespace : tuiles, états des pods, réplicas, CPU/mémoire, objets par type."""

    def __init__(self, on_helm):
        super().__init__()
        self.on_helm = on_helm
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.canvas = _OverviewCanvas(self)
        self.setWidget(self.canvas)
        self.data = None

    def show_data(self, data):
        self.data = data
        self.canvas.relayout()

    def draw(self, d, W):
        data = self.data
        if not data:
            return 100
        pad, gap = 20, 16
        y = pad
        d.text(pad, y, f"Vue d'ensemble — {data['ns']}", VIZ["ink"], "h1")
        d.text(pad, y + 32, f"{data['cluster']} · {data['flavor']} · actualisé à {data['time']}", VIZ["ink2"], "small")
        y += 62
        pods = data["pods"]
        counts = {"good": 0, "warning": 0, "critical": 0, "neutral": 0}
        restarts = 0
        for p in pods:
            _, lvl = pod_status(p)
            counts[{"ok": "good", "warn": "warning", "err": "critical", "off": "neutral"}[lvl]] += 1
            restarts += sum(cs.get("restartCount", 0) for cs in p.get("status", {}).get("containerStatuses", []) or [])
        deps = data["deployments"]
        complete = sum(1 for x in deps if x.get("status", {}).get("readyReplicas", 0) >= x.get("spec", {}).get("replicas", 0))
        helm = data["helm"]
        not_deployed = sum(1 for r in helm if r.get("info", {}).get("status") != "deployed")
        tiles = [("Pods", len(pods), f"{counts['good']} en cours", "good" if not counts["critical"] else "critical"),
                 ("Deployments", len(deps), f"{complete} complets", None),
                 ("Services", len(data["services"]), f"{len(data['routes'])} route(s) / ingress", None),
                 ("Charts Helm", len(helm), f"{not_deployed} non déployé(s)", "warning" if not_deployed else None),
                 ("Redémarrages", restarts, "cumul des conteneurs", "warning" if restarts > 20 else None)]
        tw = (W - 2 * pad - gap * (len(tiles) - 1)) / len(tiles)
        for i, (lbl, val, sub, lvl) in enumerate(tiles):
            stat_tile(d, pad + i * (tw + gap), y, tw, 96, lbl, val, sub, lvl)
        y += 96 + gap
        colw = (W - 2 * pad - gap) / 2

        dep_rows = [(x["metadata"]["name"], x.get("status", {}).get("readyReplicas", 0),
                     x.get("spec", {}).get("replicas", 0)) for x in deps + data["statefulsets"]]
        dep_rows.sort(key=lambda r: (r[1] >= r[2], r[0]))
        h = max(120, 70 + max(1, len(dep_rows[:20])) * 26)
        card(d, pad, y, colw, h, "Pods par état", f"{len(pods)} pods dans le namespace")
        status_bar(d, pad + 16, y + 64, colw - 32, counts)
        card(d, pad + colw + gap, y, colw, h, "Réplicas prêts", "Deployments et StatefulSets")
        if dep_rows:
            progress_rows(d, pad + colw + gap + 16, y + 66, colw - 32, dep_rows[:20])
        else:
            d.text(pad + colw + gap + 16, y + 66, "Aucune charge de travail", VIZ["ink2"], "small")
        y += h + gap

        m = data["metrics"]
        if m:
            cpu = sorted(((k, v[0]) for k, v in m.items()), key=lambda t: -t[1])[:10]
            mem = sorted(((k, v[1]) for k, v in m.items()), key=lambda t: -t[1])[:10]
            h = 70 + max(len(cpu), 1) * 24
            card(d, pad, y, colw, h, "Consommation CPU", "Top 10 des pods · millicœurs (metrics-server)")
            hbar_chart(d, pad + 16, y + 68, colw - 32, [(k, v, f"{k}\nCPU : {v:.0f} m") for k, v in cpu],
                       fmt=lambda v: f"{v:.0f}", unit=" m")
            card(d, pad + colw + gap, y, colw, h, "Consommation mémoire", "Top 10 des pods · Mio")
            hbar_chart(d, pad + colw + gap + 16, y + 68, colw - 32,
                       [(k, v / 2 ** 20, f"{k}\nMémoire : {human_bytes(v)}") for k, v in mem],
                       fmt=lambda v: f"{v:.0f}", unit=" Mio")
            y += h + gap
        else:
            card(d, pad, y, W - 2 * pad, 70, "Consommation CPU / mémoire",
                 "API metrics.k8s.io indisponible ou droits insuffisants sur ce namespace.")
            y += 70 + gap

        objs = sorted(((k, v) for k, v in data["counts"].items() if v), key=lambda t: -t[1])
        h = max(70 + max(len(objs), 1) * 24, 70 + max(len(helm[:12]), 1) * 44)
        card(d, pad, y, colw, h, "Objets du namespace", "Nombre d'objets par type")
        hbar_chart(d, pad + 16, y + 68, colw - 32, [(k, v, f"{k} : {v} objet(s)") for k, v in objs])
        card(d, pad + colw + gap, y, colw, h, "Charts Helm", "Releases installées (dernière révision)")
        hy, hx = y + 66, pad + colw + gap + 16
        if not helm:
            d.text(hx, hy, "Aucune release Helm dans ce namespace", VIZ["ink2"], "small")
        for r in helm[:12]:
            st = r.get("info", {}).get("status", "")
            lvl = {"deployed": "good", "failed": "critical", "pending-upgrade": "warning",
                   "pending-install": "warning", "superseded": "neutral"}.get(st, "warning")
            meta = r.get("chart", {}).get("metadata", {})
            d.ellipse(hx, hy + 4, hx + 10, hy + 14, VIZ[lvl])
            d.text(hx + 18, hy, f"{r.get('name')}", VIZ["ink"], "small_bold")
            d.text(hx + 18, hy + 18, f"{meta.get('name')}-{meta.get('version')} · app {meta.get('appVersion', '?')} · "
                                     f"rév. {r.get('version')} · {st}", VIZ["ink2"], "small")
            d.hit(hx - 4, hy - 4, pad + 2 * colw + gap - 16, hy + 38,
                  f"{r.get('name')} — double-clic pour voir la configuration",
                  lambda r=r: self.on_helm(r))
            hy += 44
        y += h + gap
        return y + pad


# ======================================================================================
# Topologie (arbre : exposition → services → pods ; charges de travail → ReplicaSets → pods)
# ======================================================================================

class TopologyView(QWidget):
    KIND_ICON = {"Deployment": "deploy", "StatefulSet": "deploy", "DaemonSet": "deploy", "ReplicaSet": "deploy",
                 "DeploymentConfig": "deploy", "Job": "job", "Pod": "pod", "Service": "net", "Route": "net",
                 "Ingress": "net", "ConfigMap": "config", "Secret": "secret", "PersistentVolumeClaim": "disk",
                 "Groupe": "topology"}

    def __init__(self, on_open):
        super().__init__()
        self.on_open = on_open
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        self.tree = QTreeWidget()
        self.tree.setObjectName("topo")
        self.tree.setColumnCount(4)
        self.tree.setHeaderLabels(["Objet", "Type", "Statut", "Détail"])
        for i, w in enumerate((380, 150, 160, 320)):
            self.tree.setColumnWidth(i, w)
        self.tree.setUniformRowHeights(True)
        self.tree.itemDoubleClicked.connect(self._open)
        enter = QAction(self.tree)
        enter.setShortcuts([QKeySequence(Qt.Key.Key_Return), QKeySequence(Qt.Key.Key_Enter)])
        enter.setShortcutContext(Qt.ShortcutContext.WidgetShortcut)
        enter.triggered.connect(lambda: self.tree.currentItem() and self._open(self.tree.currentItem()))
        self.tree.addAction(enter)
        lay.addWidget(self.tree)
        self.forest = []
        self.filter_text = ""
        self.count = 0

    def show_forest(self, forest):
        self.forest = forest
        self._fill()

    def set_filter(self, text):
        self.filter_text = text.lower()
        self._fill()

    def _fill(self):
        t = self.tree
        t.clear()
        self.count = 0
        q = self.filter_text
        bold = ui_font(13, True)

        def match(n):
            return not q or q in n["name"].lower() or any(match(ch) for ch in n["children"])

        def add(parent, n, depth):
            if not match(n):
                return
            icon = n["level"] if n["kind"] == "Pod" else self.KIND_ICON.get(n["kind"], "doc")
            it = QTreeWidgetItem([n["name"], "" if n["kind"] == "Groupe" else n["kind"], n["status"], n["note"]])
            it.setIcon(0, Icons.get(icon))
            it.setData(0, Qt.ItemDataRole.UserRole, n)
            if n["kind"] == "Groupe":
                it.setFont(0, bold)
            else:
                self.count += 1
                color = LEVEL_COLOR.get(n["level"])
                if color:
                    for i in range(4):
                        it.setForeground(i, QBrush(QColor(color)))
            if parent is None:
                t.addTopLevelItem(it)
            else:
                parent.addChild(it)
            for ch in n["children"]:
                add(it, ch, depth + 1)
            it.setExpanded(depth < 2 or bool(q))
        for n in self.forest:
            add(None, n, 0)
        if not self.forest:
            t.addTopLevelItem(QTreeWidgetItem(["Aucun objet dans ce namespace."]))

    def _open(self, item, _col=0):
        n = item.data(0, Qt.ItemDataRole.UserRole)
        if n and n["kind"] != "Groupe":
            self.on_open(n["kind"], n["name"], n.get("obj"))

    def visible_count(self):
        return self.count


# ======================================================================================
# Onglets de contenu : texte (YAML, manifeste…), logs, Helm
# ======================================================================================

class YamlHighlighter(QSyntaxHighlighter):
    _KEY = re.compile(r"^(\s*-?\s*)([^:#\s][^:]*?):(\s|$)")

    def __init__(self, doc):
        super().__init__(doc)
        self.f_key = self._fmt("#0451A5")
        self.f_str = self._fmt("#A31515")
        self.f_num = self._fmt("#098658")
        self.f_com = self._fmt("#008000")

    @staticmethod
    def _fmt(color):
        f = QTextCharFormat()
        f.setForeground(QColor(color))
        return f

    def highlightBlock(self, line):
        if line.lstrip().startswith("#"):
            self.setFormat(0, len(line), self.f_com)
            return
        m = self._KEY.match(line)
        if not m:
            return
        self.setFormat(len(m.group(1)), m.end(2) - len(m.group(1)), self.f_key)
        rest = line[m.end():]
        val = rest.strip()
        start = m.end() + (len(rest) - len(rest.lstrip()))
        if val.startswith('"'):
            self.setFormat(start, len(line) - start, self.f_str)
        elif re.match(r"^-?[0-9.]+$", val) or val in ("true", "false", "null"):
            self.setFormat(start, len(line) - start, self.f_num)


class TextTab(QWidget):
    """Texte en lecture seule avec bandeau d'outils (YAML, manifeste, notes…)."""

    def __init__(self, app, text="", filename="export.txt", yaml_highlight=True):
        super().__init__()
        self.app = app
        self.filename = filename
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        self.bar, self.bar_lay = tool_row()
        self.bar_lay.addWidget(tool_button("Copier tout", "copy", self.copy_all))
        self.bar_lay.addWidget(tool_button("Enregistrer sous…", "save", self.save_as))
        self.extra_at = self.bar_lay.count()
        self.bar_lay.addStretch(1)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Rechercher (Entrée)")
        self.search.setClearButtonEnabled(True)
        self.search.setMinimumWidth(110)
        self.search.setMaximumWidth(220)
        self.search.returnPressed.connect(self.find)
        self.bar_lay.addWidget(self.search, 1)
        lay.addWidget(self.bar)
        self.text = QPlainTextEdit()
        self.text.setObjectName("code")
        self.text.setReadOnly(True)
        self.text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.text.setFont(mono_font("", 12))
        self.text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse |
                                          Qt.TextInteractionFlag.TextSelectableByKeyboard)
        lay.addWidget(self.text)
        self.highlighter = YamlHighlighter(self.text.document()) if yaml_highlight else None
        find = QAction(self)
        find.setShortcut(QKeySequence("Ctrl+F"))
        find.setShortcutContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        find.triggered.connect(lambda: (self.search.setFocus(), self.search.selectAll()))
        self.addAction(find)
        if text:
            self.set_text(text)

    def add_tool(self, widget):
        self.bar_lay.insertWidget(self.extra_at, widget)
        self.extra_at += 1
        return widget

    def set_text(self, text):
        sb = self.text.verticalScrollBar()
        pos = sb.value()
        self.text.setPlainText(text)
        sb.setValue(pos)

    def copy_all(self):
        copy_text(self.text.toPlainText())
        self.app.flash("Copié dans le presse-papiers.")

    def save_as(self):
        path = save_text_dialog(self, self.filename, self.text.toPlainText())
        if path:
            self.app.flash(f"Enregistré : {path.replace(os.path.expanduser('~'), '~', 1)}")

    def find(self):
        q = self.search.text()
        sels = []
        first = None
        if q:
            doc = self.text.document()
            cur = doc.find(q, 0)
            fmt = QTextCharFormat()
            fmt.setBackground(QColor("#FFE08A"))
            while not cur.isNull() and len(sels) < 5000:
                sel = QTextEdit.ExtraSelection()
                sel.cursor = cur
                sel.format = fmt
                sels.append(sel)
                first = first or QTextCursor(cur)
                cur = doc.find(q, cur)
        self.text.setExtraSelections(sels)
        if first is not None:
            self.text.setTextCursor(first)
            self.text.centerCursor()
        self.app.flash(f"{len(sels)} occurrence(s) de « {q} »" if q else "")


class YamlTab(TextTab):
    def __init__(self, app, kube, res, ns, name, obj=None):
        super().__init__(app, filename=f"{name}.yaml")
        self.kube, self.res, self.ns, self.name = kube, res, ns, name
        self.obj = obj
        self.add_tool(tool_button("Actualiser", "refresh", self.reload))
        self.managed = self.add_tool(QCheckBox("managedFields"))
        self.managed.toggled.connect(lambda _v: self.render())
        self.decode = None
        if res["kind"] == "Secret":
            self.decode = self.add_tool(QCheckBox("Décoder les valeurs (base64)"))
            self.decode.toggled.connect(lambda _v: self.render())
        if obj:
            self.render()
        self.reload()

    def reload(self):
        run_async(lambda: self.kube.get(self.res, self.ns, self.name), self._loaded)

    def _loaded(self, obj, err):
        if err:
            self.app.flash(f"YAML non actualisé : {err}", 10000)
            return
        self.obj = obj
        self.render()

    def render(self):
        if not self.obj:
            return
        o = clean_for_display(self.obj, self.managed.isChecked())
        if self.decode is not None and self.decode.isChecked() and isinstance(o.get("data"), dict):
            dec = {}
            for k, v in o["data"].items():
                try:
                    dec[k] = base64.b64decode(v).decode("utf-8")
                except Exception:  # noqa: BLE001
                    dec[k] = f"<binaire, {len(v)} car. base64>"
            o["data"] = dec
        self.set_text(to_yaml(o) + "\n")


class LogHighlighter(QSyntaxHighlighter):
    def __init__(self, doc):
        super().__init__(doc)
        self.f = {}
        for k, c in (("ERROR", "#F14C4C"), ("WARN", "#E5C07B"), ("DEBUG", "#808080")):
            f = QTextCharFormat()
            f.setForeground(QColor(c))
            self.f[k] = f

    def highlightBlock(self, line):
        up = line[:120].upper()
        if "ERROR" in up or "FATAL" in up or "EXCEPTION" in up or line.startswith("\tat "):
            self.setFormat(0, len(line), self.f["ERROR"])
        elif "WARN" in up:
            self.setFormat(0, len(line), self.f["WARN"])
        elif "DEBUG" in up or "TRACE" in up:
            self.setFormat(0, len(line), self.f["DEBUG"])


class LogsTab(QWidget):
    MAX_LINES = 200000

    def __init__(self, app, kube, ns, pod_obj, container=None):
        super().__init__()
        self.app, self.kube, self.ns = app, kube, ns
        self.pod = pod_obj["metadata"]["name"]
        containers = [c["name"] for c in pod_obj.get("spec", {}).get("containers", [])]
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        bar, bl = tool_row()
        bl.addWidget(QLabel("Conteneur :"))
        self.container = QComboBox()
        self.container.addItems(containers)
        if container in containers:
            self.container.setCurrentText(container)
        bl.addWidget(self.container)
        bl.addSpacing(8)
        bl.addWidget(QLabel("Lignes :"))
        self.tail = QComboBox()
        self.tail.addItems(["100", "500", "1000", "5000", "Toutes"])
        self.tail.setCurrentText(str(app.config.settings.get("logTail", 500)))
        bl.addWidget(self.tail)
        bl.addSpacing(8)
        self.follow = QCheckBox("Suivre")
        bl.addWidget(self.follow)
        opts = QToolButton()
        opts.setText("Options")
        opts.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        om = QMenu(opts)
        self.ts = om.addAction("Horodatage")
        self.prev = om.addAction("Conteneur précédent")
        self.wrap = om.addAction("Retour à la ligne")
        for a in (self.ts, self.prev, self.wrap):
            a.setCheckable(True)
        style_menu(om)
        opts.setMenu(om)
        bl.addWidget(opts)
        bl.addStretch(1)
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("Filtrer les lignes")
        self.filter.setClearButtonEnabled(True)
        self.filter.setMinimumWidth(110)
        self.filter.setMaximumWidth(220)
        bl.addWidget(self.filter, 1)
        b_clear = tool_button("", "delete", self.clear, "Effacer l'affichage")
        b_save = tool_button("", "save", self.save, "Enregistrer les logs…")
        bl.addWidget(b_clear)
        bl.addWidget(b_save)
        lay.addWidget(bar)
        self.text = QPlainTextEdit()
        self.text.setObjectName("console")
        self.text.setReadOnly(True)
        self.text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.text.setFont(mono_font("", 12))
        self.text.setMaximumBlockCount(self.MAX_LINES)
        lay.addWidget(self.text)
        self.highlighter = LogHighlighter(self.text.document())
        self.lines = deque(maxlen=self.MAX_LINES)
        self._partial = ""
        self.q = queue.Queue()
        self.stop = threading.Event()
        self._seq = 0
        self.pump = QTimer(self)
        self.pump.setInterval(150)
        self.pump.timeout.connect(self._pump)
        self.pump.start()
        self.container.currentIndexChanged.connect(lambda _i: self.reload())
        self.tail.currentIndexChanged.connect(lambda _i: self.reload())
        for cb in (self.follow, self.ts, self.prev):
            cb.toggled.connect(lambda _v: self.reload())
        self.wrap.toggled.connect(lambda v: self.text.setLineWrapMode(
            QPlainTextEdit.LineWrapMode.WidgetWidth if v else QPlainTextEdit.LineWrapMode.NoWrap))
        self.filter.textChanged.connect(lambda _t: self._render_all())
        self.reload()

    def _tail(self):
        v = self.tail.currentText()
        return None if v == "Toutes" else int(v)

    def reload(self):
        self.stop.set()
        self.stop = threading.Event()
        self._seq += 1
        seq = self._seq
        self.q = queue.Queue()
        self.lines.clear()
        self._partial = ""
        self.text.clear()
        c, tail, ts, prev = self.container.currentText() or None, self._tail(), self.ts.isChecked(), self.prev.isChecked()
        if self.follow.isChecked() and not prev:
            stop, q = self.stop, self.q
            threading.Thread(target=self._follow, args=(c, tail, ts, stop, q), daemon=True).start()
        else:
            def done(txt, err):
                if seq != self._seq:
                    return
                if err:
                    self._append(f"[PaaS Explorer] logs indisponibles : {err}\n")
                else:
                    self._append(txt or "")
                    self.text.moveCursor(QTextCursor.MoveOperation.End)
            run_async(lambda: self.kube.logs(self.ns, self.pod, c, tail, ts, prev), done)

    def _follow(self, c, tail, ts, stop, q):
        try:
            self.kube.logs_follow(self.ns, self.pod, c, tail, ts, stop, q.put)
        except Exception as exc:  # noqa: BLE001
            q.put(f"\n[PaaS Explorer] flux interrompu : {exc}\n")

    def _pump(self):
        chunk = []
        try:
            while len(chunk) < 5000:
                chunk.append(self.q.get_nowait())
        except queue.Empty:
            pass
        if chunk:
            self._append("".join(chunk))

    def _append(self, txt):
        txt = self._partial + txt
        parts = txt.split("\n")
        self._partial = parts.pop()
        if not parts:
            return
        self.lines.extend(parts)
        q = self.filter.text().lower()
        shown = [ln for ln in parts if q in ln.lower()] if q else parts
        if not shown:
            return
        sb = self.text.verticalScrollBar()
        at_end = sb.value() >= sb.maximum() - 2
        self.text.appendPlainText("\n".join(shown))
        if at_end:
            sb.setValue(sb.maximum())

    def _render_all(self):
        q = self.filter.text().lower()
        lines = [ln for ln in self.lines if q in ln.lower()] if q else list(self.lines)
        self.text.setPlainText("\n".join(lines))
        self.text.moveCursor(QTextCursor.MoveOperation.End)

    def clear(self):
        self.lines.clear()
        self.text.clear()

    def save(self):
        path = save_text_dialog(self, f"{self.pod}.log", "\n".join(self.lines) + "\n")
        if path:
            self.app.flash(f"Logs enregistrés : {path.replace(os.path.expanduser('~'), '~', 1)}")

    def close_tab(self):
        self.stop.set()
        self.pump.stop()


class HelmTab(QWidget):
    def __init__(self, app, release):
        super().__init__()
        self.app = app
        meta = release.get("chart", {}).get("metadata", {})
        info = release.get("info", {})
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 10, 12, 6)
        head = QHBoxLayout()
        ic = QLabel()
        ic.setPixmap(Icons.get("helm").pixmap(32, 32))
        head.addWidget(ic, 0, Qt.AlignmentFlag.AlignTop)
        txt = QVBoxLayout()
        t = QLabel(f"{release.get('name')}  —  {meta.get('name')} {meta.get('version')}")
        t.setObjectName("h2")
        txt.addWidget(t)
        sub = QLabel(f"Namespace {release.get('namespace')} · révision {release.get('version')} · "
                     f"statut {info.get('status')} · app {meta.get('appVersion', '?')} · "
                     f"déployé le {fmt_time(info.get('last_deployed'))}")
        sub.setObjectName("sub")
        sub.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        txt.addWidget(sub)
        if info.get("description"):
            de = QLabel(info["description"])
            de.setObjectName("failed" if info.get("status") == "failed" else "sub")
            de.setWordWrap(True)
            txt.addWidget(de)
        head.addLayout(txt, 1)
        lay.addLayout(head)
        nb = QTabWidget()
        nb.setObjectName("pivot")
        nb.setDocumentMode(True)
        user = release.get("config") or {}
        defaults = release.get("chart", {}).get("values") or {}
        for title, content in (
                ("Valeurs personnalisées", to_yaml(user) if user else
                 "# Aucune valeur personnalisée (valeurs par défaut du chart)"),
                ("Valeurs calculées", to_yaml(deep_merge(defaults, user))),
                ("Valeurs par défaut du chart", to_yaml(defaults)),
                ("Manifeste", release.get("manifest", "")),
                ("Notes", info.get("notes", "") or "")):
            tab = TextTab(app, content, f"{release.get('name')}-{title.split()[0].lower()}.yaml",
                          yaml_highlight=title != "Notes")
            nb.addTab(tab, title)
        hist = ListView()
        hist.configure_columns([("Révision", 90, "w"), ("Statut", 110, "w"), ("Chart", 200, "w"),
                                ("Version app", 110, "w"), ("Date", 160, "w"), ("Description", 380, "w")])
        rows = []
        for r in reversed(release.get("_history", [release])):
            m = r.get("chart", {}).get("metadata", {})
            st = r.get("info", {}).get("status", "")
            rows.append({"id": str(r.get("version")), "icon": "helm",
                         "level": "err" if st == "failed" else ("off" if st == "superseded" else "ok"),
                         "values": [r.get("version"), st, f"{m.get('name')}-{m.get('version')}", m.get("appVersion", ""),
                                    fmt_time(r.get("info", {}).get("last_deployed")),
                                    r.get("info", {}).get("description", "")],
                         "sort": [r.get("version", 0)] + [""] * 5})
        hist.sort_rev = True
        hist.set_rows(rows)
        nb.addTab(hist, "Historique")
        lay.addWidget(nb, 1)


# ======================================================================================
# Volet des détails
# ======================================================================================

class DetailsPane(QScrollArea):
    def __init__(self, app):
        super().__init__()
        self.app = app
        self.setObjectName("details")
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setMinimumWidth(240)
        self.inner = QWidget()
        self.inner.setObjectName("details")
        self.setWidget(self.inner)
        self.lay = QVBoxLayout(self.inner)
        self.lay.setContentsMargins(16, 14, 14, 14)
        self.lay.setSpacing(6)
        self.clear()

    def _reset(self):
        drop_layout_items(self.lay)

    def clear(self, text="Sélectionne un élément pour afficher ses détails."):
        self._reset()
        lab = QLabel(text)
        lab.setObjectName("detKind")
        lab.setWordWrap(True)
        self.lay.addWidget(lab)
        self.lay.addStretch(1)

    def show_row(self, row):
        self._reset()
        obj = row.get("obj") or {}
        res = row.get("res") or {}
        md = obj.get("metadata", {})
        head = QHBoxLayout()
        ic = QLabel()
        ic.setPixmap(Icons.get(res.get("icon", row.get("icon", "doc"))).pixmap(32, 32))
        head.addWidget(ic, 0, Qt.AlignmentFlag.AlignTop)
        title = QLabel(str(md.get("name") or row["values"][0]))
        title.setObjectName("detTitle")
        title.setWordWrap(True)
        title.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        head.addWidget(title, 1)
        self.lay.addLayout(head)
        kind = QLabel(res.get("kind") or row.get("kind_label", ""))
        kind.setObjectName("detKind")
        self.lay.addWidget(kind)
        props = []
        if obj:
            if md.get("namespace"):
                props.append(("Namespace", md["namespace"]))
            props.append(("Créé le", fmt_time(md.get("creationTimestamp"))))
            if res.get("kind") == "Pod":
                txt, _ = pod_status(obj)
                props += [("Statut", txt), ("Nœud", obj.get("spec", {}).get("nodeName", "")),
                          ("IP du pod", obj.get("status", {}).get("podIP", "")),
                          ("Compte de service", obj.get("spec", {}).get("serviceAccountName", ""))]
            for ref in md.get("ownerReferences", []) or []:
                props.append(("Propriétaire", f"{ref.get('kind')}/{ref.get('name')}"))
            for k, v in (md.get("labels") or {}).items():
                props.append(("Label", f"{k}={v}"))
        props += list(row.get("props", []))
        if res.get("kind") == "Pod":
            sec = QLabel("Conteneurs")
            sec.setFont(ui_font(13, True))
            self.lay.addSpacing(6)
            self.lay.addWidget(sec)
            css = {c["name"]: c for c in obj.get("status", {}).get("containerStatuses", []) or []}
            for cont in obj.get("spec", {}).get("containers", []):
                cs = css.get(cont["name"], {})
                line = QHBoxLayout()
                lvl = "ok" if cs.get("ready") else ("err" if cs.get("restartCount", 0) > 3 else "warn")
                dot = QLabel()
                dot.setPixmap(Icons.get(lvl).pixmap(16, 16))
                line.addWidget(dot)
                line.addWidget(QLabel(cont["name"]), 1)
                b_term = QPushButton("Terminal ↗")
                b_term.setObjectName("small")
                b_term.setToolTip("Ouvre le terminal du pod dans la console OpenShift (navigateur)")
                b_term.clicked.connect(lambda _c=False: self.app.open_console(obj=obj, res=res, page="terminal"))
                b_logs = QPushButton("Logs")
                b_logs.setObjectName("small")
                b_logs.clicked.connect(lambda _c=False, c=cont["name"]: self.app.open_logs(obj, c))
                line.addWidget(b_term)
                line.addWidget(b_logs)
                self.lay.addLayout(line)
                img = QLabel(cont.get("image", ""))
                img.setObjectName("detKind")
                img.setWordWrap(True)
                img.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
                self.lay.addWidget(img)
        elif row.get("actions"):
            for label, cmd in row["actions"]:
                b = QPushButton(label)
                b.clicked.connect(lambda _c=False, f=cmd: f())
                self.lay.addWidget(b, 0, Qt.AlignmentFlag.AlignLeft)
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet(f"color: {C['line']};")
        self.lay.addSpacing(4)
        self.lay.addWidget(sep)
        grid = QGridLayout()
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(3)
        for i, (k, v) in enumerate(props[:40]):
            kl = QLabel(k)
            kl.setObjectName("propKey")
            vl = QLabel(str(v))
            vl.setTextFormat(Qt.TextFormat.PlainText)
            vl.setWordWrap(True)
            vl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            grid.addWidget(kl, i, 0, Qt.AlignmentFlag.AlignTop)
            grid.addWidget(vl, i, 1)
        grid.setColumnStretch(1, 1)
        self.lay.addLayout(grid)
        self.lay.addStretch(1)


# ======================================================================================
# Dialogues
# ======================================================================================

SEP = "::"
DEMO_NAME = "Démonstration"


def is_system_ns(ns):
    return ns.startswith(("openshift", "kube-", "ibm-", "calico-", "tigera-")) or ns in (
        "default", "kube-system", "kube-public", "kube-node-lease")


def short_path(path):
    home = os.path.expanduser("~")
    return "~" + path[len(home):] if path.startswith(home) else path


def _hint(text):
    lab = QLabel(text)
    lab.setTextFormat(Qt.TextFormat.PlainText)       # « <code> » doit s'afficher tel quel
    lab.setObjectName("hint")
    lab.setWordWrap(True)
    return lab


def split_namespaces(text):
    return [n for n in re.split(r"[\s,;]+", (text or "").strip().lower()) if n]


def open_passcode_page(parent, iam_url):
    """Ouvre la page IBM du code à usage unique dans le navigateur (seulement cette page-là, chez IBM)."""
    url = passcode_url(iam_url)
    u = urlsplit(url)
    ok = u.scheme == "https" and NET.permitted(u.hostname or "") and u.path == "/identity/passcode" \
        and QDesktopServices.openUrl(QUrl(url))
    if not ok:
        copy_text(url)
        QMessageBox.information(parent, APP_NAME, f"Adresse copiée : colle-la dans ton navigateur.\n\n{url}")


class LoginDialog(QDialog):
    """Connexion par code à usage unique. Les champs n'apparaissent que s'ils sont demandés :
    nom, serveur, namespaces (connexion directe), code, points d'accès IBM (compte IBM Cloud)."""

    def __init__(self, parent, title, intro="", iam_url=IAM_DEFAULT, name=None, server=None, namespaces=None,
                 code_required=True, cs_url=None, code_hint=None, console=None):
        super().__init__(parent)
        self.setWindowTitle(APP_NAME)
        self.setMinimumWidth(580)
        self.code_required = code_required
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 18, 20, 16)
        t = QLabel(title)
        t.setTextFormat(Qt.TextFormat.PlainText)
        t.setObjectName("h2")
        t.setWordWrap(True)
        lay.addWidget(t)
        if intro:
            lay.addWidget(_hint(intro))
        form = QFormLayout()
        form.setHorizontalSpacing(14)
        self.name = self.server = self.namespaces = self.iam = self.cs = self.console = None
        if name is not None:
            self.name = QLineEdit(name)
            form.addRow("Nom", self.name)
        if server is not None:
            self.server = QLineEdit(server)
            self.server.setPlaceholderText("https://c100-e.eu-de.containers.cloud.ibm.com:31234")
            form.addRow("Serveur", self.server)
        if namespaces is not None:
            self.namespaces = QLineEdit(namespaces)
            self.namespaces.setPlaceholderText("mon-namespace (plusieurs : séparés par des virgules)")
            form.addRow("Namespace(s)", self.namespaces)
        row = QHBoxLayout()
        self.code = QLineEdit()
        self.code.setEchoMode(QLineEdit.EchoMode.Password)
        self.code.setPlaceholderText("code à usage unique" + ("" if code_required else " (facultatif ici)"))
        row.addWidget(self.code, 1)
        self.iam_url = iam_url or IAM_DEFAULT
        get = QPushButton("Obtenir un code…")
        get.setAutoDefault(False)
        get.clicked.connect(lambda: open_passcode_page(self, self._iam_value()))
        row.addWidget(get)
        form.addRow("Code", row)
        lay.addLayout(form)
        lay.addWidget(_hint(code_hint or (
            f"Le code s'obtient sur {passcode_url(self.iam_url)} (connexion avec ton compte d'entreprise) : il ne "
            "sert qu'une fois et expire vite. Tu peux aussi coller un jeton OpenShift (sha256~…) copié depuis la "
            "console, ou une clé API si tu en as une. Rien de tout cela n'est enregistré.")))
        if cs_url is not None or (server is not None and name is not None):
            adv = QGroupBox("Avancé")
            af = QFormLayout(adv)
            self.iam = QLineEdit(self.iam_url)
            af.addRow("Point d'accès IAM", self.iam)
            if cs_url is not None:
                self.cs = QLineEdit(cs_url)
                af.addRow("Point d'accès Containers", self.cs)
            if console is not None:
                self.console = QLineEdit(console)
                self.console.setPlaceholderText("trouvée toute seule à la connexion (comme oc whoami --show-console)")
                af.addRow("Console web", self.console)
            af.addRow("", _hint("Réseau privé IBM : https://private.iam.cloud.ibm.com"
                                + (" · https://private.containers.cloud.ibm.com" if cs_url is not None else "")))
            lay.addWidget(adv)
        bb = QDialogButtonBox()
        ok = bb.addButton("Se connecter" if code_required else "Enregistrer", QDialogButtonBox.ButtonRole.AcceptRole)
        ok.setDefault(True)
        bb.addButton("Annuler", QDialogButtonBox.ButtonRole.RejectRole)
        bb.accepted.connect(self._ok)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)
        first = next(w for w in (self.server if server == "" else None, self.namespaces if namespaces == "" else None,
                                 self.code) if w is not None)
        first.setFocus()
        self.result_data = None

    def _iam_value(self):
        return ((self.iam.text().strip() if self.iam is not None else "") or self.iam_url).rstrip("/")

    def _https(self, label, url):
        u = urlsplit(url)
        if u.scheme != "https" or not u.hostname:
            QMessageBox.warning(self, APP_NAME, f"{label} : l'adresse doit commencer par https://")
            return False
        return True

    def _ok(self):
        r = {"code": self.code.text().strip()}
        outside = []
        if self.name is not None:
            r["name"] = self.name.text().strip().replace(SEP, ":")
            if not r["name"] or r["name"] == DEMO_NAME:
                QMessageBox.warning(self, APP_NAME, "Donne un nom à la connexion (autre que « Démonstration »).")
                return
        if self.server is not None:
            srv = self.server.text().strip().rstrip("/")
            if srv and "://" not in srv:
                srv = "https://" + srv
            if not self._https("Serveur", srv):
                return
            r["server"] = srv
            outside.append(srv)
        if self.namespaces is not None:
            nss = split_namespaces(self.namespaces.text())
            bad = [n for n in nss if not NS_RE.match(n) or len(n) > 63]
            if bad:
                QMessageBox.warning(self, APP_NAME, "Nom de namespace invalide : " + ", ".join(bad))
                return
            r["namespaces"] = nss
        if self.iam is not None:
            r["iamUrl"] = self._iam_value()
            if not self._https("Point d'accès IAM", r["iamUrl"]):
                return
            outside.append(r["iamUrl"])
        if self.console is not None:
            r["console"] = self.console.text().strip().rstrip("/")
            if r["console"] and not self._https("Console web", r["console"]):
                return
        if self.cs is not None:
            r["csUrl"] = self.cs.text().strip().rstrip("/") or CS_DEFAULT
            if not self._https("Point d'accès Containers", r["csUrl"]):
                return
            outside.append(r["csUrl"])
        if self.code_required and not r["code"]:
            QMessageBox.warning(self, APP_NAME, "Saisis le code à usage unique (bouton « Obtenir un code… »).")
            return
        outside = [u for u in outside if not NET.permitted(urlsplit(u).hostname or "")]
        if outside and not confirm(self, APP_NAME, "Ces adresses ne sont pas chez IBM Cloud :\n\n  "
                                   + "\n  ".join(outside) + "\n\nTes codes de connexion leur seront envoyés. "
                                   "Continuer ?", ok="Continuer"):
            return
        self.result_data = r
        self.accept()


def ask_login(parent, **kw):
    """Affiche la fenêtre de connexion ; renvoie les champs saisis, ou None si annulé."""
    d = LoginDialog(parent, **kw)
    return d.result_data if d.exec() == QDialog.DialogCode.Accepted else None


class SettingsDialog(QDialog):
    def __init__(self, parent, settings):
        super().__init__(parent)
        self.setWindowTitle("Paramètres")
        self.setMinimumWidth(620)
        self.s = dict(settings)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 14, 16, 14)
        tabs = QTabWidget()
        tabs.setObjectName("pivot")
        tabs.setDocumentMode(True)
        lay.addWidget(tabs, 1)

        net = QWidget()
        nl = QVBoxLayout(net)
        self.mac = QCheckBox("Faire confiance aux certificats du Mac (trousseau Système, dont ceux de l'entreprise)")
        self.mac.setChecked(bool(self.s.get("useMacCerts", True)))
        nl.addWidget(self.mac)
        row = QHBoxLayout()
        self.ca = QLineEdit(self.s.get("caFile", ""))
        self.ca.setPlaceholderText("Certificat racine de l'entreprise (.pem), si le proxy en ajoute un")
        b = QPushButton("Parcourir…")
        b.clicked.connect(self._pick_ca)
        row.addWidget(QLabel("Certificat :"))
        row.addWidget(self.ca, 1)
        row.addWidget(b)
        nl.addLayout(row)
        row = QHBoxLayout()
        self.proxy_mode = QComboBox()
        self.proxy_mode.addItems(["Automatique (réglages du Mac)", "Aucun", "Adresse :"])
        self.proxy_url = QLineEdit()
        self.proxy_url.setPlaceholderText("http://proxy.entreprise:8080")
        mode = self.s.get("proxy", "auto")
        if mode == "auto":
            self.proxy_mode.setCurrentIndex(0)
        elif mode == "none":
            self.proxy_mode.setCurrentIndex(1)
        else:
            self.proxy_mode.setCurrentIndex(2)
            self.proxy_url.setText(mode)
        self.proxy_mode.currentIndexChanged.connect(lambda i: self.proxy_url.setEnabled(i == 2))
        self.proxy_url.setEnabled(self.proxy_mode.currentIndex() == 2)
        row.addWidget(QLabel("Proxy :"))
        row.addWidget(self.proxy_mode)
        row.addWidget(self.proxy_url, 1)
        nl.addLayout(row)
        nl.addWidget(QLabel("Domaines autorisés en plus de *.cloud.ibm.com (un par ligne) :"))
        self.domains = QPlainTextEdit("\n".join(self.s.get("extraDomains") or []))
        self.domains.setFixedHeight(70)
        nl.addWidget(self.domains)
        nl.addWidget(_hint("Le programme refuse toute autre destination. Ajoute un domaine seulement si un cluster "
                           "ou un point d'accès de ton entreprise est ailleurs (exemple : appdomain.cloud)."))
        opened = hotes_autorises()
        info = QPlainTextEdit("\n".join(opened) if opened else "(aucune connexion pour l'instant)")
        info.setReadOnly(True)
        info.setFixedHeight(80)
        nl.addWidget(QLabel("Adresses contactées depuis le lancement :"))
        nl.addWidget(info)
        nl.addStretch(1)
        tabs.addTab(net, "Réseau")

        logs = QWidget()
        lf = QFormLayout(logs)
        self.tail = QComboBox()
        self.tail.addItems(["100", "500", "1000", "5000"])
        self.tail.setCurrentText(str(self.s.get("logTail", 500)))
        lf.addRow("Lignes affichées par défaut", self.tail)
        tabs.addTab(logs, "Logs")

        bb = QDialogButtonBox()
        ok = bb.addButton("Enregistrer", QDialogButtonBox.ButtonRole.AcceptRole)
        ok.setDefault(True)
        bb.addButton("Annuler", QDialogButtonBox.ButtonRole.RejectRole)
        bb.accepted.connect(self._ok)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)

    def _pick_ca(self):
        path, _f = QFileDialog.getOpenFileName(self, "Certificat racine", os.path.expanduser("~"),
                                               "Certificats (*.pem *.crt *.cer);;Tous les fichiers (*)")
        if path:
            self.ca.setText(path)

    def _ok(self):
        ca = self.ca.text().strip()
        if ca:
            try:
                ssl.create_default_context().load_verify_locations(cafile=os.path.expanduser(ca))
            except (OSError, ssl.SSLError) as exc:
                QMessageBox.warning(self, APP_NAME, f"Ce certificat est illisible :\n{exc}")
                return
        idx = self.proxy_mode.currentIndex()
        proxy = "auto" if idx == 0 else "none" if idx == 1 else (self.proxy_url.text().strip() or "auto")
        doms = []
        for d in self.domains.toPlainText().split():
            d = d.strip().lower().lstrip("*.").lstrip(".")
            if d and "." in d and re.match(r"^[a-z0-9.-]+$", d) and d not in doms:
                doms.append(d)
        self.s.update(useMacCerts=self.mac.isChecked(), caFile=ca, proxy=proxy, extraDomains=doms,
                      logTail=int(self.tail.currentText()))
        self.accept()


# ======================================================================================
# Fenêtre principale
# ======================================================================================

class PaaSWindow(QMainWindow):
    def __init__(self, config):
        super().__init__()
        self.config = config
        self.setWindowTitle(APP_NAME)
        self.setWindowIcon(Icons.get("kubernetes"))
        self.account_meta = {a["name"]: a for a in config.accounts}
        self.accounts = {}       # nom -> IbmAccount | DemoAccount (seulement quand la clé est connue)
        self.clusters = {}       # (compte, id) -> cluster
        self.kubes = {}          # (compte, id) -> client
        self.namespaces = {}     # (compte, id) -> [noms]
        self.loc = {"view": "home"}
        self.back, self.fwd = [], []
        self._load_seq = 0
        self._shown_loc = None
        self._busy = 0
        self._flash_token = 0
        self._syncing = False
        self.nav_items = {}
        self._notice = {}        # (compte, cluster) -> message à afficher dans la prochaine fenêtre du code
        self._auto_prompt = {}   # (compte, cluster) -> heure de la dernière demande automatique de code
        self._relays = []
        self._pending = {}       # (compte, cluster) -> rappels en attente d'une connexion en cours
        self._listing = set()    # comptes IBM dont la liste des clusters est en cours de chargement

        self._build_actions()
        self._build_menus()
        central = QWidget()
        cl = QVBoxLayout(central)
        cl.setContentsMargins(0, 0, 0, 0)
        cl.setSpacing(0)
        cl.addWidget(self._build_commandbar())
        cl.addWidget(self._build_addressbar())
        cl.addWidget(self._build_body(), 1)
        self.setCentralWidget(central)
        self._build_statusbar()
        self._load_accounts()
        self._restore_geometry()
        self.navigate({"view": "home"}, push=False)
        if config.imported:
            QTimer.singleShot(400, lambda: self.flash(
                "Comptes repris du PaaSExplorer d'origine (sans leurs clés : tu les retaperas).", 12000))

    # ------------------------------------------------------------------ actions
    def _action(self, text, slot, keys=(), icon=None, checkable=False):
        act = QAction(text, self)
        act.setMenuRole(QAction.MenuRole.NoRole)
        if icon:
            act.setIcon(Glyphs.get(icon))
        if keys:
            act.setShortcuts([QKeySequence(k) for k in keys])
        act.setCheckable(checkable)
        if checkable:
            act.toggled.connect(lambda on, f=slot: f(on))
        else:
            act.triggered.connect(lambda _c=False, f=slot: f())
        self.addAction(act)
        return act

    def _build_actions(self):
        A = self._action
        mac = IS_MAC
        self.act_add = A("Nouvelle connexion à un cluster…", self.add_connection, ["Ctrl+N"], "plus")
        self.act_add_ibm = A("Ajouter un compte IBM Cloud…", self.add_account)
        self.act_edit = A("Modifier la connexion sélectionnée…", self.edit_account)
        self.act_remove = A("Retirer la connexion sélectionnée", self.remove_account)
        self.act_forget = A("Fermer toutes les sessions", self.forget_secrets)
        self.act_settings = A("Paramètres…", self.open_settings, ["Ctrl+,"], "settings")
        self.act_close_tab = A("Fermer l'onglet", lambda: self.close_tab(self.tabs.currentIndex()), ["Ctrl+W"])
        self.act_quit = A("Quitter", self.close, ["Ctrl+Q"])
        self.act_copy = A("Copier", self.edit_copy, ["Ctrl+C"], "copy")
        self.act_paste = A("Coller", self.edit_paste, ["Ctrl+V"])
        self.act_select_all = A("Tout sélectionner", self.edit_select_all, ["Ctrl+A"])
        self.act_find = A("Rechercher", self.focus_search, ["Ctrl+F"], "search")
        self.act_refresh = A("Actualiser", self.refresh, ["F5", "Ctrl+R"], "refresh")
        self.act_details = A("Volet des détails", self.toggle_details, ["Ctrl+Alt+P", "Alt+Shift+P"], "pane",
                             checkable=True)
        self.act_system = A("Afficher les namespaces système", self.toggle_system, (), checkable=True)
        self.act_back = A("Précédent", self.go_back, ["Alt+Left", "Ctrl+["], "back")
        self.act_fwd = A("Suivant", self.go_forward, ["Alt+Right", "Ctrl+]"], "forward")
        self.act_up = A("Dossier parent", self.go_up, ["Alt+Up", "Ctrl+Up"], "up")
        self.act_next_tab = A("Onglet suivant", lambda: self.cycle_tab(1),
                              ["Meta+Tab", "Ctrl+Shift+]"] if mac else ["Ctrl+Tab"])
        self.act_prev_tab = A("Onglet précédent", lambda: self.cycle_tab(-1),
                              ["Meta+Shift+Tab", "Ctrl+Shift+["] if mac else ["Ctrl+Shift+Tab"])
        self.act_terminal = A("Terminal du pod (console OpenShift)", self.action_terminal, ["Ctrl+T"], "terminal")
        self.act_logs = A("Afficher les logs", self.action_logs, ["Ctrl+L"], "logs")
        self.act_yaml = A("Afficher le YAML", self.action_yaml, ["Ctrl+Y"], "yaml")
        self.act_console = A("Ouvrir dans la console OpenShift (pour modifier)", lambda: self.open_console(),
                             ["Ctrl+Shift+O"], "external")
        self.act_console_yaml = A("Modifier le YAML dans la console OpenShift", lambda: self.open_console(page="yaml"))
        self.act_cluster_console = A("Ouvrir la console du cluster", lambda: self.open_console(scope="cluster"))
        self.act_portal = A("Ouvrir le cluster dans le portail IBM Cloud", self.open_portal)
        self.act_fav = A("Ajouter aux favoris", self.toggle_favorite, ["Ctrl+D"], "star")
        self.act_goto = A("Rechercher un namespace ou un favori", self.focus_nav_search, ["Ctrl+P", "Ctrl+K"])
        self.act_private = A("Utiliser le point d'accès privé du cluster", self.toggle_private, (), checkable=True)
        self.act_reconnect = A("Reconnecter le cluster", self.reconnect)
        self.act_copy_cli = A("Copier la commande de connexion (CLI)", self.copy_cli, (), "copy")
        self.act_shortcuts = A("Raccourcis clavier", self.show_shortcuts)
        self.act_demo = A("Mode démonstration", self.toggle_demo, (), checkable=True)
        self.act_lock = A("Verrou réseau et destinations autorisées…", self.show_lock)
        self.act_about = A(f"À propos de {APP_NAME}", self.about)
        self.act_details.blockSignals(True)
        self.act_details.setChecked(bool(self.config.settings.get("detailsPane", True)))
        self.act_details.blockSignals(False)
        self.act_system.blockSignals(True)
        self.act_system.setChecked(bool(self.config.settings.get("showSystemNamespaces", False)))
        self.act_system.blockSignals(False)

    def _build_menus(self):
        mb = self.menuBar()

        def menu(title, items):
            m = mb.addMenu(title)
            for it in items:
                m.addSeparator() if it is None else m.addAction(it)
            style_menu(m)
            return m
        menu("Fichier", [self.act_add, self.act_add_ibm, None, self.act_edit, self.act_remove, self.act_forget, None,
                         self.act_settings, None,
                         self.act_close_tab, None, self.act_quit])
        menu("Édition", [self.act_copy, self.act_paste, self.act_select_all, None, self.act_find])
        menu("Affichage", [self.act_refresh, None, self.act_details, self.act_system, None, self.act_back,
                           self.act_fwd, self.act_up, None, self.act_next_tab, self.act_prev_tab, None,
                           self.act_fav, self.act_goto])
        menu("Cluster", [self.act_logs, self.act_yaml, None, self.act_console, self.act_console_yaml,
                         self.act_terminal, self.act_cluster_console, self.act_portal, None,
                         self.act_private, self.act_reconnect,
                         self.act_copy_cli])
        menu("Aide", [self.act_shortcuts, None, self.act_demo, None, self.act_lock, self.act_about])

    def _build_commandbar(self):
        bar = QFrame()
        bar.setObjectName("cmdbar")
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(8, 4, 8, 4)
        lay.setSpacing(2)
        self.cmd = {}

        def btn(key, text, act, tip=""):
            b = QToolButton()
            b.setText(text)
            b.setIcon(act.icon())
            b.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
            b.setToolTip(tip or act.text())
            b.clicked.connect(lambda _c=False: act.trigger())
            lay.addWidget(b)
            self.cmd[key] = b
            return b

        def sep():
            s = QFrame()
            s.setObjectName("cmdsep")
            s.setFixedSize(1, 22)
            lay.addSpacing(4)
            lay.addWidget(s)
            lay.addSpacing(4)
        btn("add", "Connexion", self.act_add)
        sep()
        btn("refresh", "Actualiser", self.act_refresh)
        sep()
        btn("logs", "Logs", self.act_logs)
        btn("yaml", "YAML", self.act_yaml)
        sep()
        cons = btn("console", "Console", self.act_console,
                   "Ouvre la page de l'objet (ou du namespace) dans la console OpenShift : c'est là que se font "
                   "les modifications (mettre à l'échelle, redémarrer, supprimer, modifier)")
        cmenu = QMenu(cons)
        for act in (self.act_console, self.act_console_yaml, self.act_terminal, None, self.act_cluster_console,
                    self.act_portal):
            cmenu.addSeparator() if act is None else cmenu.addAction(act)
        style_menu(cmenu)
        cons.setMenu(cmenu)
        cons.setPopupMode(QToolButton.ToolButtonPopupMode.MenuButtonPopup)
        btn("terminal", "Terminal", self.act_terminal, "Ouvre le terminal du pod dans la console OpenShift")
        sep()
        fav = btn("fav", "Favori", self.act_fav, "Ajouter ou retirer l'endroit affiché des favoris (Cmd+D)")
        fav.setCheckable(True)
        lay.addStretch(1)
        ro = QLabel("Lecture seule")
        ro.setObjectName("badgeRO")
        ro.setToolTip("Cet outil ne modifie rien. Pour modifier : bouton « Console » (console OpenShift).")
        lay.addWidget(ro)
        lay.addSpacing(6)
        b = btn("details", "Détails", self.act_details)
        b.setCheckable(True)
        b.setChecked(self.act_details.isChecked())
        self.act_details.toggled.connect(b.setChecked)
        return bar

    def _build_addressbar(self):
        row = QFrame()
        row.setObjectName("addrRow")
        lay = QHBoxLayout(row)
        lay.setContentsMargins(6, 6, 8, 6)
        lay.setSpacing(4)
        for act in (self.act_back, self.act_fwd, self.act_up):
            b = QToolButton()
            b.setIcon(act.icon())
            b.setToolTip(act.text())
            b.clicked.connect(lambda _c=False, a=act: a.trigger())
            lay.addWidget(b)
        self.crumbs = QFrame()
        self.crumbs.setObjectName("addressBar")
        self.crumbs.setFixedHeight(32)
        self.crumb_lay = QHBoxLayout(self.crumbs)
        self.crumb_lay.setContentsMargins(6, 0, 6, 0)
        self.crumb_lay.setSpacing(0)
        lay.addWidget(self.crumbs, 1)
        self.search = QLineEdit()
        self.search.setObjectName("searchBox")
        self.search.setClearButtonEnabled(True)
        self.search.setFixedWidth(280)
        self.search.addAction(Glyphs.get("search", C["text2"]), QLineEdit.ActionPosition.LeadingPosition)
        self.search.textChanged.connect(lambda _t: self._apply_filter())
        lay.addWidget(self.search)
        esc = QAction(self.search)
        esc.setShortcut(QKeySequence(Qt.Key.Key_Escape))
        esc.setShortcutContext(Qt.ShortcutContext.WidgetShortcut)
        esc.triggered.connect(self.search.clear)
        self.search.addAction(esc)
        return row

    def _build_body(self):
        self.split = QSplitter(Qt.Orientation.Horizontal)
        self.split.setChildrenCollapsible(False)
        self.nav = QTreeWidget()
        self.nav.setObjectName("nav")
        self.nav.setHeaderHidden(True)
        self.nav.setIconSize(QSize(16, 16))
        self.nav.setIndentation(14)
        self.nav.setMinimumWidth(180)
        self.nav.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.nav.customContextMenuRequested.connect(self._nav_menu)
        self.nav.itemExpanded.connect(lambda it: self._expand(it.data(0, Qt.ItemDataRole.UserRole)))
        self.nav.currentItemChanged.connect(self._nav_current)
        self.nav.itemClicked.connect(self._nav_clicked)
        pane = QWidget()
        pane.setObjectName("navPane")
        pl = QVBoxLayout(pane)
        pl.setContentsMargins(6, 6, 0, 0)
        pl.setSpacing(4)
        self.nav_search = QLineEdit()
        self.nav_search.setObjectName("navSearch")
        self.nav_search.setClearButtonEnabled(True)
        self.nav_search.setPlaceholderText("Namespace ou favori…")
        self.nav_search.setToolTip("Filtre l'arbre : namespaces (nsxxxx), favoris, clusters. Entrée : ouvrir le "
                                   "premier trouvé. " + QKeySequence("Ctrl+P").toString(
                                       QKeySequence.SequenceFormat.NativeText))
        self.nav_search.addAction(Glyphs.get("search", C["text2"]), QLineEdit.ActionPosition.LeadingPosition)
        self.nav_search.textChanged.connect(self._filter_nav)
        self.nav_search.returnPressed.connect(self._nav_search_go)
        esc = QAction(self.nav_search)
        esc.setShortcut(QKeySequence(Qt.Key.Key_Escape))
        esc.setShortcutContext(Qt.ShortcutContext.WidgetShortcut)
        esc.triggered.connect(self.nav_search.clear)
        self.nav_search.addAction(esc)
        down = QAction(self.nav_search)
        down.setShortcut(QKeySequence(Qt.Key.Key_Down))
        down.setShortcutContext(Qt.ShortcutContext.WidgetShortcut)
        down.triggered.connect(self.nav.setFocus)
        self.nav_search.addAction(down)
        pl.addWidget(self.nav_search)
        pl.addWidget(self.nav, 1)
        self.split.addWidget(pane)

        self.tabs = QTabWidget()
        self.tabs.setObjectName("main")
        self.tabs.setDocumentMode(True)
        self.tabs.setTabsClosable(True)
        self.tabs.setMovable(True)
        self.tabs.setUsesScrollButtons(True)
        self.tabs.setElideMode(Qt.TextElideMode.ElideRight)
        self.tabs.tabCloseRequested.connect(self.close_tab)
        self.tabs.tabBar().setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tabs.tabBar().customContextMenuRequested.connect(self._tab_menu)
        self.tabs.tabBar().installEventFilter(self)
        self.stack = QStackedWidget()
        self.stack.setObjectName("page")
        self.listview = ListView()
        self.listview.selection_changed.connect(self._selection_changed)
        self.listview.activated.connect(self._list_open)
        self.listview.menu_requested.connect(self._list_menu)
        self.listview.counts_changed.connect(self.update_status_counts)
        up = QAction(self.listview.tree)
        up.setShortcut(QKeySequence(Qt.Key.Key_Backspace))
        up.setShortcutContext(Qt.ShortcutContext.WidgetShortcut)
        up.triggered.connect(self.go_up)
        self.listview.tree.addAction(up)
        self.overview = OverviewView(self.open_helm_tab)
        self.topology = TopologyView(self.open_yaml_by_kind)
        self.message = QWidget()
        self.message.setObjectName("page")
        for w in (self.listview, self.overview, self.topology, self.message):
            self.stack.addWidget(w)
        self.tabs.addTab(self.stack, Icons.get("folder"), "Explorateur")
        for side in (QTabBar.ButtonPosition.LeftSide, QTabBar.ButtonPosition.RightSide):
            self.tabs.tabBar().setTabButton(0, side, None)
        self.split.addWidget(self.tabs)
        self.details = DetailsPane(self)
        self.split.addWidget(self.details)
        self.split.setStretchFactor(0, 0)
        self.split.setStretchFactor(1, 1)
        self.split.setStretchFactor(2, 0)
        nav_w = int(self.config.settings.get("navWidth", 290) or 290)
        self.split.setSizes([nav_w, 900, 300])
        self.details.setVisible(self.act_details.isChecked())
        return self.split

    def _build_statusbar(self):
        sb = self.statusBar()
        sb.setSizeGripEnabled(False)
        self.st_count = QLabel("")
        self.st_msg = QLabel("")
        sb.addWidget(self.st_count)
        sb.addWidget(self.st_msg, 1)
        self.st_demo = QLabel("MODE DÉMO")
        self.st_demo.setObjectName("badgeDemo")
        self.st_demo.hide()
        self.st_conn = QLabel("Non connecté")
        self.st_ver = QLabel(f"v{VERSION}")
        self.st_ver.setToolTip(version_details())
        for w in (self.st_demo, self.st_conn, self.st_ver):
            sb.addPermanentWidget(w)

    def _restore_geometry(self):
        geo = self.config.settings.get("windowGeometry") or ""
        ok = False
        if geo:
            try:
                ok = self.restoreGeometry(QByteArray.fromBase64(geo.encode()))
            except Exception:  # noqa: BLE001
                ok = False
        if not ok:
            self.resize(1320, 820)

    # ------------------------------------------------------------------ utilitaires
    def flash(self, text, ms=5000):
        self._flash_token += 1
        tok = self._flash_token
        self.st_msg.setText(text)
        QTimer.singleShot(ms, lambda: tok == self._flash_token and self.st_msg.setText(""))

    def bg(self, fn, ok=None, err=None):
        """Lance fn() en arrière-plan ; ok(résultat) ou err(message) ensuite, dans l'interface."""
        self._busy += 1
        if self._busy == 1:
            QApplication.setOverrideCursor(Qt.CursorShape.BusyCursor)

        def done(res, error):
            self._busy = max(0, self._busy - 1)
            if self._busy == 0:
                QApplication.restoreOverrideCursor()
            if error is not None:
                if err:
                    err(error)
                else:
                    self.flash(f"Erreur : {error}", 10000)
                    QMessageBox.warning(self, APP_NAME, str(error))
            elif ok:
                ok(res)
        run_async(fn, done)

    def _save(self):
        try:
            self.config.save()
        except OSError as exc:
            self.flash(f"Réglages non enregistrés : {exc}", 10000)

    def _kube(self):
        return self.kubes.get((self.loc.get("acc"), self.loc.get("cid")))

    # ------------------------------------------------------------------ arbre de navigation
    def _nav_add(self, parent_iid, iid, text, icon=None, index=None, placeholder=None, color=None):
        it = QTreeWidgetItem([text])
        it.setData(0, Qt.ItemDataRole.UserRole, iid)
        if icon:
            it.setIcon(0, Icons.get(icon))
        if color:
            it.setForeground(0, QBrush(QColor(color)))
        parent = self.nav_items.get(parent_iid) if parent_iid else None
        if parent is None:
            if index is None:
                self.nav.addTopLevelItem(it)
            else:
                self.nav.insertTopLevelItem(index, it)
        else:
            parent.addChild(it)
        self.nav_items[iid] = it
        if placeholder is not None:
            ph = QTreeWidgetItem([placeholder])
            ph.setData(0, Qt.ItemDataRole.UserRole, iid + SEP + "~")
            ph.setFlags(Qt.ItemFlag.ItemIsEnabled)
            ph.setForeground(0, QBrush(QColor(C["text2"])))
            it.addChild(ph)
            self.nav_items[iid + SEP + "~"] = ph
        return it

    def _nav_children(self, iid):
        it = self.nav_items.get(iid)
        if it is None:
            return []
        return [it.child(i).data(0, Qt.ItemDataRole.UserRole) for i in range(it.childCount())]

    def _nav_is_lazy(self, iid):
        kids = self._nav_children(iid)
        return len(kids) == 1 and str(kids[0]).endswith(SEP + "~")

    def _nav_set_placeholder(self, iid, text):
        ph = self.nav_items.get(iid + SEP + "~")
        if ph is not None:
            ph.setText(0, text)

    def _nav_clear(self, iid):
        it = self.nav_items.get(iid)
        if it is None:
            return
        for child_iid in list(self._descendants(it)):
            self.nav_items.pop(child_iid, None)
        it.takeChildren()

    def _descendants(self, it):
        for i in range(it.childCount()):
            ch = it.child(i)
            yield ch.data(0, Qt.ItemDataRole.UserRole)
            yield from self._descendants(ch)

    def _nav_remove(self, iid):
        it = self.nav_items.get(iid)
        if it is None:
            return
        self._nav_clear(iid)
        self.nav_items.pop(iid, None)
        parent = it.parent()
        if parent is None:
            self.nav.takeTopLevelItem(self.nav.indexOfTopLevelItem(it))
        else:
            parent.removeChild(it)

    def _nav_current(self, cur, _prev):
        if self._syncing or cur is None:
            return
        loc = self._loc_from_iid(cur.data(0, Qt.ItemDataRole.UserRole) or "")
        if loc and loc != self.loc:
            self.navigate(loc)

    def _nav_clicked(self, item, _col):
        if self._syncing:
            return
        loc = self._loc_from_iid(item.data(0, Qt.ItemDataRole.UserRole) or "")
        if loc and loc != self.loc:
            self.navigate(loc)
        elif not loc and str(item.data(0, Qt.ItemDataRole.UserRole)).startswith("G" + SEP):
            item.setExpanded(not item.isExpanded())

    # ------------------------------------------------------------------ connexions et comptes
    def _load_accounts(self):
        self._render_favorites()
        for a in self.config.accounts:
            self._register_account(a)

    @staticmethod
    def _is_direct(meta):
        return (meta or {}).get("kind") == "cluster"

    def _acc_iid(self, name):
        meta = self.account_meta.get(name)
        return f"C{SEP}{name}{SEP}{DirectAccount.CID}" if self._is_direct(meta) else f"A{SEP}{name}"

    def _known_namespaces(self, acc, cid):
        """Namespaces déjà connus d'une connexion (indiqués à la main + vus à la dernière connexion)."""
        meta = self.account_meta.get(acc, {})
        cached = self.config.data.get("nsCache", {}).get(f"{acc}{SEP}{cid}", [])
        names = set(meta.get("namespaces", []) if self._is_direct(meta) else []) | set(cached)
        show_sys = self.act_system.isChecked()
        return sorted(n for n in names if show_sys or not is_system_ns(n) or n in meta.get("namespaces", []))

    def _register_account(self, meta, index=None):
        name = meta["name"]
        self.account_meta[name] = meta
        if self._is_direct(meta):
            acc = self.accounts[name] = DirectAccount(meta)
            self.clusters[(name, acc.CID)] = acc.cluster()
            iid = self._acc_iid(name)
            if iid not in self.nav_items:
                known = self._known_namespaces(name, acc.CID)
                self._nav_add(None, iid, name, "openshift", index=index,
                              placeholder=None if known else "Code à saisir (clic pour se connecter)")
                for ns in known:            # namespaces déjà connus : visibles (et cherchables) avant connexion
                    self._nav_add(iid, f"N{SEP}{name}{SEP}{acc.CID}{SEP}{ns}", ns,
                                  "folder_sys" if is_system_ns(ns) else "folder", placeholder="")
            return
        secret = SESSION_SECRETS.get(name)
        if secret:
            self.accounts[name] = IbmAccount(name, apikey=secret, iam_url=meta.get("iamUrl"),
                                             cs_url=meta.get("csUrl"))
        iid = f"A{SEP}{name}"
        if iid not in self.nav_items:
            self._nav_add(None, iid, name, "account", index=index,
                          placeholder="Chargement…" if secret else "Code à saisir (clic pour se connecter)")

    def _ensure_account(self, name, ask=True, notice=""):
        """Compte IBM Cloud ouvert ; demande un code à usage unique (ou une clé API) si besoin."""
        acc = self.accounts.get(name)
        if acc is not None or not ask:
            return acc
        meta = self.account_meta.get(name)
        if not meta:
            return None
        r = ask_login(self, title=f"Compte IBM Cloud « {name} »",
                      intro=(notice.rstrip(".") + ".\n\n" if notice else "") +
                      "Comme « ibmcloud login --sso » : un code à usage unique suffit (pas de clé API).",
                      iam_url=meta.get("iamUrl"))
        if not r or not r.get("code"):
            return None
        return self._open_ibm(meta, r["code"])

    def _open_ibm(self, meta, code):
        name = meta["name"]
        if is_api_key(code):
            SESSION_SECRETS[name] = code
            acc = IbmAccount(name, apikey=code, iam_url=meta.get("iamUrl"), cs_url=meta.get("csUrl"))
        else:
            acc = IbmAccount(name, passcode=code, iam_url=meta.get("iamUrl"), cs_url=meta.get("csUrl"))
        self.accounts[name] = acc
        self._nav_set_placeholder(f"A{SEP}{name}", "Chargement…")
        return acc

    def add_connection(self):
        """Connexion directe à un cluster OpenShift : serveur + namespace(s) + code à usage unique."""
        r = ask_login(self, title="Nouvelle connexion à un cluster OpenShift",
                      intro="Comme « oc login -u passcode -p <code> --server=<serveur> », puis « oc project "
                            "<namespace> ». L'adresse du serveur figure dans la console IBM Cloud (« Master URL ») "
                            "ou dans la commande de connexion de la console OpenShift.",
                      name="", server="", namespaces="", iam_url=IAM_DEFAULT, console="")
        if r:
            self._store_meta(r, None, r.get("code"))

    def add_account(self):
        r = ask_login(self, title="Nouveau compte IBM Cloud",
                      intro="Liste les clusters du compte, si tes droits IBM le permettent. Sinon, utilise plutôt "
                            "« Nouvelle connexion à un cluster » (serveur + namespace).",
                      name="Mon compte IBM Cloud", iam_url=IAM_DEFAULT, cs_url=CS_DEFAULT)
        if r:
            self._store_meta(dict(r, kind="ibm"), None, r.get("code"))

    def _store_meta(self, r, old_name, code=None):
        meta = clean_account(r)
        if old_name:
            secret = SESSION_SECRETS.pop(old_name, None)
            self._forget_account(old_name)
            if secret and not code:
                SESSION_SECRETS[meta["name"]] = secret
        self._forget_account(meta["name"])
        self.config.data["accounts"] = [a for a in self.config.accounts if a["name"] not in (meta["name"], old_name)]
        self.config.data["accounts"].append(meta)
        self.account_meta.pop(old_name, None)
        self._save()
        self._register_account(meta)
        if self._is_direct(meta):
            loc = {"view": "cluster", "acc": meta["name"], "cid": DirectAccount.CID}
            if code:
                def failed(e):
                    QMessageBox.warning(self, APP_NAME, f"Connexion à « {meta['name']} » impossible :\n\n{e}")
                    self.navigate({"view": "home"}) if self.loc.get("view") != "home" else self.load_view()
                self._connect(meta["name"], DirectAccount.CID,
                              lambda kube: (self._fill_cluster(meta["name"], DirectAccount.CID), self.navigate(loc)),
                              on_err=failed, code=code)
                return
            self.navigate(loc)
            return
        if code and meta["name"] not in self.accounts:
            self._open_ibm(meta, code)
        it = self.nav_items.get(f"A{SEP}{meta['name']}")
        if it is not None and meta["name"] in self.accounts:
            it.setExpanded(True)
        self.navigate({"view": "account", "acc": meta["name"]})

    def _selected_account(self):
        name = self.loc.get("acc")
        if self.loc.get("view") == "home":
            sel = self.listview.selected()
            name = sel[0]["id"] if sel else None
        return name if name and name != DEMO_NAME and name in self.account_meta else None

    def edit_account(self):
        name = self._selected_account()
        if not name:
            QMessageBox.information(self, APP_NAME, "Sélectionne d'abord une connexion ou un compte.")
            return
        meta = self.account_meta[name]
        if self._is_direct(meta):
            r = ask_login(self, title=f"Connexion « {name} »", name=name, server=meta["server"],
                          namespaces=", ".join(meta.get("namespaces", [])), iam_url=meta.get("iamUrl"),
                          code_required=False, console=meta.get("console", ""))
        else:
            r = ask_login(self, title=f"Compte IBM Cloud « {name} »", name=name, iam_url=meta.get("iamUrl"),
                          cs_url=meta.get("csUrl"), code_required=False)
            if r:
                r["kind"] = "ibm"
        if r:
            self._store_meta(r, name, r.get("code"))

    def remove_account(self):
        name = self._selected_account()
        if not name:
            QMessageBox.information(self, APP_NAME, "Sélectionne d'abord une connexion ou un compte.")
            return
        if not confirm(self, APP_NAME, f"Retirer « {name} » de la liste ?\n\n(Rien n'est supprimé chez IBM Cloud "
                                       "ni sur le cluster.)", ok="Retirer"):
            return
        self._forget_account(name)
        SESSION_SECRETS.pop(name, None)
        self.account_meta.pop(name, None)
        self.config.data["accounts"] = [a for a in self.config.accounts if a["name"] != name]
        self._save()
        self.navigate({"view": "home"})

    def _forget_account(self, name):
        iid = self._acc_iid(name) if name in self.account_meta else None
        self.accounts.pop(name, None)
        for k in [k for k in self.kubes if k[0] == name]:
            self.kubes.pop(k)
        for k in [k for k in self.clusters if k[0] == name]:
            self.clusters.pop(k)
        for i in {iid, f"A{SEP}{name}", f"C{SEP}{name}{SEP}{DirectAccount.CID}"} - {None}:
            self._nav_remove(i)

    def forget_secrets(self):
        """Ferme toutes les sessions : codes, jetons et clés sont oubliés (ils seront redemandés)."""
        SESSION_SECRETS.clear()
        for name, meta in list(self.account_meta.items()):
            self._forget_account(name)
            self._register_account(meta)
        self.flash("Sessions fermées : un nouveau code sera demandé.")
        if self.loc.get("acc") in self.account_meta:
            self.navigate({"view": "home"})

    def toggle_demo(self, on):
        iid = f"A{SEP}{DEMO_NAME}"
        if on:
            self.accounts[DEMO_NAME] = DemoAccount()
            if iid not in self.nav_items:
                self._nav_add(None, iid, f"{DEMO_NAME} (données simulées)", "account", index=0,
                              placeholder="Chargement…", color="#A4239A")
            self.st_demo.show()
            self.nav_items[iid].setExpanded(True)
            self.navigate({"view": "account", "acc": DEMO_NAME})
            self.flash("Mode démonstration : données simulées, aucune connexion.")
        else:
            self._forget_account(DEMO_NAME)
            self.st_demo.hide()
            for i in reversed(range(1, self.tabs.count())):
                if getattr(self.tabs.widget(i), "demo_tab", False):
                    self.close_tab(i)
            if self.loc.get("acc") == DEMO_NAME:
                self.navigate({"view": "home"})

    # ------------------------------------------------------------------ navigation
    def _nav_iid(self, loc):
        v = loc.get("view")
        acc, cid, ns = loc.get("acc"), loc.get("cid"), loc.get("ns")
        if v == "account":
            return f"A{SEP}{acc}"
        if v == "cluster":
            return f"C{SEP}{acc}{SEP}{cid}"
        if v == "clusterres":
            return f"R{SEP}{acc}{SEP}{cid}"
        if v == "list" and not ns:
            return f"RV{SEP}{acc}{SEP}{cid}{SEP}{loc['res']['key']}"
        if v == "list":
            return f"V{SEP}{acc}{SEP}{cid}{SEP}{ns}{SEP}{loc['res']['key']}"
        if v in ("overview", "topology", "helm", "all"):
            return f"V{SEP}{acc}{SEP}{cid}{SEP}{ns}{SEP}{v}"
        return None

    def _loc_from_iid(self, iid):
        p = str(iid).split(SEP)
        t = p[0]
        if p[-1] == "~":
            return None
        if t == "FAV" and len(p) == 2 and p[1].isdigit():
            favs = self.config.data.get("favorites", [])
            return self._fav_loc(favs[int(p[1])]) if int(p[1]) < len(favs) else None
        if t == "A" and len(p) == 2:
            return {"view": "account", "acc": p[1]}
        if t == "C" and len(p) == 3:
            return {"view": "cluster", "acc": p[1], "cid": p[2]}
        if t == "R" and len(p) == 3:
            return {"view": "clusterres", "acc": p[1], "cid": p[2]}
        if t == "RV" and len(p) == 4 and p[3] in CATALOG_BY_KEY:
            return {"view": "list", "acc": p[1], "cid": p[2], "res": CATALOG_BY_KEY[p[3]]}
        if t == "N" and len(p) == 4:
            return {"view": "overview", "acc": p[1], "cid": p[2], "ns": p[3]}
        if t == "V" and len(p) == 5:
            if p[4] in ("overview", "topology", "helm", "all"):
                return {"view": p[4], "acc": p[1], "cid": p[2], "ns": p[3]}
            if p[4] in CATALOG_BY_KEY:
                return {"view": "list", "acc": p[1], "cid": p[2], "ns": p[3], "res": CATALOG_BY_KEY[p[4]]}
        return None

    def navigate(self, loc, push=True):
        if push and self.loc != loc:
            self.back.append(self.loc)
            del self.back[:-50]
            self.fwd.clear()
        self.loc = loc
        self.search.blockSignals(True)
        self.search.clear()
        self.search.blockSignals(False)
        self.listview.filter_text = ""
        self.topology.filter_text = ""
        self._render_crumbs()
        self._sync_nav()
        self._update_conn()
        self.details.clear()
        self.listview.tree.clearSelection()
        self._update_commands()
        self.act_back.setEnabled(bool(self.back))
        self.act_fwd.setEnabled(bool(self.fwd))
        self.load_view()

    def _sync_nav(self):
        loc = self.loc
        if loc.get("ns") and loc.get("cid"):
            niid = f"N{SEP}{loc['acc']}{SEP}{loc['cid']}{SEP}{loc['ns']}"
            if niid in self.nav_items:
                if self._nav_is_lazy(niid):
                    self._fill_namespace(loc["acc"], loc["cid"], loc["ns"])
                self.nav_items[niid].setExpanded(True)
                if loc["view"] == "list":
                    for g in self._nav_children(niid):
                        if str(g).startswith("G" + SEP) and any(str(c).endswith(SEP + loc["res"]["key"])
                                                                for c in self._nav_children(g)):
                            self.nav_items[g].setExpanded(True)
        iid = self._nav_iid(loc)
        it = self.nav_items.get(iid) if iid else None
        self._syncing = True
        try:
            if it is not None:
                self.nav.setCurrentItem(it)
                self.nav.scrollToItem(it)
            else:
                self.nav.clearSelection()
                self.nav.setCurrentItem(None)
        finally:
            self._syncing = False

    def go_back(self):
        if self.back:
            self.fwd.append(self.loc)
            self.navigate(self.back.pop(), push=False)

    def go_forward(self):
        if self.fwd:
            self.back.append(self.loc)
            self.navigate(self.fwd.pop(), push=False)

    def go_up(self):
        loc = self.loc
        v = loc["view"]
        direct = self._is_direct(self.account_meta.get(loc.get("acc")))
        if v == "account" or (v == "cluster" and direct):
            self.navigate({"view": "home"})
        elif v == "cluster":
            self.navigate({"view": "account", "acc": loc["acc"]})
        elif v == "overview" or (v == "list" and not loc.get("ns")) or v == "clusterres":
            self.navigate({"view": "cluster", "acc": loc["acc"], "cid": loc["cid"]})
        elif loc.get("ns"):
            self.navigate({"view": "overview", "acc": loc["acc"], "cid": loc["cid"], "ns": loc["ns"]})

    def refresh(self):
        loc = self.loc
        if loc.get("cid") and loc["view"] == "cluster":
            self.namespaces.pop((loc["acc"], loc["cid"]), None)
        if loc["view"] == "account":
            for k in [k for k in self.clusters if k[0] == loc["acc"]]:
                self.clusters.pop(k)
            iid = f"A{SEP}{loc['acc']}"
            if iid in self.nav_items:
                self._nav_clear(iid)
                ph = QTreeWidgetItem(["Chargement…"])
                ph.setData(0, Qt.ItemDataRole.UserRole, iid + SEP + "~")
                ph.setFlags(Qt.ItemFlag.ItemIsEnabled)
                self.nav_items[iid].addChild(ph)
                self.nav_items[iid + SEP + "~"] = ph
        self._shown_loc = None
        self.load_view()

    def cycle_tab(self, d):
        n = self.tabs.count()
        if n:
            self.tabs.setCurrentIndex((self.tabs.currentIndex() + d) % n)

    # ------------------------------------------------------------------ fil d'Ariane, barre d'état
    @staticmethod
    def _view_label(loc):
        v = loc.get("view")
        if v == "list":
            return loc["res"]["label"]
        return {"overview": "Vue d'ensemble", "topology": "Topologie", "helm": "Charts Helm",
                "all": "Tous les objets", "clusterres": "Ressources du cluster"}.get(v, "")

    def _render_crumbs(self):
        drop_layout_items(self.crumb_lay)
        loc = self.loc
        parts = [("Connexions", {"view": "home"})]
        if loc.get("acc") and not self._is_direct(self.account_meta.get(loc["acc"])):
            parts.append((loc["acc"], {"view": "account", "acc": loc["acc"]}))
        if loc.get("cid"):
            cl = self.clusters.get((loc["acc"], loc["cid"]), {})
            parts.append((cl.get("name", loc["cid"]), {"view": "cluster", "acc": loc["acc"], "cid": loc["cid"]}))
        if loc.get("ns"):
            parts.append((loc["ns"], {"view": "overview", "acc": loc["acc"], "cid": loc["cid"], "ns": loc["ns"]}))
        label = self._view_label(loc)
        if label and loc["view"] not in ("home", "account", "cluster", "overview"):
            parts.append((label, dict(loc)))
        icon = QLabel()
        icon.setPixmap(Icons.get("account").pixmap(16, 16))
        self.crumb_lay.addWidget(icon)
        self.crumb_lay.addSpacing(4)
        for i, (txt, target) in enumerate(parts):
            if i:
                s = QLabel("›")
                s.setObjectName("crumbSep")
                self.crumb_lay.addWidget(s)
            b = QToolButton()
            b.setText(txt)
            b.clicked.connect(lambda _c=False, t=target: self.navigate(t))
            self.crumb_lay.addWidget(b)
        self.crumb_lay.addStretch(1)
        what = {"list": label, "topology": "la topologie", "account": "les clusters", "cluster": "les namespaces",
                "all": "les types", "home": "les connexions", "helm": "les charts", "clusterres": "les ressources"}.get(
            loc["view"], "")
        self.search.setPlaceholderText(f"Rechercher dans {what}" if what else "Rechercher")

    def update_status_counts(self):
        w = self.stack.currentWidget()
        if w is self.listview:
            n = self.listview.visible_count()
            s = len(self.listview.tree.selectedItems())
            self.st_count.setText(f"{n} élément{'s' if n > 1 else ''}" +
                                  (f"    {s} sélectionné{'s' if s > 1 else ''}" if s else ""))
        elif w is self.topology:
            self.st_count.setText(f"{self.topology.visible_count()} objets")
        else:
            self.st_count.setText("")

    def _update_conn(self):
        loc = self.loc
        if loc.get("cid"):
            cl = self.clusters.get((loc["acc"], loc["cid"]), {})
            kube = self.kubes.get((loc["acc"], loc["cid"]))
            state = (f"connecté ({kube.user})" if getattr(kube, "user", "") else "connecté") if kube \
                else "non connecté"
            self.st_conn.setText(f"{cl.get('name')} · {'OpenShift' if cl.get('type') == 'openshift' else 'Kubernetes'} "
                                 f"{cl.get('version', '')} · {cl.get('region', '')} · {state}")
            self.act_private.blockSignals(True)
            self.act_private.setChecked(bool(self.config.cluster_pref(loc["cid"]).get("private", False)))
            self.act_private.blockSignals(False)
        elif loc.get("acc"):
            self.st_conn.setText(f"Compte : {loc['acc']}")
        else:
            self.st_conn.setText("Non connecté")
        cl = self.clusters.get((loc.get("acc"), loc.get("cid")), {})
        self.act_private.setEnabled(bool(cl.get("private")) and loc.get("acc") != DEMO_NAME)
        self.act_reconnect.setEnabled(bool(loc.get("cid")))
        self.act_copy_cli.setEnabled(bool(loc.get("cid")))



    # ------------------------------------------------------------------ pages
    def _show(self, widget):
        self.stack.setCurrentWidget(widget)
        self.tabs.setCurrentIndex(0)
        self.update_status_counts()

    def _show_message(self, title, text="", icon="welcome", buttons=()):
        old = self.message.layout()
        if old is not None:
            drop_layout_items(old)
            QWidget().setLayout(old)
        lay = QVBoxLayout(self.message)
        lay.setContentsMargins(40, 40, 40, 40)
        lay.addStretch(2)
        ic = QLabel()
        ic.setPixmap(Icons.get(icon).pixmap(48, 48))
        ic.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(ic)
        t = QLabel(title)
        t.setTextFormat(Qt.TextFormat.PlainText)
        t.setObjectName("h1")
        t.setAlignment(Qt.AlignmentFlag.AlignCenter)
        t.setWordWrap(True)
        lay.addWidget(t)
        if text:
            s = QLabel(text)
            s.setTextFormat(Qt.TextFormat.PlainText)
            s.setObjectName("sub")
            s.setWordWrap(True)
            s.setAlignment(Qt.AlignmentFlag.AlignCenter)
            s.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            s.setMaximumWidth(620)
            lay.addWidget(s, 0, Qt.AlignmentFlag.AlignHCenter)
        for label, cmd in buttons:
            b = QPushButton(label)
            b.clicked.connect(lambda _c=False, f=cmd: f())
            lay.addWidget(b, 0, Qt.AlignmentFlag.AlignHCenter)
        lay.addStretch(3)
        self._show(self.message)

    # ------------------------------------------------------------------ remplissage de l'arbre
    def _expand(self, iid):
        if not iid or not self._nav_is_lazy(iid):
            return
        p = str(iid).split(SEP)
        t = p[0]
        if t == "A":
            name = p[1]
            if name in self._listing:               # liste déjà demandée : on attend sa réponse
                return
            acc = self._ensure_account(name)
            if acc is None:
                self.nav_items[iid].setExpanded(False)
                return
            self._listing.add(name)

            def err(e):
                self._listing.discard(name)
                if getattr(e, "status", None) in (400, 401) and name != DEMO_NAME:
                    self.accounts.pop(name, None)            # code refusé ou session finie : on en redemande un
                    self._nav_set_placeholder(iid, "Code à saisir (clic pour se connecter)")
                    self.nav_items[iid].setExpanded(False)
                    if time.time() - self._auto_prompt.get(name, 0) > 20:
                        self._auto_prompt[name] = time.time()
                        QTimer.singleShot(0, lambda: self._expand_account(name, notice=str(e)))
                        return
                else:
                    self._nav_set_placeholder(iid, "Erreur — voir la barre d'état")
                self.flash(f"IBM Cloud : {e}", 15000)
                if self.loc.get("view") == "account" and self.loc.get("acc") == name:
                    buttons = [("Réessayer", self.refresh)]
                    if getattr(e, "status", None) == 403:
                        buttons = [("Nouvelle connexion à un cluster…", self.add_connection)]
                    self._show_message("Clusters indisponibles", str(e), "err", buttons)
            self.bg(acc.list_clusters, lambda cls: (self._listing.discard(name), self._fill_clusters(name, cls)), err)
        elif t == "C":
            self._connect(p[1], p[2], lambda kube: self._fill_cluster(p[1], p[2]),
                          on_err=lambda e: self.nav_items.get(iid) and self.nav_items[iid].setExpanded(False))
        elif t == "N":
            self._fill_namespace(p[1], p[2], p[3])

    def _fill_clusters(self, acc, clusters):
        iid = f"A{SEP}{acc}"
        if iid not in self.nav_items:
            return
        self._nav_clear(iid)
        for c in clusters:
            self.clusters[(acc, c["id"])] = c
            ciid = f"C{SEP}{acc}{SEP}{c['id']}"
            self._nav_add(iid, ciid, c["name"], c["type"], placeholder="Connexion…")
        if not clusters:
            self._nav_add(iid, iid + SEP + "none", "(aucun cluster Kubernetes / OpenShift)")
            self.nav_items[iid + SEP + "none"].setFlags(Qt.ItemFlag.ItemIsEnabled)
        self.nav_items[iid].setExpanded(True)
        if self.loc.get("view") == "account" and self.loc.get("acc") == acc:
            self.load_view()

    def _connect(self, acc, cid, then, on_err=None, code=None, attempt=0, waiting=None):
        key = (acc, cid)
        if key in self.kubes:
            then(self.kubes[key])
            return
        if key in self._pending:                     # connexion déjà en cours : on attend son résultat
            self._pending[key].append((then, on_err))
            return
        account = self.accounts.get(acc)
        cluster = self.clusters.get(key)
        if not account or not cluster:
            if on_err:
                on_err(ErrText("Connexion indisponible : rouvre le compte ou la connexion."))
            return
        private = bool(self.config.cluster_pref(cid).get("private", False)) and bool(cluster.get("private"))
        ciid = f"C{SEP}{acc}{SEP}{cid}"
        self._pending[key] = waiting or [(then, on_err)]
        needs = getattr(account, "needs_code", None)
        if not code and needs and needs(cluster, private):
            r = self._ask_cluster_code(acc, cid)
            if not r or not r.get("code"):
                self._nav_set_placeholder(ciid, "Code à saisir (clic pour se connecter)")
                for _then, fail in self._pending.pop(key, []):
                    if fail:
                        fail(ErrText("Connexion annulée : il faut un code à usage unique."))
                return
            code = r["code"]
            cluster = self.clusters.get(key, cluster)
        meta = self.account_meta.get(acc, {})
        declared = meta.get("namespaces", []) if self._is_direct(meta) else \
            self.config.cluster_pref(cid).get("namespaces", [])
        self.flash(f"Connexion à {cluster['name']}…", 30000)
        self._nav_set_placeholder(ciid, "Connexion…")

        console_set = meta.get("console", "") if self._is_direct(meta) else ""
        ingress = cluster.get("ingress", "")

        def work():
            kube = account.connect(cluster, private, code) if code else account.connect(cluster, private)
            names, how = kube.namespaces(declared)
            fallback = f"https://console-openshift-console.{ingress}" if ingress and cluster["type"] == "openshift" \
                else ""
            kube.console = console_set or kube.find_console(fallback)
            return kube, names, how

        def ok(res):
            kube, nss, how = res
            self.kubes[key] = kube
            self.namespaces[key] = nss
            who = f" en tant que {kube.user}" if getattr(kube, "user", "") else ""
            note = {"tous": "", "projets": " (tes projets)", "déclarés": " (indiqués dans la connexion)"}.get(how, "")
            self.flash(f"Connecté à {cluster['name']}{who} : {len(nss)} namespace(s){note}.", 8000)
            self.config.data.setdefault("nsCache", {})[f"{acc}{SEP}{cid}"] = list(nss)[:3000]
            self._save()
            if ciid in self.nav_items:
                self._fill_cluster(acc, cid)
            self._update_conn()
            self._update_commands()
            for then_cb, _fail in self._pending.pop(key, []):
                if then_cb:
                    then_cb(kube)

        def err(e):
            if getattr(e, "status", None) == 401 and needs and attempt < 2 and acc != DEMO_NAME:
                self._notice[key] = str(e)              # code refusé ou expiré : on en redemande un tout de suite
                self._connect(acc, cid, None, attempt=attempt + 1, waiting=self._pending.pop(key, []))
                return
            needs_now = needs and needs(cluster, private)
            self._nav_set_placeholder(ciid, "Code à saisir (clic pour se connecter)" if needs_now
                                      else "Échec de connexion")
            self.flash(f"Connexion impossible : {e}", 20000)
            waiting = self._pending.pop(key, [])
            if any(fail for _then, fail in waiting):
                for _then, fail in waiting:
                    if fail:
                        fail(e)
            else:
                QMessageBox.warning(self, APP_NAME, f"Connexion au cluster {cluster['name']} impossible :\n\n{e}")
        self.bg(work, ok, err)

    def _ask_cluster_code(self, acc, cid):
        """Fenêtre du code pour un cluster ; pour une connexion directe, serveur et namespaces y sont modifiables."""
        meta = self.account_meta.get(acc, {})
        cluster = self.clusters[(acc, cid)]
        notice = self._notice.pop((acc, cid), "")
        lead = (notice.rstrip(".") + ".\n\n") if notice else ""
        if self._is_direct(meta):
            r = ask_login(self, title=f"Connexion à « {acc} »",
                          intro=lead + "Comme « oc login -u passcode -p <code> --server=<serveur> ».",
                          server=meta["server"], namespaces=", ".join(meta.get("namespaces", [])),
                          iam_url=meta.get("iamUrl"))
            if r and (r["server"] != meta["server"] or r["namespaces"] != meta.get("namespaces", [])):
                new = clean_account(dict(meta, server=r["server"], namespaces=r["namespaces"]))
                self.config.data["accounts"] = [new if a["name"] == acc else a for a in self.config.accounts]
                self.account_meta[acc] = new
                self.accounts[acc].update(new)
                self.clusters[(acc, cid)] = self.accounts[acc].cluster()
                self._save()
            return r
        prefs = self.config.cluster_pref(cid)
        account = self.accounts.get(acc)
        r = ask_login(self, title=f"Cluster « {cluster['name']} »",
                      intro=lead + "Comme « oc login -u passcode » : il faut un nouveau code (chacun ne sert qu'une "
                            "fois). "
                            "Indique tes namespaces si le cluster ne te laisse pas les lister.",
                      namespaces=", ".join(prefs.get("namespaces", [])),
                      iam_url=getattr(account, "iam_url", IAM_DEFAULT))
        if r and r.get("namespaces") != prefs.get("namespaces", []):
            prefs["namespaces"] = r.get("namespaces", [])
            self._save()
        return r

    def _drop_session(self, key):
        """Session refusée (HTTP 401) : on oublie le jeton ; la prochaine connexion redemandera un code."""
        self.kubes.pop(key, None)
        acc, cl = self.accounts.get(key[0]), self.clusters.get(key)
        if acc is not None and cl is not None and hasattr(acc, "invalidate"):
            acc.invalidate(cl)
        self._update_conn()

    def _load_error(self, seq, title, e):
        if seq != self._load_seq:
            return
        if getattr(e, "status", None) == 401 or "HTTP 401" in str(e):
            key = (self.loc.get("acc"), self.loc.get("cid"))
            self._drop_session(key)
            if time.time() - self._auto_prompt.get(key, 0) > 20:       # session expirée : nouveau code demandé
                self._auto_prompt[key] = time.time()
                self._notice[key] = "Ta session a expiré : saisis un nouveau code à usage unique"
                self.load_view()
                return
            self._show_message("Session expirée", "Le cluster n'accepte plus ta session. Reconnecte-toi avec un "
                               "nouveau code à usage unique.", "warn", [("Se reconnecter…", self.load_view)])
            return
        self._show_message(title, str(e), "err", [("Réessayer", self.load_view)])

    def _fill_cluster(self, acc, cid):
        ciid = f"C{SEP}{acc}{SEP}{cid}"
        if ciid not in self.nav_items:
            return
        expanded = {i for i, it in self.nav_items.items() if it.isExpanded()}
        self._nav_clear(ciid)
        riid = f"R{SEP}{acc}{SEP}{cid}"
        self._nav_add(ciid, riid, "Ressources du cluster", "clusterres")
        for k in CLUSTER_KEYS:
            r = CATALOG_BY_KEY[k]
            self._nav_add(riid, f"RV{SEP}{acc}{SEP}{cid}{SEP}{k}", r["label"], r["icon"])
        show_sys = self.act_system.isChecked()
        for ns in self.namespaces.get((acc, cid), []):
            if not show_sys and is_system_ns(ns):
                continue
            niid = f"N{SEP}{acc}{SEP}{cid}{SEP}{ns}"
            self._nav_add(ciid, niid, ns, "folder_sys" if is_system_ns(ns) else "folder", placeholder="")
            if niid in expanded:
                self._fill_namespace(acc, cid, ns)
                self.nav_items[niid].setExpanded(True)
        self.nav_items[ciid].setExpanded(True)
        self._sync_nav()

    def _fill_namespace(self, acc, cid, ns):
        niid = f"N{SEP}{acc}{SEP}{cid}{SEP}{ns}"
        if niid not in self.nav_items:
            return
        self._nav_clear(niid)
        base = f"V{SEP}{acc}{SEP}{cid}{SEP}{ns}{SEP}"
        cl = self.clusters.get((acc, cid), {})
        for v, label, icon in (("overview", "Vue d'ensemble", "overview"), ("topology", "Topologie", "topology"),
                               ("helm", "Charts Helm", "helm")):
            self._nav_add(niid, base + v, label, icon)
        for gname, _gicon, keys in NAV_GROUPS:
            giid = f"G{SEP}{acc}{SEP}{cid}{SEP}{ns}{SEP}{gname}"
            self._nav_add(niid, giid, gname, "folder")
            for k in keys:
                if k in OPENSHIFT_ONLY and cl.get("type") != "openshift":
                    continue
                r = CATALOG_BY_KEY[k]
                self._nav_add(giid, base + k, r["label"], r["icon"])
        self._nav_add(niid, base + "events", "Événements", "event")
        self._nav_add(niid, base + "all", "Tous les objets", "all")

    def toggle_system(self, on):
        self.config.settings["showSystemNamespaces"] = bool(on)
        self._save()
        for (acc, cid) in list(self.kubes):
            self._fill_cluster(acc, cid)
        if self.loc.get("view") == "cluster":
            self.load_view()

    def toggle_details(self, on):
        self.config.settings["detailsPane"] = bool(on)
        self.details.setVisible(bool(on))
        self._save()

    def toggle_private(self, on):
        loc = self.loc
        if not loc.get("cid"):
            return
        self.config.cluster_pref(loc["cid"])["private"] = bool(on)
        self._save()
        self.kubes.pop((loc["acc"], loc["cid"]), None)
        self.flash("Point d'accès modifié : reconnexion.")
        self.load_view()

    def reconnect(self):
        loc = self.loc
        if loc.get("cid"):
            self._drop_session((loc["acc"], loc["cid"]))
            self._shown_loc = None
            self.load_view()



    # ------------------------------------------------------------------ contenus
    def load_view(self):
        self._load_seq += 1
        seq = self._load_seq
        loc = self.loc
        v = loc["view"]
        if v == "home":
            self._shown_loc = loc
            names = list(self.account_meta) + ([DEMO_NAME] if DEMO_NAME in self.accounts else [])
            if names:
                rows = []
                for a in names:
                    meta = self.account_meta.get(a, {})
                    if a == DEMO_NAME:
                        vals, icon, lvl, props = [a, "Démonstration", "données simulées", "", "simulé"], "account", \
                            "ok", []
                    elif self._is_direct(meta):
                        on = (a, DirectAccount.CID) in self.kubes
                        vals = [a, "Cluster OpenShift", meta["server"], ", ".join(meta.get("namespaces", [])),
                                "connecté" if on else "code à saisir"]
                        icon, lvl = "openshift", "ok" if on else "off"
                        props = [("Serveur", meta["server"]), ("Namespaces", ", ".join(meta.get("namespaces", [])))]
                    else:
                        on = a in self.accounts
                        vals = [a, "Compte IBM Cloud", meta.get("csUrl", ""), "", "session ouverte" if on
                                else "code à saisir"]
                        icon, lvl = "account", "ok" if on else "off"
                        props = [("Point d'accès IAM", meta.get("iamUrl", "")),
                                 ("Point d'accès Containers", meta.get("csUrl", ""))]
                    rows.append({"id": a, "values": vals, "icon": icon, "level": lvl, "props": props,
                                 "kind_label": vals[1]})
                self.listview.configure_columns([("Nom", 240, "w"), ("Type", 150, "w"), ("Adresse", 360, "w"),
                                                 ("Namespaces", 200, "w"), ("État", 120, "w")])
                self.listview.set_rows(rows)
                self._show(self.listview)
            else:
                self._show_message(f"Bienvenue dans {APP_NAME}",
                                   "Ajoute une connexion à un cluster OpenShift : adresse du serveur, namespace et "
                                   "code à usage unique (comme « oc login -u passcode »). Pas besoin de clé API.\n\n"
                                   "Si tes droits IBM Cloud permettent de lister les clusters, tu peux aussi ajouter "
                                   "le compte IBM Cloud entier. Pour essayer sans rien connecter : Aide › Mode "
                                   "démonstration.",
                                   "welcome", [("Nouvelle connexion à un cluster…", self.add_connection),
                                               ("Ajouter un compte IBM Cloud…", self.add_account),
                                               ("Essayer le mode démonstration", lambda: self.act_demo.setChecked(True))])
            return
        if v == "account":
            acc = loc["acc"]
            if acc not in self.accounts:
                self._show_message(f"Compte « {acc} »", "Ouvre une session avec un code à usage unique (comme "
                                   "« ibmcloud login --sso »).", "account",
                                   [("Se connecter…", lambda: self._expand_account(acc))])
                return
            cls = [c for (a, _), c in self.clusters.items() if a == acc]
            iid = f"A{SEP}{acc}"
            if not cls and self._nav_is_lazy(iid):
                self._show_message("Chargement des clusters…", "Interrogation de l'API IBM Cloud Containers.", "account")
                self.nav_items[iid].setExpanded(True)
                self._expand(iid)
                return
            self._shown_loc = loc
            self.listview.configure_columns([("Nom", 230, "w"), ("Type", 110, "w"), ("Version", 150, "w"),
                                             ("Région", 90, "w"), ("État", 90, "w"), ("Workers", 70, "e"),
                                             ("Groupe de ressources", 150, "w"), ("Point d'accès", 320, "w")])
            rows = []
            for c in cls:
                lvl = "ok" if c["state"] == "normal" else ("warn" if c["state"] in ("warning", "pending", "deploying")
                                                           else "err")
                private = self.config.cluster_pref(c["id"]).get("private") and c["private"]
                rows.append({"id": c["id"], "icon": c["type"], "level": lvl, "cluster": c,
                             "values": [c["name"], "OpenShift" if c["type"] == "openshift" else "Kubernetes",
                                        c["version"], c["region"], c["state"], c["workers"], c["resourceGroup"],
                                        c["private"] if private else c["public"]],
                             "kind_label": "Cluster " + ("OpenShift" if c["type"] == "openshift" else "Kubernetes"),
                             "props": [("ID", c["id"]), ("Fournisseur", c["provider"]), ("Ingress", c["ingress"]),
                                       ("Point d'accès public", c["public"] or "—"),
                                       ("Point d'accès privé", c["private"] or "—")]})
            self.listview.set_rows(rows, "Aucun cluster Kubernetes ou OpenShift dans ce compte.")
            self._show(self.listview)
            return
        key = (loc["acc"], loc["cid"])
        if key not in self.kubes:
            cl = self.clusters.get(key)
            if cl is None:
                self._show_message("Cluster inconnu", "Rouvre le compte pour recharger la liste des clusters.", "err",
                                   [("Ouvrir le compte", lambda: self.navigate({"view": "account",
                                                                                "acc": loc["acc"]}))])
                return
            self._show_message("Connexion au cluster…", cl.get("name", ""), cl.get("type", "kubernetes"))

            def failed(e):
                if self.loc is loc:
                    cancelled = str(e).startswith("Connexion annulée")
                    self._show_message("Pas encore connecté" if cancelled else "Connexion impossible", str(e),
                                       "openshift" if cancelled else "err",
                                       [("Se connecter…" if cancelled else "Réessayer", self.load_view)])
            self._connect(loc["acc"], loc["cid"], lambda kube: self.loc is loc and self._after_connect(loc),
                          on_err=failed)
            return
        kube = self.kubes[key]
        if self._shown_loc != loc and v != "clusterres":
            label = self._view_label(loc) or (self.clusters.get(key, {}).get("name", "") if v == "cluster" else "")
            self._show_message("Chargement…", label, {"overview": "overview", "topology": "topology",
                                                      "helm": "helm"}.get(v, "folder"))
        self._shown_loc = loc
        if v == "cluster":
            if self._nav_is_lazy(f"C{SEP}{loc['acc']}{SEP}{loc['cid']}"):
                self._fill_cluster(*key)
            self._load_list(seq, kube, CATALOG_BY_KEY["namespaces"], None, ns_mode=True)
        elif v == "clusterres":
            rows = [{"id": k, "values": [CATALOG_BY_KEY[k]["label"], "Ressource du cluster"],
                     "icon": CATALOG_BY_KEY[k]["icon"], "goto": k} for k in CLUSTER_KEYS]
            self.listview.configure_columns([("Nom", 300, "w"), ("Type", 200, "w")])
            self.listview.set_rows(rows)
            self._show(self.listview)
        elif v == "list":
            self._load_list(seq, kube, loc["res"], loc.get("ns"))
        elif v == "overview":
            self._load_overview(seq, kube, loc)
        elif v == "topology":
            self._load_topology(seq, kube, loc)
        elif v == "helm":
            self._load_helm(seq, kube, loc)
        elif v == "all":
            self._load_all(seq, kube, loc)

    def _reopen_account(self, name):
        """Nouvelle session IBM Cloud (nouveau code) pour ce compte."""
        meta = self.account_meta.get(name)
        if not meta or self._is_direct(meta):
            return
        SESSION_SECRETS.pop(name, None)
        self._forget_account(name)
        self._register_account(meta)
        self.navigate({"view": "account", "acc": name}) if self.loc.get("acc") != name else self.load_view()

    def _expand_account(self, name, notice=""):
        if self._ensure_account(name, notice=notice) is not None:
            iid = f"A{SEP}{name}"
            if iid in self.nav_items:
                self.nav_items[iid].setExpanded(True)
            self.load_view()

    def _after_connect(self, loc):
        if loc["view"] == "cluster" or self._nav_is_lazy(f"C{SEP}{loc['acc']}{SEP}{loc['cid']}"):
            self._fill_cluster(loc["acc"], loc["cid"])
        self._sync_nav()
        self.load_view()

    def _load_list(self, seq, kube, res, ns, ns_mode=False):
        cols = [("Nom", 280, "w")] + [(h, 380 if h in ("Message", "Images", "Labels", "Sujets") else 140, "w")
                                      for h in res.get("headers", [])] + [("Âge", 60, "e")]

        def ok(items):
            if seq != self._load_seq:
                return
            self.listview.configure_columns(cols)
            rows = object_rows(res, items)
            if ns_mode:
                for r in rows:
                    r["icon"] = "folder_sys" if is_system_ns(r["values"][0]) else "folder"
                if not self.act_system.isChecked():
                    rows = [r for r in rows if not is_system_ns(r["values"][0])]
            self.listview.set_rows(rows, f"Aucun objet « {res['label']} » ici.")
            self._show(self.listview)
            self._apply_filter()

        key = (self.loc.get("acc"), self.loc.get("cid"))

        def err(e):
            if seq != self._load_seq:
                return
            if ns_mode and getattr(e, "status", None) == 403:       # pas le droit de lister : ceux qu'on connaît
                ok([{"metadata": {"name": n, "uid": n}, "status": {"phase": ""}}
                    for n in self.namespaces.get(key, [])])
                return
            self._load_error(seq, f"Impossible de lister {res['label']}", e)
        self.bg(lambda: kube.list(res, ns), ok, err)

    @staticmethod
    def _parallel_lists(kube, keys, ns):
        out, lock, todo = {}, threading.Lock(), list(keys)

        def worker():
            while True:
                with lock:
                    if not todo:
                        return
                    k = todo.pop()
                try:
                    items = kube.list(CATALOG_BY_KEY[k], ns)
                except KubeError:
                    items = []
                with lock:
                    out[k] = items
        threads = [threading.Thread(target=worker, daemon=True) for _ in range(min(8, len(keys)))]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        return out

    def _load_overview(self, seq, kube, loc):
        ns = loc["ns"]
        cl = self.clusters.get((loc["acc"], loc["cid"]), {})

        def work():
            out = {"ns": ns, "cluster": cl.get("name", ""),
                   "flavor": "OpenShift" if cl.get("type") == "openshift" else "Kubernetes",
                   "time": time.strftime("%H:%M:%S")}
            keys = [k for g in NAV_GROUPS for k in g[2]] + ["events"]
            keys = [k for k in keys if not (k in OPENSHIFT_ONLY and cl.get("type") != "openshift")]
            lists = self._parallel_lists(kube, keys, ns)
            out.update(pods=lists.get("pods", []), deployments=lists.get("deployments", []),
                       statefulsets=lists.get("statefulsets", []), services=lists.get("services", []),
                       routes=lists.get("routes", []) + lists.get("ingresses", []))
            out["helm"] = helm_releases(lists.get("secrets", []))
            out["counts"] = {CATALOG_BY_KEY[k]["label"]: len(v) for k, v in lists.items()}
            out["metrics"] = kube.pod_metrics(ns)
            return out

        def ok(data):
            if seq == self._load_seq:
                self.overview.show_data(data)
                self._show(self.overview)

        def err(e):
            self._load_error(seq, "Vue d'ensemble indisponible", e)
        self.bg(work, ok, err)

    def _load_topology(self, seq, kube, loc):
        ns = loc["ns"]
        cl = self.clusters.get((loc["acc"], loc["cid"]), {})

        def work():
            keys = [k for k in ("pods", "replicasets", "deployments", "statefulsets", "daemonsets", "jobs", "services",
                                "ingresses", "routes", "deploymentconfigs")
                    if not (k in OPENSHIFT_ONLY and cl.get("type") != "openshift")]
            return build_topology(self._parallel_lists(kube, keys, ns))

        def ok(forest):
            if seq == self._load_seq:
                self.topology.show_forest(forest)
                self._show(self.topology)

        def err(e):
            self._load_error(seq, "Topologie indisponible", e)
        self.bg(work, ok, err)

    def _load_helm(self, seq, kube, loc):
        def ok(releases):
            if seq != self._load_seq:
                return
            self.listview.configure_columns([("Release", 220, "w"), ("Chart", 200, "w"), ("Version du chart", 120, "w"),
                                             ("Version app", 110, "w"), ("Révision", 70, "e"), ("Statut", 110, "w"),
                                             ("Mise à jour", 150, "w"), ("Âge", 50, "e")])
            rows = []
            for r in releases:
                m = r.get("chart", {}).get("metadata", {})
                info = r.get("info", {})
                st = info.get("status", "")
                rows.append({"id": r.get("name"), "icon": "helm", "helm": r,
                             "level": "ok" if st == "deployed" else ("err" if st == "failed" else "warn"),
                             "values": [r.get("name"), m.get("name"), m.get("version"), m.get("appVersion", ""),
                                        r.get("version"), st, fmt_time(info.get("last_deployed")),
                                        age(info.get("first_deployed"))],
                             "kind_label": "Release Helm",
                             "props": [("Chart", f"{m.get('name')} {m.get('version')}"),
                                       ("Description", m.get("description", "")), ("Statut", st),
                                       ("Révisions", len(r.get("_history", [])))],
                             "actions": [("Voir la configuration", lambda r=r: self.open_helm_tab(r))]})
            self.listview.set_rows(rows, "Aucune release Helm dans ce namespace.")
            self._show(self.listview)

        def err(e):
            self._load_error(seq, "Charts Helm indisponibles", e)
        self.bg(lambda: helm_releases(kube.list(CATALOG_BY_KEY["secrets"], loc["ns"], "owner=helm")), ok, err)

    def _load_all(self, seq, kube, loc):
        ns = loc["ns"]

        def ok(disc):
            if seq != self._load_seq:
                return
            known = {(r["group"], r["name"]): r for r in CATALOG}
            res_list = []
            for d in disc:
                if not d["namespaced"] or "list" not in d["verbs"] or d["name"] in ("events", "bindings"):
                    continue
                if d["group"] in ("events.k8s.io", "metrics.k8s.io", "authorization.k8s.io", "authentication.k8s.io"):
                    continue
                r = dict(known.get((d["group"], d["name"])) or generic_resource(d))
                r["version"] = d["version"]
                res_list.append(r)
            self.listview.configure_columns([("Type", 260, "w"), ("Groupe d'API", 260, "w"), ("Objets", 80, "e")])
            rows = [{"id": f"{r['group']}/{r['name']}", "icon": r.get("icon", "doc"), "goto_res": r,
                     "values": [r["kind"], f"{r['group'] or 'core'}/{r['version']}", "…"],
                     "sort": [r["kind"], r["group"], -1], "kind_label": "Type de ressource",
                     "props": [("Ressource", r["name"])]} for r in res_list]
            self.listview.set_rows(rows)
            self._show(self.listview)
            self._count_all(seq, kube, ns, rows)

        def err(e):
            self._load_error(seq, "Types d'objets indisponibles", e)
        self.bg(kube.discovery, ok, err)

    def _count_all(self, seq, kube, ns, rows):
        relay = _Relay()
        self._relays = [r for r in self._relays if r is not None][-3:] + [relay]
        relay.done.connect(lambda row, n: self._set_count(seq, row, n), Qt.ConnectionType.QueuedConnection)
        lock = threading.Lock()
        pending = list(rows)

        def worker():
            while True:
                with lock:
                    if not pending or seq != self._load_seq:
                        return
                    row = pending.pop()
                try:
                    n = len(kube.list(row["goto_res"], ns))
                except Exception:  # noqa: BLE001
                    n = -1
                relay.done.emit(row, n)
        for _ in range(6):
            threading.Thread(target=worker, daemon=True).start()

    def _set_count(self, seq, row, n):
        if seq != self._load_seq:
            return
        row["values"][2] = n if n >= 0 else "refusé"
        row["sort"][2] = n
        row["level"] = "off" if n == 0 else ("warn" if n < 0 else "ok")
        self.listview.update_row(row)

    # ------------------------------------------------------------------ interaction
    def _apply_filter(self):
        txt = self.search.text()
        w = self.stack.currentWidget()
        if w is self.listview:
            self.listview.set_filter(txt)
        elif w is self.topology:
            self.topology.set_filter(txt)
        self.update_status_counts()

    def focus_search(self):
        tab = self.tabs.currentWidget()
        if isinstance(tab, TextTab):
            tab.search.setFocus()
            tab.search.selectAll()
            return
        if isinstance(tab, LogsTab):
            tab.filter.setFocus()
            tab.filter.selectAll()
            return
        self.tabs.setCurrentIndex(0)
        self.search.setFocus()
        self.search.selectAll()

    def _selection_changed(self):
        sel = self.listview.selected()
        if len(sel) == 1:
            self.details.show_row(sel[0])
        elif sel:
            self.details.clear(f"{len(sel)} éléments sélectionnés")
        else:
            self.details.clear()
        self._update_commands()

    def _sel_objects(self):
        if self.stack.currentWidget() is not self.listview or self.tabs.currentIndex() != 0:
            return []
        return [r for r in self.listview.selected() if r.get("obj") and r.get("res")]

    def _update_commands(self):
        objs = self._sel_objects()
        kinds = {r["res"]["kind"] for r in objs}
        one = len(objs) == 1
        loc = self.loc
        in_cluster = bool(loc.get("cid"))
        states = {
            self.act_terminal: one and kinds == {"Pod"},
            self.act_logs: one and kinds == {"Pod"},
            self.act_yaml: one,
            self.act_console: in_cluster,
            self.act_console_yaml: one,
            self.act_cluster_console: in_cluster,
            self.act_portal: in_cluster and loc.get("acc") != DEMO_NAME,
            self.act_fav: in_cluster,
        }
        for act, on in states.items():
            act.setEnabled(bool(on))
        for key, act in (("terminal", self.act_terminal), ("logs", self.act_logs), ("yaml", self.act_yaml),
                         ("console", self.act_console), ("fav", self.act_fav)):
            b = self.cmd.get(key)
            if b is not None:
                b.setEnabled(act.isEnabled())
        is_fav = self._fav_index(self._fav_key(loc)) is not None
        self.act_fav.setText("Retirer des favoris" if is_fav else "Ajouter aux favoris")
        self.act_fav.setIcon(Glyphs.get("starfill" if is_fav else "star"))
        b = self.cmd.get("fav")
        if b is not None:
            b.setChecked(is_fav)
            b.setIcon(self.act_fav.icon())

    def _list_open(self):
        sel = self.listview.selected()
        if not sel:
            return
        r = sel[0]
        loc = self.loc
        if loc["view"] == "home":
            if self._is_direct(self.account_meta.get(r["id"])):
                self.navigate({"view": "cluster", "acc": r["id"], "cid": DirectAccount.CID})
            else:
                self.navigate({"view": "account", "acc": r["id"]})
        elif loc["view"] == "account" and r.get("cluster"):
            self.navigate({"view": "cluster", "acc": loc["acc"], "cid": r["cluster"]["id"]})
        elif loc["view"] == "cluster" and r.get("obj"):
            ns = r["obj"]["metadata"]["name"]
            niid = f"N{SEP}{loc['acc']}{SEP}{loc['cid']}{SEP}{ns}"
            if niid in self.nav_items:
                self.nav_items[niid].setExpanded(True)
            self.navigate({"view": "overview", "acc": loc["acc"], "cid": loc["cid"], "ns": ns})
        elif r.get("goto"):
            self.navigate({"view": "list", "acc": loc["acc"], "cid": loc["cid"], "res": CATALOG_BY_KEY[r["goto"]]})
        elif r.get("goto_res"):
            self.navigate({"view": "list", "acc": loc["acc"], "cid": loc["cid"], "ns": loc["ns"],
                           "res": r["goto_res"]})
        elif r.get("helm"):
            self.open_helm_tab(r["helm"])
        elif r.get("obj"):
            if r["res"]["kind"] == "Pod":
                self.action_logs()
            else:
                self.action_yaml()

    def _list_menu(self, gpos):
        m = QMenu(self)
        sel = self.listview.selected()
        objs = self._sel_objects()
        if sel and not objs:
            a = m.addAction("Ouvrir", self._list_open)
            f = a.font()
            f.setBold(True)
            a.setFont(f)
        if objs:
            kinds = {r["res"]["kind"] for r in objs}
            one = len(objs) == 1
            if one and kinds == {"Pod"}:
                obj = objs[0]["obj"]
                conts = [c["name"] for c in obj.get("spec", {}).get("containers", [])]
                if len(conts) > 1:
                    sub2 = m.addMenu(Glyphs.get("logs"), "Afficher les logs")
                    for c in conts:
                        sub2.addAction(c, lambda c=c: self.open_logs(obj, c))
                else:
                    m.addAction(self.act_logs)
            if one:
                m.addAction(self.act_yaml)
            m.addSeparator()
            act = m.addAction(Glyphs.get("external"), "Ouvrir dans la console OpenShift (modifier, mettre à "
                              "l'échelle, redémarrer, supprimer)" if one else "Ouvrir la liste dans la console OpenShift",
                              lambda: self.open_console())
            f = act.font()
            f.setBold(not sel or bool(objs))
            if one:
                m.addAction(self.act_console_yaml)
            if one and kinds == {"Pod"}:
                m.addAction(self.act_terminal)
            m.addSeparator()
            m.addAction(Glyphs.get("copy"), "Copier le nom",
                        lambda: self._copy("\n".join(r["obj"]["metadata"]["name"] for r in objs)))
            if self.loc["view"] == "cluster" and one:
                ns = objs[0]["obj"]["metadata"]["name"]
                loc_ns = {"view": "overview", "acc": self.loc["acc"], "cid": self.loc["cid"], "ns": ns}
                in_fav = self._fav_index(self._fav_key(loc_ns)) is not None
                m.addAction(Glyphs.get("starfill" if in_fav else "star"),
                            "Retirer des favoris" if in_fav else "Ajouter aux favoris",
                            lambda: self.toggle_favorite(loc_ns))
        if self.loc["view"] == "account" and sel and sel[0].get("cluster"):
            m.addAction(Glyphs.get("copy"), "Copier la commande de connexion (CLI)",
                        lambda c=sel[0]["cluster"]: self._copy(self._cli_for(c, self.loc.get("acc"))))
        m.addSeparator()
        m.addAction(self.act_refresh)
        popup(m, gpos)

    def _nav_menu(self, pos):
        it = self.nav.itemAt(pos)
        gpos = self.nav.viewport().mapToGlobal(pos)
        m = QMenu(self)
        if it is None:
            m.addAction(self.act_add)
            m.addAction(self.act_demo)
            popup(m, gpos)
            return
        iid = it.data(0, Qt.ItemDataRole.UserRole) or ""
        loc = self._loc_from_iid(iid)
        kind = str(iid).split(SEP)[0]
        if loc:
            m.addAction("Ouvrir", lambda: self.navigate(loc))
        if kind == "FAV":
            i = int(str(iid).split(SEP)[1])
            m.addAction("Renommer…", lambda: self.rename_favorite(i))
            m.addAction(Glyphs.get("star"), "Retirer des favoris", lambda: self.remove_favorite(i))
        elif loc and loc.get("cid") and kind in ("N", "V", "C"):
            in_fav = self._fav_index(self._fav_key(loc)) is not None
            m.addAction(Glyphs.get("starfill" if in_fav else "star"),
                        "Retirer des favoris" if in_fav else "Ajouter aux favoris", lambda: self.toggle_favorite(loc))
        if loc and loc.get("cid") and kind in ("N", "V", "C", "FAV"):
            m.addAction(Glyphs.get("external"), "Ouvrir dans la console OpenShift",
                        lambda: (self.navigate(loc) if self.loc != loc else None, self.open_console()))
        if str(iid).startswith("C" + SEP) and loc:
            if loc["acc"] != DEMO_NAME:
                cl = self.clusters.get((loc["acc"], loc["cid"]), {})
                m.addAction("Ouvrir le cluster dans le portail IBM Cloud", lambda: self.open_url(portal_link(cl)))
            cl = self.clusters.get((loc["acc"], loc["cid"]))
            if cl:
                m.addAction(Glyphs.get("copy"), "Copier la commande de connexion (CLI)",
                            lambda: self._copy(self._cli_for(cl, loc["acc"])))
            m.addAction(Glyphs.get("refresh"), "Se reconnecter (nouveau code)",
                        lambda: (self._drop_session((loc["acc"], loc["cid"])), self.navigate(loc)
                                 if self.loc != loc else self.load_view()))
        if loc and loc["acc"] in self.account_meta and loc["view"] in ("account", "cluster") \
                and (loc["view"] == "account" or self._is_direct(self.account_meta[loc["acc"]])):
            if loc["view"] == "account":
                m.addAction(Glyphs.get("refresh"), "Se reconnecter (nouveau code)",
                            lambda: self._reopen_account(loc["acc"]))
            m.addAction("Modifier…", lambda: (self.navigate(loc), self.edit_account()))
            m.addAction("Retirer", lambda: (self.navigate(loc), self.remove_account()))
        m.addSeparator()
        m.addAction(self.act_refresh)
        popup(m, gpos)

    def _copy(self, text):
        copy_text(text)
        self.flash("Copié dans le presse-papiers.")

    def _cli_for(self, cl, acc=None):
        if cl["type"] == "openshift":
            cmd = f'oc login -u passcode -p "<code>" --server={cl["public"] or cl["private"]}'
            meta = self.account_meta.get(acc or self.loc.get("acc"), {})
            nss = meta.get("namespaces") if self._is_direct(meta) else \
                self.config.cluster_pref(cl["id"]).get("namespaces")
            return cmd + (f" && oc project {nss[0]}" if nss else "")
        return f"ibmcloud ks cluster config --cluster {cl['id']}"

    def copy_cli(self):
        cl = self.clusters.get((self.loc.get("acc"), self.loc.get("cid")))
        if cl:
            self._copy(self._cli_for(cl))

    # ------------------------------------------------------------------ édition (copier / coller)


    def edit_copy(self):
        w = QApplication.focusWidget()
        if isinstance(w, (QLineEdit, QPlainTextEdit)):
            w.copy()
            return
        objs = self._sel_objects()
        if objs:
            self._copy("\n".join(r["obj"]["metadata"]["name"] for r in objs))

    def edit_paste(self):
        w = QApplication.focusWidget()
        if isinstance(w, QLineEdit):
            w.paste()

    def edit_select_all(self):
        w = QApplication.focusWidget()
        if isinstance(w, (QLineEdit, QPlainTextEdit)):
            w.selectAll()
        elif w is self.listview.tree:
            self.listview.tree.selectAll()

    # ------------------------------------------------------------------ actions sur les objets
    def action_terminal(self):
        objs = self._sel_objects()
        if len(objs) == 1 and objs[0]["res"]["kind"] == "Pod":
            self.open_console(page="terminal")

    def action_logs(self):
        objs = self._sel_objects()
        if len(objs) == 1 and objs[0]["res"]["kind"] == "Pod":
            self.open_logs(objs[0]["obj"])

    def action_yaml(self):
        objs = self._sel_objects()
        if len(objs) == 1:
            r = objs[0]
            md = r["obj"]["metadata"]
            self.open_yaml(r["res"], md.get("namespace"), md["name"], r["obj"])



    # ------------------------------------------------------------------ onglets
    def _add_tab(self, widget, title, icon):
        widget.demo_tab = self.loc.get("acc") == DEMO_NAME
        i = self.tabs.addTab(widget, Icons.get(icon), title)
        self.tabs.setTabToolTip(i, title)
        self.tabs.setCurrentIndex(i)
        return i

    def close_tab(self, index):
        if index <= 0 or index >= self.tabs.count():
            return
        w = self.tabs.widget(index)
        if hasattr(w, "close_tab"):
            w.close_tab()
        self.tabs.removeTab(index)
        w.deleteLater()

    def eventFilter(self, obj, ev):
        if obj is self.tabs.tabBar() and ev.type() == QEvent.Type.MouseButtonRelease \
                and ev.button() == Qt.MouseButton.MiddleButton:
            self.close_tab(obj.tabAt(ev.position().toPoint()))
            return True
        return super().eventFilter(obj, ev)

    def _tab_menu(self, pos):
        bar = self.tabs.tabBar()
        i = bar.tabAt(pos)
        if i <= 0:
            return
        m = QMenu(self)
        m.addAction("Fermer l'onglet", lambda: self.close_tab(i))
        m.addAction("Fermer les autres onglets",
                    lambda: [self.close_tab(j) for j in reversed(range(1, self.tabs.count())) if j != i])
        popup(m, bar.mapToGlobal(pos))

    def open_logs(self, pod_obj, container=None):
        kube = self._kube()
        if kube is None:
            return
        tab = LogsTab(self, kube, pod_obj["metadata"]["namespace"], pod_obj, container)
        self._add_tab(tab, f"Logs · {pod_obj['metadata']['name'][:28]}", "logs")

    def open_yaml(self, res, ns, name, obj=None):
        kube = self._kube()
        if kube is None:
            return
        self._add_tab(YamlTab(self, kube, res, ns, name, obj), f"{res['kind']} · {name[:30]}", "yaml")

    def open_yaml_by_kind(self, kind, name, obj=None):
        res = next((r for r in CATALOG if r["kind"] == kind), None)
        if res:
            self.open_yaml(res, self.loc.get("ns"), name, obj)

    def open_helm_tab(self, release):
        self._add_tab(HelmTab(self, release), f"Helm · {release.get('name')}", "helm")

    # ------------------------------------------------------------------ console OpenShift et portail IBM Cloud
    def _console_base(self, acc=None, cid=None):
        acc, cid = acc or self.loc.get("acc"), cid or self.loc.get("cid")
        kube = self.kubes.get((acc, cid))
        if kube is not None and getattr(kube, "console", ""):
            return kube.console
        meta = self.account_meta.get(acc, {})
        if self._is_direct(meta) and meta.get("console"):
            return meta["console"]
        cl = self.clusters.get((acc, cid), {})
        if cl.get("ingress") and cl.get("type") == "openshift":
            return f"https://console-openshift-console.{cl['ingress']}"
        server = cl.get("public") or cl.get("private") or ""
        return server.rstrip("/") + "/console" if server else ""

    def open_url(self, url):
        """Ouvre une page dans le navigateur : https seulement, chez IBM Cloud ou sur la console du cluster."""
        u = urlsplit(url or "")
        host = (u.hostname or "").lower()
        consoles = {urlsplit(self._console_base(a, c)).hostname for (a, c) in self.clusters}
        ok = u.scheme == "https" and host and (NET.permitted(host) or host.endswith(".appdomain.cloud")
                                               or host in consoles)
        if not ok:
            QMessageBox.warning(self, APP_NAME, f"Adresse refusée : {url}")
            return False
        if not QDesktopServices.openUrl(QUrl(url)):
            copy_text(url)
            QMessageBox.information(self, APP_NAME, f"Adresse copiée : colle-la dans ton navigateur.\n\n{url}")
        else:
            self.flash(f"Ouvert dans le navigateur : {url}", 8000)
        return True

    def open_console(self, obj=None, res=None, page="", scope=""):
        """Page de la console OpenShift qui correspond à ce qui est affiché ou sélectionné (là où l'on modifie)."""
        loc = self.loc
        base = self._console_base()
        if not base:
            QMessageBox.information(self, APP_NAME, "Adresse de la console inconnue : connecte-toi d'abord au "
                                                    "cluster, ou indique-la dans la connexion (Modifier…).")
            return
        if scope == "cluster":
            return self.open_url(base)
        if obj is None and self.tabs.currentIndex() == 0 and self.stack.currentWidget() is self.listview:
            sel = self.listview.selected()
            if len(sel) == 1 and sel[0].get("helm"):
                r = sel[0]["helm"]
                return self.open_url(console_link(base, "helm", r.get("namespace") or loc.get("ns"), name=r.get("name")))
            objs = self._sel_objects()
            if len(objs) == 1:
                obj, res = objs[0]["obj"], objs[0]["res"]
        if obj is not None and res is not None:
            md = obj.get("metadata", {})
            ns = md.get("namespace") or loc.get("ns")
            if res.get("key") == "namespaces":
                return self.open_url(console_link(base, ns=md.get("name")))
            return self.open_url(console_link(base, res=res, ns=ns, name=md.get("name"), page=page))
        v = loc.get("view")
        if v == "list":
            return self.open_url(console_link(base, res=loc["res"], ns=loc.get("ns")))
        if v in ("topology", "helm"):
            return self.open_url(console_link(base, v, loc.get("ns")))
        return self.open_url(console_link(base, ns=loc.get("ns")))

    def open_portal(self):
        cl = self.clusters.get((self.loc.get("acc"), self.loc.get("cid")))
        if cl is not None:
            self.open_url(portal_link(cl))

    # ------------------------------------------------------------------ favoris
    @staticmethod
    def _fav_key(loc):
        if not loc or not loc.get("cid") or loc.get("view") not in ("cluster", "overview", "list", "topology",
                                                                     "helm", "all"):
            return None
        return (loc.get("acc"), loc.get("cid"), loc.get("ns") or "", loc.get("view"),
                (loc.get("res") or {}).get("key", "") if loc.get("view") == "list" else "")

    def _fav_index(self, key):
        if key is None:
            return None
        for i, f in enumerate(self.config.data.get("favorites", [])):
            if (f.get("acc"), f.get("cid"), f.get("ns", ""), f.get("view"), f.get("res", "")) == key:
                return i
        return None

    @staticmethod
    def _fav_loc(f):
        loc = {"view": f.get("view", "overview"), "acc": f.get("acc"), "cid": f.get("cid")}
        if f.get("ns"):
            loc["ns"] = f["ns"]
        if loc["view"] == "list":
            res = CATALOG_BY_KEY.get(f.get("res", ""))
            if res is None:
                return None
            loc["res"] = res
        return loc

    def _fav_default_label(self, loc):
        if loc.get("ns"):
            extra = {"list": (loc.get("res") or {}).get("label", ""), "topology": "Topologie", "helm": "Charts Helm",
                     "all": "Tous les objets"}.get(loc["view"], "")
            return loc["ns"] + (f" · {extra}" if extra else "")
        return self.clusters.get((loc.get("acc"), loc.get("cid")), {}).get("name") or loc.get("acc", "")

    def toggle_favorite(self, loc=None):
        loc = loc or self.loc
        key = self._fav_key(loc)
        if key is None:
            return
        favs = self.config.data.setdefault("favorites", [])
        i = self._fav_index(key)
        if i is not None:
            removed = favs.pop(i)
            self.flash(f"Retiré des favoris : {removed.get('label')}")
        else:
            label = self._fav_default_label(loc)
            favs.append({"acc": key[0], "cid": key[1], "ns": key[2], "view": key[3], "res": key[4], "label": label})
            self.flash(f"Ajouté aux favoris : {label} (clic droit sur le favori › Renommer pour lui donner un nom "
                       "parlant)", 8000)
        self._save()
        self._render_favorites()
        self._update_commands()

    def rename_favorite(self, i):
        favs = self.config.data.get("favorites", [])
        if not 0 <= i < len(favs):
            return
        text, ok = QInputDialog.getText(self, "Renommer le favori",
                                        f"Nom affiché pour {favs[i].get('ns') or favs[i].get('acc')} :",
                                        QLineEdit.EchoMode.Normal, favs[i].get("label", ""))
        if ok and text.strip():
            favs[i]["label"] = text.strip()[:80]
            self._save()
            self._render_favorites()

    def remove_favorite(self, i):
        favs = self.config.data.get("favorites", [])
        if 0 <= i < len(favs):
            favs.pop(i)
            self._save()
            self._render_favorites()
            self._update_commands()

    def _render_favorites(self):
        expanded = self.nav_items["FAVS"].isExpanded() if "FAVS" in self.nav_items else True
        self._nav_remove("FAVS")
        favs = self.config.data.get("favorites", [])
        root = self._nav_add(None, "FAVS", "Favoris", "fav", index=0)
        root.setFlags(Qt.ItemFlag.ItemIsEnabled)
        root.setFont(0, ui_font(13, True))
        if not favs:
            hint = self._nav_add("FAVS", f"FAVS{SEP}aide", "Clic droit sur un namespace › Ajouter aux favoris")
            hint.setFlags(Qt.ItemFlag.ItemIsEnabled)
            hint.setForeground(0, QBrush(QColor(C["text2"])))
        for i, f in enumerate(favs):
            label = f.get("label") or f.get("ns") or f.get("acc")
            text = label if not f.get("ns") or f["ns"] in label else f"{label}  ({f['ns']})"
            icon = {"topology": "topology", "helm": "helm", "all": "all", "cluster": "openshift"}.get(
                f.get("view"), "folder")
            if f.get("view") == "list":
                icon = (CATALOG_BY_KEY.get(f.get("res", "")) or {}).get("icon", "doc")
            it = self._nav_add("FAVS", f"FAV{SEP}{i}", text, icon)
            cl = self.clusters.get((f.get("acc"), f.get("cid")), {})
            it.setToolTip(0, " › ".join(x for x in (f.get("acc"), cl.get("name") if cl.get("name") != f.get("acc")
                                                    else "", f.get("ns")) if x))
        root.setExpanded(expanded)
        if self.nav_search.text() if hasattr(self, "nav_search") else "":
            self._filter_nav(self.nav_search.text())

    # ------------------------------------------------------------------ recherche dans l'arbre
    def focus_nav_search(self):
        self.nav_search.setFocus()
        self.nav_search.selectAll()

    def _filter_nav(self, text):
        """Filtre l'arbre : namespaces, favoris, clusters et comptes dont le nom contient le texte."""
        q = (text or "").strip().lower()

        def kind(it):
            return str(it.data(0, Qt.ItemDataRole.UserRole) or "").split(SEP)[0]

        def walk(it):
            k = kind(it)
            own = bool(q) and k in ("N", "FAV", "C", "A") and (q in it.text(0).lower() or q in (it.toolTip(0) or
                                                                                              "").lower())
            any_child = False
            for i in range(it.childCount()):
                any_child = walk(it.child(i)) or any_child
            visible = not q or own or any_child
            it.setHidden(not visible)
            if q and any_child:
                it.setExpanded(True)
            return visible and bool(q)

        self._syncing = True
        try:
            for i in range(self.nav.topLevelItemCount()):
                walk(self.nav.topLevelItem(i))
        finally:
            self._syncing = False

    def _nav_search_go(self):
        """Entrée dans la recherche : ouvre le premier favori ou namespace trouvé."""
        found = []

        def walk(it):
            if not it.isHidden():
                if str(it.data(0, Qt.ItemDataRole.UserRole) or "").split(SEP)[0] in ("FAV", "N"):
                    found.append(it)
                for i in range(it.childCount()):
                    walk(it.child(i))
        for i in range(self.nav.topLevelItemCount()):
            walk(self.nav.topLevelItem(i))
        if found and self.nav_search.text().strip():
            loc = self._loc_from_iid(found[0].data(0, Qt.ItemDataRole.UserRole))
            if loc:
                self.navigate(loc)
                self.nav.setFocus()

    # ------------------------------------------------------------------ paramètres, aide
    def open_settings(self):
        d = SettingsDialog(self, self.config.settings)
        if d.exec() != QDialog.DialogCode.Accepted:
            return
        self.config.settings.update(d.s)
        self._save()
        NET.configure(self.config.settings)
        self.flash("Paramètres enregistrés.")

    def show_shortcuts(self):
        k = (lambda s: QKeySequence(s).toString(QKeySequence.SequenceFormat.NativeText))
        lines = [(k("F5"), "Actualiser"), (k("Ctrl+L"), "Logs du pod"), (k("Ctrl+Y"), "YAML de l'objet"),
                 (k("Ctrl+Shift+O"), "Ouvrir dans la console OpenShift (pour modifier)"),
                 (k("Ctrl+T"), "Terminal du pod (console OpenShift)"),
                 (k("Ctrl+D"), "Ajouter / retirer des favoris"), (k("Ctrl+P"), "Rechercher un namespace ou un favori"),
                 (k("Ctrl+F"), "Rechercher dans la liste"), (f"{k('Ctrl+[')} / {k('Ctrl+]')}", "Précédent / Suivant"),
                 (f"{k('Ctrl+Up')} ou {k('Backspace')}", "Dossier parent"), (k("Ctrl+W"), "Fermer l'onglet"),
                 (k("Meta+Tab") if IS_MAC else k("Ctrl+Tab"), "Onglet suivant"),
                 (k("Ctrl+Alt+P"), "Volet des détails")]
        QMessageBox.information(self, "Raccourcis clavier", "\n".join(f"{a}\t{b}" for a, b in lines))

    def show_lock(self):
        opened = hotes_autorises()
        text = ("Verrou anti-exfiltration : " + ("actif" if _VERROU["actif"] else "INACTIF") + "\n"
                "Aucun autre programme ne peut être lancé.\n\n"
                "Destinations permises :\n  " + "\n  ".join("*." + d for d in NET.domains()) +
                ("\n  " + "\n  ".join(sorted(NET.declared)) if NET.declared else "") +
                "\n\nAdresses contactées depuis le lancement :\n  " +
                ("\n  ".join(opened) if opened else "(aucune)") +
                "\n\nCertificats : " + ("ceux du Mac et ceux de Python" if NET.use_mac and NET.mac_pem
                                        else "ceux de Python") +
                (f" + {short_path(os.path.expanduser(NET.ca_file))}" if NET.ca_file else "") +
                "\nProxy : " + {"auto": "automatique", "none": "aucun"}.get(NET.proxy, NET.proxy))
        QMessageBox.information(self, "Verrou réseau", text)

    def about(self):
        etat = {True: "fichier intact", False: "FICHIER MODIFIÉ OU ABÎMÉ : à retélécharger",
                None: "fichier non vérifié"}[fichier_intact()]
        QMessageBox.about(self, f"À propos de {APP_NAME}",
                          f"<b>{APP_NAME} {VERSION}</b> du {VERSION_DATE}<br>{etat}<br><br>"
                          "Explorateur de clusters IBM Cloud Kubernetes Service et Red Hat OpenShift on IBM Cloud, "
                          "d'après le PaaSExplorer d'origine.<br><br>"
                          f"{version_details()}<br>"
                          "Lecture seule : les modifications se font dans la console OpenShift.<br>"
                          "Codes à usage unique, jetons et clés : en mémoire seulement, jamais "
                          "enregistrés.<br>"
                          f"Réglages : {short_path(self.config.path)}<br>"
                          f"Script : {short_path(os.path.abspath(__file__))}")

    # ------------------------------------------------------------------ fermeture
    def closeEvent(self, ev):
        st = self.config.settings
        try:
            st["windowGeometry"] = bytes(self.saveGeometry().toBase64()).decode()
            sizes = self.split.sizes()
            if sizes and sizes[0] > 0:
                st["navWidth"] = sizes[0]
        except Exception:  # noqa: BLE001
            pass
        self._save()
        for i in reversed(range(1, self.tabs.count())):
            self.close_tab(i)
        super().closeEvent(ev)


# ======================================================================================
# Lancement
# ======================================================================================

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
    os.environ.setdefault("QT_MAC_WANTS_LAYER", "1")
    mac_pem = certificats_du_mac()           # avant le verrou : ensuite, plus aucun programme ne peut être lancé
    installer_verrou()
    config = Config()
    NET.configure(config.settings, mac_pem)
    app = QApplication(sys.argv[:1])
    from PySide6.QtCore import QLibraryInfo, QTranslator
    tr = QTranslator(app)
    if tr.load("qtbase_fr", QLibraryInfo.path(QLibraryInfo.LibraryPath.TranslationsPath)):
        app.installTranslator(tr)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(VERSION)
    app.setOrganizationName(ORG_NAME)
    apply_theme(app)
    app.setWindowIcon(Icons.get("kubernetes"))
    win = PaaSWindow(config)
    win.show()
    problems = controle_reseau()
    if problems:
        QMessageBox.critical(win, APP_NAME, "Le verrou a détecté un module interdit :\n" + "\n".join(problems))
    QTimer.singleShot(500, avertir_si_abime)
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
