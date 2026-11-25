#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Explorateur — gestionnaire de fichiers au look de l'Explorateur Windows 11, pour macOS.

Lancement :   python explorateur.py [dossier]
Dépendance :  PySide6   (python -m pip install PySide6)

Pas de réseau, pas d'admin, rien d'installé dans le système : c'est un script.
Les icônes sont dessinées par le programme (aucune image de Microsoft).

Sécurité (vérifié) :
  - aucun accès réseau : seuls QtCore, QtGui et QtWidgets sont chargés, jamais QtNetwork ;
  - aucune donnée envoyée nulle part ; seuls réglages enregistrés : taille de fenêtre,
    dernier dossier, dossiers épinglés, mode d'affichage (registre Windows / préférences Mac) ;
  - les commandes système sont lancées par leur chemin complet, sans passer par un shell ;
  - les archives ZIP piégées (« zip-slip ») sont détectées à l'extraction.

Raccourcis (Cmd et Ctrl marchent tous les deux) :
  Entrée              ouvrir                      F2                renommer
  ⌫ (retour arrière)  dossier précédent           Suppr / Cmd+⌫     mettre à la corbeille
  Maj+Suppr           supprimer définitivement    Espace            aperçu (Quick Look)
  Ctrl+C / X / V      copier / couper / coller    Ctrl+Maj+N        nouveau dossier
  Ctrl+T / Ctrl+W     nouvel onglet / fermer      Ctrl+Tab          onglet suivant
  Alt+← / → / ↑       précédent / suivant / parent
  Ctrl+L, Alt+D, F4   barre d'adresse             Ctrl+F, F3        rechercher (Entrée = sous-dossiers)
  Ctrl+Maj+1…6        changer d'affichage         Ctrl+molette      zoom des icônes
  F5                  actualiser                  Alt+Entrée        propriétés
Sur un clavier Mac, la touche Suppr s'obtient avec fn+⌫.
"""

import atexit
import collections
import errno
import functools
import html
import math
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
import zipfile

try:
    from PySide6.QtCore import (QDir, QEvent, QFile, QFileInfo, QFileSystemWatcher,
                                QItemSelectionModel, QMimeData, QModelIndex, QObject, QPoint,
                                QPointF, QProcess, QRect, QRectF, QSettings, QSize,
                                QSortFilterProxyModel, QStandardPaths, QStorageInfo, QTimer,
                                QUrl, Qt, Signal, Slot)
    from PySide6.QtGui import (QAction, QActionGroup, QColor, QDesktopServices, QDrag,
                               QFontMetrics, QGuiApplication, QIcon, QImage, QImageReader,
                               QKeySequence, QLinearGradient, QPainter, QPainterPath, QPalette,
                               QPen, QPixmap, QPolygonF)
    try:
        from PySide6.QtGui import QFileSystemModel
    except ImportError:  # anciennes versions
        from PySide6.QtWidgets import QFileSystemModel
    from PySide6.QtWidgets import (QAbstractItemView, QApplication, QCompleter, QDialog,
                                   QDialogButtonBox, QFileDialog, QFileIconProvider,
                                   QFormLayout, QFrame, QHBoxLayout, QInputDialog, QLabel,
                                   QLineEdit, QListView, QListWidget, QListWidgetItem,
                                   QMainWindow, QMenu, QMessageBox, QProgressDialog,
                                   QPushButton, QSplitter, QStackedLayout, QStackedWidget,
                                   QStyle, QStyledItemDelegate, QTabBar, QToolButton,
                                   QTreeView, QTreeWidget, QTreeWidgetItem,
                                   QTreeWidgetItemIterator, QVBoxLayout, QWidget,
                                   QWidgetAction)
except ImportError:
    sys.stderr.write("PySide6 n'est pas installé.  Commande :  python -m pip install PySide6\n")
    sys.exit(1)


# ======================================================================================
# Constantes, couleurs, petites fonctions
# ======================================================================================

IS_MAC = sys.platform == "darwin"
IS_WIN = sys.platform.startswith("win")
_P = os.path   # module de chemins (remplaçable dans les tests)
APP_NAME = "Explorateur"
ORG_NAME = "explorateur-maison"


def norm(path):
    """Chemin normalisé, toujours avec des « / » (comme Qt), y compris sous Windows."""
    p = _P.normpath(path)
    if IS_WIN:
        p = p.replace("\\", "/")
        if len(p) == 2 and p[1] == ":":
            p += "/"
    return p


def pjoin(*parts):
    return norm(_P.join(*parts))


def pdir(path):
    return norm(_P.dirname(path))


def native(path):
    """Chemin tel que l'utilisateur l'attend (antislashs sous Windows)."""
    return path.replace("/", "\\") if IS_WIN and path else path


HOME = norm(os.path.expanduser("~"))
HOME_LOC = "::accueil"
PC_LOC = "::ce-pc"
SPECIAL_LOCS = (HOME_LOC, PC_LOC)
SPECIAL_NAMES = {HOME_LOC: "Accueil", PC_LOC: "Ce PC"}
REVEAL_LABEL = ("Afficher dans le Finder" if sys.platform == "darwin" else
                "Ouvrir dans l'Explorateur Windows" if sys.platform.startswith("win") else
                "Ouvrir dans le gestionnaire de fichiers")

ROLE_PATH = int(Qt.ItemDataRole.UserRole)
ROLE_KIND = ROLE_PATH + 1
ROLE_SUB = ROLE_PATH + 2
ROLE_RATIO = ROLE_PATH + 3
ROLE_THUMB = ROLE_PATH + 4

# Thème clair façon Windows 11
C = {
    "strip": "#E9EDF2",       # bande des onglets
    "chrome": "#F7F9FC",      # onglet actif, barre d'adresse, barre de commandes
    "body": "#FFFFFF",
    "border": "#E3E3E3",
    "line": "#EBEBEB",
    "text": "#1A1A1A",
    "text2": "#616161",
    "disabled": "#A3A3A3",
    "hover": "#EEF4FB",
    "select": "#CCE4F7",
    "selhover": "#BDDCF5",
    "navsel": "#E6ECF4",
    "navhover": "#F1F4F8",
    "accent": "#005FB8",
    "menu": "#F9F9F9",
    "danger": "#C42B1C",
}

VIEW_MODES = collections.OrderedDict([
    ("xl", ("Très grandes icônes", 256)),
    ("large", ("Grandes icônes", 96)),
    ("medium", ("Icônes moyennes", 48)),
    ("small", ("Petites icônes", 16)),
    ("list", ("Liste", 16)),
    ("details", ("Détails", 16)),
])
ZOOM_ORDER = ["details", "list", "small", "medium", "large", "xl"]

PACKAGE_EXTS = {
    ".app", ".bundle", ".framework", ".plugin", ".kext", ".appex", ".prefpane",
    ".qlgenerator", ".mdimporter", ".saver", ".photoslibrary", ".musiclibrary",
    ".tvlibrary", ".pages", ".numbers", ".key", ".rtfd", ".xcarchive", ".playground",
    ".scptd", ".workflow", ".action", ".pkg", ".mpkg", ".fcpbundle", ".band", ".logicx",
}
DOCUMENT_PACKAGES = {".pages", ".numbers", ".key", ".rtfd"}
# Formats d'image pour les miniatures : liste fixe, pour que Qt ne charge que ces lecteurs-là
# (demander la liste à Qt charge tous ses modules d'image, dont le lecteur PDF qui embarque QtNetwork).
IMAGE_FORMATS = {".jpg": b"jpeg", ".jpeg": b"jpeg", ".png": b"png", ".gif": b"gif", ".bmp": b"bmp",
                 ".webp": b"webp", ".tif": b"tiff", ".tiff": b"tiff", ".ico": b"ico"}
IMAGE_EXTS = set(IMAGE_FORMATS)

_SPECIAL = [   # (nom affiché, emplacement standard, sous-dossier par défaut, icône)
    ("Bureau", "DesktopLocation", "Desktop", "desktop"),
    ("Téléchargements", "DownloadLocation", "Downloads", "downloads"),
    ("Documents", "DocumentsLocation", "Documents", "documents"),
    ("Images", "PicturesLocation", "Pictures", "pictures"),
    ("Musique", "MusicLocation", "Music", "music"),
    ("Vidéos", "MoviesLocation", "Videos" if IS_WIN else "Movies", "videos"),
]


@functools.lru_cache(maxsize=1)
def special_folders():
    """Bureau, Documents… à leur vrai emplacement (y compris redirigés vers OneDrive sous Windows)."""
    out = []
    for label, location, sub, icon in _SPECIAL:
        try:
            path = QStandardPaths.writableLocation(getattr(QStandardPaths.StandardLocation, location))
        except Exception:  # noqa: BLE001
            path = ""
        path = norm(path) if path else pjoin(HOME, sub)
        if path != HOME:
            out.append((label, path, icon))
    return out


def ext_of(name):
    return os.path.splitext(name)[1].lower()


def is_package_dir(path):
    if ext_of(path.rstrip("/")) in PACKAGE_EXTS:
        return True
    return IS_MAC and QFileInfo(path).isBundle()


def is_folder(path):
    """Vrai pour un dossier dans lequel on « entre » (pas un .app, .pages…)."""
    return bool(path) and path not in SPECIAL_LOCS and os.path.isdir(path) and not is_package_dir(path)


def fold(text):
    """Minuscules sans accents (macOS stocke souvent les accents décomposés)."""
    text = unicodedata.normalize("NFKD", text)
    return "".join(c for c in text if not unicodedata.combining(c)).casefold()


_DIGITS = re.compile(r"(\d+)")


@functools.lru_cache(maxsize=100000)
def natural_key(name):
    """Tri « naturel » comme Windows : photo 2 avant photo 10."""
    parts = _DIGITS.split(fold(name))
    return tuple((0, int(p), "") if p.isdecimal() else (1, 0, p) for p in parts if p)


def fmt_ko(n):
    return "{:,}".format((n + 1023) // 1024).replace(",", " ") + " Ko"


def fmt_human(n):
    if n < 1024:
        return f"{n} octet" + ("s" if n > 1 else "")
    value = float(n)
    unit = "Ko"
    for unit in ("Ko", "Mo", "Go", "To", "Po"):
        value /= 1024.0
        if value < 1024:
            break
    txt = f"{value:.2f}" if value < 10 else (f"{value:.1f}" if value < 100 else f"{value:.0f}")
    return txt.replace(".", ",") + " " + unit


def fmt_bytes_exact(n):
    return "{:,}".format(n).replace(",", " ") + " octets"


def type_text(info):
    if info.isSymLink():
        return "Raccourci" if info.exists() else "Raccourci (cassé)"
    suffix = info.suffix()
    ext = ("." + suffix.lower()) if suffix else ""
    if info.isDir():
        if ext == ".app":
            return "Application"
        if ext in DOCUMENT_PACKAGES:
            return f"Fichier {suffix.upper()}"
        if ext in PACKAGE_EXTS:
            return "Paquet"
        return "Dossier de fichiers"
    return f"Fichier {suffix.upper()}" if suffix else "Fichier"


def is_dir_like(info):
    return info.isDir() and ("." + info.suffix().lower()) not in PACKAGE_EXTS


def split_name(name, is_dir):
    if is_dir and ext_of(name) not in PACKAGE_EXTS:
        return name, ""
    stem, ext = os.path.splitext(name)
    return (stem, ext) if stem else (name, "")


def unique_path(folder, name, is_dir=False, copy_style=False):
    """« Nouveau dossier (2) » ou « rapport - Copie (2).pdf », comme Windows."""
    stem, ext = split_name(name, is_dir)
    base = f"{stem} - Copie" if copy_style else stem
    candidate = pjoin(folder, base + ext)
    n = 2
    while os.path.lexists(candidate):
        candidate = pjoin(folder, f"{base} ({n}){ext}")
        n += 1
    return candidate


def local_paths(mime):
    out = []
    if mime is None or not mime.hasUrls():
        return out
    for url in mime.urls():
        if url.isLocalFile():
            p = url.toLocalFile()
            if p:
                out.append(norm(p))
    return out


def same_device(a, b):
    try:
        return os.lstat(a).st_dev == os.stat(b).st_dev
    except OSError:
        return False


def settings():
    return QSettings(ORG_NAME, APP_NAME)


def pinned_folders():
    value = settings().value("pinned", [])
    if isinstance(value, str):
        value = [value]
    return [p for p in (value or []) if isinstance(p, str)]


def set_pinned_folders(paths):
    settings().setValue("pinned", list(paths))


def _win_dir(*parts):
    return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), *parts)


# Toujours le chemin complet : un programme du même nom posé dans le dossier courant
# ne peut pas être lancé à la place du vrai.
CMD = {
    "open": "/usr/bin/open",
    "qlmanage": "/usr/bin/qlmanage",
    "mdfind": "/usr/bin/mdfind",
    "diskutil": "/usr/sbin/diskutil",
    "cp": "/bin/cp",
    "ditto": "/usr/bin/ditto",
    "explorer": _win_dir("explorer.exe"),
    "openwith": _win_dir("System32", "OpenWith.exe"),
    "powershell": _win_dir("System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
    "wt": os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "WindowsApps", "wt.exe"),
}


@functools.lru_cache(maxsize=1)
def vscode_path():
    """Emplacement de Visual Studio Code s'il est installé, sinon chaîne vide."""
    if IS_MAC:
        for base in ("/Applications", pjoin(HOME, "Applications")):
            app = pjoin(base, "Visual Studio Code.app")
            if os.path.isdir(app):
                return app
        try:   # installé ailleurs : on demande à Spotlight (local)
            out = subprocess.run([CMD["mdfind"], "kMDItemCFBundleIdentifier == 'com.microsoft.VSCode'"],
                                 capture_output=True, text=True, timeout=2).stdout
            for line in out.splitlines():
                if line.endswith(".app") and os.path.isdir(line):
                    return line
        except (OSError, subprocess.SubprocessError):
            pass
        return ""
    if IS_WIN:
        candidates = [os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "Microsoft VS Code", "Code.exe")]
        for var in ("ProgramFiles", "ProgramFiles(x86)"):
            if os.environ.get(var):
                candidates.append(os.path.join(os.environ[var], "Microsoft VS Code", "Code.exe"))
        return next((c for c in candidates if os.path.isfile(c)), "")
    return shutil.which("code") or ""


ANNOTATE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tif", ".tiff"}


def annoter_script():
    """L'annoteur (annoter.py), s'il est rangé à côté de ce programme."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "annoter.py")
    return path if os.path.isfile(path) else ""


def blocnotes_script():
    """Bloc-notes Pro (blocnotes.py), s'il est rangé à côté de ce programme."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "blocnotes.py")
    return path if os.path.isfile(path) else ""


def detached(program, args, workdir=""):
    program = CMD.get(program, program)
    if workdir:
        QProcess.startDetached(program, list(args), workdir)
    else:
        QProcess.startDetached(program, list(args))


def system_volume_label():
    label = QStorageInfo("/").displayName()
    return label if label and label != "/" else ("Macintosh HD" if IS_MAC else "Disque local")


def volumes():
    out = []
    for vol in QStorageInfo.mountedVolumes():
        if not vol.isValid() or not vol.isReady():
            continue
        root = vol.rootPath()
        if IS_WIN:
            root = norm(root)
            out.append((location_title(root), root))
        elif root == "/":
            out.append((system_volume_label(), root))
        elif root.startswith("/Volumes/"):
            out.append((vol.displayName() or os.path.basename(root), root))
    out.sort(key=lambda v: v[1].lower() if IS_WIN else ("" if v[1] == "/" else v[0].lower()))
    return out


def volume_root(path):
    """Racine du disque : « C:/ » sous Windows, « / » ou « /Volumes/Clé » sur Mac."""
    if IS_WIN:
        drive = _P.splitdrive(path)[0]
        return norm(drive + "/") if drive else "/"
    if path.startswith("/Volumes/"):
        return "/".join(path.split("/")[:3])
    return "/"


def is_volume_root(loc):
    return bool(loc) and loc not in SPECIAL_LOCS and loc == volume_root(loc)


def location_title(loc):
    if loc in SPECIAL_NAMES:
        return SPECIAL_NAMES[loc]
    if is_volume_root(loc):
        if IS_WIN:
            drive = loc.rstrip("/")
            name = QStorageInfo(loc).displayName()
            if len(drive) == 2:
                if name in ("", loc, drive, drive + "\\"):
                    name = "Disque local"
                return f"{name} ({drive})"
            return name or loc
        if loc == "/":
            return system_volume_label()
        return QStorageInfo(loc).displayName() or _P.basename(loc)
    return _P.basename(loc.rstrip("/")) or loc


def special_folder_icon_name(path):
    for _label, folder, icon in special_folders():
        if path == folder:
            return icon
    return None


def is_hidden_entry(entry):
    if entry.name.startswith("."):
        return True
    if IS_WIN:   # attribut « caché » de Windows
        try:
            return bool(entry.stat(follow_symlinks=False).st_file_attributes & 2)
        except (OSError, AttributeError):
            return False
    return False


def subfolders(path, show_hidden=False):
    out = []
    try:
        with os.scandir(path) as it:
            for entry in it:
                if not show_hidden and is_hidden_entry(entry):
                    continue
                try:
                    if entry.is_dir() and ext_of(entry.name) not in PACKAGE_EXTS:
                        out.append(norm(entry.path))
                except OSError:
                    pass
    except OSError:
        pass
    out.sort(key=lambda p: natural_key(os.path.basename(p)))
    return out


def shortcut_keys(*sequences):
    """Chaque raccourci Cmd+X existe aussi en Ctrl+X (la touche Ctrl physique du Mac)."""
    out = []
    for seq in sequences:
        out.append(QKeySequence(seq))
        if IS_MAC and seq.startswith("Ctrl+"):
            out.append(QKeySequence("Meta+" + seq[5:]))
    return out


class State:
    windows = []
    cut_paths = set()
    thumbs = None


# ======================================================================================
# Icônes dessinées (dessin maison, style « Fluent » épuré)
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


@_icon("search")
def _(p, c):
    _pen(p, c, 1.3); p.drawEllipse(QRectF(2.2, 2.2, 8.4, 8.4)); _line(p, 9.4, 9.4, 13.8, 13.8)


@_icon("plus")
def _(p, c):
    _pen(p, c, 1.3); _line(p, 8, 2.5, 8, 13.5); _line(p, 2.5, 8, 13.5, 8)


@_icon("new")
def _(p, c):
    _pen(p, c, 1.2); p.drawEllipse(QRectF(1.6, 1.6, 12.8, 12.8))
    _line(p, 8, 4.8, 8, 11.2); _line(p, 4.8, 8, 11.2, 8)


@_icon("cut")
def _(p, c):
    _pen(p, c, 1.2)
    p.drawEllipse(QRectF(2.2, 10.2, 3.8, 3.8)); p.drawEllipse(QRectF(10.0, 10.2, 3.8, 3.8))
    _line(p, 5.3, 10.6, 11.0, 2.0); _line(p, 10.7, 10.6, 5.0, 2.0)


@_icon("copy")
def _(p, c):
    _pen(p, c, 1.2)
    p.drawRoundedRect(QRectF(5.2, 5.0, 8.3, 9.2), 1.6, 1.6)
    _poly(p, (2.5, 10.8), (2.5, 3.6), (3.6, 2.4), (9.6, 2.4))


@_icon("paste")
def _(p, c):
    _pen(p, c, 1.2)
    p.drawRoundedRect(QRectF(2.8, 3.0, 10.4, 11.6), 1.6, 1.6)
    p.drawRoundedRect(QRectF(5.6, 1.6, 4.8, 2.8), 0.9, 0.9)
    _line(p, 5.6, 8.0, 10.4, 8.0); _line(p, 5.6, 10.6, 9.0, 10.6)


@_icon("rename")
def _(p, c):
    _pen(p, c, 1.2)
    _poly(p, (10.2, 4.5), (2.8, 4.5), (1.6, 5.7), (1.6, 10.3), (2.8, 11.5), (10.2, 11.5))
    _line(p, 12.8, 2.4, 12.8, 13.6); _line(p, 11.4, 2.4, 14.2, 2.4); _line(p, 11.4, 13.6, 14.2, 13.6)


@_icon("delete")
def _(p, c):
    _pen(p, c, 1.2)
    _line(p, 2.4, 4.0, 13.6, 4.0); _poly(p, (6.0, 4.0), (6.4, 2.2), (9.6, 2.2), (10.0, 4.0))
    path = QPainterPath(); path.moveTo(3.8, 4.0); path.lineTo(4.7, 13.0)
    path.quadTo(4.8, 14.2, 6.0, 14.2); path.lineTo(10.0, 14.2); path.quadTo(11.2, 14.2, 11.3, 13.0)
    path.lineTo(12.2, 4.0); p.drawPath(path)
    _line(p, 6.8, 6.6, 6.8, 11.6); _line(p, 9.2, 6.6, 9.2, 11.6)


@_icon("sort")
def _(p, c):
    _pen(p, c, 1.2)
    _line(p, 5, 13.5, 5, 2.5); _poly(p, (2.6, 4.9), (5, 2.5), (7.4, 4.9))
    _line(p, 11, 2.5, 11, 13.5); _poly(p, (8.6, 11.1), (11, 13.5), (13.4, 11.1))


@_icon("view")
def _(p, c):
    _pen(p, c, 1.2)
    for y in (3.5, 8.0, 12.5):
        p.drawRoundedRect(QRectF(1.8, y - 1.3, 2.6, 2.6), 0.6, 0.6)
        _line(p, 6.4, y, 14.2, y)


@_icon("tiles")
def _(p, c):
    _pen(p, c, 1.2)
    for x, y in ((2.0, 2.0), (9.0, 2.0), (2.0, 9.0), (9.0, 9.0)):
        p.drawRoundedRect(QRectF(x, y, 5.0, 5.0), 1.0, 1.0)


@_icon("more")
def _(p, c):
    p.setPen(Qt.PenStyle.NoPen); p.setBrush(QColor(c))
    for x in (3.2, 8.0, 12.8):
        p.drawEllipse(QPointF(x, 8.0), 1.15, 1.15)


@_icon("chevdown")
def _(p, c):
    _pen(p, c, 1.3); _poly(p, (3.5, 6), (8, 10.5), (12.5, 6))


@_icon("chevup")
def _(p, c):
    _pen(p, c, 1.3); _poly(p, (3.5, 10), (8, 5.5), (12.5, 10))


@_icon("chevright")
def _(p, c):
    _pen(p, c, 1.3); _poly(p, (6, 3.5), (10.5, 8), (6, 12.5))


@_icon("chevleft")
def _(p, c):
    _pen(p, c, 1.3); _poly(p, (10, 3.5), (5.5, 8), (10, 12.5))


@_icon("close")
def _(p, c):
    _pen(p, c, 1.2); _line(p, 4.5, 4.5, 11.5, 11.5); _line(p, 11.5, 4.5, 4.5, 11.5)


@_icon("check")
def _(p, c):
    _pen(p, c, 1.4); _poly(p, (3.2, 8.4), (6.4, 11.6), (12.8, 4.6))


@_icon("dot")
def _(p, c):
    p.setPen(Qt.PenStyle.NoPen); p.setBrush(QColor(c)); p.drawEllipse(QPointF(8, 8), 2.6, 2.6)


@_icon("pin")
def _(p, c):
    _pen(p, c, 1.1)
    _line(p, 2.5, 13.5, 6.2, 9.8)
    path = QPainterPath()
    path.moveTo(9.6, 2.2); path.lineTo(13.8, 6.4); path.lineTo(11.4, 7.6); path.lineTo(9.4, 11.6)
    path.lineTo(4.4, 6.6); path.lineTo(8.4, 4.6); path.closeSubpath()
    p.drawPath(path)


@_icon("home")
def _(p, c):
    _pen(p, c, 1.2)
    _poly(p, (1.8, 7.6), (8, 2.2), (14.2, 7.6))
    _poly(p, (3.6, 6.3), (3.6, 13.6), (12.4, 13.6), (12.4, 6.3))
    _poly(p, (6.7, 13.6), (6.7, 9.6), (9.3, 9.6), (9.3, 13.6))


@_icon("terminal")
def _(p, c):
    _pen(p, c, 1.2); p.drawRoundedRect(QRectF(1.6, 2.6, 12.8, 10.8), 1.6, 1.6)
    _poly(p, (4.2, 6.2), (6.4, 8.0), (4.2, 9.8)); _line(p, 7.6, 10.2, 11.0, 10.2)


@_icon("info")
def _(p, c):
    _pen(p, c, 1.2); p.drawEllipse(QRectF(1.6, 1.6, 12.8, 12.8)); _line(p, 8, 7.2, 8, 11.4)
    p.setBrush(QColor(c)); p.drawEllipse(QPointF(8, 4.9), 0.5, 0.5)


@_icon("zip")
def _(p, c):
    _pen(p, c, 1.2); p.drawRoundedRect(QRectF(2.5, 1.8, 11, 12.4), 1.6, 1.6)
    for y in (3.6, 5.6, 7.6):
        _line(p, 7.2, y, 8.8, y)
    p.drawRoundedRect(QRectF(6.6, 9.0, 2.8, 3.2), 0.6, 0.6)


@_icon("finder")
def _(p, c):
    _pen(p, c, 1.2); p.drawRoundedRect(QRectF(1.6, 1.6, 12.8, 12.8), 2.4, 2.4)
    _line(p, 8, 1.6, 7, 14.4); p.drawArc(QRectF(4, 8, 8, 4), 200 * 16, 140 * 16)


@_icon("openwith")
def _(p, c):
    _pen(p, c, 1.2); p.drawRoundedRect(QRectF(1.8, 4.2, 10, 10), 1.6, 1.6)
    _line(p, 7.5, 8.5, 14, 2); _poly(p, (9.8, 2), (14, 2), (14, 6.2))


@_icon("wrench")
def _(p, c):
    _pen(p, c, 1.3)
    p.drawArc(QRectF(8.0, 1.9, 6.2, 6.2), 75 * 16, 300 * 16)
    _pen(p, c, 2.0)
    _line(p, 8.9, 7.3, 3.0, 13.2)


@_icon("code")
def _(p, c):
    _pen(p, "#1F7BD6", 1.4)
    _poly(p, (5.4, 4.4), (2.2, 8.0), (5.4, 11.6))
    _poly(p, (10.6, 4.4), (13.8, 8.0), (10.6, 11.6))
    _line(p, 9.1, 3.2, 6.9, 12.8)


@_icon("annotate")
def _(p, c):
    _pen(p, "#E81123", 1.3)
    p.drawRoundedRect(QRectF(1.8, 3.2, 9.4, 7.4), 1.0, 1.0)
    _pen(p, c, 1.2)
    p.drawPolygon(QPolygonF([QPointF(12.6, 6.0), QPointF(14.4, 7.8), QPointF(8.4, 13.8), QPointF(6.2, 14.4),
                             QPointF(6.8, 12.2)]))


@_icon("notepad")
def _(p, c):
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#FFFFFF"))
    p.drawRect(QRectF(2.5, 1.5, 11, 13))
    _pen(p, "#7A8696", 0.9)
    p.drawRect(QRectF(2.5, 1.5, 11, 13))
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#1A9E8F"))
    p.drawRect(QRectF(2.5, 1.5, 11, 2.6))
    p.setBrush(QColor("#5B6B7F"))
    for y, w in ((6.2, 7.6), (8.4, 5.8), (10.6, 6.8)):
        p.drawRect(QRectF(4.2, y, w, 0.9))


@_icon("moreoptions")
def _(p, c):
    _pen(p, c, 1.2)
    _poly(p, (8.0, 2.2), (3.4, 2.2), (2.2, 3.4), (2.2, 12.6), (3.4, 13.8), (12.6, 13.8), (13.8, 12.6), (13.8, 8.0))
    _line(p, 7.8, 8.2, 13.6, 2.4)
    _poly(p, (9.6, 2.4), (13.6, 2.4), (13.6, 6.4))


@_icon("selectall")
def _(p, c):
    _pen(p, c, 1.2); p.setPen(QPen(QColor(c), 1.1, Qt.PenStyle.DashLine))
    p.drawRoundedRect(QRectF(1.8, 1.8, 12.4, 12.4), 1.6, 1.6)
    _pen(p, c, 1.3); _poly(p, (4.8, 8.2), (7.0, 10.4), (11.2, 5.8))


@_icon("pane")
def _(p, c):
    _pen(p, c, 1.2); p.drawRoundedRect(QRectF(1.6, 2.4, 12.8, 11.2), 1.6, 1.6); _line(p, 5.6, 2.4, 5.6, 13.6)


# ---- icônes en couleur ----

@_icon("folder")
def _(p, c):
    p.setPen(Qt.PenStyle.NoPen)
    back = QPainterPath()
    back.moveTo(1.5, 4.0); back.quadTo(1.5, 2.8, 2.7, 2.8); back.lineTo(6.0, 2.8); back.lineTo(7.4, 4.2)
    back.lineTo(13.3, 4.2); back.quadTo(14.5, 4.2, 14.5, 5.4); back.lineTo(14.5, 12.3)
    back.quadTo(14.5, 13.5, 13.3, 13.5); back.lineTo(2.7, 13.5); back.quadTo(1.5, 13.5, 1.5, 12.3)
    back.closeSubpath()
    p.setBrush(QColor("#E0A11B")); p.drawPath(back)
    front = QPainterPath(); front.addRoundedRect(QRectF(1.5, 5.7, 13.0, 7.8), 1.1, 1.1)
    grad = QLinearGradient(0, 5.7, 0, 13.5)
    grad.setColorAt(0, QColor("#FFD96A")); grad.setColorAt(1, QColor("#FFC22F"))
    p.setBrush(grad); p.drawPath(front)


@_icon("desktop")
def _(p, c):
    p.setPen(Qt.PenStyle.NoPen)
    grad = QLinearGradient(0, 2, 0, 12); grad.setColorAt(0, QColor("#4FB1F7")); grad.setColorAt(1, QColor("#1E78D6"))
    p.setBrush(grad); p.drawRoundedRect(QRectF(1.2, 2.2, 13.6, 9.4), 1.4, 1.4)
    p.setBrush(QColor("#7A8594")); p.drawRect(QRectF(7.2, 11.6, 1.6, 1.8))
    p.drawRoundedRect(QRectF(4.6, 13.2, 6.8, 1.3), 0.6, 0.6)


@_icon("downloads")
def _(p, c):
    _pen(p, "#13A10E", 2.0); _line(p, 8, 1.8, 8, 10.4); _poly(p, (4.0, 6.8), (8, 10.8), (12.0, 6.8))
    _pen(p, "#13A10E", 1.6); _line(p, 2.8, 14.0, 13.2, 14.0)


@_icon("documents")
def _(p, c):
    path = QPainterPath(); path.moveTo(3.0, 1.6); path.lineTo(9.8, 1.6); path.lineTo(13.0, 4.8)
    path.lineTo(13.0, 14.4); path.lineTo(3.0, 14.4); path.closeSubpath()
    p.setPen(QPen(QColor("#7A8594"), 0.9)); p.setBrush(QColor("#F4F7FB")); p.drawPath(path)
    _pen(p, "#7A8594", 0.9); _poly(p, (9.8, 1.6), (9.8, 4.8), (13.0, 4.8))
    _pen(p, "#2F80E0", 1.1)
    for y, x2 in ((7.4, 10.8), (9.8, 10.8), (12.2, 8.8)):
        _line(p, 5.2, y, x2, y)


@_icon("pictures")
def _(p, c):
    p.setPen(Qt.PenStyle.NoPen)
    grad = QLinearGradient(0, 2, 0, 14); grad.setColorAt(0, QColor("#63B9FA")); grad.setColorAt(1, QColor("#2F86E0"))
    p.setBrush(grad); p.drawRoundedRect(QRectF(1.2, 2.4, 13.6, 11.2), 1.6, 1.6)
    p.setBrush(QColor("#FFD24D")); p.drawEllipse(QPointF(10.8, 5.8), 1.5, 1.5)
    mount = QPainterPath(); mount.moveTo(1.2, 12.0); mount.lineTo(5.6, 7.2); mount.lineTo(9.0, 10.6)
    mount.lineTo(10.8, 9.0); mount.lineTo(14.8, 12.6); mount.lineTo(14.8, 13.6); mount.lineTo(1.2, 13.6)
    mount.closeSubpath()
    p.setBrush(QColor("#1A5EA8")); p.drawPath(mount)


@_icon("music")
def _(p, c):
    p.setPen(Qt.PenStyle.NoPen); p.setBrush(QColor("#E8590C"))
    p.drawEllipse(QRectF(2.0, 10.2, 4.4, 3.6)); p.drawEllipse(QRectF(9.0, 8.8, 4.4, 3.6))
    _pen(p, "#E8590C", 1.4); _line(p, 6.0, 11.8, 6.0, 3.6); _line(p, 13.0, 10.4, 13.0, 2.2)
    _pen(p, "#E8590C", 2.0); _line(p, 6.0, 3.6, 13.0, 2.2)


@_icon("videos")
def _(p, c):
    p.setPen(Qt.PenStyle.NoPen); p.setBrush(QColor("#8A4FD8"))
    p.drawRoundedRect(QRectF(1.2, 3.0, 13.6, 10.0), 1.8, 1.8)
    p.setBrush(QColor("#FFFFFF"))
    p.drawPolygon(QPolygonF([QPointF(6.4, 5.4), QPointF(11.0, 8.0), QPointF(6.4, 10.6)]))


@_icon("cloud")
def _(p, c):
    path = QPainterPath()
    path.moveTo(4.4, 12.4); path.cubicTo(1.6, 12.4, 1.4, 8.4, 4.0, 8.0)
    path.cubicTo(4.0, 4.4, 8.6, 3.4, 10.0, 6.4); path.cubicTo(13.8, 5.8, 15.6, 11.6, 11.8, 12.4)
    path.closeSubpath()
    p.setPen(Qt.PenStyle.NoPen); p.setBrush(QColor("#2F86E0")); p.drawPath(path)


@_icon("pc")
def _(p, c):
    p.setPen(QPen(QColor("#4A5260"), 0.9))
    grad = QLinearGradient(0, 2, 0, 11); grad.setColorAt(0, QColor("#5FB6F8")); grad.setColorAt(1, QColor("#2B7FDA"))
    p.setBrush(grad); p.drawRoundedRect(QRectF(1.4, 2.0, 13.2, 9.0), 1.2, 1.2)
    p.setPen(Qt.PenStyle.NoPen); p.setBrush(QColor("#6B7482"))
    p.drawRect(QRectF(7.0, 11.0, 2.0, 2.0)); p.drawRoundedRect(QRectF(4.4, 13.0, 7.2, 1.4), 0.6, 0.6)


@_icon("drive")
def _(p, c):
    p.setPen(QPen(QColor("#6E7784"), 0.8))
    grad = QLinearGradient(0, 5, 0, 12); grad.setColorAt(0, QColor("#F2F4F7")); grad.setColorAt(1, QColor("#C9D0D9"))
    p.setBrush(grad); p.drawRoundedRect(QRectF(1.2, 5.0, 13.6, 7.0), 1.4, 1.4)
    p.setPen(Qt.PenStyle.NoPen); p.setBrush(QColor("#3C4350")); p.drawRect(QRectF(2.6, 9.6, 8.0, 0.9))
    p.setBrush(QColor("#2DBE5A")); p.drawEllipse(QPointF(12.6, 10.0), 0.8, 0.8)


@_icon("textfile")
def _(p, c):
    path = QPainterPath(); path.moveTo(3.0, 1.6); path.lineTo(9.8, 1.6); path.lineTo(13.0, 4.8)
    path.lineTo(13.0, 14.4); path.lineTo(3.0, 14.4); path.closeSubpath()
    p.setPen(QPen(QColor("#7A8594"), 0.9)); p.setBrush(QColor("#FFFFFF")); p.drawPath(path)
    _pen(p, "#7A8594", 0.9); _poly(p, (9.8, 1.6), (9.8, 4.8), (13.0, 4.8))
    _pen(p, "#9AA3AF", 1.0)
    for y in (7.4, 9.6, 11.8):
        _line(p, 5.2, y, 10.8, y)


class Icons:
    _cache = {}

    @classmethod
    def get(cls, name, size=16, color=None):
        color = color or C["text"]
        key = (name, size, color)
        icon = cls._cache.get(key)
        if icon is None:
            icon = QIcon()
            sizes = [size] if size > 64 else [size, size * 2]
            for px in sizes:
                for mode, col in ((QIcon.Mode.Normal, color), (QIcon.Mode.Disabled, C["disabled"]),
                                  (QIcon.Mode.Selected, color)):
                    icon.addPixmap(cls.pixmap(name, px, col), mode)
            cls._cache[key] = icon
        return icon

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
    def big(cls, name):
        """Icône couleur disponible de 16 à 256 px (dossiers, lecteurs…)."""
        key = (name, "big")
        icon = cls._cache.get(key)
        if icon is None:
            icon = QIcon()
            for px in (16, 20, 24, 32, 40, 48, 64, 96, 128, 192, 256, 512):
                icon.addPixmap(cls.pixmap(name, px))
            cls._cache[key] = icon
        return icon


def location_icon(loc):
    if loc == HOME_LOC:
        return Icons.get("home")
    if loc == PC_LOC:
        return Icons.big("pc")
    if is_volume_root(loc):
        return Icons.big("drive")
    special = special_folder_icon_name(loc)
    return Icons.big(special or "folder")


# ======================================================================================
# Thème (feuille de style)
# ======================================================================================

STYLESHEET = """
QWidget { color: @text; }
QMainWindow, QWidget#body, QStackedWidget, QWidget#page { background: @body; }
QFrame#tabStrip { background: @strip; }
QTabBar { background: transparent; qproperty-drawBase: 0; }
QTabBar::tab {
    background: transparent; color: @text; border: none;
    margin-top: 6px; margin-right: 2px; padding: 0 4px 0 10px;
    height: 34px; min-width: 150px; max-width: 240px;
    border-top-left-radius: 8px; border-top-right-radius: 8px;
}
QTabBar::tab:hover:!selected { background: rgba(255, 255, 255, 0.55); }
QTabBar::tab:selected { background: @chrome; }
QTabBar::close-button { image: url(@img_close); subcontrol-position: right; border-radius: 4px; margin: 2px; }
QTabBar::close-button:!selected { background: transparent; border: none; }
QTabBar::close-button:hover { background: rgba(0, 0, 0, 0.07); }
QTabBar QToolButton { background: @strip; border: none; }
QTabBar QToolButton#tabClose { background: transparent; border-radius: 4px; padding: 0; }
QTabBar QToolButton#tabClose:hover { background: rgba(0, 0, 0, 0.07); }
QToolButton#newTab { margin-top: 6px; }
QFrame#chrome { background: @chrome; }
QFrame#cmdbar { background: @chrome; border-bottom: 1px solid @border; }
QToolButton {
    background: transparent; border: 1px solid transparent; border-radius: 4px;
    padding: 4px; color: @text;
}
QToolButton:hover { background: rgba(0, 0, 0, 0.055); }
QToolButton:pressed { background: rgba(0, 0, 0, 0.09); }
QToolButton:checked { background: rgba(0, 0, 0, 0.07); }
QToolButton:disabled { color: @disabled; }
QToolButton[popupMode="2"] { padding-right: 20px; }
QToolButton::menu-indicator {
    image: url(@img_chevdown); subcontrol-origin: padding; subcontrol-position: center right;
    width: 10px; height: 10px; right: 6px;
}
QToolButton::menu-indicator:pressed, QToolButton::menu-indicator:open { top: 0; left: 0; }
QFrame#addressBar { background: @body; border: 1px solid @border; border-radius: 4px; }
QFrame#addressBar QToolButton { padding: 2px 4px; border-radius: 3px; border: none; }
QFrame#addressBar QToolButton#chev { padding: 2px 1px; }
QLineEdit#addressEdit { border: none; background: transparent; padding: 0 6px; }
QLineEdit#searchBox {
    background: @body; border: 1px solid @border; border-bottom: 1px solid #C9C9C9;
    border-radius: 4px; padding: 0 6px; min-height: 30px;
}
QLineEdit#searchBox:focus { border-bottom: 2px solid @accent; }
QLineEdit {
    background: @body; border: 1px solid #D4D4D4; border-bottom: 1px solid #ABABAB;
    border-radius: 4px; padding: 3px 6px; selection-background-color: @accent; selection-color: white;
}
QLineEdit:focus { border-bottom: 2px solid @accent; }
QAbstractItemView QLineEdit { padding: 0 2px; border: 1px solid @accent; border-radius: 2px; }
QTreeView, QListView, QTreeWidget, QListWidget {
    background: @body; border: none; outline: 0;
    selection-background-color: @select; selection-color: @text;
}
QTreeView#files::item, QTreeWidget#recent::item { height: 30px; border: none; padding-left: 2px; }
QTreeView#files::item:hover, QTreeWidget#recent::item:hover { background: @hover; }
QTreeView#files::item:selected, QTreeWidget#recent::item:selected { background: @select; color: @text; }
QTreeView#files::item:selected:hover, QTreeWidget#recent::item:selected:hover { background: @selhover; }
QTreeView#files::branch, QTreeWidget#recent::branch { background: transparent; }
QListWidget#tiles::item { background: transparent; }
QTreeWidget#nav { background: @body; selection-background-color: transparent; }
QTreeWidget#nav::item, QTreeWidget#nav::item:selected, QTreeWidget#nav::item:hover { background: transparent; }
QTreeWidget#nav::branch { background: transparent; image: none; border-image: none; }
QHeaderView { background: @body; border: none; }
QHeaderView::section {
    background: @body; color: @text2; border: none; border-right: 1px solid @line;
    padding: 0 8px; height: 32px;
}
QHeaderView::section:hover { background: #F5F5F5; color: @text; }
QHeaderView::down-arrow { image: url(@img_chevup); subcontrol-position: top center; width: 9px; height: 7px; top: 1px; }
QHeaderView::up-arrow { image: url(@img_chevdown); subcontrol-position: top center; width: 9px; height: 7px; top: 1px; }
QSplitter::handle { background: @line; }
QSplitter::handle:horizontal { width: 1px; }
QStatusBar { background: @body; color: @text; }
QStatusBar::item { border: none; }
QStatusBar QToolButton { padding: 2px; }
QLabel#section { font-weight: 600; font-size: 15px; padding: 6px 0 4px 2px; }
QMenu {
    background: @menu; border: 1px solid #D9D9D9; border-radius: 8px; padding: 4px;
}
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
QDialog, QMessageBox, QProgressDialog, QInputDialog { background: @menu; }
QPushButton {
    background: @body; border: 1px solid #D4D4D4; border-bottom-color: #BDBDBD;
    border-radius: 4px; padding: 5px 16px; min-width: 64px; color: @text;
}
QPushButton:hover { background: #F6F6F6; }
QPushButton:pressed { background: #EDEDED; }
QPushButton:default { background: @accent; color: white; border: 1px solid #0054A3; }
QPushButton:default:hover { background: #1A6FC2; }
QPushButton:disabled { color: @disabled; }
QProgressBar { border: none; background: #E3E3E3; border-radius: 2px; max-height: 4px; text-align: center; color: transparent; }
QProgressBar::chunk { background: @accent; border-radius: 2px; }
"""


def apply_theme(app):
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
    pal.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text, QColor(C["disabled"]))
    pal.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.WindowText, QColor(C["disabled"]))
    pal.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText, QColor(C["disabled"]))
    app.setPalette(pal)

    font = app.font()
    if IS_WIN:   # police de Windows 11 ; ailleurs, la police du système
        font.setFamilies(["Segoe UI Variable Text", "Segoe UI", font.family()])
    font.setPixelSize(13)
    app.setFont(font)

    # petites images utilisées par la feuille de style (dossier temporaire supprimé à la fin)
    img_dir = tempfile.mkdtemp(prefix="explorateur-theme-")
    atexit.register(shutil.rmtree, img_dir, True)
    images = {}
    for name, color in (("close", C["text"]), ("chevdown", C["text2"]), ("chevup", C["text2"]),
                        ("chevright", C["text2"]), ("check", C["text"]), ("dot", C["text"])):
        base = os.path.join(img_dir, name)
        Icons.pixmap(name, 16, color).save(base + ".png", "PNG")
        Icons.pixmap(name, 32, color).save(base + "@2x.png", "PNG")
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


def make_menu(parent=None):
    return style_menu(QMenu(parent))


def popup(menu, global_pos):
    """Affiche un menu contextuel puis le libère."""
    style_menu(menu)
    menu.exec(global_pos)
    menu.deleteLater()


def menu_item(menu, text, fn, icon=None, enabled=True, shortcut=None):
    act = QAction(text, menu)
    if icon:
        act.setIcon(Icons.get(icon) if isinstance(icon, str) else icon)
    if shortcut:
        act.setText(f"{text}\t{shortcut}")
    act.setEnabled(enabled)
    act.triggered.connect(lambda _c=False: fn())
    menu.addAction(act)
    return act


def key_text(seq):
    return QKeySequence(seq).toString(QKeySequence.SequenceFormat.NativeText)


def icon_row(menu, entries):
    """Rangée d'icônes en haut des menus contextuels (Couper, Copier, Renommer…)."""
    row = QWidget()
    lay = QHBoxLayout(row)
    lay.setContentsMargins(6, 2, 6, 4)
    lay.setSpacing(2)
    for icon, tip, fn, enabled in entries:
        btn = QToolButton()
        btn.setIcon(Icons.get(icon))
        btn.setIconSize(QSize(16, 16))
        btn.setFixedSize(34, 32)
        btn.setToolTip(tip)
        btn.setEnabled(enabled)
        btn.clicked.connect(lambda _c=False, f=fn: (menu.close(), f()))
        lay.addWidget(btn)
    lay.addStretch(1)
    act = QWidgetAction(menu)
    act.setDefaultWidget(row)
    menu.addAction(act)
    menu.addSeparator()


def safe_tip(text):
    """Info-bulle affichée telle quelle, même si le nom contient du HTML."""
    return "<p style='white-space:pre'>" + html.escape(text) + "</p>"


def section_label(text):
    label = QLabel(text)
    label.setObjectName("section")
    return label


def vline():
    line = QFrame()
    line.setFixedSize(1, 22)
    line.setStyleSheet(f"background: {C['border']};")
    return line


# ======================================================================================
# Opérations sur les fichiers (exécutées dans un thread)
# ======================================================================================

def run_cmd(args):
    result = subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    if result.returncode != 0:
        msg = result.stderr.decode("utf-8", "replace").strip()
        raise RuntimeError(msg.splitlines()[-1] if msg else f"échec de {args[0]}")


def copy_item(src, dst):
    if os.path.lexists(dst):
        raise FileExistsError(f"« {os.path.basename(dst)} » existe déjà")
    if IS_MAC:
        run_cmd([CMD["cp"], "-pR", src, dst])   # garde tags, métadonnées et signature des applis
    elif os.path.isdir(src) and not os.path.islink(src):
        shutil.copytree(src, dst, symlinks=True)
    else:
        shutil.copy2(src, dst, follow_symlinks=False)


def remove_item(path):
    if os.path.isdir(path) and not os.path.islink(path):
        shutil.rmtree(path)
    else:
        os.remove(path)


def move_item(src, dst):
    if os.path.lexists(dst):
        raise FileExistsError(f"« {os.path.basename(dst)} » existe déjà")
    try:
        os.rename(src, dst)
    except OSError as exc:
        if exc.errno != errno.EXDEV:
            raise
        copy_item(src, dst)       # autre disque : copie puis suppression de l'original
        remove_item(src)


def trash_item(path):
    result = QFile.moveToTrash(path)
    ok = result[0] if isinstance(result, tuple) else bool(result)
    if not ok:
        raise RuntimeError("impossible de le mettre à la corbeille (volume réseau ?). "
                           "Maj+Suppr pour le supprimer définitivement.")


def zip_items(sources, dst):
    if IS_MAC and len(sources) == 1:
        run_cmd([CMD["ditto"], "-c", "-k", "--sequesterRsrc", "--keepParent", sources[0], dst])
        return
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED, strict_timestamps=False) as archive:
        for src in sources:
            base = os.path.dirname(src)
            if os.path.isdir(src) and not os.path.islink(src):
                for root, _dirs, files in os.walk(src):
                    archive.write(root, os.path.relpath(root, base))
                    for name in files:
                        if name == ".DS_Store":
                            continue
                        full = os.path.join(root, name)
                        if os.path.exists(full) and not os.path.islink(full):
                            archive.write(full, os.path.relpath(full, base))
            else:
                archive.write(src, os.path.basename(src))


def zip_is_clean(src):
    """Refuse les archives piégées : chemins absolus, « .. », liens symboliques (attaque « zip-slip »)."""
    try:
        with zipfile.ZipFile(src) as archive:
            for info in archive.infolist():
                name = info.filename.replace("\\", "/")
                if name.startswith("/") or re.match(r"^[A-Za-z]:", name) or ".." in name.split("/"):
                    return False
                if stat.S_ISLNK(info.external_attr >> 16):
                    return False
        return True
    except (zipfile.BadZipFile, OSError):
        return False


def unzip_item(src, parent):
    """Extrait à côté de l'archive, sans créer « dossier/dossier » inutile."""
    tmp = tempfile.mkdtemp(prefix=".extraction-", dir=parent)
    try:
        if IS_MAC and zip_is_clean(src):
            run_cmd([CMD["ditto"], "-x", "-k", src, tmp])
        else:
            with zipfile.ZipFile(src) as archive:
                archive.extractall(tmp)
        macosx = os.path.join(tmp, "__MACOSX")
        if os.path.isdir(macosx):
            shutil.rmtree(macosx, ignore_errors=True)
        entries = os.listdir(tmp)
        if len(entries) == 1:
            inner = os.path.join(tmp, entries[0])
            dst = unique_path(parent, entries[0], is_dir=os.path.isdir(inner))
            os.rename(inner, dst)
        else:
            stem = os.path.splitext(os.path.basename(src))[0]
            dst = unique_path(parent, stem, is_dir=True)
            os.rename(tmp, dst)
            tmp = None
        return dst
    finally:
        if tmp and os.path.isdir(tmp):
            shutil.rmtree(tmp, ignore_errors=True)


class FileJob(QObject):
    """Exécute une liste d'opérations dans un thread, avec une fenêtre de progression."""
    progressed = Signal(int, int, str)
    completed = Signal(list, list)

    def __init__(self, win, ops, title):
        super().__init__(win)
        self.win, self.ops, self.title = win, ops, title
        self.cancelled = False
        self.dlg = QProgressDialog(title, "Annuler", 0, max(1, len(ops)), win)
        self.dlg.setWindowTitle(APP_NAME)
        self.dlg.setWindowModality(Qt.WindowModality.NonModal)
        self.dlg.setMinimumDuration(600)
        self.dlg.setAutoClose(False)
        self.dlg.setAutoReset(False)
        self.dlg.setMinimumWidth(420)
        label = QLabel(title)
        label.setTextFormat(Qt.TextFormat.PlainText)
        self.dlg.setLabel(label)
        self.dlg.canceled.connect(self.cancel)
        self.progressed.connect(self._on_progress)
        self.completed.connect(self._on_completed)

    def start(self):
        self.dlg.setValue(0)
        threading.Thread(target=self._run, daemon=True).start()

    @Slot()
    def cancel(self):
        self.cancelled = True

    def _run(self):
        created, errors = [], []
        total = len(self.ops)
        for i, op in enumerate(self.ops):
            if self.cancelled:
                errors.append("Opération annulée.")
                break
            kind = op[0]
            label = os.path.basename(op[1] if isinstance(op[1], str) else op[2])
            self.progressed.emit(i, total, label)
            try:
                if kind in ("copy", "move"):
                    src, dst, replace = op[1], op[2], op[3]
                    if replace and os.path.lexists(dst):
                        trash_item(dst)   # l'élément remplacé part à la corbeille
                    (copy_item if kind == "copy" else move_item)(src, dst)
                    created.append(dst)
                elif kind == "trash":
                    trash_item(op[1])
                elif kind == "delete":
                    remove_item(op[1])
                elif kind == "zip":
                    zip_items(op[1], op[2])
                    created.append(op[2])
                elif kind == "unzip":
                    created.append(unzip_item(op[1], op[2]))
            except Exception as exc:  # noqa: BLE001 — on remonte tout à l'utilisateur
                errors.append(f"{label} : {getattr(exc, 'strerror', None) or exc}")
        self.completed.emit(created, errors)

    @Slot(int, int, str)
    def _on_progress(self, i, total, label):
        self.dlg.setValue(i)
        self.dlg.setLabelText(f"{self.title}\n{label}")

    @Slot(list, list)
    def _on_completed(self, created, errors):
        self.dlg.canceled.disconnect(self.cancel)
        self.dlg.close()
        self.dlg.deleteLater()
        self.win.job_finished(self, created, errors)
        self.deleteLater()


# ======================================================================================
# Miniatures des images (vues en icônes)
# ======================================================================================

class ThumbCache(QObject):
    loaded = Signal(str, object, int, QImage)
    updated = Signal(str)
    MAX = 800

    def __init__(self):
        super().__init__()
        self.cache = collections.OrderedDict()
        self.pending = set()
        self.queue = []
        self.cv = threading.Condition()
        self.loaded.connect(self._on_loaded)
        threading.Thread(target=self._worker, daemon=True).start()

    def get(self, path, mtime, size):
        key = (path, mtime, size)
        if key in self.cache:
            self.cache.move_to_end(key)
            return self.cache[key]
        if key not in self.pending:
            self.pending.add(key)
            with self.cv:
                self.queue.append(key)
                if len(self.queue) > 600:
                    dropped = self.queue.pop(0)
                    self.pending.discard(dropped)
                self.cv.notify()
        return None

    def _worker(self):
        while True:
            with self.cv:
                while not self.queue:
                    self.cv.wait()
                path, mtime, size = self.queue.pop()   # les plus récents d'abord (zone visible)
            image = QImage()
            try:
                reader = QImageReader(path, IMAGE_FORMATS.get(ext_of(path), b""))
                reader.setAutoDetectImageFormat(False)   # pas d'essai des autres lecteurs
                reader.setDecideFormatFromContent(False)
                reader.setAutoTransform(True)
                src = reader.size()
                if src.isValid() and src.width() > 0 and src.height() > 0:
                    scale = min(size / src.width(), size / src.height(), 1.0)
                    reader.setScaledSize(QSize(max(1, int(src.width() * scale)),
                                               max(1, int(src.height() * scale))))
                image = reader.read()
            except Exception:  # noqa: BLE001
                image = QImage()
            try:
                self.loaded.emit(path, mtime, size, image)
            except RuntimeError:
                return

    @Slot(str, object, int, QImage)
    def _on_loaded(self, path, mtime, size, image):
        key = (path, mtime, size)
        self.pending.discard(key)
        self.cache[key] = QIcon(QPixmap.fromImage(image)) if not image.isNull() else False
        while len(self.cache) > self.MAX:
            self.cache.popitem(last=False)
        self.updated.emit(path)


# ======================================================================================
# Modèle de la liste de fichiers
# ======================================================================================

class FileProxy(QSortFilterProxyModel):
    """Colonnes à la Windows, dossiers en premier, tri naturel, recherche, miniatures."""
    HEADERS = {0: "Nom", 1: "Taille", 2: "Type", 3: "Modifié le"}

    def __init__(self, tab):
        super().__init__(tab)
        self.tab = tab
        self.root = ""
        self.needle = ""
        self.thumb_size = 0
        self.setDynamicSortFilter(True)

    def _refilter(self, change):
        if hasattr(self, "beginFilterChange"):   # Qt récent
            self.beginFilterChange()
            change()
            self.endFilterChange(QSortFilterProxyModel.Direction.Rows)
        else:
            change()
            self.invalidateFilter()

    def set_root(self, path):
        self._refilter(lambda: setattr(self, "root", path))

    def set_needle(self, text):
        self._refilter(lambda: setattr(self, "needle", fold(text.strip())))

    def filterAcceptsRow(self, row, parent):
        if not self.needle:
            return True
        src = self.sourceModel()
        if src.filePath(parent) != self.root:
            return True
        return self.needle in fold(src.fileName(src.index(row, 0, parent)))

    def lessThan(self, left, right):
        src = self.sourceModel()
        li, ri = src.fileInfo(left), src.fileInfo(right)
        ld, rd = is_dir_like(li), is_dir_like(ri)
        if ld != rd:  # dossiers toujours en haut
            return ld if self.sortOrder() == Qt.SortOrder.AscendingOrder else rd
        col = left.column()
        if col == 1:
            a, b = (0 if ld else li.size()), (0 if rd else ri.size())
            if a != b:
                return a < b
        elif col == 2:
            a, b = type_text(li), type_text(ri)
            if a != b:
                return natural_key(a) < natural_key(b)
        elif col == 3:
            a, b = li.lastModified().toMSecsSinceEpoch(), ri.lastModified().toMSecsSinceEpoch()
            if a != b:
                return a < b
        return natural_key(li.fileName()) < natural_key(ri.fileName())

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        col = index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            if col in (1, 2, 3):
                info = self.sourceModel().fileInfo(self.mapToSource(index))
                if col == 1:
                    return "" if info.isDir() else fmt_ko(info.size())
                if col == 2:
                    return type_text(info)
                return info.lastModified().toString("dd/MM/yyyy HH:mm")
            if col == 0 and self.tab.win.hide_ext:
                info = self.sourceModel().fileInfo(self.mapToSource(index))
                if not info.isDir() and info.completeBaseName():
                    return info.completeBaseName()
        elif role == Qt.ItemDataRole.DecorationRole and col == 0:
            info = self.sourceModel().fileInfo(self.mapToSource(index))
            if is_dir_like(info):
                special = special_folder_icon_name(info.absoluteFilePath())
                return Icons.big(special or "folder")
            thumb = self._thumb(info)
            if thumb is not None:
                return thumb
            icon = super().data(index, role)
            if not isinstance(icon, QIcon) or icon.isNull():
                return Icons.big("textfile")
            return icon
        elif role == ROLE_THUMB:
            return self._thumb(self.sourceModel().fileInfo(self.mapToSource(index))) is not None
        elif role == Qt.ItemDataRole.TextAlignmentRole and col == 1:
            return Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        elif role == Qt.ItemDataRole.ForegroundRole and (State.cut_paths or self.tab.win.show_hidden):
            src = self.sourceModel()
            sidx = self.mapToSource(index)
            if src.filePath(sidx) in State.cut_paths or src.fileName(sidx).startswith("."):
                return QColor("#8A8A8A")
        return super().data(index, role)

    def _thumb(self, info):
        if self.thumb_size and State.thumbs and ext_of(info.fileName()) in IMAGE_EXTS:
            thumb = State.thumbs.get(info.absoluteFilePath(),
                                     info.lastModified().toMSecsSinceEpoch(), self.thumb_size)
            if thumb is not None and thumb is not False:
                return thumb
        return None

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self.HEADERS.get(section, "")
        return super().headerData(section, orientation, role)

    def flags(self, index):
        f = super().flags(index)
        if index.isValid() and index.column() == 0:
            f |= Qt.ItemFlag.ItemIsEditable
        return f


# ======================================================================================
# Vues de fichiers (Détails et icônes)
# ======================================================================================

def drop_action(event, sources, target):
    """Comme Windows : même disque = déplacer, autre disque = copier.
    Mac : Option ou Ctrl = copier, Cmd ou Maj = déplacer. Windows : Ctrl = copier, Maj = déplacer."""
    if not sources or not target or target in SPECIAL_LOCS or not os.path.isdir(target):
        return None
    t = norm(target)
    for s in sources:
        if t == s or t.startswith(s.rstrip("/") + "/"):
            return None
    mods = event.modifiers()
    if IS_MAC:
        copy_mods = Qt.KeyboardModifier.AltModifier | Qt.KeyboardModifier.MetaModifier
        move_mods = Qt.KeyboardModifier.ShiftModifier | Qt.KeyboardModifier.ControlModifier
    else:
        copy_mods = Qt.KeyboardModifier.ControlModifier
        move_mods = Qt.KeyboardModifier.ShiftModifier
    if mods & copy_mods:
        act = Qt.DropAction.CopyAction
    elif mods & move_mods:
        act = Qt.DropAction.MoveAction
    else:
        if all(pdir(s) == t for s in sources):
            return None
        same = all(same_device(s, t) for s in sources)
        act = Qt.DropAction.MoveAction if same else Qt.DropAction.CopyAction
    possible = event.possibleActions()
    if not (possible & act):
        act = Qt.DropAction.CopyAction if possible & Qt.DropAction.CopyAction else None
    return act


class DragDropMixin:
    def drop_target(self, pos):
        return None

    def startDrag(self, _actions):
        rows = [i for i in self.selectionModel().selectedIndexes() if i.column() == 0]
        if not rows and self.currentIndex().isValid():
            rows = [self.currentIndex().siblingAtColumn(0)]
        if not rows:
            return
        mime = self.model().mimeData(rows)
        if mime is None:
            return
        drag = QDrag(self)
        drag.setMimeData(mime)
        icon = rows[0].data(Qt.ItemDataRole.DecorationRole)
        if isinstance(icon, QIcon):
            drag.setPixmap(icon.pixmap(48, 48))
        drag.exec(Qt.DropAction.CopyAction | Qt.DropAction.MoveAction | Qt.DropAction.LinkAction,
                  Qt.DropAction.MoveAction)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragMoveEvent(self, event):
        super().dragMoveEvent(event)  # défilement automatique
        act = drop_action(event, local_paths(event.mimeData()),
                          self.drop_target(event.position().toPoint()))
        if act is None:
            event.ignore()
        else:
            event.setDropAction(act)
            event.accept()

    def dropEvent(self, event):
        sources = local_paths(event.mimeData())
        target = self.drop_target(event.position().toPoint())
        act = drop_action(event, sources, target)
        super().dropEvent(event)  # nettoyage visuel (le modèle est en lecture seule)
        if act is None:
            event.ignore()
            return
        event.setDropAction(act)
        event.accept()
        win = self.window()
        move = act == Qt.DropAction.MoveAction
        QTimer.singleShot(0, win, lambda: win.transfer(sources, target, move))


class FileViewMixin(DragDropMixin):
    """Comportements communs aux vues Détails et icônes."""

    def setup_file_view(self, tab):
        self.tab = tab
        self._last_text_key = 0.0
        self.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setDragDropMode(QAbstractItemView.DragDropMode.DragDrop)
        self.setDragEnabled(True)
        self.setAcceptDrops(True)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setMouseTracking(True)
        self.setAttribute(Qt.WidgetAttribute.WA_MacShowFocusRect, False)
        self.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.setItemDelegate(RenameDelegate(tab))

    def drop_target(self, pos):
        idx = self.indexAt(pos)
        if idx.isValid():
            path = self.tab.path_of(idx)
            if is_folder(path):
                return path
        return self.tab.dir

    def keyPressEvent(self, event):
        if self.state() == QAbstractItemView.State.EditingState:
            return super().keyPressEvent(event)
        key, mods = event.key(), event.modifiers()
        plain = mods in (Qt.KeyboardModifier.NoModifier, Qt.KeyboardModifier.KeypadModifier)
        win = self.tab.win
        if plain and key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            win.open_selection()
            return None
        typing = time.monotonic() - self._last_text_key < 0.8
        if IS_MAC and plain and key == Qt.Key.Key_Space and not typing:
            win.quick_look()
            return None
        if plain and key == Qt.Key.Key_Backspace:
            self.tab.go_back()
            return None
        if event.text() and event.text().isprintable() and key != Qt.Key.Key_Space:
            self._last_text_key = time.monotonic()
        return super().keyPressEvent(event)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.BackButton:
            self.tab.go_back()
            return
        if event.button() == Qt.MouseButton.ForwardButton:
            self.tab.go_forward()
            return
        if event.button() == Qt.MouseButton.MiddleButton:
            idx = self.indexAt(event.position().toPoint())
            if idx.isValid() and is_folder(self.tab.path_of(idx)):
                self.tab.win.add_tab(self.tab.path_of(idx), activate=False)
                return
        super().mousePressEvent(event)

    def paintEvent(self, event):
        super().paintEvent(event)
        tab = self.tab
        if tab.dir and tab.loaded and tab.proxy.rowCount(self.rootIndex()) == 0:
            text = ("Aucun élément ne correspond à votre recherche." if tab.proxy.needle
                    else "Ce dossier est vide.")
            p = QPainter(self.viewport())
            p.setPen(QColor(C["text2"]))
            top = self.header().height() + 14 if isinstance(self, QTreeView) else 24
            p.drawText(QRect(0, top, self.viewport().width(), 30), int(Qt.AlignmentFlag.AlignHCenter), text)
            p.end()

    def wheelEvent(self, event):
        mods = event.modifiers()
        if mods & (Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.MetaModifier):
            step = 1 if event.angleDelta().y() > 0 else -1
            if event.angleDelta().y() != 0:
                self.tab.zoom(step)
            event.accept()
            return
        super().wheelEvent(event)


class DetailsView(FileViewMixin, QTreeView):
    def __init__(self, tab):
        super().__init__(tab)
        self.setObjectName("files")
        self.setup_file_view(tab)
        self.setRootIsDecorated(False)
        self.setItemsExpandable(False)
        self.setUniformRowHeights(True)
        self.setSortingEnabled(True)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setAllColumnsShowFocus(True)
        self.setIndentation(0)


class IconsView(FileViewMixin, QListView):
    def __init__(self, tab):
        super().__init__(tab)
        self.setObjectName("icons")
        self.setup_file_view(tab)
        self.setResizeMode(QListView.ResizeMode.Adjust)
        self.setMovement(QListView.Movement.Static)
        self.setUniformItemSizes(True)
        self.setSelectionRectVisible(True)
        self.setTextElideMode(Qt.TextElideMode.ElideRight)
        self.setItemDelegate(IconDelegate(tab, self))
        self.setSpacing(0)

    def set_mode(self, mode):
        size = VIEW_MODES[mode][1]
        self.setIconSize(QSize(size, size))
        if mode in ("small", "list"):
            self.setViewMode(QListView.ViewMode.ListMode)
            self.setFlow(QListView.Flow.LeftToRight if mode == "small" else QListView.Flow.TopToBottom)
            self.setWrapping(True)
            self.setWordWrap(False)
            self.setGridSize(QSize(220 if mode == "small" else 250, 26))
        else:
            self.setViewMode(QListView.ViewMode.IconMode)
            self.setFlow(QListView.Flow.LeftToRight)
            self.setWrapping(True)
            self.setWordWrap(True)
            grid = {"medium": QSize(104, 104), "large": QSize(132, 156), "xl": QSize(282, 318)}[mode]
            self.setGridSize(grid)
        self.setMovement(QListView.Movement.Static)
        self.setResizeMode(QListView.ResizeMode.Adjust)


class RenameDelegate(QStyledItemDelegate):
    """F2 : sélectionne le nom sans l'extension, comme Windows."""

    def __init__(self, tab):
        super().__init__(tab)
        self.tab = tab

    def setEditorData(self, editor, index):
        name = self.tab.fs.fileName(self.tab.proxy.mapToSource(index))
        editor.setText(name)
        path = self.tab.path_of(index)
        if is_folder(path):
            length = len(name)
        else:
            stem, _ext = os.path.splitext(name)
            length = len(stem) if stem else len(name)

        def select():
            try:
                editor.setSelection(0, length)
            except (RuntimeError, AttributeError):
                pass
        QTimer.singleShot(0, select)

    def setModelData(self, editor, model, index):
        new_name = editor.text() if hasattr(editor, "text") else ""
        old_path = self.tab.path_of(index)
        win = self.tab.win
        QTimer.singleShot(0, win, lambda: win.rename_path(old_path, new_name))


def wrap_lines(text, fm, width, max_lines):
    """Coupe un nom sur plusieurs lignes, avec « … » à la fin si ça déborde."""
    lines, rest = [], text
    while rest and len(lines) < max_lines:
        if len(lines) == max_lines - 1 or fm.horizontalAdvance(rest) <= width:
            lines.append(fm.elidedText(rest, Qt.TextElideMode.ElideRight, width))
            break
        cut = len(rest)
        while cut > 1 and fm.horizontalAdvance(rest[:cut]) > width:
            cut -= 1
        space = rest.rfind(" ", 0, cut + 1)
        if space > 0:
            cut = space
        lines.append(rest[:cut].rstrip())
        rest = rest[cut:].lstrip()
    return lines


class IconDelegate(RenameDelegate):
    """Vues icônes façon Windows : icône centrée, nom sur 2 lignes, sélection arrondie."""

    def __init__(self, tab, view):
        super().__init__(tab)
        self.view = view

    def _icon_mode(self):
        return self.view.viewMode() == QListView.ViewMode.IconMode

    def sizeHint(self, option, index):
        grid = self.view.gridSize()
        if grid.isValid():
            return QSize(grid.width() - 4, grid.height() - 4)
        return super().sizeHint(option, index)

    def _text_rect(self, rect):
        size = self.view.iconSize().width()
        if self._icon_mode():
            return QRect(rect.left() + 4, rect.top() + size + 10, rect.width() - 8, rect.height() - size - 12)
        return QRect(rect.left() + 28, rect.top(), rect.width() - 32, rect.height())

    def paint(self, p, option, index):
        r = option.rect.adjusted(2, 2, -2, -2)
        p.save()
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        selected = bool(option.state & QStyle.StateFlag.State_Selected)
        hovered = bool(option.state & QStyle.StateFlag.State_MouseOver)
        if selected or hovered:
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QColor(C["selhover"] if selected and hovered else C["select"] if selected else C["hover"]))
            p.drawRoundedRect(QRectF(r), 4, 4)
        icon = index.data(Qt.ItemDataRole.DecorationRole)
        size = self.view.iconSize().width()
        is_thumb = bool(index.data(ROLE_THUMB))
        if self._icon_mode():
            icon_rect = QRect(r.center().x() - size // 2, r.top() + 6, size, size)
        else:
            icon_rect = QRect(r.left() + 6, r.center().y() - size // 2, size, size)
        if isinstance(icon, QIcon):
            if is_thumb:
                actual = icon.actualSize(QSize(size, size))
                target = QRect(0, 0, actual.width(), actual.height())
                target.moveCenter(icon_rect.center())
                if self._icon_mode():
                    target.moveBottom(icon_rect.bottom())
                icon.paint(p, target)
                p.setPen(QPen(QColor(0, 0, 0, 40), 1))
                p.setBrush(Qt.BrushStyle.NoBrush)
                p.drawRect(QRectF(target).adjusted(0.5, 0.5, -0.5, -0.5))
            else:
                icon.paint(p, icon_rect)
        color = index.data(Qt.ItemDataRole.ForegroundRole)
        p.setPen(color if isinstance(color, QColor) else QColor(C["text"]))
        p.setFont(option.font)
        fm = QFontMetrics(option.font)
        text = index.data(Qt.ItemDataRole.DisplayRole) or ""
        tr = self._text_rect(r)
        if self._icon_mode():
            max_lines = 3 if selected else 2
            lines = wrap_lines(text, fm, tr.width(), max_lines)
            y = tr.top()
            for line in lines:
                p.drawText(QRect(tr.left(), y, tr.width(), fm.height()), int(Qt.AlignmentFlag.AlignHCenter), line)
                y += fm.height()
        else:
            p.drawText(tr, int(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft),
                       fm.elidedText(text, Qt.TextElideMode.ElideRight, tr.width()))
        p.restore()

    def updateEditorGeometry(self, editor, option, index):
        r = option.rect.adjusted(2, 2, -2, -2)
        tr = self._text_rect(r)
        height = max(22, QFontMetrics(option.font).height() + 6)
        if self._icon_mode():
            editor.setGeometry(QRect(r.left() + 2, tr.top() - 3, r.width() - 4, height))
        else:
            editor.setGeometry(QRect(tr.left() - 4, r.center().y() - height // 2, max(tr.width(), 120), height))


# ======================================================================================
# Barre d'adresse (fil d'Ariane cliquable) et recherche
# ======================================================================================

class CrumbArea(QWidget):
    clicked = Signal()

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)


class AddressBar(QFrame):
    def __init__(self, win):
        super().__init__(win)
        self.win = win
        self.setObjectName("addressBar")
        self.setFixedHeight(32)
        self.location = None
        self.segs = []
        self.parts = []
        self.hidden_count = 0
        self.stack = QStackedLayout(self)
        self.area = CrumbArea()
        self.area.clicked.connect(self.start_edit)
        self.row = QHBoxLayout(self.area)
        self.row.setContentsMargins(6, 0, 4, 0)
        self.row.setSpacing(0)
        self.edit = QLineEdit()
        self.edit.setObjectName("addressEdit")
        completer = QCompleter(win.dirfs, self.edit)
        completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.edit.setCompleter(completer)
        self.edit.installEventFilter(self)
        self.edit.returnPressed.connect(self._commit)
        self.stack.addWidget(self.area)
        self.stack.addWidget(self.edit)

    def _segments(self, loc):
        if loc in SPECIAL_LOCS:
            return [(SPECIAL_NAMES[loc], loc)]
        root = volume_root(loc)
        segs = [("Ce PC", PC_LOC), (location_title(root), root)]
        rest = loc[len(root):].strip("/")
        current = root
        for part in rest.split("/") if rest else []:
            current = pjoin(current, part)
            segs.append((part, current))
        return segs

    def set_location(self, loc):
        self.location = loc
        self.segs = self._segments(loc)
        while self.row.count():
            item = self.row.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.hide()
                widget.deleteLater()
        icon = QLabel()
        icon.setPixmap(location_icon(loc).pixmap(16, 16))
        icon.setFixedWidth(22)
        self.row.addWidget(icon)
        self.overflow = QToolButton()
        self.overflow.setIcon(Icons.get("chevleft", 12, C["text2"]))
        self.overflow.setIconSize(QSize(10, 10))
        self.overflow.setToolTip("Emplacements précédents")
        self.overflow.clicked.connect(self._overflow_menu)
        self.row.addWidget(self.overflow)
        self.parts = []
        for label, target in self.segs:
            btn = QToolButton()
            btn.setText(label)
            btn.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextOnly)
            btn.clicked.connect(lambda _c=False, t=target: self.win.tab.navigate(t))
            chev = QToolButton()
            chev.setObjectName("chev")
            chev.setIcon(Icons.get("chevright", 12, C["text2"]))
            chev.setIconSize(QSize(10, 10))
            chev.clicked.connect(lambda _c=False, t=target, b=chev: self._chevron_menu(t, b))
            if target == HOME_LOC:
                chev.hide()
            self.row.addWidget(btn)
            self.row.addWidget(chev)
            self.parts.append((btn, chev))
        self.row.addStretch(1)
        self.stop_edit()
        self._fit()
        QTimer.singleShot(0, self, self._fit)

    def _fit(self):
        if not self.parts:
            return
        available = max(80, self.area.width() - 50)
        widths = [b.sizeHint().width() + c.sizeHint().width() for b, c in self.parts]
        total = sum(widths)
        hidden = 0
        while total > available and hidden < len(self.parts) - 1:
            total -= widths[hidden]
            hidden += 1
        self.hidden_count = hidden
        for i, (btn, chev) in enumerate(self.parts):
            btn.setVisible(i >= hidden)
            chev.setVisible(i >= hidden and self.segs[i][1] != HOME_LOC)
        self.overflow.setVisible(hidden > 0)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._fit()

    def _overflow_menu(self):
        menu = make_menu(self)
        for label, target in reversed(self.segs[:self.hidden_count]):
            menu_item(menu, label, lambda t=target: self.win.tab.navigate(t), icon=location_icon(target))
        popup(menu, self.overflow.mapToGlobal(QPoint(0, self.overflow.height())))

    def _chevron_menu(self, target, button):
        menu = make_menu(self)
        if target == PC_LOC:
            entries = [(label, root, Icons.big("drive")) for label, root in volumes()]
        else:
            entries = [(os.path.basename(p), p, location_icon(p))
                       for p in subfolders(target, self.win.show_hidden)[:400]]
        for label, path, icon in entries:
            menu_item(menu, label, lambda p=path: self.win.tab.navigate(p), icon=icon)
        if not entries:
            menu_item(menu, "Aucun sous-dossier", lambda: None, enabled=False)
        popup(menu, button.mapToGlobal(QPoint(0, button.height())))

    def start_edit(self):
        tab = self.win.tab
        if tab is None:
            return
        self.edit.setText(native(tab.dir) if tab.dir else SPECIAL_NAMES.get(tab.current, ""))
        self.stack.setCurrentWidget(self.edit)
        self.edit.setFocus()
        self.edit.selectAll()

    def stop_edit(self):
        self.stack.setCurrentWidget(self.area)

    def _commit(self):
        text = self.edit.text().strip()
        target = {"accueil": HOME_LOC, "ce pc": PC_LOC, "ce mac": PC_LOC}.get(fold(text), text)
        if self.win.tab.navigate(target):
            self.stop_edit()
            self.win.focus_content()

    def eventFilter(self, obj, event):
        if obj is self.edit:
            if event.type() == QEvent.Type.FocusOut:
                popup = self.edit.completer().popup() if self.edit.completer() else None
                if not (popup and popup.isVisible()):
                    QTimer.singleShot(0, self, self.stop_edit)
            elif event.type() == QEvent.Type.KeyPress and event.key() == Qt.Key.Key_Escape:
                self.stop_edit()
                self.win.focus_content()
                return True
        return super().eventFilter(obj, event)


class SearchBox(QLineEdit):
    def __init__(self, win):
        super().__init__(win)
        self.win = win
        self.setObjectName("searchBox")
        self.setFixedWidth(260)
        self.setClearButtonEnabled(True)
        self.addAction(Icons.get("search", 16, C["text2"]), QLineEdit.ActionPosition.TrailingPosition)
        self.setToolTip("Filtre le dossier en cours.\nEntrée : chercher aussi dans les sous-dossiers.")

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Escape:
            self.clear()
            self.win.focus_content()
            return
        super().keyPressEvent(event)


# ======================================================================================
# Volet de navigation (Accueil, Accès rapide, Ce PC)
# ======================================================================================

def quick_access_entries():
    out = []
    for label, path, icon in special_folders():
        if os.path.isdir(path):
            out.append((label, path, "quick", icon))
    for path in pinned_folders():
        out.append((os.path.basename(path) or path, path, "pinned", None))
    return out


def cloud_entries():
    out = []
    if IS_WIN:
        seen = set()
        for var in ("OneDriveCommercial", "OneDriveConsumer", "OneDrive"):
            path = os.environ.get(var)
            if path and os.path.isdir(path) and norm(path) not in seen:
                seen.add(norm(path))
                out.append((os.path.basename(norm(path)) or "OneDrive", norm(path)))
        return out
    icloud = os.path.join(HOME, "Library", "Mobile Documents", "com~apple~CloudDocs")
    if os.path.isdir(icloud):
        out.append(("iCloud Drive", icloud))
    cloud = os.path.join(HOME, "Library", "CloudStorage")   # OneDrive, Google Drive…
    try:
        for entry in sorted(os.listdir(cloud)):
            path = os.path.join(cloud, entry)
            if not entry.startswith(".") and os.path.isdir(path):
                out.append((entry.replace("-", " - ", 1), path))
    except OSError:
        pass
    return out


class NavDelegate(QStyledItemDelegate):
    ROW_H = 30
    SEP_H = 13
    INDENT = 14

    def sizeHint(self, option, index):
        return QSize(120, self.SEP_H if index.data(ROLE_KIND) == "sep" else self.ROW_H)

    def paint(self, p, option, index):
        tree = self.parent()
        kind = index.data(ROLE_KIND)
        r = option.rect
        p.save()
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        if kind == "sep":
            p.setPen(QPen(QColor(C["line"]), 1))
            y = r.center().y()
            p.drawLine(12, y, tree.viewport().width() - 12, y)
            p.restore()
            return
        item = tree.itemFromIndex(index)
        depth = tree.depth(item)
        bg = QRectF(4, r.top() + 1, tree.viewport().width() - 8, r.height() - 2)
        selected = bool(option.state & QStyle.StateFlag.State_Selected)
        hovered = bool(option.state & QStyle.StateFlag.State_MouseOver)
        if selected or hovered:
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QColor(C["navsel"] if selected else C["navhover"]))
            p.drawRoundedRect(bg, 4, 4)
        if selected:
            p.setBrush(QColor(C["accent"]))
            p.drawRoundedRect(QRectF(5, r.center().y() - 8, 3, 16), 1.5, 1.5)
        x = 8 + depth * self.INDENT
        if item.childCount():
            name = "chevdown" if item.isExpanded() else "chevright"
            Icons.get(name, 12, C["text2"]).paint(p, QRect(x + 2, r.center().y() - 6, 12, 12))
        x += 18
        icon = index.data(Qt.ItemDataRole.DecorationRole)
        if isinstance(icon, QIcon):
            icon.paint(p, QRect(x, r.center().y() - 8, 16, 16))
        x += 24
        pinned = kind in ("quick", "pinned")
        right = int(bg.right()) - (24 if pinned else 6)
        p.setFont(option.font)
        p.setPen(QColor(C["text"]))
        text = QFontMetrics(option.font).elidedText(index.data(Qt.ItemDataRole.DisplayRole) or "",
                                                     Qt.TextElideMode.ElideRight, max(10, right - x))
        p.drawText(QRect(x, r.top(), right - x, r.height()),
                   int(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft), text)
        if pinned:
            Icons.get("pin", 14, "#8A8A8A").paint(p, QRect(int(bg.right()) - 20, r.center().y() - 7, 14, 14))
        p.restore()


class NavTree(DragDropMixin, QTreeWidget):
    def __init__(self, win):
        super().__init__(win)
        self.win = win
        self._syncing = False
        self.setObjectName("nav")
        self.setHeaderHidden(True)
        self.setIndentation(0)
        self.setRootIsDecorated(False)
        self.setUniformRowHeights(False)
        self.setItemDelegate(NavDelegate(self))
        self.setMouseTracking(True)
        self.viewport().setAttribute(Qt.WidgetAttribute.WA_Hover)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setAttribute(Qt.WidgetAttribute.WA_MacShowFocusRect, False)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.setDragDropMode(QAbstractItemView.DragDropMode.DropOnly)
        self.setDragEnabled(False)
        self.setAcceptDrops(True)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._menu)
        self.itemExpanded.connect(self._populate)
        self.itemClicked.connect(self._clicked)
        self.currentItemChanged.connect(self._current_changed)

    # ---- construction ----
    def _item(self, parent, label, path, kind, icon, expandable):
        item = QTreeWidgetItem(parent if parent is not None else self, [label])
        item.setData(0, ROLE_PATH, path)
        item.setData(0, ROLE_KIND, kind)
        item.setIcon(0, icon)
        item.setToolTip(0, safe_tip(native(path) if path not in SPECIAL_LOCS else label))
        if expandable:
            placeholder = QTreeWidgetItem(item, [""])
            placeholder.setData(0, ROLE_KIND, "placeholder")
        return item

    def _sep(self):
        item = QTreeWidgetItem(self, [""])
        item.setData(0, ROLE_KIND, "sep")
        item.setFlags(Qt.ItemFlag.NoItemFlags)

    def rebuild(self):
        self._syncing = True
        try:
            self.clear()
            self._item(None, "Accueil", HOME_LOC, "special", Icons.get("home"), False)
            for label, path in cloud_entries():
                self._item(None, label, path, "folder", Icons.big("cloud"), True)
            self._sep()
            for label, path, kind, icon in quick_access_entries():
                self._item(None, label, path, kind, Icons.big(icon or "folder"), True)
            self._sep()
            pc = self._item(None, "Ce PC", PC_LOC, "pc", Icons.big("pc"), True)
            pc.setExpanded(False)
        finally:
            self._syncing = False
        if self.win.tab is not None:
            self.sync(self.win.tab.current)

    def _populate(self, item):
        if item.childCount() != 1 or item.child(0).data(0, ROLE_KIND) != "placeholder":
            return
        item.takeChild(0)
        path = item.data(0, ROLE_PATH)
        if path == PC_LOC:
            for label, root in volumes():
                self._item(item, label, root, "drive", Icons.big("drive"), True)
        else:
            for sub in subfolders(path, self.win.show_hidden):
                self._item(item, os.path.basename(sub), sub, "folder", location_icon(sub), True)

    def depth(self, item):
        d = 0
        parent = item.parent()
        while parent is not None:
            d += 1
            parent = parent.parent()
        return d

    # ---- interactions ----
    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.BackButton:
            self.win.tab.go_back()
            return
        if event.button() == Qt.MouseButton.ForwardButton:
            self.win.tab.go_forward()
            return
        pos = event.position().toPoint()
        item = self.itemAt(pos)
        if item is not None and item.data(0, ROLE_KIND) == "sep":
            return
        if item is not None and event.button() == Qt.MouseButton.MiddleButton:
            self.win.add_tab(item.data(0, ROLE_PATH), activate=False)
            return
        if item is not None and item.childCount() and event.button() == Qt.MouseButton.LeftButton:
            x = 8 + self.depth(item) * NavDelegate.INDENT
            if x <= pos.x() <= x + 18:
                item.setExpanded(not item.isExpanded())
                return
        super().mousePressEvent(event)

    def drawBranches(self, painter, rect, index):
        pass   # les flèches sont dessinées par NavDelegate

    def drop_target(self, pos):
        item = self.itemAt(pos)
        path = item.data(0, ROLE_PATH) if item is not None else None
        return path if is_folder(path) else None

    def _go(self, item):
        path = item.data(0, ROLE_PATH) if item is not None else None
        if path and self.win.tab is not None and path != self.win.tab.current:
            self.win.tab.navigate(path)

    def _clicked(self, item, _col=0):
        if not self._syncing:
            self._go(item)

    def _current_changed(self, current, _previous):
        if not self._syncing and current is not None:
            self._go(current)

    def sync(self, loc):
        self._syncing = True
        try:
            match = None
            it = QTreeWidgetItemIterator(self)
            while it.value() is not None:
                item = it.value()
                if item.data(0, ROLE_PATH) == loc:
                    match = item
                    break
                it += 1
            if match is not None:
                self.setCurrentItem(match)
            else:
                self.selectionModel().clear()
        finally:
            self._syncing = False
        self.viewport().update()

    def _menu(self, pos):
        item = self.itemAt(pos)
        if item is None or not item.data(0, ROLE_PATH):
            return
        path, kind = item.data(0, ROLE_PATH), item.data(0, ROLE_KIND)
        win = self.win
        menu = make_menu(self)
        menu_item(menu, "Ouvrir", lambda: win.tab.navigate(path))
        menu_item(menu, "Ouvrir dans un nouvel onglet", lambda: win.add_tab(path))
        menu_item(menu, "Ouvrir dans une nouvelle fenêtre", lambda: win.new_window(path))
        if path not in SPECIAL_LOCS:
            menu.addSeparator()
            if kind == "pinned":
                menu_item(menu, "Désépingler de l'Accès rapide", lambda: win.unpin(path), icon="pin")
            elif kind in ("folder", "drive"):
                menu_item(menu, "Épingler dans Accès rapide", lambda: win.pin(path), icon="pin")
            paste_ok = bool(local_paths(QGuiApplication.clipboard().mimeData()))
            menu_item(menu, "Coller dans ce dossier", lambda: win.paste(target=path), icon="paste", enabled=paste_ok)
            menu_item(menu, "Copier le chemin", lambda: win.copy_path([path]), icon="copy")
            if IS_MAC and kind == "drive" and path != "/":
                menu_item(menu, "Éjecter", lambda: win.eject(path))
            menu_item(menu, "Ouvrir dans le Terminal", lambda: win.open_terminal(path), icon="terminal")
            if vscode_path():
                menu_item(menu, "Ouvrir avec Code", lambda: win.open_in_vscode([path]), icon="code")
            if IS_MAC:
                menu_item(menu, "Afficher dans le Finder", lambda: detached("open", ["-R", path]), icon="finder")
            menu.addSeparator()
            menu_item(menu, "Propriétés", lambda: PropertiesDialog(win, [path]).show(), icon="info")
        popup(menu, self.viewport().mapToGlobal(pos))


# ======================================================================================
# Pages « Accueil » et « Ce PC »
# ======================================================================================

class TileDelegate(QStyledItemDelegate):
    """Tuile icône + nom + sous-titre (Accès rapide, lecteurs)."""

    def __init__(self, parent, size, with_bar=False):
        super().__init__(parent)
        self.size = size
        self.with_bar = with_bar

    def sizeHint(self, option, index):
        return self.size

    def paint(self, p, option, index):
        r = QRectF(option.rect).adjusted(3, 3, -3, -3)
        p.save()
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        selected = bool(option.state & QStyle.StateFlag.State_Selected)
        hovered = bool(option.state & QStyle.StateFlag.State_MouseOver)
        if selected or hovered:
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QColor(C["select"] if selected else C["hover"]))
            p.drawRoundedRect(r, 6, 6)
        icon_size = 40 if self.with_bar else 32
        icon = index.data(Qt.ItemDataRole.DecorationRole)
        if isinstance(icon, QIcon):
            icon.paint(p, QRect(int(r.left()) + 10, int(r.center().y()) - icon_size // 2, icon_size, icon_size))
        x = int(r.left()) + 20 + icon_size
        width = int(r.right()) - x - 8
        font = option.font
        fm = QFontMetrics(font)
        name = fm.elidedText(index.data(Qt.ItemDataRole.DisplayRole) or "", Qt.TextElideMode.ElideRight, width)
        sub = index.data(ROLE_SUB) or ""
        p.setFont(font)
        p.setPen(QColor(C["text"]))
        top = int(r.top()) + (8 if self.with_bar else 9)
        p.drawText(QRect(x, top, width, 18), int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter), name)
        if self.with_bar:
            ratio = index.data(ROLE_RATIO)
            if ratio is not None:
                bar = QRectF(x, top + 23, min(width, 200), 6)
                p.setPen(Qt.PenStyle.NoPen)
                p.setBrush(QColor("#E1E1E1"))
                p.drawRoundedRect(bar, 3, 3)
                p.setBrush(QColor(C["danger"] if ratio > 0.9 else C["accent"]))
                p.drawRoundedRect(QRectF(bar.left(), bar.top(), max(6.0, bar.width() * ratio), 6), 3, 3)
            top += 34
        else:
            top += 19
        small = option.font
        small.setPixelSize(12)
        p.setFont(small)
        p.setPen(QColor(C["text2"]))
        p.drawText(QRect(x, top, width, 16), int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter),
                   QFontMetrics(small).elidedText(sub, Qt.TextElideMode.ElideRight, width))
        p.restore()


class TileList(QListWidget):
    def __init__(self, tile_size, with_bar=False):
        super().__init__()
        self.setObjectName("tiles")
        self.tile_size = tile_size
        self.setViewMode(QListView.ViewMode.IconMode)
        self.setFlow(QListView.Flow.LeftToRight)
        self.setWrapping(True)
        self.setResizeMode(QListView.ResizeMode.Adjust)
        self.setMovement(QListView.Movement.Static)
        self.setUniformItemSizes(True)
        self.setGridSize(tile_size)
        self.setItemDelegate(TileDelegate(self, tile_size, with_bar))
        self.setMouseTracking(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setAttribute(Qt.WidgetAttribute.WA_MacShowFocusRect, False)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)

    def fit_height(self):
        per_row = max(1, self.viewport().width() // self.tile_size.width())
        rows = max(1, math.ceil(self.count() / per_row))
        self.setFixedHeight(rows * self.tile_size.height() + 6)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.fit_height()


class HomePage(QWidget):
    recent_ready = Signal(list)

    def __init__(self, tab):
        super().__init__(tab)
        self.tab = tab
        self.setObjectName("page")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 10, 18, 6)
        layout.setSpacing(4)
        layout.addWidget(section_label("Accès rapide"))
        self.tiles = TileList(QSize(236, 58))
        self.tiles.itemActivated.connect(lambda it: self.tab.navigate(it.data(ROLE_PATH)))
        self.tiles.customContextMenuRequested.connect(self._tile_menu)
        layout.addWidget(self.tiles)
        layout.addSpacing(6)
        layout.addWidget(section_label("Récent"))
        self.recent = QTreeWidget()
        self.recent.setObjectName("recent")
        self.recent.setHeaderLabels(["Nom", "Date de modification", "Emplacement"])
        self.recent.setRootIsDecorated(False)
        self.recent.setUniformRowHeights(True)
        self.recent.setFrameShape(QFrame.Shape.NoFrame)
        self.recent.setIndentation(0)
        self.recent.setColumnWidth(0, 340)
        self.recent.setColumnWidth(1, 170)
        self.recent.setMouseTracking(True)
        self.recent.setAttribute(Qt.WidgetAttribute.WA_MacShowFocusRect, False)
        self.recent.itemActivated.connect(lambda it, _c=0: self.tab.win.open_paths([it.data(0, ROLE_PATH)]))
        self.recent.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.recent.customContextMenuRequested.connect(self._recent_menu)
        layout.addWidget(self.recent, 1)
        self.recent_ready.connect(self._show_recent)
        self._scan_id = 0

    def refresh(self):
        self.tiles.clear()
        for label, path, kind, icon in quick_access_entries():
            item = QListWidgetItem(Icons.big(icon or "folder"), label)
            item.setData(ROLE_PATH, path)
            item.setData(ROLE_KIND, kind)
            item.setData(ROLE_SUB, "Épinglé" if kind == "pinned" else "Ce PC")
            item.setToolTip(safe_tip(native(path)))
            self.tiles.addItem(item)
        for label, path in cloud_entries():
            item = QListWidgetItem(Icons.big("cloud"), label)
            item.setData(ROLE_PATH, path)
            item.setData(ROLE_KIND, "folder")
            item.setData(ROLE_SUB, "Cloud")
            self.tiles.addItem(item)
        self.tiles.fit_height()
        self._scan_id += 1
        folders = [path for label, path, _icon in special_folders()
                   if label in ("Bureau", "Documents", "Téléchargements")]
        threading.Thread(target=self._scan, args=(self._scan_id, folders), daemon=True).start()

    def _scan(self, scan_id, folders):
        found = []
        budget = 6000

        def visit(folder, depth):
            nonlocal budget
            try:
                with os.scandir(folder) as it:
                    for entry in it:
                        budget -= 1
                        if budget < 0:
                            return
                        if entry.name.startswith("."):
                            continue
                        try:
                            if entry.is_file(follow_symlinks=False):
                                found.append((entry.stat(follow_symlinks=False).st_mtime, norm(entry.path)))
                            elif depth == 0 and entry.is_dir(follow_symlinks=False) \
                                    and ext_of(entry.name) not in PACKAGE_EXTS:
                                visit(entry.path, 1)
                        except OSError:
                            pass
            except OSError:
                pass

        for folder in folders:
            visit(folder, 0)
        found.sort(reverse=True)
        try:
            self.recent_ready.emit([scan_id] + found[:40])
        except RuntimeError:
            pass

    @Slot(list)
    def _show_recent(self, data):
        if not data or data[0] != self._scan_id:
            return
        self.recent.clear()
        provider = self.tab.win.icons
        for mtime, path in data[1:]:
            folder = pdir(path)
            where = native(folder)
            when = time.strftime("%d/%m/%Y %H:%M", time.localtime(mtime))
            item = QTreeWidgetItem(self.recent, [os.path.basename(path), when, where])
            item.setIcon(0, provider.icon(QFileInfo(path)))
            item.setData(0, ROLE_PATH, path)
            item.setToolTip(0, safe_tip(native(path)))

    def _tile_menu(self, pos):
        item = self.tiles.itemAt(pos)
        if item is None:
            return
        path, kind = item.data(ROLE_PATH), item.data(ROLE_KIND)
        win = self.tab.win
        menu = make_menu(self)
        menu_item(menu, "Ouvrir", lambda: self.tab.navigate(path))
        menu_item(menu, "Ouvrir dans un nouvel onglet", lambda: win.add_tab(path))
        menu_item(menu, "Ouvrir dans une nouvelle fenêtre", lambda: win.new_window(path))
        menu.addSeparator()
        if kind == "pinned":
            menu_item(menu, "Désépingler de l'Accès rapide", lambda: win.unpin(path), icon="pin")
        menu_item(menu, "Copier le chemin", lambda: win.copy_path([path]), icon="copy")
        menu_item(menu, "Propriétés", lambda: PropertiesDialog(win, [path]).show(), icon="info")
        popup(menu, self.tiles.viewport().mapToGlobal(pos))

    def _recent_menu(self, pos):
        item = self.recent.itemAt(pos)
        if item is None:
            return
        path = item.data(0, ROLE_PATH)
        win = self.tab.win
        menu = make_menu(self)
        menu_item(menu, "Ouvrir", lambda: win.open_paths([path]))
        menu_item(menu, "Ouvrir l'emplacement du fichier",
                  lambda: self.tab.navigate(pdir(path), select=path), icon="folder")
        menu_item(menu, "Copier le chemin", lambda: win.copy_path([path]), icon="copy")
        menu_item(menu, "Propriétés", lambda: PropertiesDialog(win, [path]).show(), icon="info")
        popup(menu, self.recent.viewport().mapToGlobal(pos))


class ThisPCPage(QWidget):
    def __init__(self, tab):
        super().__init__(tab)
        self.tab = tab
        self.setObjectName("page")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 10, 18, 6)
        layout.setSpacing(4)
        layout.addWidget(section_label("Périphériques et lecteurs"))
        self.drives = TileList(QSize(300, 78), with_bar=True)
        self.drives.itemActivated.connect(lambda it: self.tab.navigate(it.data(ROLE_PATH)))
        self.drives.customContextMenuRequested.connect(self._menu)
        layout.addWidget(self.drives)
        layout.addStretch(1)

    def refresh(self):
        self.drives.clear()
        for label, root in volumes():
            info = QStorageInfo(root)
            total, free = info.bytesTotal(), info.bytesAvailable()
            item = QListWidgetItem(Icons.big("drive"), label)
            item.setData(ROLE_PATH, root)
            item.setData(ROLE_KIND, "drive")
            if total > 0:
                item.setData(ROLE_RATIO, 1.0 - free / total)
                item.setData(ROLE_SUB, f"{fmt_human(free)} disponibles sur {fmt_human(total)}")
            item.setToolTip(safe_tip(native(root)))
            self.drives.addItem(item)
        self.drives.fit_height()

    def _menu(self, pos):
        item = self.drives.itemAt(pos)
        if item is None:
            return
        path = item.data(ROLE_PATH)
        win = self.tab.win
        menu = make_menu(self)
        menu_item(menu, "Ouvrir", lambda: self.tab.navigate(path))
        menu_item(menu, "Ouvrir dans un nouvel onglet", lambda: win.add_tab(path))
        menu_item(menu, "Ouvrir dans une nouvelle fenêtre", lambda: win.new_window(path))
        menu.addSeparator()
        if IS_MAC and path != "/":
            menu_item(menu, "Éjecter", lambda: win.eject(path))
        menu_item(menu, "Propriétés", lambda: PropertiesDialog(win, [path]).show(), icon="info")
        popup(menu, self.drives.viewport().mapToGlobal(pos))


# ======================================================================================
# Dialogues
# ======================================================================================

def plain_label(text):
    label = QLabel(text)
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    label.setWordWrap(True)
    return label


class PropertiesDialog(QDialog):
    sized = Signal(object, object, object, bool)

    def __init__(self, win, paths):
        super().__init__(win)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.setWindowTitle("Propriétés")
        self.setMinimumWidth(460)
        self.cancelled = False
        layout = QVBoxLayout(self)
        form = QFormLayout()
        form.setVerticalSpacing(10)
        layout.addLayout(form)
        has_dir = any(os.path.isdir(p) and not os.path.islink(p) for p in paths)
        if len(paths) == 1:
            path = paths[0]
            info = QFileInfo(path)
            icon_label = QLabel()
            icon = location_icon(path) if is_folder(path) else win.icons.icon(info)
            icon_label.setPixmap(icon.pixmap(48, 48))
            form.addRow(icon_label, QLabel(f"<b>{html.escape(location_title(path))}</b>"))
            form.addRow("Type :", plain_label(type_text(info)))
            form.addRow("Emplacement :", plain_label(native(pdir(path))))
            if info.isSymLink():
                form.addRow("Cible :", plain_label(info.symLinkTarget()))
        else:
            form.addRow("", QLabel(f"<b>{len(paths)} éléments</b>"))
            form.addRow("Emplacement :", plain_label(native(norm(os.path.commonpath(paths)))))
        self.size_label = plain_label("Calcul…")
        form.addRow("Taille :", self.size_label)
        self.content_label = plain_label("Calcul…")
        if has_dir:
            form.addRow("Contenu :", self.content_label)
        if len(paths) == 1:
            info = QFileInfo(paths[0])
            fmt = "dd/MM/yyyy HH:mm:ss"
            if info.birthTime().isValid():
                form.addRow("Créé le :", plain_label(info.birthTime().toString(fmt)))
            form.addRow("Modifié le :", plain_label(info.lastModified().toString(fmt)))
            form.addRow("Dernier accès :", plain_label(info.lastRead().toString(fmt)))
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        buttons.accepted.connect(self.close)
        layout.addWidget(buttons)
        self.sized.connect(self._on_sized)
        threading.Thread(target=self._compute, args=(list(paths),), daemon=True).start()

    def _compute(self, paths):
        total = files = dirs = 0
        last = time.monotonic()
        roots = set(paths)
        stack = list(paths)
        while stack:
            if self.cancelled:
                return
            path = stack.pop()
            try:
                st = os.lstat(path)
            except OSError:
                continue
            if stat.S_ISDIR(st.st_mode):
                if path not in roots:
                    dirs += 1
                try:
                    with os.scandir(path) as it:
                        stack.extend(entry.path for entry in it)
                except OSError:
                    pass
            else:
                total += st.st_size
                files += 1
            now = time.monotonic()
            if now - last > 0.2:
                last = now
                self._emit(total, files, dirs, False)
        self._emit(total, files, dirs, True)

    def _emit(self, total, files, dirs, final):
        try:
            self.sized.emit(total, files, dirs, final)
        except RuntimeError:  # fenêtre fermée entre-temps
            self.cancelled = True

    @Slot(object, object, object, bool)
    def _on_sized(self, total, files, dirs, final):
        suffix = "" if final else " …"
        self.size_label.setText(f"{fmt_human(total)} ({fmt_bytes_exact(total)}){suffix}")
        self.content_label.setText(
            f"{files} fichier{'s' if files > 1 else ''}, {dirs} dossier{'s' if dirs > 1 else ''}{suffix}")

    def closeEvent(self, event):
        self.cancelled = True
        super().closeEvent(event)


class SearchDialog(QDialog):
    """Recherche dans les sous-dossiers : Spotlight sur Mac (rapide), sinon parcours complet."""
    MAX = 5000
    found = Signal(int, list)
    walk_done = Signal(int)

    def __init__(self, win, root, text):
        super().__init__(win)
        self.win, self.root, self.text = win, root, text
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.setWindowTitle(f"Résultats de la recherche : {text}")
        self.resize(880, 540)
        self.proc = None
        self.mode = ""
        self.seen = set()
        self.buffer = b""
        self.walk_id = 0
        self.show_hidden = win.show_hidden
        self.found.connect(self._on_found)
        self.walk_done.connect(self._on_walk_done)
        self.file_icon = Icons.big("textfile")
        self.dir_icon = Icons.big("folder")

        layout = QVBoxLayout(self)
        self.info = plain_label("")
        layout.addWidget(self.info)
        self.results = QTreeWidget()
        self.results.setObjectName("recent")
        self.results.setHeaderLabels(["Nom", "Dossier"])
        self.results.setRootIsDecorated(False)
        self.results.setUniformRowHeights(True)
        self.results.setIndentation(0)
        self.results.setColumnWidth(0, 320)
        self.results.setMouseTracking(True)
        self.results.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.results.itemActivated.connect(self._activate)
        self.results.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.results.customContextMenuRequested.connect(self._menu)
        layout.addWidget(self.results)
        row = QHBoxLayout()
        self.full_button = QPushButton("Chercher sans Spotlight (plus lent)")
        self.full_button.clicked.connect(lambda *_: self.start(False))
        close_button = QPushButton("Fermer")
        close_button.clicked.connect(self.close)
        row.addWidget(self.full_button)
        self.full_button.setVisible(IS_MAC)
        row.addStretch(1)
        row.addWidget(close_button)
        layout.addLayout(row)
        self.start(IS_MAC and os.path.exists(CMD["mdfind"]))

    def start(self, spotlight):
        self._stop()
        self.results.setSortingEnabled(False)
        self.results.clear()
        self.seen = set()
        self.buffer = b""
        self.mode = "spotlight" if spotlight else "walk"
        if spotlight:
            self.proc = QProcess(self)
            self.proc.setStandardErrorFile(QProcess.nullDevice())
            self.proc.readyReadStandardOutput.connect(self._read)
            self.proc.finished.connect(self._finished)
            self.proc.errorOccurred.connect(self._error)
            self.info.setText(f"Recherche Spotlight de « {self.text} » dans {native(self.root)}…")
            self.proc.start(CMD["mdfind"], ["-onlyin", self.root, "-name", self.text])
        else:
            self.info.setText(f"Recherche de « {self.text} » dans {native(self.root)}… (parcours complet)")
            threading.Thread(target=self._walk, args=(self.walk_id, self.root, fold(self.text)),
                             daemon=True).start()
        self.full_button.setEnabled(spotlight)

    def _walk(self, walk_id, root, needle):
        batch, count, last = [], 0, time.monotonic()
        try:
            for dirpath, dirnames, filenames in os.walk(root):
                if walk_id != self.walk_id:
                    return
                if not self.show_hidden:
                    dirnames[:] = [d for d in dirnames if not d.startswith(".")]
                for name in dirnames + filenames:
                    if needle in fold(name):
                        batch.append(pjoin(dirpath, name))
                        count += 1
                now = time.monotonic()
                if batch and (now - last > 0.25 or len(batch) >= 200):
                    self.found.emit(walk_id, batch)
                    batch, last = [], now
                if count >= self.MAX:
                    break
            self.found.emit(walk_id, batch)
            self.walk_done.emit(walk_id)
        except RuntimeError:   # fenêtre fermée entre-temps
            pass

    @Slot(int, list)
    def _on_found(self, walk_id, paths):
        if walk_id == self.walk_id:
            self._add_paths(paths)

    @Slot(int)
    def _on_walk_done(self, walk_id):
        if walk_id == self.walk_id:
            self._finished()

    def _stop(self):
        self.walk_id += 1   # arrête un parcours en cours
        if self.proc is not None:
            self.proc.blockSignals(True)
            if self.proc.state() != QProcess.ProcessState.NotRunning:
                self.proc.kill()
                self.proc.waitForFinished(500)
            self.proc.deleteLater()
            self.proc = None

    def _add_lines(self, lines):
        self._add_paths([norm(os.fsdecode(raw).rstrip("\r")) for raw in lines if raw.strip()])

    def _add_paths(self, paths):
        for path in paths:
            if len(self.seen) >= self.MAX:
                return
            if not path or path == self.root or path in self.seen:
                continue
            self.seen.add(path)
            item = QTreeWidgetItem(self.results, [os.path.basename(path), native(pdir(path))])
            item.setIcon(0, self.dir_icon if os.path.isdir(path) else self.file_icon)
            item.setData(0, ROLE_PATH, path)
            item.setToolTip(0, safe_tip(native(path)))

    def _read(self):
        if self.proc is None:
            return
        self.buffer += bytes(self.proc.readAllStandardOutput())
        lines = self.buffer.split(b"\n")
        self.buffer = lines.pop()
        self._add_lines(lines)

    def _finished(self, *_args):
        if self.proc is not None:
            self.buffer += bytes(self.proc.readAllStandardOutput())
        if self.buffer:
            self._add_lines([self.buffer])
            self.buffer = b""
        self.results.setSortingEnabled(True)
        self.results.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        n = len(self.seen)
        how = "Spotlight" if self.mode == "spotlight" else "parcours complet"
        text = f"{n} résultat{'s' if n > 1 else ''} ({how})"
        if n >= self.MAX:
            text += " — limite atteinte, affine ta recherche"
        if n == 0 and self.mode == "spotlight":
            text = "Aucun résultat via Spotlight. Essaie « Chercher sans Spotlight »."
        self.info.setText(text)

    def _error(self, err):
        if err == QProcess.ProcessError.FailedToStart:
            if self.mode == "spotlight":
                QTimer.singleShot(0, self, lambda: self.start(False))
            else:
                self.info.setText("Impossible de lancer la recherche.")

    def _paths(self):
        return [it.data(0, ROLE_PATH) for it in self.results.selectedItems()]

    def _activate(self, item, _col=0):
        path = item.data(0, ROLE_PATH)
        tab = self.win.tab
        if is_folder(path):
            tab.navigate(path)
        else:
            tab.navigate(pdir(path), select=path)
        self.win.raise_()
        self.win.activateWindow()

    def _menu(self, pos):
        item = self.results.itemAt(pos)
        if item is None:
            return
        menu = make_menu(self)
        menu_item(menu, "Ouvrir", lambda: self.win.open_paths(self._paths()))
        menu_item(menu, "Ouvrir l'emplacement du fichier", lambda: self._activate(item), icon="folder")
        menu_item(menu, "Copier le chemin", lambda: self.win.copy_path(self._paths()), icon="copy")
        popup(menu, self.results.viewport().mapToGlobal(pos))

    def closeEvent(self, event):
        self._stop()
        super().closeEvent(event)


# ======================================================================================
# Un onglet
# ======================================================================================

class ExplorerTab(QWidget):
    location_changed = Signal()
    status_changed = Signal()

    def __init__(self, win):
        super().__init__(win)
        self.win = win
        self.current = None
        self.loaded = False
        self.back_stack, self.fwd_stack = [], []
        self.search_text = ""
        mode = settings().value("view_mode", "details")
        self.view_mode = mode if mode in VIEW_MODES else "details"

        self.fs = self._make_fs()
        self.proxy = FileProxy(self)
        self.proxy.setSourceModel(self.fs)
        self.apply_filters()

        self.details = DetailsView(self)
        self.details.setModel(self.proxy)
        self._setup_header()
        self.icons = IconsView(self)
        self.icons.setModel(self.proxy)
        self.icons.setModelColumn(0)
        for view in (self.details, self.icons):
            view.selectionModel().selectionChanged.connect(self._changed)
            view.doubleClicked.connect(lambda idx: self.win.open_paths([self.path_of(idx)]))
            view.customContextMenuRequested.connect(lambda pos, v=view: self.win.file_menu(self, v, pos))
        for sig in (self.proxy.rowsInserted, self.proxy.rowsRemoved, self.proxy.modelReset,
                    self.proxy.layoutChanged):
            sig.connect(self._changed)

        self.home = HomePage(self)
        self.pc = ThisPCPage(self)
        self.stack = QStackedWidget()
        for widget in (self.home, self.pc, self.details, self.icons):
            self.stack.addWidget(widget)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.stack)

        self._status_timer = QTimer(self)
        self._status_timer.setSingleShot(True)
        self._status_timer.setInterval(60)
        self._status_timer.timeout.connect(self.status_changed.emit)
        if State.thumbs is not None:
            State.thumbs.updated.connect(self._thumb_updated)
        self._apply_view_mode()

    # ---- modèle ----
    def _make_fs(self):
        fs = QFileSystemModel(self)
        fs.setReadOnly(True)
        fs.directoryLoaded.connect(self._dir_loaded)
        return fs

    def _dir_loaded(self, path):
        if path == self.dir:
            self.loaded = True
            self.view.viewport().update()
        self._changed()

    def apply_filters(self):
        hidden = (QDir.Filter.Hidden | QDir.Filter.System) if self.win.show_hidden else QDir.Filter(0)
        self.fs.setFilter(QDir.Filter.AllEntries | QDir.Filter.NoDotAndDotDot | hidden)

    def _setup_header(self):
        header = self.details.header()
        header.setSectionsMovable(True)
        header.setStretchLastSection(False)
        header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        header.setHighlightSections(False)
        state = settings().value("header")
        if state is not None and header.restoreState(state):
            self.details.sortByColumn(header.sortIndicatorSection(), header.sortIndicatorOrder())
        else:
            header.moveSection(header.visualIndex(3), 1)   # Nom | Modifié le | Type | Taille
            header.moveSection(header.visualIndex(2), 2)
            for col, width in ((0, 320), (3, 160), (2, 150), (1, 100)):
                header.resizeSection(col, width)
            self.details.sortByColumn(0, Qt.SortOrder.AscendingOrder)

    def _changed(self, *_args):
        self._status_timer.start()

    def _thumb_updated(self, path):
        if self.dir and self.proxy.thumb_size and pdir(path) == self.dir:
            sidx = self.fs.index(path)
            pidx = self.proxy.mapFromSource(sidx) if sidx.isValid() else QModelIndex()
            if pidx.isValid():
                self.proxy.dataChanged.emit(pidx, pidx, [Qt.ItemDataRole.DecorationRole])

    # ---- infos ----
    @property
    def dir(self):
        return self.current if self.current and self.current not in SPECIAL_LOCS else None

    @property
    def view(self):
        return self.details if self.view_mode == "details" else self.icons

    def title(self):
        return location_title(self.current) if self.current else ""

    def path_of(self, proxy_index):
        return self.fs.filePath(self.proxy.mapToSource(proxy_index))

    def selected_paths(self):
        if not self.dir:
            return []
        rows = [i for i in self.view.selectionModel().selectedIndexes() if i.column() == 0]
        rows.sort(key=lambda i: i.row())
        return [self.path_of(i) for i in rows]

    def status_text(self):
        if self.current == HOME_LOC:
            return ""
        if self.current == PC_LOC:
            n = self.pc.drives.count()
            return f"{n} élément{'s' if n != 1 else ''}"
        count = self.proxy.rowCount(self.view.rootIndex())
        text = f"{count} élément{'s' if count != 1 else ''}"
        rows = [i for i in self.view.selectionModel().selectedIndexes() if i.column() == 0]
        if rows:
            size, files = 0, 0
            for idx in rows:
                info = self.fs.fileInfo(self.proxy.mapToSource(idx))
                if info.isFile():
                    size += info.size()
                    files += 1
            n = len(rows)
            text += f"   |   {n} élément{'s' if n > 1 else ''} sélectionné{'s' if n > 1 else ''}"
            if files:
                text += f"  {fmt_human(size)}"
        return text

    # ---- navigation ----
    def navigate(self, loc, record=True, select=None):
        if loc in SPECIAL_LOCS:
            target = loc
        else:
            path = norm(os.path.expanduser(os.path.expandvars(str(loc).strip().strip('"'))))
            if not os.path.isdir(path):
                if os.path.exists(path):
                    self.win.open_paths([path])
                else:
                    self.win.warn(f"Impossible de trouver « {path} ».\n"
                                  "Vérifiez l'orthographe et réessayez.")
                return False
            try:
                os.scandir(path).close()
            except PermissionError:
                self.win.warn(f"Accès refusé à :\n{path}\n\nS'il s'agit de Bureau, Documents ou "
                              "Téléchargements, accepte la demande de macOS ou va dans Réglages Système > "
                              "Confidentialité et sécurité > Fichiers et dossiers.")
                return False
            except OSError:
                pass
            target = path
        if record and self.current and target != self.current:
            self.back_stack.append(self.current)
            self.fwd_stack.clear()
        self.current = target
        self.search_text = ""
        self.proxy.needle = ""
        if target == HOME_LOC:
            self.home.refresh()
            self.stack.setCurrentWidget(self.home)
        elif target == PC_LOC:
            self.pc.refresh()
            self.stack.setCurrentWidget(self.pc)
        else:
            self.loaded = False
            QTimer.singleShot(400, self, self._assume_loaded)
            self.proxy.set_root(target)
            src_root = self.fs.setRootPath(target)
            root = self.proxy.mapFromSource(src_root)
            for view in (self.details, self.icons):
                view.setRootIndex(root)
                view.selectionModel().clearSelection()
            self.stack.setCurrentWidget(self.view)
            if select:
                self.select_paths([select])
        self.location_changed.emit()
        self._changed()
        return True

    def _assume_loaded(self):
        self.loaded = True
        self.view.viewport().update()

    def go_back(self):
        while self.back_stack:
            target = self.back_stack.pop()
            previous = self.current
            select = previous if previous and previous not in SPECIAL_LOCS else None
            if self.navigate(target, record=False, select=select):
                self.fwd_stack.append(previous)
                self.location_changed.emit()
                return

    def go_forward(self):
        while self.fwd_stack:
            target = self.fwd_stack.pop()
            previous = self.current
            if self.navigate(target, record=False):
                self.back_stack.append(previous)
                self.location_changed.emit()
                return

    def parent_location(self):
        if not self.dir:
            return None
        if self.dir == volume_root(self.dir):
            return PC_LOC
        return pdir(self.dir)

    def go_up(self):
        parent = self.parent_location()
        if parent:
            self.navigate(parent, select=self.dir)

    def refresh(self):
        if self.dir:
            header_state = self.details.header().saveState()
            old = self.fs
            self.fs = self._make_fs()
            self.apply_filters()
            self.proxy.setSourceModel(self.fs)
            old.deleteLater()
            self.details.header().restoreState(header_state)
        self.navigate(self.current or HOME_LOC, record=False)

    # ---- affichage ----
    def set_view_mode(self, mode):
        if mode not in VIEW_MODES or mode == self.view_mode:
            return
        selected = self.selected_paths()
        self.view_mode = mode
        settings().setValue("view_mode", mode)
        self._apply_view_mode()
        if self.dir:
            self.stack.setCurrentWidget(self.view)
            self.select_paths(selected)
        self.location_changed.emit()
        self._changed()

    def _apply_view_mode(self):
        if self.view_mode != "details":
            self.icons.set_mode(self.view_mode)
            size = VIEW_MODES[self.view_mode][1]
            screen = QGuiApplication.primaryScreen()
            dpr = max(self.devicePixelRatioF(), screen.devicePixelRatio() if screen else 1.0)
            self.proxy.thumb_size = int(size * max(1.0, dpr)) if size >= 32 else 0
        else:
            self.proxy.thumb_size = 0
        self.icons.viewport().update()

    def zoom(self, step):
        i = ZOOM_ORDER.index(self.view_mode) + step
        if 0 <= i < len(ZOOM_ORDER):
            self.set_view_mode(ZOOM_ORDER[i])

    def select_paths(self, paths, edit=False, attempt=0):
        """Sélectionne des éléments du dossier courant (attend qu'ils apparaissent)."""
        if not self.dir:
            return
        wanted = [norm(p) for p in paths if pdir(norm(p)) == self.dir]
        if not wanted:
            return
        found = []
        for path in wanted:
            sidx = self.fs.index(path)
            pidx = self.proxy.mapFromSource(sidx) if sidx.isValid() else QModelIndex()
            if pidx.isValid():
                found.append(pidx)
        if len(found) < len(wanted) and attempt < 25:
            QTimer.singleShot(80, self, lambda: self.select_paths(paths, edit, attempt + 1))
            return
        if not found:
            return
        view = self.view
        sel = view.selectionModel()
        sel.clearSelection()
        flags = QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows
        for idx in found:
            sel.select(idx, flags)
        sel.setCurrentIndex(found[0], QItemSelectionModel.SelectionFlag.NoUpdate)
        view.scrollTo(found[0])
        view.setFocus()
        if edit:
            view.edit(found[0])


# ======================================================================================
# Fenêtre principale
# ======================================================================================

class TabBar(QTabBar):
    def __init__(self, win):
        super().__init__(win)
        self.win = win

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.MouseButton.MiddleButton:
            i = self.tabAt(event.position().toPoint())
            if i >= 0:
                self.win.close_tab(i)
                return
        super().mouseReleaseEvent(event)

    def mouseDoubleClickEvent(self, event):
        if self.tabAt(event.position().toPoint()) < 0:
            self.win.add_tab(HOME_LOC)
            return
        super().mouseDoubleClickEvent(event)


class MainWindow(QMainWindow):
    def __init__(self, start=None):
        super().__init__()
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        State.windows.append(self)
        self.jobs = set()
        self.tabs = {}
        self._quicklook = None
        self.icons = QFileIconProvider()
        s = settings()
        self.show_hidden = s.value("show_hidden", False, type=bool)
        self.hide_ext = s.value("hide_ext", False, type=bool)
        self.dirfs = QFileSystemModel(self)   # complétion de la barre d'adresse
        self.dirfs.setFilter(QDir.Filter.AllDirs | QDir.Filter.NoDotAndDotDot)
        self.dirfs.setRootPath("")

        self._build_actions()
        self._build_ui()
        self._build_menubar()
        self._restore_geometry()

        if os.path.isdir("/Volumes"):
            self._volume_watch = QFileSystemWatcher(["/Volumes"], self)
            self._volume_watch.directoryChanged.connect(lambda _p: QTimer.singleShot(800, self, self.volumes_changed))
        QGuiApplication.clipboard().dataChanged.connect(self.update_commands)

        start = start or s.value("last_location", HOME_LOC) or HOME_LOC
        if start not in SPECIAL_LOCS and not os.path.isdir(str(start)):
            start = HOME_LOC
        self.add_tab(start)

    # ---------- actions ----------

    def _action(self, text, slot, keys=(), icon=None, checkable=False):
        act = QAction(text, self)
        act.setMenuRole(QAction.MenuRole.NoRole)
        if icon:
            act.setIcon(Icons.get(icon))
        if keys:
            act.setShortcuts(shortcut_keys(*keys))
            act.setToolTip(f"{text} ({QKeySequence(keys[0]).toString(QKeySequence.SequenceFormat.NativeText)})")
        act.setCheckable(checkable)
        act.triggered.connect(lambda _c=False, f=slot: f())
        self.addAction(act)
        return act

    def _build_actions(self):
        A = self._action
        self.act_back = A("Précédent", lambda: self.tab.go_back(), ["Alt+Left", "Ctrl+["], "back")
        self.act_fwd = A("Suivant", lambda: self.tab.go_forward(), ["Alt+Right", "Ctrl+]"], "forward")
        self.act_up = A("Dossier parent", lambda: self.tab.go_up(), ["Alt+Up", "Ctrl+Up"], "up")
        self.act_refresh = A("Actualiser", lambda: self.tab.refresh(), ["F5", "Ctrl+R"], "refresh")
        self.act_new_folder = A("Dossier", self.new_folder, ["Ctrl+Shift+N"], "folder")
        self.act_new_text = A("Document texte", self.new_text_file, (), "textfile")
        self.act_new_zip = A("Dossier compressé (zip)", self.new_zip_file, (), "zip")
        self.act_cut = A("Couper", lambda: self.copy_selection(cut=True), ["Ctrl+X"], "cut")
        self.act_copy = A("Copier", lambda: self.copy_selection(cut=False), ["Ctrl+C"], "copy")
        self.act_paste = A("Coller", self.paste, ["Ctrl+V"], "paste")
        self.act_paste_move = A("Coller en déplaçant", lambda: self.paste(force_move=True), ["Ctrl+Alt+V"])
        self.act_rename = A("Renommer", self.rename_selected, ["F2"], "rename")
        self.act_delete = A("Supprimer", self.trash_selection, ["Delete", "Ctrl+Backspace"], "delete")
        self.act_delete_perm = A("Supprimer définitivement…", self.delete_selection, ["Shift+Delete"])
        self.act_select_all = A("Sélectionner tout", self.select_all, ["Ctrl+A"], "selectall")
        self.act_select_none = A("Ne rien sélectionner", self.select_none)
        self.act_invert = A("Inverser la sélection", self.invert_selection)
        self.act_copy_path = A("Copier en tant que chemin d'accès", self.copy_path_action,
                               ["Ctrl+Shift+C", "Ctrl+Alt+C"], "copy")
        self.act_open = A("Ouvrir", self.open_selection, ["Ctrl+O", "Ctrl+Down"])
        self.act_open_with = A("Ouvrir avec…", self.open_with, (), "openwith")
        self.act_quicklook = A("Aperçu (Quick Look)", self.quick_look, ["Ctrl+Y"])
        self.act_properties = A("Propriétés", self.properties, ["Alt+Return", "Ctrl+I"], "wrench")
        self.act_compress = A("Compresser en fichier ZIP", self.compress_selection, (), "zip")
        self.act_extract = A("Extraire tout", self.extract_selection, (), "zip")
        self.act_terminal = A("Ouvrir dans le Terminal", lambda: self.open_terminal(self.tab.dir), (), "terminal")
        self.act_reveal = A(REVEAL_LABEL, self.reveal_in_finder, (), "finder")
        self.act_new_tab = A("Nouvel onglet", lambda: self.add_tab(HOME_LOC), ["Ctrl+T"], "plus")
        self.act_close_tab = A("Fermer l'onglet", lambda: self.close_tab(self.tabbar.currentIndex()), ["Ctrl+W"])
        self.act_next_tab = A("Onglet suivant", lambda: self.cycle_tab(1), ["Ctrl+Tab"])
        self.act_prev_tab = A("Onglet précédent", lambda: self.cycle_tab(-1), ["Ctrl+Shift+Tab"])
        self.act_new_window = A("Nouvelle fenêtre", lambda: self.new_window(self.tab.current), ["Ctrl+N"])
        self.act_address = A("Barre d'adresse", lambda: self.address.start_edit(),
                             ["Ctrl+L", "Alt+D", "F4", "Ctrl+Shift+G"])
        self.act_search = A("Rechercher", self.focus_search, ["Ctrl+F", "F3", "Ctrl+E"], "search")
        self.act_hidden = A("Éléments masqués", self.toggle_hidden, ["Ctrl+Shift+.", "Ctrl+Shift+>", "Meta+H"],
                            checkable=True)
        self.act_hidden.setChecked(self.show_hidden)
        self.act_ext = A("Extensions de noms de fichiers", self.toggle_ext, (), checkable=True)
        self.act_ext.setChecked(not self.hide_ext)
        self.act_navpane = A("Volet de navigation", self.toggle_navpane, (), checkable=True)
        self.act_navpane.setChecked(True)
        self.act_home_folder = A("Dossier personnel", lambda: self.tab.navigate(HOME), ["Ctrl+Shift+H"], "home")
        self.act_go_home = A("Accueil", lambda: self.tab.navigate(HOME_LOC), (), "home")
        self.act_go_pc = A("Ce PC", lambda: self.tab.navigate(PC_LOC))
        self.act_go_pc.setIcon(Icons.big("pc"))

        self.view_group = QActionGroup(self)
        self.view_group.setExclusive(True)
        self.view_actions = {}
        for i, (mode, (label, _size)) in enumerate(VIEW_MODES.items(), start=1):
            act = A(label, lambda m=mode: self.tab.set_view_mode(m), [f"Ctrl+Shift+{i}"], checkable=True)
            act.setIcon(Icons.get("view" if mode in ("details", "list") else "tiles"))
            self.view_group.addAction(act)
            self.view_actions[mode] = act

        self.sort_group = QActionGroup(self)
        self.sort_actions = {}
        for col, label in ((0, "Nom"), (3, "Modifié le"), (2, "Type"), (1, "Taille")):
            act = A(label, lambda c=col: self.sort_by(c), (), checkable=True)
            self.sort_group.addAction(act)
            self.sort_actions[col] = act
        self.order_group = QActionGroup(self)
        self.act_asc = A("Croissant", lambda: self.sort_by(None, Qt.SortOrder.AscendingOrder), (), checkable=True)
        self.act_desc = A("Décroissant", lambda: self.sort_by(None, Qt.SortOrder.DescendingOrder), (), checkable=True)
        self.order_group.addAction(self.act_asc)
        self.order_group.addAction(self.act_desc)

    def _tool(self, action=None, icon=None, text=None, tip=None, menu=None, with_text=False):
        btn = QToolButton()
        if action is not None:
            btn.setDefaultAction(action)
        if icon:
            btn.setIcon(Icons.get(icon))
        if text:
            btn.setText(text)
        if tip:
            btn.setToolTip(tip)
        btn.setIconSize(QSize(16, 16))
        btn.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon if with_text
                               else Qt.ToolButtonStyle.ToolButtonIconOnly)
        if menu is not None:
            btn.setMenu(menu)
            btn.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        btn.setMinimumHeight(32)
        if not with_text:
            btn.setFixedWidth(36)
        return btn

    def _build_ui(self):
        central = QWidget()
        central.setObjectName("body")
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # --- bande des onglets ---
        strip = QFrame()
        strip.setObjectName("tabStrip")
        h = QHBoxLayout(strip)
        h.setContentsMargins(8, 0, 8, 0)
        h.setSpacing(2)
        self.tabbar = TabBar(self)
        self.tabbar.setTabsClosable(False)
        self.tabbar.setMovable(True)
        self.tabbar.setExpanding(False)
        self.tabbar.setDocumentMode(True)
        self.tabbar.setDrawBase(False)
        self.tabbar.setElideMode(Qt.TextElideMode.ElideRight)
        self.tabbar.setUsesScrollButtons(True)
        self.tabbar.setIconSize(QSize(16, 16))
        self.tabbar.currentChanged.connect(self._on_tab_changed)
        self.tabbar.tabCloseRequested.connect(self.close_tab)
        new_tab = QToolButton()
        new_tab.setObjectName("newTab")
        new_tab.setDefaultAction(self.act_new_tab)
        new_tab.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonIconOnly)
        new_tab.setFixedSize(34, 30)
        h.addWidget(self.tabbar)
        h.addWidget(new_tab)
        h.addStretch(1)
        root.addWidget(strip)

        # --- navigation + adresse + recherche ---
        nav_row = QFrame()
        nav_row.setObjectName("chrome")
        h = QHBoxLayout(nav_row)
        h.setContentsMargins(8, 6, 10, 4)
        h.setSpacing(2)
        for act in (self.act_back, self.act_fwd, self.act_up, self.act_refresh):
            h.addWidget(self._tool(act))
        h.addSpacing(6)
        self.address = AddressBar(self)
        h.addWidget(self.address, 1)
        h.addSpacing(6)
        self.search = SearchBox(self)
        self.search.textChanged.connect(self._search_changed)
        self.search.returnPressed.connect(self.deep_search)
        h.addWidget(self.search)
        root.addWidget(nav_row)

        # --- barre de commandes ---
        cmd = QFrame()
        cmd.setObjectName("cmdbar")
        h = QHBoxLayout(cmd)
        h.setContentsMargins(8, 2, 8, 6)
        h.setSpacing(2)
        new_menu = make_menu(self)
        new_menu.addAction(self.act_new_folder)
        new_menu.addSeparator()
        new_menu.addAction(self.act_new_text)
        new_menu.addAction(self.act_new_zip)
        self.btn_new = self._tool(icon="new", text=" Nouveau", menu=new_menu, with_text=True,
                                  tip="Créer un nouvel élément à cet emplacement.")
        h.addWidget(self.btn_new)
        h.addSpacing(4)
        h.addWidget(vline())
        h.addSpacing(4)
        for act in (self.act_cut, self.act_copy, self.act_paste, self.act_rename, self.act_delete):
            h.addWidget(self._tool(act))
        h.addSpacing(4)
        h.addWidget(vline())
        h.addSpacing(4)
        self.sort_menu = make_menu(self)
        for col in (0, 3, 2, 1):
            self.sort_menu.addAction(self.sort_actions[col])
        self.sort_menu.addSeparator()
        self.sort_menu.addAction(self.act_asc)
        self.sort_menu.addAction(self.act_desc)
        self.sort_menu.aboutToShow.connect(self._sync_sort_actions)
        self.btn_sort = self._tool(icon="sort", text=" Trier", menu=self.sort_menu, with_text=True)
        h.addWidget(self.btn_sort)
        self.view_menu = make_menu(self)
        for act in self.view_actions.values():
            self.view_menu.addAction(act)
        self.view_menu.addSeparator()
        show = self.view_menu.addMenu("Afficher")
        show.addAction(self.act_navpane)
        show.addAction(self.act_ext)
        show.addAction(self.act_hidden)
        style_menu(self.view_menu)
        self.btn_view = self._tool(icon="view", text=" Afficher", menu=self.view_menu, with_text=True)
        h.addWidget(self.btn_view)
        more = make_menu(self)
        for act in (self.act_select_all, self.act_select_none, self.act_invert):
            more.addAction(act)
        more.addSeparator()
        for act in (self.act_copy_path, self.act_compress, self.act_extract):
            more.addAction(act)
        more.addSeparator()
        if IS_MAC or IS_WIN:
            more.addAction(self.act_terminal)
            more.addAction(self.act_reveal)
            more.addSeparator()
        more.addAction(self.act_properties)
        self.btn_more = self._tool(icon="more", menu=more, tip="Voir plus")
        self.btn_more.setFixedWidth(36)
        self.btn_more.setStyleSheet("QToolButton::menu-indicator { image: none; width: 0; }"
                                    "QToolButton { padding-right: 4px; }")
        h.addWidget(self.btn_more)
        h.addStretch(1)
        root.addWidget(cmd)

        # --- volet de navigation + contenu ---
        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        self.splitter.setChildrenCollapsible(False)
        self.splitter.setHandleWidth(1)
        self.nav = NavTree(self)
        self.nav.setMinimumWidth(170)
        self.tab_stack = QStackedWidget()
        self.splitter.addWidget(self.nav)
        self.splitter.addWidget(self.tab_stack)
        self.splitter.setStretchFactor(1, 1)
        self.splitter.setSizes([240, 900])
        root.addWidget(self.splitter, 1)
        self.setCentralWidget(central)

        # --- barre d'état ---
        bar = self.statusBar()
        bar.setSizeGripEnabled(False)
        self.status_label = QLabel()
        self.status_label.setContentsMargins(10, 0, 0, 0)
        bar.addWidget(self.status_label, 1)
        self.btn_details = QToolButton()
        self.btn_details.setIcon(Icons.get("view"))
        self.btn_details.setToolTip("Afficher les informations sur chaque élément (Détails)")
        self.btn_details.setCheckable(True)
        self.btn_details.clicked.connect(lambda: self.tab.set_view_mode("details"))
        self.btn_large = QToolButton()
        self.btn_large.setIcon(Icons.get("tiles"))
        self.btn_large.setToolTip("Afficher les éléments avec de grandes miniatures")
        self.btn_large.setCheckable(True)
        self.btn_large.clicked.connect(lambda: self.tab.set_view_mode("large"))
        bar.addPermanentWidget(self.btn_details)
        bar.addPermanentWidget(self.btn_large)

        self.nav.rebuild()

    def _build_menubar(self):
        bar = self.menuBar()
        if not IS_MAC:
            bar.hide()   # sur Mac, la barre de menus est en haut de l'écran
        m = bar.addMenu("Fichier")
        for act in (self.act_new_window, self.act_new_tab, self.act_close_tab):
            m.addAction(act)
        m.addSeparator()
        m.addAction(self.act_new_folder)
        m.addAction(self.act_new_text)
        m.addAction(self.act_new_zip)
        m.addSeparator()
        for act in (self.act_open, self.act_open_with, self.act_quicklook, self.act_properties):
            m.addAction(act)
        m = bar.addMenu("Édition")
        for act in (self.act_cut, self.act_copy, self.act_paste, self.act_paste_move, None,
                    self.act_select_all, self.act_select_none, self.act_invert, None,
                    self.act_copy_path, self.act_rename, self.act_delete, self.act_delete_perm, None,
                    self.act_compress, self.act_extract):
            m.addSeparator() if act is None else m.addAction(act)
        m = bar.addMenu("Affichage")
        for act in self.view_actions.values():
            m.addAction(act)
        m.addSeparator()
        for act in (self.act_navpane, self.act_ext, self.act_hidden, None, self.act_refresh):
            m.addSeparator() if act is None else m.addAction(act)
        m = bar.addMenu("Aller")
        for act in (self.act_back, self.act_fwd, self.act_up, None, self.act_go_home, self.act_go_pc,
                    self.act_home_folder, None, self.act_address, self.act_search, None,
                    self.act_next_tab, self.act_prev_tab, None, self.act_terminal, self.act_reveal):
            m.addSeparator() if act is None else m.addAction(act)

    def _restore_geometry(self):
        s = settings()
        others = [w for w in State.windows if w is not self]
        if others:
            self.resize(others[-1].size())
            self.move(others[-1].pos() + QPoint(30, 30))
        elif s.value("geometry") is not None:
            self.restoreGeometry(s.value("geometry"))
        else:
            self.resize(1180, 720)
        if s.value("splitter") is not None:
            self.splitter.restoreState(s.value("splitter"))

    def save_state(self):
        s = settings()
        s.setValue("geometry", self.saveGeometry())
        s.setValue("splitter", self.splitter.saveState())
        if self.tab is not None:
            s.setValue("header", self.tab.details.header().saveState())
            s.setValue("last_location", self.tab.current or HOME_LOC)

    def closeEvent(self, event):
        if self.jobs:
            QMessageBox.information(self, APP_NAME, "Une copie ou un déplacement est en cours. "
                                    "Attends la fin avant de fermer la fenêtre.")
            event.ignore()
            return
        self.save_state()
        if self in State.windows:
            State.windows.remove(self)
        super().closeEvent(event)

    # ---------- onglets ----------

    @property
    def tab(self):
        if not hasattr(self, "tabbar"):
            return None
        return self.tabs.get(self.tabbar.tabData(self.tabbar.currentIndex()))

    def all_tabs(self):
        return list(self.tabs.values())

    def add_tab(self, loc=HOME_LOC, activate=True):
        tab = ExplorerTab(self)
        key = id(tab)
        self.tabs[key] = tab
        tab.location_changed.connect(lambda t=tab: self._tab_location_changed(t))
        tab.status_changed.connect(lambda t=tab: self._tab_status_changed(t))
        self.tab_stack.addWidget(tab)
        insert_at = self.tabbar.currentIndex() + 1 if self.tabbar.count() else 0
        i = self.tabbar.insertTab(insert_at, "")
        self.tabbar.setTabData(i, key)
        close = QToolButton()
        close.setObjectName("tabClose")
        close.setIcon(Icons.get("close", 12))
        close.setIconSize(QSize(10, 10))
        close.setFixedSize(22, 22)
        close.setToolTip("Fermer l'onglet (Ctrl+W)")
        close.clicked.connect(lambda _c=False, t=tab: self.close_tab(self.tab_index(t)))
        self.tabbar.setTabButton(i, QTabBar.ButtonPosition.RightSide, close)
        if not tab.navigate(loc, record=False):
            tab.navigate(HOME_LOC, record=False)
        if activate:
            self.tabbar.setCurrentIndex(self.tab_index(tab))
            self.refresh_chrome()
        return tab

    def tab_index(self, tab):
        for i in range(self.tabbar.count()):
            if self.tabbar.tabData(i) == id(tab):
                return i
        return -1

    def close_tab(self, index):
        if index < 0:
            return
        if self.tabbar.count() <= 1:
            self.close()
            return
        key = self.tabbar.tabData(index)
        tab = self.tabs.pop(key, None)
        self.tabbar.removeTab(index)
        if tab is not None:
            self.tab_stack.removeWidget(tab)
            tab.deleteLater()
        self.refresh_chrome()

    def cycle_tab(self, step):
        n = self.tabbar.count()
        if n > 1:
            self.tabbar.setCurrentIndex((self.tabbar.currentIndex() + step) % n)

    def _on_tab_changed(self, _index):
        tab = self.tab
        if tab is None:
            return
        self.tab_stack.setCurrentWidget(tab)
        self.search.blockSignals(True)
        self.search.setText(tab.search_text)
        self.search.blockSignals(False)
        self.refresh_chrome()

    def _tab_location_changed(self, tab):
        i = self.tab_index(tab)
        if i >= 0:
            self.tabbar.setTabText(i, tab.title())
            self.tabbar.setTabIcon(i, location_icon(tab.current))
            self.tabbar.setTabToolTip(i, safe_tip(native(tab.dir) if tab.dir else tab.title()))
        if tab is self.tab:
            self.tab_stack.setCurrentWidget(tab)
            self.search.blockSignals(True)
            self.search.setText(tab.search_text)
            self.search.blockSignals(False)
            self.refresh_chrome()

    def _tab_status_changed(self, tab):
        if tab is self.tab:
            self.status_label.setText(tab.status_text())
            self.update_commands()

    def refresh_chrome(self):
        tab = self.tab
        if tab is None or tab.current is None:
            return
        self.tab_stack.setCurrentWidget(tab)
        self.address.set_location(tab.current)
        self.search.setPlaceholderText(f"Rechercher dans {tab.title()}")
        self.nav.sync(tab.current)
        self.setWindowTitle(tab.title())
        self.act_back.setEnabled(bool(tab.back_stack))
        self.act_fwd.setEnabled(bool(tab.fwd_stack))
        self.act_up.setEnabled(tab.parent_location() is not None)
        self.view_actions[tab.view_mode].setChecked(True)
        self.btn_details.setChecked(tab.view_mode == "details")
        self.btn_large.setChecked(tab.view_mode == "large")
        self.status_label.setText(tab.status_text())
        self.update_commands()

    def update_commands(self):
        tab = self.tab
        if tab is None:
            return
        has_dir = bool(tab.dir)
        sel = tab.selected_paths()
        for act in (self.act_cut, self.act_copy, self.act_rename, self.act_delete, self.act_delete_perm,
                    self.act_open, self.act_open_with, self.act_quicklook, self.act_compress):
            act.setEnabled(bool(sel))
        clip = bool(local_paths(QGuiApplication.clipboard().mimeData()))
        self.act_paste.setEnabled(has_dir and clip)
        self.act_paste_move.setEnabled(has_dir and clip)
        for act in (self.act_new_folder, self.act_new_text, self.act_new_zip, self.act_terminal, self.act_select_all,
                    self.act_invert, self.act_select_none, self.btn_sort, self.btn_view):
            act.setEnabled(has_dir)
        self.btn_new.setEnabled(has_dir)
        self.act_extract.setEnabled(any(ext_of(p) == ".zip" for p in sel))
        self.act_copy_path.setEnabled(bool(sel) or has_dir)

    def focus_content(self):
        if self.tab is not None:
            self.tab.stack.currentWidget().setFocus()

    def focus_search(self):
        self.search.setFocus()
        self.search.selectAll()

    def _search_changed(self, text):
        tab = self.tab
        if tab is not None and tab.dir:
            tab.search_text = text
            tab.proxy.set_needle(text)

    def new_window(self, loc=None):
        MainWindow(loc or HOME_LOC).show()

    # ---------- affichage ----------

    def sort_by(self, column=None, order=None):
        header = self.tab.details.header()
        column = header.sortIndicatorSection() if column is None else column
        order = header.sortIndicatorOrder() if order is None else order
        for tab in self.all_tabs():
            tab.details.sortByColumn(column, order)

    def _sync_sort_actions(self):
        header = self.tab.details.header()
        act = self.sort_actions.get(header.sortIndicatorSection())
        if act:
            act.setChecked(True)
        (self.act_asc if header.sortIndicatorOrder() == Qt.SortOrder.AscendingOrder else self.act_desc).setChecked(True)

    def toggle_hidden(self):
        value = not self.show_hidden
        settings().setValue("show_hidden", value)
        for win in State.windows:
            win.show_hidden = value
            win.act_hidden.setChecked(value)
            for tab in win.all_tabs():
                tab.apply_filters()
                tab.view.viewport().update()

    def toggle_ext(self):
        value = not self.hide_ext
        settings().setValue("hide_ext", value)
        for win in State.windows:
            win.hide_ext = value
            win.act_ext.setChecked(not value)
            for tab in win.all_tabs():
                tab.view.viewport().update()

    def toggle_navpane(self):
        self.nav.setVisible(not self.nav.isVisible())
        self.act_navpane.setChecked(self.nav.isVisible())

    # ---------- utilitaires ----------

    def targets(self):
        return self.tab.selected_paths() if self.tab is not None else []

    def focused_line_edit(self):
        widget = QApplication.focusWidget()
        return widget if isinstance(widget, QLineEdit) else None

    def confirm(self, text):
        box = QMessageBox(QMessageBox.Icon.Question, APP_NAME, text,
                          QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, self)
        box.setTextFormat(Qt.TextFormat.PlainText)
        box.setDefaultButton(QMessageBox.StandardButton.No)
        return box.exec() == QMessageBox.StandardButton.Yes

    def warn(self, text):
        box = QMessageBox(QMessageBox.Icon.Warning, APP_NAME, text, QMessageBox.StandardButton.Ok, self)
        box.setTextFormat(Qt.TextFormat.PlainText)
        box.exec()

    # ---------- ouvrir ----------

    def open_selection(self):
        self.open_paths(self.targets())

    def open_paths(self, paths):
        if not paths:
            return
        folders = [p for p in paths if is_folder(p)]
        files = [p for p in paths if p not in folders]
        if len(files) > 15 and not self.confirm(f"Ouvrir {len(files)} fichiers ?"):
            return
        for path in files:
            QDesktopServices.openUrl(QUrl.fromLocalFile(path))
        if len(folders) == 1 and not files:
            self.tab.navigate(folders[0])
        else:
            for path in folders:
                self.add_tab(path, activate=False)

    def open_with(self):
        paths = self.targets()
        if not paths:
            return
        if IS_WIN:   # la fenêtre « Ouvrir avec » de Windows
            detached("openwith", [native(paths[0])])
            return
        if not IS_MAC:
            return
        app, _ = QFileDialog.getOpenFileName(self, "Ouvrir avec…", "/Applications", "Applications (*.app)")
        if app:
            detached("open", ["-a", app] + paths)

    def quick_look(self):
        paths = self.targets()
        if not paths:
            return
        if not IS_MAC:
            self.open_paths(paths)
            return
        if self._quicklook is not None and self._quicklook.poll() is None:
            self._quicklook.terminate()
            self._quicklook = None
            return
        self._quicklook = subprocess.Popen([CMD["qlmanage"], "-p"] + paths,
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def reveal_in_finder(self):
        paths = self.targets() or ([self.tab.dir] if self.tab.dir else [])
        if paths:
            self.reveal(paths[0])

    def reveal(self, path):
        """Montre l'élément dans le gestionnaire de fichiers du système."""
        if IS_MAC:
            detached("open", ["-R", path])
        elif IS_WIN:
            proc = QProcess(self)
            proc.setProgram(CMD["explorer"])
            proc.setNativeArguments(f'/select,"{native(path)}"')
            proc.startDetached()
        else:
            QDesktopServices.openUrl(QUrl.fromLocalFile(path if os.path.isdir(path) else pdir(path)))

    def annotate(self, paths):
        script = annoter_script()
        for path in [p for p in paths if ext_of(p) in ANNOTATE_EXTS][:5]:
            detached(sys.executable, [script, path])

    def edit_in_blocnotes(self, paths):
        script = blocnotes_script()
        files = [p for p in paths if p and p not in SPECIAL_LOCS and os.path.isfile(p)][:20]
        if script and files:
            detached(sys.executable, [script] + files)

    def open_in_vscode(self, paths):
        app = vscode_path()
        paths = [p for p in paths if p and p not in SPECIAL_LOCS]
        if not app or not paths:
            return
        if IS_MAC:
            detached("open", ["-a", app] + paths)
        elif IS_WIN:
            detached(app, [native(p) for p in paths])
        else:
            detached(app, paths)

    def open_terminal(self, folder):
        if not folder:
            return
        if IS_MAC:
            detached("open", ["-a", "Terminal", folder])
        elif IS_WIN:
            if os.path.exists(CMD["wt"]):
                detached("wt", ["-d", native(folder)])
            else:
                detached("powershell", ["-NoExit"], native(folder))
        else:
            for term in ("x-terminal-emulator", "gnome-terminal", "konsole", "xterm"):
                found = shutil.which(term)
                if found:
                    detached(found, [], folder)
                    break

    # ---------- sélection et presse-papiers ----------

    def select_all(self):
        line = self.focused_line_edit()
        if line:
            line.selectAll()
        elif self.tab.dir:
            self.tab.view.setFocus()
            self.tab.view.selectAll()

    def select_none(self):
        if self.tab.dir:
            self.tab.view.selectionModel().clearSelection()

    def invert_selection(self):
        tab = self.tab
        if not tab.dir:
            return
        view = tab.view
        root = view.rootIndex()
        sel = view.selectionModel()
        flags = QItemSelectionModel.SelectionFlag.Toggle | QItemSelectionModel.SelectionFlag.Rows
        for row in range(tab.proxy.rowCount(root)):
            sel.select(tab.proxy.index(row, 0, root), flags)

    def copy_selection(self, cut=False):
        line = self.focused_line_edit()
        if line:
            line.cut() if cut else line.copy()
            return
        paths = self.targets()
        if not paths:
            return
        mime = QMimeData()
        mime.setUrls([QUrl.fromLocalFile(p) for p in paths])
        mime.setText("\n".join(paths))
        QGuiApplication.clipboard().setMimeData(mime)
        State.cut_paths = set(paths) if cut else set()
        self.repaint_all_views()
        self.update_commands()

    def repaint_all_views(self):
        for win in State.windows:
            for tab in win.all_tabs():
                tab.view.viewport().update()

    def paste(self, target=None, force_move=False):
        line = self.focused_line_edit()
        if line and target is None:
            line.paste()
            return
        sources = local_paths(QGuiApplication.clipboard().mimeData())
        target = target or self.tab.dir
        if not sources or not target:
            return
        move = force_move or (bool(State.cut_paths) and set(sources) == State.cut_paths)
        self.transfer(sources, target, move)
        if move and State.cut_paths:
            State.cut_paths = set()
            QGuiApplication.clipboard().clear()

    def copy_path(self, paths):
        paths = [p for p in paths if p and p not in SPECIAL_LOCS]
        if paths:
            QGuiApplication.clipboard().setText("\n".join(native(p) for p in paths))
            self.statusBar().showMessage("Chemin copié", 2000)

    def copy_path_action(self):
        self.copy_path(self.targets() or [self.tab.dir])

    # ---------- opérations ----------

    def transfer(self, sources, target, move):
        target = norm(target)
        plan, conflicts, errors = [], [], []
        for src in sources:
            src = norm(src)
            if not os.path.lexists(src):
                continue
            name = os.path.basename(src)
            dst = pjoin(target, name)
            if target == src or target.startswith(src.rstrip("/") + "/"):
                errors.append(f"« {name} » : impossible de le mettre dans lui-même.")
            elif pdir(src) == target:
                if not move:  # copier dans le même dossier → « nom - Copie »
                    plan.append([src, unique_path(target, name, os.path.isdir(src), copy_style=True), False])
            elif os.path.lexists(dst):
                plan.append([src, dst, None])
                conflicts.append(name)
            else:
                plan.append([src, dst, False])
        if conflicts:
            choice = self.ask_conflict(conflicts)
            if choice is None:
                return
            resolved = []
            for src, dst, replace in plan:
                if replace is None:
                    if choice == "skip":
                        continue
                    if choice == "both":
                        dst, replace = unique_path(target, os.path.basename(src), os.path.isdir(src)), False
                    elif (src + "/").startswith(dst.rstrip("/") + "/"):
                        errors.append(f"« {os.path.basename(src)} » : la destination contient l'original.")
                        continue
                    else:
                        replace = True
                resolved.append([src, dst, replace])
            plan = resolved
        if errors:
            self.warn("\n".join(errors))
        if not plan:
            return
        kind = "move" if move else "copy"
        n = len(plan)
        title = ("Déplacement" if move else "Copie") + f" de {n} élément{'s' if n > 1 else ''}…"
        self.run_ops([(kind, s, d, r) for s, d, r in plan], title)

    def ask_conflict(self, names):
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Question)
        box.setTextFormat(Qt.TextFormat.PlainText)
        box.setWindowTitle("Remplacer ou ignorer les fichiers")
        if len(names) == 1:
            box.setText(f"La destination contient déjà un élément nommé « {names[0]} ».")
        else:
            box.setText(f"La destination contient déjà {len(names)} éléments portant le même nom.")
            box.setDetailedText("\n".join(names))
        box.setInformativeText("Les éléments remplacés partent à la corbeille.")
        b_replace = box.addButton("Remplacer", QMessageBox.ButtonRole.AcceptRole)
        b_both = box.addButton("Conserver les deux", QMessageBox.ButtonRole.AcceptRole)
        b_skip = box.addButton("Ignorer", QMessageBox.ButtonRole.AcceptRole)
        box.addButton("Annuler", QMessageBox.ButtonRole.RejectRole)
        box.setDefaultButton(b_both)
        box.exec()
        clicked = box.clickedButton()
        if clicked == b_replace:
            return "replace"
        if clicked == b_both:
            return "both"
        if clicked == b_skip:
            return "skip"
        return None

    def run_ops(self, ops, title):
        if not ops:
            return
        job = FileJob(self, ops, title)
        self.jobs.add(job)
        job.start()

    def job_finished(self, job, created, errors):
        self.jobs.discard(job)
        if errors:
            shown = errors[:12]
            more = len(errors) - len(shown)
            text = "Certaines opérations ont échoué :\n\n" + "\n".join(shown)
            if more > 0:
                text += f"\n… et {more} autre(s)"
            self.warn(text)
        for win in State.windows:
            for tab in win.all_tabs():
                if tab.dir and not os.path.isdir(tab.dir):
                    parent = tab.dir
                    while not os.path.isdir(parent) and pdir(parent) != parent:
                        parent = pdir(parent)
                    tab.navigate(parent if os.path.isdir(parent) else PC_LOC, record=False)
        if created and self.tab is not None:
            self.tab.select_paths(created)

    def trash_selection(self):
        if self.focused_line_edit():
            return
        paths = self.targets()
        if paths:
            n = len(paths)
            self.run_ops([("trash", p, None, False) for p in paths],
                         f"Mise à la corbeille de {n} élément{'s' if n > 1 else ''}…")

    def delete_selection(self):
        if self.focused_line_edit():
            return
        paths = self.targets()
        if not paths:
            return
        what = f"« {os.path.basename(paths[0])} »" if len(paths) == 1 else f"ces {len(paths)} éléments"
        if self.confirm(f"Voulez-vous vraiment supprimer définitivement {what} ?\n\n"
                        "Ils ne passeront pas par la corbeille."):
            self.run_ops([("delete", p, None, False) for p in paths], "Suppression…")

    def rename_selected(self):
        if self.focused_line_edit():
            return
        tab = self.tab
        if not tab.dir:
            return
        view = tab.view
        idx = view.currentIndex()
        rows = [i for i in view.selectionModel().selectedIndexes() if i.column() == 0]
        if not idx.isValid() or idx.siblingAtColumn(0) not in rows:
            if not rows:
                return
            idx = rows[0]
        view.edit(idx.siblingAtColumn(0))

    def rename_path(self, old, new):
        new = new.strip()
        old_name = os.path.basename(old)
        if not new or new == old_name:
            return
        forbidden = '\\/:*?"<>|' if IS_WIN else "/"
        if any(c in new for c in forbidden) or new in (".", ".."):
            self.warn("Un nom de fichier ne peut pas contenir les caractères suivants :\n" + " ".join(forbidden))
            return
        if IS_MAC and new.startswith(".") and not old_name.startswith("."):
            if not self.confirm("Sur macOS, un nom qui commence par un point rend l'élément caché.\n\nContinuer ?"):
                return
        if not is_folder(old) and ext_of(new) != ext_of(old_name):
            if not self.confirm("Si vous modifiez l'extension du nom de fichier, le fichier risque "
                                "de devenir inutilisable.\n\nVoulez-vous vraiment la modifier ?"):
                return
        dst = pjoin(pdir(old), new)
        if os.path.lexists(dst):
            try:
                same = os.path.samefile(old, dst)   # simple changement de majuscules
            except OSError:
                same = False
            if not same:
                self.warn(f"Il existe déjà un élément nommé « {new} » à cet emplacement.")
                return
        try:
            os.rename(old, dst)
        except OSError as exc:
            self.warn(f"Impossible de renommer « {old_name} » : {exc.strerror or exc}")
            return
        for win in State.windows:
            for tab in win.all_tabs():
                if tab.dir and (tab.dir == old or tab.dir.startswith(old + "/")):
                    tab.navigate(dst + tab.dir[len(old):], record=False)
        if self.tab.dir == pdir(dst):
            self.tab.select_paths([dst])

    def new_folder(self):
        tab = self.tab
        if not tab.dir:
            return
        path = unique_path(tab.dir, "Nouveau dossier", is_dir=True)
        try:
            os.mkdir(path)
        except OSError as exc:
            self.warn(f"Impossible de créer le dossier : {exc.strerror or exc}")
            return
        self.search.clear()
        tab.select_paths([path], edit=True)

    def new_text_file(self):
        tab = self.tab
        if not tab.dir:
            return
        path = unique_path(tab.dir, "Nouveau document texte.txt")
        try:
            with open(path, "x", encoding="utf-8"):
                pass
        except OSError as exc:
            self.warn(f"Impossible de créer le fichier : {exc.strerror or exc}")
            return
        self.search.clear()
        tab.select_paths([path], edit=True)

    def new_zip_file(self):
        tab = self.tab
        if not tab.dir:
            return
        path = unique_path(tab.dir, "Nouveau dossier compressé.zip")
        try:
            zipfile.ZipFile(path, "x").close()
        except OSError as exc:
            self.warn(f"Impossible de créer l'archive : {exc.strerror or exc}")
            return
        self.search.clear()
        tab.select_paths([path], edit=True)

    def compress_selection(self):
        paths = self.targets()
        if not paths:
            return
        if len(paths) == 1:
            name = split_name(os.path.basename(paths[0]), os.path.isdir(paths[0]))[0]
        else:
            name = "Archive"
        dst = unique_path(self.tab.dir, name + ".zip")
        self.run_ops([("zip", paths, dst, False)], "Compression…")

    def extract_selection(self):
        zips = [p for p in self.targets() if ext_of(p) == ".zip" and os.path.isfile(p)]
        if zips:
            self.run_ops([("unzip", p, pdir(p), False) for p in zips], "Extraction…")

    def properties(self):
        tab = self.tab
        paths = self.targets() or ([tab.dir] if tab.dir else [])
        if paths:
            PropertiesDialog(self, paths).show()

    def deep_search(self):
        text = self.search.text().strip()
        root = self.tab.dir or HOME
        if text:
            SearchDialog(self, root, text).show()

    # ---------- accès rapide / volumes ----------

    def pin(self, path):
        pins = pinned_folders()
        if path not in pins:
            pins.append(path)
            set_pinned_folders(pins)
            self.quick_access_changed()

    def unpin(self, path):
        set_pinned_folders([p for p in pinned_folders() if p != path])
        self.quick_access_changed()

    def quick_access_changed(self):
        for win in State.windows:
            win.nav.rebuild()
            for tab in win.all_tabs():
                if tab.current == HOME_LOC:
                    tab.home.refresh()

    def volumes_changed(self):
        self.nav.rebuild()
        for tab in self.all_tabs():
            if tab.current == PC_LOC:
                tab.pc.refresh()

    def eject(self, path):
        for win in State.windows:
            for tab in win.all_tabs():
                if tab.dir and (tab.dir == path or tab.dir.startswith(path + "/")):
                    tab.navigate(PC_LOC)
        proc = QProcess(self)
        proc.finished.connect(lambda code, _status, p=proc: self._eject_done(p, path, code))
        proc.start(CMD["diskutil"], ["eject", path])

    def _eject_done(self, proc, path, code):
        if code != 0:
            err = bytes(proc.readAllStandardError()).decode("utf-8", "replace").strip()
            self.warn(f"Impossible d'éjecter {path}\n\n{err}")
        proc.deleteLater()
        for win in State.windows:
            win.volumes_changed()

    # ---------- menu contextuel des fichiers ----------

    def file_menu(self, tab, view, pos):
        idx = view.indexAt(pos)
        sel = view.selectionModel()
        if idx.isValid() and not sel.isSelected(idx.siblingAtColumn(0)):
            view.setCurrentIndex(idx)
            sel.select(idx, QItemSelectionModel.SelectionFlag.ClearAndSelect |
                       QItemSelectionModel.SelectionFlag.Rows)
        if not idx.isValid():
            sel.clearSelection()
        paths = tab.selected_paths()
        global_pos = view.viewport().mapToGlobal(pos)
        menu = make_menu(self)
        if paths:
            self._item_menu(menu, tab, paths, global_pos)
        else:
            self._background_menu(menu, tab, global_pos)
        popup(menu, global_pos)

    def _more_options_later(self, tab, paths, global_pos):
        """« Afficher d'autres options » : ouvre le menu complet juste après la fermeture du premier."""
        QTimer.singleShot(0, self, lambda: self._classic_menu(tab, paths, global_pos))

    def _background_menu(self, menu, tab, global_pos):
        """Clic droit dans une zone vide, dans le même ordre que Windows 11."""
        clip = bool(local_paths(QGuiApplication.clipboard().mimeData()))
        view_sub = menu.addMenu(Icons.get("tiles"), "Affichage")
        for act in self.view_actions.values():
            view_sub.addAction(act)
        sort_sub = menu.addMenu(Icons.get("sort"), "Trier par")
        for col in (0, 3, 2, 1):
            sort_sub.addAction(self.sort_actions[col])
        sort_sub.addSeparator()
        sort_sub.addAction(self.act_asc)
        sort_sub.addAction(self.act_desc)
        self._sync_sort_actions()
        menu.addSeparator()
        if clip:
            menu_item(menu, "Coller", lambda: self.paste(target=tab.dir), icon="paste", shortcut=key_text("Ctrl+V"))
            menu.addSeparator()
        new = menu.addMenu(Icons.get("new"), "Nouveau")
        new.addAction(self.act_new_folder)
        new.addSeparator()
        new.addAction(self.act_new_text)
        new.addAction(self.act_new_zip)
        menu_item(menu, "Propriétés", lambda: PropertiesDialog(self, [tab.dir]).show(), icon="wrench",
                  shortcut="Alt+Entrée")
        menu.addSeparator()
        menu_item(menu, "Ouvrir dans le Terminal", lambda: self.open_terminal(tab.dir), icon="terminal")
        if vscode_path():
            menu_item(menu, "Ouvrir avec Code", lambda: self.open_in_vscode([tab.dir]), icon="code")
        menu.addSeparator()
        menu_item(menu, "Afficher d'autres options", lambda: self._more_options_later(tab, [], global_pos),
                  icon="moreoptions")

    def _item_menu(self, menu, tab, paths, global_pos):
        """Clic droit sur un ou plusieurs éléments."""
        single = paths[0] if len(paths) == 1 else None
        folder = single if single and is_folder(single) else None
        icon_row(menu, [
            ("cut", "Couper", lambda: self.copy_selection(cut=True), True),
            ("copy", "Copier", lambda: self.copy_selection(cut=False), True),
            ("rename", "Renommer", self.rename_selected, bool(single)),
            ("delete", "Supprimer", self.trash_selection, True),
        ])
        menu_item(menu, "Ouvrir", lambda: self.open_paths(paths), shortcut="Entrée")
        if folder:
            menu_item(menu, "Ouvrir dans un nouvel onglet", lambda: self.add_tab(folder, activate=False))
            menu_item(menu, "Ouvrir dans une nouvelle fenêtre", lambda: self.new_window(folder))
        elif IS_MAC or (IS_WIN and single):
            menu_item(menu, "Ouvrir avec…", self.open_with)
        if IS_MAC and not folder:
            menu_item(menu, "Aperçu", self.quick_look, shortcut="Espace")
        if vscode_path():
            menu_item(menu, "Ouvrir avec Code", lambda: self.open_in_vscode(paths), icon="code")
        if blocnotes_script() and not folder and any(os.path.isfile(p) for p in paths):
            menu_item(menu, "Ouvrir avec Bloc-notes Pro", lambda: self.edit_in_blocnotes(paths), icon="notepad")
        if annoter_script() and any(ext_of(p) in ANNOTATE_EXTS for p in paths):
            menu_item(menu, "Annoter", lambda: self.annotate(paths), icon="annotate")
        if folder:
            menu_item(menu, "Épingler dans Accès rapide", lambda: self.pin(folder), icon="pin")
        menu_item(menu, "Compresser en fichier ZIP", self.compress_selection, icon="zip")
        if any(ext_of(p) == ".zip" for p in paths):
            menu_item(menu, "Extraire tout…", self.extract_selection, icon="zip")
        menu_item(menu, "Copier en tant que chemin d'accès", lambda: self.copy_path(paths), icon="copy",
                  shortcut=key_text("Ctrl+Shift+C"))
        menu_item(menu, "Propriétés", lambda: PropertiesDialog(self, paths).show(), icon="wrench",
                  shortcut="Alt+Entrée")
        if folder:
            menu.addSeparator()
            menu_item(menu, "Ouvrir dans le Terminal", lambda: self.open_terminal(folder), icon="terminal")
        menu.addSeparator()
        menu_item(menu, "Afficher d'autres options", lambda: self._more_options_later(tab, paths, global_pos),
                  icon="moreoptions")

    def _classic_menu(self, tab, paths, global_pos):
        """Le menu « complet » (équivalent du menu classique de Windows)."""
        if self.tab is not tab or not tab.dir:
            return
        clip = bool(local_paths(QGuiApplication.clipboard().mimeData()))
        menu = make_menu(self)
        if not paths:
            menu_item(menu, "Actualiser", tab.refresh, icon="refresh", shortcut="F5")
            menu.addSeparator()
            menu_item(menu, "Coller", lambda: self.paste(target=tab.dir), icon="paste", enabled=clip)
            menu_item(menu, "Coller en déplaçant", lambda: self.paste(target=tab.dir, force_move=True), enabled=clip)
            menu.addSeparator()
            menu_item(menu, "Sélectionner tout", self.select_all, icon="selectall", shortcut=key_text("Ctrl+A"))
            menu.addAction(self.act_hidden)
            menu.addSeparator()
            menu_item(menu, "Épingler dans Accès rapide", lambda: self.pin(tab.dir), icon="pin")
            menu_item(menu, "Copier en tant que chemin d'accès", lambda: self.copy_path([tab.dir]), icon="copy")
            menu_item(menu, "Ouvrir dans un nouvel onglet", lambda: self.add_tab(tab.dir, activate=False))
            menu.addSeparator()
            menu_item(menu, REVEAL_LABEL, lambda: self.reveal(tab.dir), icon="finder")
        else:
            single = paths[0] if len(paths) == 1 else None
            menu_item(menu, "Couper", lambda: self.copy_selection(cut=True), icon="cut", shortcut=key_text("Ctrl+X"))
            menu_item(menu, "Copier", lambda: self.copy_selection(cut=False), icon="copy", shortcut=key_text("Ctrl+C"))
            if single and is_folder(single):
                menu_item(menu, "Coller dans ce dossier", lambda: self.paste(target=single), icon="paste", enabled=clip)
            menu.addSeparator()
            menu_item(menu, "Renommer", self.rename_selected, icon="rename", enabled=bool(single), shortcut="F2")
            menu_item(menu, "Supprimer", self.trash_selection, icon="delete", shortcut="Suppr")
            menu_item(menu, "Supprimer définitivement…", self.delete_selection, shortcut="Maj+Suppr")
            if single and os.path.isdir(single) and is_package_dir(single):
                menu.addSeparator()
                menu_item(menu, "Afficher le contenu du paquet", lambda: tab.navigate(single))
            menu.addSeparator()
            menu_item(menu, REVEAL_LABEL, lambda: self.reveal(paths[0]), icon="finder")
        popup(menu, global_pos)


# ======================================================================================

def main():
    args = [a for a in sys.argv[1:] if not a.startswith("-psn")]
    app = QApplication([sys.argv[0]])
    app.setApplicationName(APP_NAME)
    app.setOrganizationName(ORG_NAME)
    apply_theme(app)
    app.setWindowIcon(Icons.big("folder"))
    State.thumbs = ThumbCache()
    window = MainWindow(args[0] if args else None)
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
