#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Annoteur — captures d'écran annotées pour la documentation, au look Windows 11.

Lancement :   python annoter.py [image]
Dépendance :  PySide6-Essentials (déjà installé pour l'explorateur)

Pas de réseau, pas d'admin, rien d'installé dans le système : c'est un script.
Seuls QtCore, QtGui et QtWidgets sont chargés, jamais QtNetwork.

Utilisation :
  1. Coller une capture (Ctrl+V), ouvrir une image (Ctrl+O) ou la glisser dans la fenêtre.
     Bouton « Capturer » : fais ta capture (Mac : Cmd+Ctrl+Maj+4 ; Windows : la sélection
     s'ouvre toute seule), elle arrive directement ici.
  2. Découper : Rogner (C), Lasso (L, le reste devient transparent), Fond transparent (B).
  3. Mettre en évidence : Cadre (R), Cercle (E), Flèche (F), Texte (T), Numéro d'étape (N),
     Surligneur (H), Pixeliser (P), Masquer sous un bloc opaque (M, le plus sûr pour un
     mot de passe). Sélection/déplacement : V.
  4. Copier (Ctrl+C) pour coller dans Confluence, Word, Teams… ou Enregistrer en PNG (Ctrl+S).
Annuler : Ctrl+Z — Rétablir : Ctrl+Y — Supprimer une annotation : Suppr.
Zoom : Ctrl+molette, Ctrl+0 (ajuster), Ctrl+1 (taille réelle).
"""

import atexit
import hashlib
import math
import os
import random
import shutil
import sys
import tempfile
import time

try:
    from PySide6.QtCore import (QEvent, QLineF, QPoint, QPointF, QProcess, QRect, QRectF, QSettings,
                                QSize, QTimer, Qt)
    from PySide6.QtGui import (QAction, QColor, QFont, QFontMetrics, QGuiApplication, QIcon, QImage,
                               QImageReader, QKeySequence, QLinearGradient, QPainter, QPainterPath,
                               QPainterPathStroker, QPalette, QPen, QPixmap, QPolygonF)
    from PySide6.QtWidgets import (QApplication, QColorDialog, QFileDialog, QFrame,
                                   QGraphicsEllipseItem, QGraphicsItem, QGraphicsPathItem,
                                   QGraphicsPixmapItem, QGraphicsRectItem, QGraphicsScene,
                                   QGraphicsTextItem, QGraphicsView, QHBoxLayout, QLabel,
                                   QMainWindow, QMenu, QMessageBox, QStyle, QToolButton,
                                   QVBoxLayout, QWidget)
except ImportError:
    sys.stderr.write("PySide6 n'est pas installé.  Commande :  python -m pip install PySide6-Essentials\n")
    sys.exit(1)


IS_MAC = sys.platform == "darwin"
IS_WIN = sys.platform.startswith("win")
APP_NAME = "Annoteur"
VERSION = "1.1"          # à augmenter à chaque modification
VERSION_DATE = "26/11/2026"
ORG_NAME = "explorateur-maison"


def version_details():
    """Version du script, de Python et de PySide6 (pour comparer avec un collègue)."""
    try:
        import PySide6
        qt = PySide6.__version__
    except ImportError:
        qt = "absent"
    return f"{APP_NAME} {VERSION} du {VERSION_DATE} — Python {sys.version.split()[0]}, PySide6 {qt}"


EMPREINTE = "8e12ceb640990f7e"          # remplie à la livraison : sert à voir si le fichier a été abîmé en le copiant


def empreinte_fichier(path):
    """Empreinte d'un script (fins de ligne normalisées, ligne EMPREINTE vidée) ; None si illisible."""
    import hashlib
    import re as _re
    try:
        with open(path, "rb") as fh:
            text = fh.read().decode("utf-8", "replace")
    except OSError:
        return None
    text = text.replace("\r\n", "\n")
    text = _re.sub(r'^EMPREINTE = "[0-9a-f]*"', 'EMPREINTE = ""', text, count=1, flags=_re.M)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


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
        QMessageBox.warning(None, APP_NAME, f"Le fichier {name} n'est pas tel qu'il a été livré : il a été modifié "
                                            "ou abîmé pendant sa copie (caractères disparus, fichier coupé…).\n\n"
                                            "Certaines fonctions peuvent mal marcher. Récupère-le en téléchargeant "
                                            "la pièce jointe telle quelle, sans copier-coller son contenu.")

C = {
    "chrome": "#F7F9FC", "body": "#FFFFFF", "border": "#E3E3E3", "line": "#EBEBEB",
    "text": "#1A1A1A", "text2": "#616161", "disabled": "#A3A3A3", "accent": "#005FB8",
    "menu": "#F9F9F9", "canvas": "#E9EDF2", "checked": "#DCE6F2",
}
SWATCHES = [("Rouge", "#E81123"), ("Orange", "#F7630C"), ("Jaune", "#FFB900"), ("Vert", "#16C60C"),
            ("Bleu", "#0078D4"), ("Violet", "#8764B8"), ("Noir", "#1A1A1A"), ("Blanc", "#FFFFFF")]
WIDTHS = [("Fin", 2), ("Moyen", 3), ("Épais", 5), ("Très épais", 8)]
TEXT_SIZES = [("Petit", 14), ("Moyen", 18), ("Grand", 24), ("Très grand", 32)]
HIGHLIGHT = QColor(255, 230, 0, 100)

# Lecteurs d'images : liste fixe, pour ne charger que ces modules-là (jamais le lecteur PDF de Qt,
# qui embarque la bibliothèque réseau).
IMAGE_FORMATS = {".png": b"png", ".jpg": b"jpeg", ".jpeg": b"jpeg", ".gif": b"gif", ".bmp": b"bmp",
                 ".webp": b"webp", ".tif": b"tiff", ".tiff": b"tiff"}

TOOLS = [  # (clé, nom, raccourci, icône, aide)
    ("select", "Sélection", "V", "select",
     "Clique sur une annotation pour la déplacer · Suppr pour l'effacer · double-clic sur un texte pour le modifier"),
    ("crop", "Rogner", "C", "crop", "Trace le rectangle à garder"),
    ("lasso", "Lasso", "L", "lasso", "Entoure à main levée la zone à garder : le reste devient transparent"),
    ("transparent", "Fond transparent", "B", "dropper",
     "Clique sur une couleur de fond : elle devient transparente dans toute l'image"),
    ("rect", "Cadre", "R", "rect", "Trace un cadre autour de la zone (Maj = carré)"),
    ("ellipse", "Cercle", "E", "ellipse", "Trace un cercle autour de la zone (Maj = cercle parfait)"),
    ("arrow", "Flèche", "F", "arrow", "Trace une flèche du départ vers la cible (Maj = droite)"),
    ("text", "Texte", "T", "text", "Clique où écrire, tape le texte, puis clique ailleurs"),
    ("step", "Numéro d'étape", "N", "step", "Clique pour poser un numéro d'étape : 1, 2, 3…"),
    ("highlight", "Surligneur", "H", "marker", "Trace la zone à surligner"),
    ("pixelate", "Pixeliser", "P", "pixelate",
     "Trace la zone à flouter (pour un mot de passe ou un token, préfère « Masquer », touche M)"),
    ("redact", "Masquer", "M", "redact",
     "Trace la zone à cacher sous un bloc opaque : le plus sûr pour un mot de passe ou un token"),
]
TOOL_KEYS = {int(getattr(Qt.Key, "Key_" + key)): name for name, _l, key, _i, _h in TOOLS}


def settings():
    return QSettings(ORG_NAME, APP_NAME)


def key_text(seq):
    return QKeySequence(seq).toString(QKeySequence.SequenceFormat.NativeText)


def load_image(path):
    """Lit une image en n'utilisant que le lecteur correspondant à son extension."""
    fmt = IMAGE_FORMATS.get(os.path.splitext(path)[1].lower())
    if not fmt:
        return QImage()
    reader = QImageReader(path, fmt)
    reader.setAutoDetectImageFormat(False)
    reader.setDecideFormatFromContent(False)
    reader.setAutoTransform(True)
    return reader.read()


# ======================================================================================
# Icônes dessinées
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


@_icon("select")
def _(p, c):
    _pen(p, c, 1.2)
    p.drawPolygon(QPolygonF([QPointF(x, y) for x, y in
                             ((4, 1.8), (4, 13.2), (6.9, 10.4), (9.0, 14.6), (10.9, 13.7), (8.8, 9.6), (12.6, 9.4))]))


@_icon("crop")
def _(p, c):
    _pen(p, c, 1.3)
    _poly(p, (4.5, 1.5), (4.5, 11.5), (14.5, 11.5))
    _poly(p, (1.5, 4.5), (11.5, 4.5), (11.5, 14.5))


@_icon("lasso")
def _(p, c):
    pen = QPen(QColor(c), 1.2, Qt.PenStyle.DashLine)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    p.setPen(pen)
    p.drawEllipse(QRectF(1.8, 1.8, 12.4, 8.4))
    _pen(p, c, 1.2)
    p.drawArc(QRectF(2.6, 9.0, 4.0, 5.6), 90 * 16, 200 * 16)


@_icon("dropper")
def _(p, c):
    _pen(p, c, 1.2)
    _line(p, 2.6, 13.4, 8.6, 7.4)
    _line(p, 2.6, 13.4, 2.2, 13.8)
    p.setBrush(QColor(c))
    p.drawEllipse(QPointF(11.0, 5.0), 2.6, 2.6)
    _pen(p, c, 1.2)
    _line(p, 7.2, 6.0, 10.0, 8.8)


@_icon("rect")
def _(p, c):
    _pen(p, "#E81123", 1.5)
    p.drawRoundedRect(QRectF(2.0, 3.5, 12.0, 9.0), 1.2, 1.2)


@_icon("ellipse")
def _(p, c):
    _pen(p, "#E81123", 1.5)
    p.drawEllipse(QRectF(1.8, 3.0, 12.4, 10.0))


@_icon("arrow")
def _(p, c):
    _pen(p, "#E81123", 1.6)
    _line(p, 3.0, 13.0, 12.0, 4.0)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#E81123"))
    p.drawPolygon(QPolygonF([QPointF(13.6, 2.4), QPointF(12.4, 8.0), QPointF(8.0, 3.6)]))


@_icon("text")
def _(p, c):
    _pen(p, c, 1.5)
    _line(p, 3.0, 3.0, 13.0, 3.0)
    _line(p, 8.0, 3.0, 8.0, 13.5)
    _line(p, 6.3, 13.5, 9.7, 13.5)


@_icon("step")
def _(p, c):
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#E81123"))
    p.drawEllipse(QRectF(1.5, 1.5, 13.0, 13.0))
    _pen(p, "#FFFFFF", 1.4)
    _line(p, 8.4, 4.6, 8.4, 11.4)
    _line(p, 6.6, 6.0, 8.4, 4.6)


@_icon("marker")
def _(p, c):
    _pen(p, c, 1.2)
    p.drawPolygon(QPolygonF([QPointF(9.6, 1.8), QPointF(13.8, 6.0), QPointF(7.4, 12.4), QPointF(3.2, 8.2)]))
    _poly(p, (3.2, 8.2), (2.0, 12.0), (5.8, 11.6))
    _pen(p, "#FFB900", 2.2)
    _line(p, 1.6, 14.6, 14.4, 14.6)


@_icon("pixelate")
def _(p, c):
    p.setPen(Qt.PenStyle.NoPen)
    shades = ["#5F6B7A", "#AEB6C1", "#8692A0", "#D2D7DE"]
    for i in range(3):
        for j in range(3):
            p.setBrush(QColor(shades[(i * 2 + j) % 4]))
            p.drawRect(QRectF(1.8 + j * 4.2, 1.8 + i * 4.2, 4.0, 4.0))


@_icon("redact")
def _(p, c):
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#2B2B2B"))
    p.drawRoundedRect(QRectF(1.5, 4.0, 13.0, 8.0), 1.2, 1.2)
    _pen(p, "#8A8A8A", 1.0)
    _line(p, 3.8, 8.0, 12.2, 8.0)


@_icon("undo")
def _(p, c):
    _pen(p, c, 1.3)
    path = QPainterPath()
    path.moveTo(3.0, 6.5)
    path.lineTo(10.0, 6.5)
    path.cubicTo(14.2, 6.5, 14.2, 13.5, 10.0, 13.5)
    path.lineTo(7.0, 13.5)
    p.drawPath(path)
    _poly(p, (6.0, 3.5), (3.0, 6.5), (6.0, 9.5))


@_icon("redo")
def _(p, c):
    _pen(p, c, 1.3)
    path = QPainterPath()
    path.moveTo(13.0, 6.5)
    path.lineTo(6.0, 6.5)
    path.cubicTo(1.8, 6.5, 1.8, 13.5, 6.0, 13.5)
    path.lineTo(9.0, 13.5)
    p.drawPath(path)
    _poly(p, (10.0, 3.5), (13.0, 6.5), (10.0, 9.5))


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


@_icon("save")
def _(p, c):
    _pen(p, c, 1.2)
    _poly(p, (2.2, 2.2), (11.4, 2.2), (13.8, 4.6), (13.8, 13.8), (2.2, 13.8), (2.2, 2.2))
    p.drawRect(QRectF(4.8, 2.2, 5.6, 3.6))
    p.drawRoundedRect(QRectF(4.4, 8.6, 7.2, 5.2), 0.8, 0.8)


@_icon("open")
def _(p, c):
    _pen(p, c, 1.2)
    _poly(p, (1.8, 12.8), (1.8, 3.4), (5.8, 3.4), (7.2, 4.8), (13.0, 4.8), (13.0, 7.0))
    _poly(p, (1.8, 12.8), (4.2, 7.4), (14.6, 7.4), (12.2, 12.8), (1.8, 12.8))


@_icon("capture")
def _(p, c):
    _pen(p, c, 1.2)
    p.drawEllipse(QRectF(2.2, 10.2, 3.8, 3.8))
    p.drawEllipse(QRectF(10.0, 10.2, 3.8, 3.8))
    _line(p, 5.3, 10.6, 11.0, 2.0)
    _line(p, 10.7, 10.6, 5.0, 2.0)


@_icon("fit")
def _(p, c):
    _pen(p, c, 1.2)
    for (x1, y1, x2, y2, x3, y3) in ((2, 6, 2, 2, 6, 2), (10, 2, 14, 2, 14, 6),
                                     (14, 10, 14, 14, 10, 14), (6, 14, 2, 14, 2, 10)):
        _poly(p, (x1, y1), (x2, y2), (x3, y3))


@_icon("minus")
def _(p, c):
    _pen(p, c, 1.3)
    _line(p, 3.5, 8, 12.5, 8)


@_icon("plus")
def _(p, c):
    _pen(p, c, 1.3)
    _line(p, 8, 3.5, 8, 12.5)
    _line(p, 3.5, 8, 12.5, 8)


@_icon("chevdown")
def _(p, c):
    _pen(p, c, 1.3)
    _poly(p, (3.5, 6), (8, 10.5), (12.5, 6))


@_icon("chevright")
def _(p, c):
    _pen(p, c, 1.3)
    _poly(p, (6, 3.5), (10.5, 8), (6, 12.5))


@_icon("check")
def _(p, c):
    _pen(p, c, 1.4)
    _poly(p, (3.2, 8.4), (6.4, 11.6), (12.8, 4.6))


@_icon("dot")
def _(p, c):
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor(c))
    p.drawEllipse(QPointF(8, 8), 2.6, 2.6)


@_icon("app")
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
    _line(p, 13.0, 12.0, 9.2, 8.2)


class Icons:
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
    def get(cls, name, size=16, color=None):
        color = color or C["text"]
        key = (name, size, color)
        if key not in cls._cache:
            icon = QIcon()
            for px in (size, size * 2):
                icon.addPixmap(cls.pixmap(name, px, color), QIcon.Mode.Normal)
                icon.addPixmap(cls.pixmap(name, px, C["disabled"]), QIcon.Mode.Disabled)
            cls._cache[key] = icon
        return cls._cache[key]

    @classmethod
    def swatch(cls, color):
        icon = QIcon()
        for px in (18, 36):
            pm = QPixmap(px, px)
            pm.fill(Qt.GlobalColor.transparent)
            p = QPainter(pm)
            p.setRenderHint(QPainter.RenderHint.Antialiasing)
            p.setPen(QPen(QColor("#8A8A8A"), px / 18.0))
            p.setBrush(QColor(color))
            m = px * 0.12
            p.drawEllipse(QRectF(m, m, px - 2 * m, px - 2 * m))
            p.end()
            icon.addPixmap(pm)
        return icon


# ======================================================================================
# Thème Windows 11
# ======================================================================================

STYLESHEET = """
QWidget { color: @text; }
QMainWindow, QWidget#body { background: @body; }
QFrame#cmdbar { background: @chrome; border-bottom: 1px solid @border; }
QToolButton {
    background: transparent; border: 1px solid transparent; border-radius: 4px; padding: 4px; color: @text;
}
QToolButton:hover { background: rgba(0, 0, 0, 0.055); }
QToolButton:pressed { background: rgba(0, 0, 0, 0.09); }
QToolButton:checked { background: @checked; border: 1px solid #C5D5E8; }
QToolButton:disabled { color: @disabled; }
QToolButton[popupMode="2"] { padding-right: 18px; }
QToolButton::menu-indicator {
    image: url(@img_chevdown); subcontrol-origin: padding; subcontrol-position: center right;
    width: 10px; height: 10px; right: 5px;
}
QToolButton#accent { background: @accent; color: white; border: 1px solid #0054A3; padding: 4px 12px; }
QToolButton#accent:hover { background: #1A6FC2; }
QToolButton#accent:pressed { background: #00519E; }
QGraphicsView { border: none; }
QStatusBar { background: @body; color: @text2; }
QStatusBar::item { border: none; }
QStatusBar QLabel { color: @text2; padding: 0 6px; }
QMenu { background: @menu; border: 1px solid #D9D9D9; border-radius: 8px; padding: 4px; }
QMenu::item { padding: 6px 28px 6px 10px; border-radius: 4px; margin: 1px 0; color: @text; }
QMenu::item:selected { background: rgba(0, 0, 0, 0.055); }
QMenu::separator { height: 1px; background: #E5E5E5; margin: 4px 6px; }
QMenu::indicator { width: 14px; height: 14px; padding-left: 6px; }
QMenu::indicator:exclusive:checked { image: url(@img_dot); }
QMenu::indicator:non-exclusive:checked { image: url(@img_check); }
QScrollBar:vertical { background: transparent; width: 12px; margin: 2px 1px; }
QScrollBar:horizontal { background: transparent; height: 12px; margin: 1px 2px; }
QScrollBar::handle:vertical { background: #B8BEC6; min-height: 32px; border-radius: 3px; margin: 0 3px; }
QScrollBar::handle:horizontal { background: #B8BEC6; min-width: 32px; border-radius: 3px; margin: 3px 0; }
QScrollBar::handle:hover { background: #8C8C8C; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }
QToolTip { background: @menu; color: @text; border: 1px solid #D9D9D9; padding: 4px 6px; border-radius: 4px; }
QDialog, QMessageBox { background: @menu; }
QPushButton {
    background: @body; border: 1px solid #D4D4D4; border-bottom-color: #BDBDBD;
    border-radius: 4px; padding: 5px 16px; min-width: 64px; color: @text;
}
QPushButton:hover { background: #F6F6F6; }
QPushButton:default { background: @accent; color: white; border: 1px solid #0054A3; }
"""


def apply_theme(app):
    app.setStyle("Fusion")
    pal = QPalette()
    for role, value in ((QPalette.ColorRole.Window, C["body"]), (QPalette.ColorRole.Base, C["body"]),
                        (QPalette.ColorRole.Text, C["text"]), (QPalette.ColorRole.WindowText, C["text"]),
                        (QPalette.ColorRole.Button, C["body"]), (QPalette.ColorRole.ButtonText, C["text"]),
                        (QPalette.ColorRole.Highlight, "#CCE4F7"), (QPalette.ColorRole.HighlightedText, C["text"]),
                        (QPalette.ColorRole.ToolTipBase, C["menu"]), (QPalette.ColorRole.ToolTipText, C["text"])):
        pal.setColor(role, QColor(value))
    app.setPalette(pal)
    font = app.font()
    if IS_WIN:
        font.setFamilies(["Segoe UI Variable Text", "Segoe UI", font.family()])
    font.setPixelSize(13)
    app.setFont(font)
    img_dir = tempfile.mkdtemp(prefix="annoteur-theme-")
    atexit.register(shutil.rmtree, img_dir, True)
    css = STYLESHEET
    for name, color in (("chevdown", C["text2"]), ("check", C["text"]), ("dot", C["text"])):
        base = os.path.join(img_dir, name)
        Icons.pixmap(name, 16, color).save(base + ".png", "PNG")
        Icons.pixmap(name, 32, color).save(base + "@2x.png", "PNG")
        css = css.replace("@img_" + name, (base + ".png").replace("\\", "/"))
    for key in sorted(C, key=len, reverse=True):
        css = css.replace("@" + key, C[key])
    app.setStyleSheet(css)


def style_menu(menu):
    menu.setWindowFlags(menu.windowFlags() | Qt.WindowType.FramelessWindowHint)
    menu.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
    return menu


# ======================================================================================
# Annotations (restent modifiables jusqu'à l'export)
# ======================================================================================

FLAGS_EDITABLE = QGraphicsItem.GraphicsItemFlag.ItemIsSelectable | QGraphicsItem.GraphicsItemFlag.ItemIsMovable


def make_pen(color, width):
    pen = QPen(QColor(color), width)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    return pen


class RectItem(QGraphicsRectItem):
    kind = "rect"

    def __init__(self, rect, color, width):
        super().__init__(rect)
        self.set_style(color, width, None)
        self.setFlags(FLAGS_EDITABLE)

    def set_style(self, color, width, _size):
        self.color, self.width = QColor(color), width
        self.setPen(make_pen(color, width))

    def state(self):
        r = self.rect()
        return {"x1": r.x(), "y1": r.y(), "w": r.width(), "h": r.height(),
                "c": self.color.name(QColor.NameFormat.HexArgb), "lw": self.width}

    @classmethod
    def build(cls, d):
        return cls(QRectF(d["x1"], d["y1"], d["w"], d["h"]), QColor(d["c"]), d["lw"])


class EllipseItem(QGraphicsEllipseItem):
    kind = "ellipse"
    set_style = RectItem.set_style
    state = RectItem.state

    def __init__(self, rect, color, width):
        super().__init__(rect)
        self.set_style(color, width, None)
        self.setFlags(FLAGS_EDITABLE)

    @classmethod
    def build(cls, d):
        return cls(QRectF(d["x1"], d["y1"], d["w"], d["h"]), QColor(d["c"]), d["lw"])


class HighlightItem(QGraphicsRectItem):
    kind = "highlight"

    def __init__(self, rect, color=None):
        super().__init__(rect)
        self.set_style(color or HIGHLIGHT, None, None)
        self.setPen(QPen(Qt.PenStyle.NoPen))
        self.setFlags(FLAGS_EDITABLE)

    def set_style(self, color, _width, _size):
        c = QColor(color)
        if c.alpha() == 255:
            c.setAlpha(100)
        self.color = c
        self.setBrush(c)

    def state(self):
        r = self.rect()
        return {"x1": r.x(), "y1": r.y(), "w": r.width(), "h": r.height(),
                "c": self.color.name(QColor.NameFormat.HexArgb)}

    @classmethod
    def build(cls, d):
        return cls(QRectF(d["x1"], d["y1"], d["w"], d["h"]), QColor(d["c"]))


class ArrowItem(QGraphicsItem):
    kind = "arrow"

    def __init__(self, p1, p2, color, width):
        super().__init__()
        self.p1, self.p2 = QPointF(p1), QPointF(p2)
        self.set_style(color, width, None)
        self.setFlags(FLAGS_EDITABLE)

    def set_style(self, color, width, _size):
        self.prepareGeometryChange()
        self.color, self.width = QColor(color), width
        self.update()

    def set_end(self, p2):
        self.prepareGeometryChange()
        self.p2 = QPointF(p2)
        self.update()

    def head_len(self):
        return max(12.0, self.width * 4.2)

    def boundingRect(self):
        h = self.head_len() + self.width
        return QRectF(self.p1, self.p2).normalized().adjusted(-h, -h, h, h)

    def shape(self):
        path = QPainterPath(self.p1)
        path.lineTo(self.p2)
        stroker = QPainterPathStroker()
        stroker.setWidth(self.width + 10)
        return stroker.createStroke(path)

    def paint(self, p, option, widget=None):
        line = QLineF(self.p1, self.p2)
        if line.length() < 1:
            return
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        h = min(self.head_len(), line.length())
        angle = math.atan2(line.dy(), line.dx())
        tip = self.p2
        back = QPointF(tip.x() - h * math.cos(angle), tip.y() - h * math.sin(angle))
        spread = h * 0.55
        left = QPointF(back.x() + spread * math.sin(angle), back.y() - spread * math.cos(angle))
        right = QPointF(back.x() - spread * math.sin(angle), back.y() + spread * math.cos(angle))
        p.setPen(make_pen(self.color, self.width))
        shaft_end = QPointF(tip.x() - h * 0.8 * math.cos(angle), tip.y() - h * 0.8 * math.sin(angle))
        p.drawLine(self.p1, shaft_end)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(self.color)
        p.drawPolygon(QPolygonF([tip, left, right]))
        if self.isSelected():
            p.setPen(QPen(QColor(C["accent"]), 1))
            p.setBrush(QColor("#FFFFFF"))
            for pt in (self.p1, self.p2):
                p.drawEllipse(pt, 3.5, 3.5)

    def state(self):
        return {"x1": self.p1.x(), "y1": self.p1.y(), "x2": self.p2.x(), "y2": self.p2.y(),
                "c": self.color.name(QColor.NameFormat.HexArgb), "lw": self.width}

    @classmethod
    def build(cls, d):
        return cls(QPointF(d["x1"], d["y1"]), QPointF(d["x2"], d["y2"]), QColor(d["c"]), d["lw"])


class TextItem(QGraphicsTextItem):
    kind = "text"

    def __init__(self, text, color, size, canvas=None):
        super().__init__(text)
        self.canvas = canvas
        self.document().setDocumentMargin(6)
        self.set_style(color, None, size)
        self.setFlags(FLAGS_EDITABLE | QGraphicsItem.GraphicsItemFlag.ItemIsFocusable)
        self.setTextInteractionFlags(Qt.TextInteractionFlag.NoTextInteraction)

    def set_style(self, color, _width, size):
        self.color = QColor(color)
        if size:
            self.size = size
            font = QFont(QApplication.font())
            font.setPixelSize(size)
            font.setWeight(QFont.Weight.DemiBold)
            self.setFont(font)
        self.setDefaultTextColor(self.color)

    def paint(self, p, option, widget=None):
        p.save()
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(255, 255, 255, 230))
        p.drawRoundedRect(self.boundingRect().adjusted(1, 1, -1, -1), 4, 4)
        p.restore()
        super().paint(p, option, widget)

    def start_edit(self):
        self.setTextInteractionFlags(Qt.TextInteractionFlag.TextEditorInteraction)
        self.setFocus(Qt.FocusReason.MouseFocusReason)
        cursor = self.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        self.setTextCursor(cursor)

    def mouseDoubleClickEvent(self, event):
        self.start_edit()
        super().mouseDoubleClickEvent(event)

    def keyPressEvent(self, event):
        if event.matches(QKeySequence.StandardKey.Paste):   # coller = texte brut uniquement
            self.textCursor().insertText(QGuiApplication.clipboard().text())
            event.accept()
            return
        super().keyPressEvent(event)

    def dragEnterEvent(self, event):
        event.setAccepted(event.mimeData().hasText())

    def dragMoveEvent(self, event):
        event.setAccepted(event.mimeData().hasText())

    def dropEvent(self, event):
        if event.mimeData().hasText():
            self.textCursor().insertText(event.mimeData().text())
            event.accept()
        else:
            event.ignore()

    def focusOutEvent(self, event):
        super().focusOutEvent(event)
        self.setPlainText(self.toPlainText())   # retire toute mise en forme ou image glissée
        self.setTextInteractionFlags(Qt.TextInteractionFlag.NoTextInteraction)
        cursor = self.textCursor()
        cursor.clearSelection()
        self.setTextCursor(cursor)
        if self.canvas is not None:
            QTimer.singleShot(0, self.canvas, lambda: self.canvas.text_done(self))

    def state(self):
        return {"text": self.toPlainText(), "c": self.color.name(QColor.NameFormat.HexArgb), "s": self.size}

    @classmethod
    def build(cls, d, canvas=None):
        return cls(d["text"], QColor(d["c"]), d["s"], canvas)


class StepItem(QGraphicsItem):
    kind = "step"

    def __init__(self, number, color, size):
        super().__init__()
        self.number = number
        self.set_style(color, None, size)
        self.setFlags(FLAGS_EDITABLE)

    def set_style(self, color, _width, size):
        self.prepareGeometryChange()
        self.color = QColor(color)
        if size:
            self.size = size
        self.update()

    def diameter(self):
        return round(self.size * 1.8)

    def boundingRect(self):
        d = self.diameter() + 4
        return QRectF(-d / 2, -d / 2, d, d)

    def paint(self, p, option, widget=None):
        d = self.diameter()
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setPen(QPen(QColor("#FFFFFF"), 2))
        p.setBrush(self.color)
        p.drawEllipse(QRectF(-d / 2, -d / 2, d, d))
        font = QFont(QApplication.font())
        font.setPixelSize(round(self.size * 0.95))
        font.setBold(True)
        p.setFont(font)
        light = self.color.lightness() > 170
        p.setPen(QColor("#1A1A1A") if light else QColor("#FFFFFF"))
        p.drawText(QRectF(-d / 2, -d / 2, d, d), int(Qt.AlignmentFlag.AlignCenter), str(self.number))
        if self.isSelected():
            p.setPen(QPen(QColor(C["accent"]), 1, Qt.PenStyle.DashLine))
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawRect(self.boundingRect().adjusted(0.5, 0.5, -0.5, -0.5))

    def state(self):
        return {"n": self.number, "c": self.color.name(QColor.NameFormat.HexArgb), "s": self.size}

    @classmethod
    def build(cls, d):
        return cls(d["n"], QColor(d["c"]), d["s"])


class PixelateItem(QGraphicsPixmapItem):
    """Zone pixelisée : calculée à partir de l'image, opaque, donc rien ne transparaît à l'export."""
    kind = "pixelate"

    def __init__(self, rect, block=12, seed=None):
        super().__init__()
        self.area = QRectF(rect).toAlignedRect()
        self.block = block
        # graine tirée au hasard par le système : le bruit ne peut pas être recalculé
        self.seed = seed if seed is not None else random.SystemRandom().getrandbits(64)
        self.setFlags(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable)

    def set_style(self, *_args):
        pass

    def refresh(self, image):
        r = self.area.intersected(image.rect())
        if r.isEmpty():
            self.setPixmap(QPixmap())
            return
        part = image.copy(r).convertToFormat(QImage.Format.Format_RGB32)
        small = part.scaled(max(1, r.width() // self.block), max(1, r.height() // self.block),
                            Qt.AspectRatioMode.IgnoreAspectRatio, Qt.TransformationMode.SmoothTransformation)
        small = small.convertToFormat(QImage.Format.Format_RGB32)
        rng = random.Random(self.seed)
        for y in range(small.height()):
            for x in range(small.width()):
                c = small.pixelColor(x, y)
                n = rng.randint(-22, 22)
                small.setPixelColor(x, y, QColor(min(255, max(0, c.red() + n)), min(255, max(0, c.green() + n)),
                                                 min(255, max(0, c.blue() + n))))
        big = small.scaled(r.width(), r.height(), Qt.AspectRatioMode.IgnoreAspectRatio,
                           Qt.TransformationMode.FastTransformation)
        self.setPixmap(QPixmap.fromImage(big))
        self.setOffset(QPointF(r.topLeft() - self.area.topLeft()))

    def paint(self, p, option, widget=None):
        super().paint(p, option, widget)
        if self.isSelected():
            p.setPen(QPen(QColor(C["accent"]), 1, Qt.PenStyle.DashLine))
            p.drawRect(self.boundingRect().adjusted(0.5, 0.5, -0.5, -0.5))

    def state(self):
        return {"x1": self.area.x(), "y1": self.area.y(), "w": self.area.width(), "h": self.area.height(),
                "b": self.block, "seed": self.seed}

    @classmethod
    def build(cls, d):
        return cls(QRectF(d["x1"], d["y1"], d["w"], d["h"]), d["b"], d["seed"])


class RedactItem(QGraphicsRectItem):
    """Bloc opaque : rien de ce qu'il couvre ne subsiste dans l'image exportée."""
    kind = "redact"
    FILL = QColor("#2B2B2B")

    def __init__(self, rect):
        super().__init__(rect)
        self.setPen(QPen(Qt.PenStyle.NoPen))
        self.setBrush(self.FILL)
        self.setFlags(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable)

    def set_style(self, *_args):
        pass

    def paint(self, p, option, widget=None):
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(self.FILL)
        p.drawRect(self.rect())
        if self.isSelected():
            p.setPen(QPen(QColor(C["accent"]), 1, Qt.PenStyle.DashLine))
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawRect(self.rect())

    def state(self):
        r = self.rect()
        return {"x1": r.x(), "y1": r.y(), "w": r.width(), "h": r.height()}

    @classmethod
    def build(cls, d):
        return cls(QRectF(d["x1"], d["y1"], d["w"], d["h"]))


ITEM_TYPES = {cls.kind: cls for cls in (RectItem, EllipseItem, HighlightItem, ArrowItem, TextItem,
                                        StepItem, PixelateItem, RedactItem)}


# ======================================================================================
# Zone de dessin
# ======================================================================================

class Canvas(QGraphicsView):
    def __init__(self, win):
        super().__init__(win)
        self.win = win
        self.setScene(QGraphicsScene(self))
        self.setRenderHints(QPainter.RenderHint.Antialiasing | QPainter.RenderHint.SmoothPixmapTransform |
                            QPainter.RenderHint.TextAntialiasing)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.ViewportAnchor.AnchorViewCenter)
        self.setViewportUpdateMode(QGraphicsView.ViewportUpdateMode.FullViewportUpdate)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setAcceptDrops(True)
        self.image = QImage()
        self.base = QGraphicsPixmapItem()
        self.base.setZValue(-100000)
        self.base.setTransformationMode(Qt.TransformationMode.SmoothTransformation)
        self.scene().addItem(self.base)
        self.tool = "select"
        self.temp = None
        self.start = None
        self.lasso = []
        self.z = 0

    # ---- image ----
    def has_image(self):
        return not self.image.isNull()

    def annotations(self):
        return [it for it in self.scene().items() if getattr(it, "kind", None) in ITEM_TYPES and it is not self.temp]

    def set_image(self, image, keep_items=False, fit=True):
        if image.format() != QImage.Format.Format_ARGB32:
            image = image.convertToFormat(QImage.Format.Format_ARGB32)
        self.image = image
        self.base.setPixmap(QPixmap.fromImage(image))
        if not keep_items:
            for it in self.annotations():
                self.scene().removeItem(it)
        for it in self.annotations():
            if isinstance(it, PixelateItem):
                it.refresh(image)
        margin = 80
        self.scene().setSceneRect(QRectF(image.rect()).adjusted(-margin, -margin, margin, margin))
        if fit:
            QTimer.singleShot(0, self, self.zoom_fit)
        self.viewport().update()

    def flatten(self):
        """Image finale : la capture + toutes les annotations, à la taille réelle."""
        if not self.has_image():
            return QImage()
        selected = self.scene().selectedItems()
        for it in selected:
            it.setSelected(False)
        focus = self.scene().focusItem()
        if focus is not None:
            focus.clearFocus()
        out = QImage(self.image.size(), QImage.Format.Format_ARGB32_Premultiplied)
        out.fill(Qt.GlobalColor.transparent)
        p = QPainter(out)
        p.setRenderHints(QPainter.RenderHint.Antialiasing | QPainter.RenderHint.SmoothPixmapTransform |
                         QPainter.RenderHint.TextAntialiasing)
        self.scene().render(p, QRectF(out.rect()), QRectF(self.image.rect()))
        p.end()
        for it in selected:
            it.setSelected(True)
        return out.convertToFormat(QImage.Format.Format_ARGB32)

    # ---- état (annuler / rétablir) ----
    def state(self):
        items = []
        for it in sorted(self.annotations(), key=lambda i: i.zValue()):
            d = {"k": it.kind, "px": it.pos().x(), "py": it.pos().y(), "z": it.zValue()}
            d.update(it.state())
            items.append(d)
        return {"image": self.image, "key": self.image.cacheKey(), "items": items}

    def restore(self, st):
        self.temp = None
        for it in self.annotations():
            self.scene().removeItem(it)
        self.set_image(st["image"], keep_items=False, fit=False) if not st["image"].isNull() else self._clear()
        for d in st["items"]:
            cls = ITEM_TYPES[d["k"]]
            it = cls.build(d, self) if cls is TextItem else cls.build(d)
            it.setPos(d["px"], d["py"])
            it.setZValue(d["z"])
            self.scene().addItem(it)
            if isinstance(it, PixelateItem):
                it.refresh(self.image)
            self.z = max(self.z, d["z"])

    def _clear(self):
        self.image = QImage()
        self.base.setPixmap(QPixmap())
        self.viewport().update()

    # ---- opérations ----
    def next_z(self, low=False):
        self.z += 1
        return self.z - 50000 if low else self.z

    def add(self, item, low=False):
        item.setZValue(self.next_z(low))
        self.scene().addItem(item)
        return item

    def delete_selected(self):
        items = self.scene().selectedItems()
        for it in items:
            self.scene().removeItem(it)
        return bool(items)

    def crop(self, rect):
        r = rect.toAlignedRect().intersected(self.image.rect())
        if r.width() < 3 or r.height() < 3:
            return False
        offset = QPointF(r.topLeft())
        new = self.image.copy(r)
        for it in self.annotations():
            if isinstance(it, PixelateItem):
                it.area = it.area.translated(-r.topLeft())
                it.setPos(QPointF(it.area.topLeft()))
            else:
                it.setPos(it.pos() - offset)
        self.set_image(new, keep_items=True)
        bounds = QRectF(new.rect())
        for it in self.annotations():
            if not it.sceneBoundingRect().intersects(bounds):
                self.scene().removeItem(it)
        return True

    def cut_lasso(self, points):
        if len(points) < 3:
            return False
        path = QPainterPath()
        path.addPolygon(QPolygonF(points))
        path.closeSubpath()
        flat = self.flatten()
        r = path.boundingRect().toAlignedRect().intersected(flat.rect())
        if r.width() < 3 or r.height() < 3:
            return False
        out = QImage(r.size(), QImage.Format.Format_ARGB32_Premultiplied)
        out.fill(Qt.GlobalColor.transparent)
        p = QPainter(out)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.translate(-QPointF(r.topLeft()))
        p.setClipPath(path)
        p.drawImage(0, 0, flat)
        p.end()
        self.set_image(out.convertToFormat(QImage.Format.Format_ARGB32), keep_items=False)
        return True

    def make_transparent(self, pos):
        pt = QPoint(int(pos.x()), int(pos.y()))
        if not self.image.rect().contains(pt):
            return False
        color = self.image.pixelColor(pt)
        if color.alpha() == 0:
            return False
        mask = self.image.createMaskFromColor(color.rgba(), Qt.MaskMode.MaskOutColor)
        out = self.image.copy()
        out.setAlphaChannel(mask.convertToFormat(QImage.Format.Format_Grayscale8))
        self.set_image(out, keep_items=True, fit=False)
        return True

    # ---- zoom ----
    def zoom_fit(self):
        if not self.has_image():
            return
        self.resetTransform()
        area = self.viewport().rect().adjusted(24, 24, -24, -24)
        img = self.image.size()
        scale = min(1.0, area.width() / max(1, img.width()), area.height() / max(1, img.height()))
        self.scale(scale, scale)
        self.centerOn(QRectF(self.image.rect()).center())
        self.win.update_zoom()

    def zoom_100(self):
        self.resetTransform()
        if self.has_image():
            self.centerOn(QRectF(self.image.rect()).center())
        self.win.update_zoom()

    def zoom_by(self, factor):
        current = self.transform().m11()
        target = min(16.0, max(0.05, current * factor))
        self.scale(target / current, target / current)
        self.win.update_zoom()

    def zoom_level(self):
        return self.transform().m11()

    # ---- dessin du fond ----
    def drawBackground(self, p, rect):
        p.fillRect(rect, QColor(C["canvas"]))
        if not self.has_image():
            return
        r = QRectF(self.image.rect())
        p.save()
        p.setPen(Qt.PenStyle.NoPen)
        for i, alpha in enumerate((18, 12, 7)):
            p.setBrush(QColor(0, 0, 0, alpha))
            d = (i + 1) * 1.5 / max(0.2, self.zoom_level())
            p.drawRect(r.adjusted(-d, -d + 1, d, d + 1))
        # damier sous l'image : montre les zones transparentes
        p.fillRect(r, QColor("#FFFFFF"))
        cell = 8
        p.setBrush(QColor("#E6E6E6"))
        visible = r.intersected(rect)
        x0 = int((visible.left() - r.left()) // cell)
        y0 = int((visible.top() - r.top()) // cell)
        x1 = int((visible.right() - r.left()) // cell) + 1
        y1 = int((visible.bottom() - r.top()) // cell) + 1
        if (x1 - x0) * (y1 - y0) < 60000:
            for gy in range(y0, y1):
                for gx in range(x0, x1):
                    if (gx + gy) % 2:
                        p.drawRect(QRectF(r.left() + gx * cell, r.top() + gy * cell, cell, cell).intersected(r))
        p.restore()

    def drawForeground(self, p, rect):
        if self.has_image():
            return
        p.save()
        p.resetTransform()
        vr = self.viewport().rect()
        p.setPen(QColor(C["text2"]))
        font = QFont(QApplication.font())
        font.setPixelSize(15)
        p.setFont(font)
        capture = "Cmd+Ctrl+Maj+4" if IS_MAC else "Win+Maj+S"
        text = ("Colle une capture ({})  ·  ouvre une image ({})  ·  ou glisse un fichier ici\n\n"
                "Pour capturer une zone de l'écran : bouton « Capturer », ou {} puis colle ici."
                ).format(key_text("Ctrl+V"), key_text("Ctrl+O"), capture)
        p.drawText(vr, int(Qt.AlignmentFlag.AlignCenter), text)
        p.restore()

    # ---- souris ----
    def scene_pos(self, event):
        return self.mapToScene(event.position().toPoint())

    def mousePressEvent(self, event):
        if not self.has_image() or event.button() != Qt.MouseButton.LeftButton or self.tool == "select":
            return super().mousePressEvent(event)
        pos = self.scene_pos(event)
        win = self.win
        tool = self.tool
        if tool == "text":
            hit = self.itemAt(event.position().toPoint())
            if isinstance(hit, TextItem):
                return super().mousePressEvent(event)
            focus = self.scene().focusItem()
            if isinstance(focus, TextItem):   # un clic à côté termine le texte en cours
                focus.clearFocus()
                return None
            item = self.add(TextItem("", win.color, win.text_size, self))
            item.setPos(pos - QPointF(6, item.boundingRect().height() / 2))
            item.start_edit()
            return None
        if tool == "step":
            numbers = [it.number for it in self.annotations() if isinstance(it, StepItem)]
            item = self.add(StepItem(max(numbers, default=0) + 1, win.color, win.text_size))
            item.setPos(pos)
            win.commit()
            return None
        if tool == "transparent":
            if self.make_transparent(pos):
                win.commit()
            return None
        self.scene().clearSelection()
        self.start = pos
        if tool in ("rect", "ellipse"):
            cls = RectItem if tool == "rect" else EllipseItem
            self.temp = self.add(cls(QRectF(pos, pos), win.color, win.width))
        elif tool == "highlight":
            self.temp = self.add(HighlightItem(QRectF(pos, pos)), low=True)
        elif tool == "redact":
            self.temp = self.add(RedactItem(QRectF(pos, pos)), low=True)
        elif tool == "arrow":
            self.temp = self.add(ArrowItem(pos, pos, win.color, win.width))
        elif tool in ("crop", "pixelate"):
            self.temp = QGraphicsRectItem(QRectF(pos, pos))
            pen = QPen(QColor(C["accent"]), 0, Qt.PenStyle.DashLine)
            self.temp.setPen(pen)
            self.temp.setBrush(QColor(0, 95, 184, 30))
            self.temp.setZValue(1e9)
            self.scene().addItem(self.temp)
        elif tool == "lasso":
            self.lasso = [pos]
            self.temp = QGraphicsPathItem()
            self.temp.setPen(QPen(QColor(C["accent"]), 0, Qt.PenStyle.DashLine))
            self.temp.setBrush(QColor(0, 95, 184, 30))
            self.temp.setZValue(1e9)
            self.scene().addItem(self.temp)
        return None

    def mouseMoveEvent(self, event):
        if self.temp is None:
            return super().mouseMoveEvent(event)
        pos = self.scene_pos(event)
        shift = bool(event.modifiers() & Qt.KeyboardModifier.ShiftModifier)
        if self.tool == "lasso":
            if QLineF(self.lasso[-1], pos).length() >= 2:
                self.lasso.append(pos)
                path = QPainterPath()
                path.addPolygon(QPolygonF(self.lasso))
                self.temp.setPath(path)
            return None
        if self.tool == "arrow":
            if shift:   # angles multiples de 45°
                line = QLineF(self.start, pos)
                angle = round(line.angle() / 45) * 45
                line.setAngle(angle)
                pos = line.p2()
            self.temp.set_end(pos)
            return None
        if shift:
            side = max(abs(pos.x() - self.start.x()), abs(pos.y() - self.start.y()))
            pos = QPointF(self.start.x() + math.copysign(side, pos.x() - self.start.x()),
                          self.start.y() + math.copysign(side, pos.y() - self.start.y()))
        self.temp.setRect(QRectF(self.start, pos).normalized())
        return None

    def mouseReleaseEvent(self, event):
        if self.temp is None:
            super().mouseReleaseEvent(event)
            if self.tool == "select":
                self.win.commit()
            return
        temp, self.temp = self.temp, None
        tool = self.tool
        changed = False
        if tool in ("rect", "ellipse", "highlight", "redact"):
            r = temp.rect()
            if r.width() < 4 or r.height() < 4:
                self.scene().removeItem(temp)
            else:
                changed = True
        elif tool == "arrow":
            if QLineF(temp.p1, temp.p2).length() < 6:
                self.scene().removeItem(temp)
            else:
                changed = True
        elif tool == "pixelate":
            r = temp.rect().toAlignedRect().intersected(self.image.rect())
            self.scene().removeItem(temp)
            if r.width() >= 4 and r.height() >= 4:
                item = PixelateItem(QRectF(r))
                item.refresh(self.image)
                item.setPos(QPointF(r.topLeft()))
                item.area = QRect(r)
                self.add(item, low=True)
                changed = True
        elif tool == "crop":
            self.scene().removeItem(temp)
            changed = self.crop(temp.rect())
        elif tool == "lasso":
            self.scene().removeItem(temp)
            changed = self.cut_lasso(self.lasso)
            self.lasso = []
        if changed:
            self.win.commit()

    def text_done(self, item):
        if item.scene() is None:
            return
        if not item.toPlainText().strip():
            self.scene().removeItem(item)
        self.win.commit()

    # ---- clavier / molette ----
    def keyPressEvent(self, event):
        focus = self.scene().focusItem()
        if isinstance(focus, TextItem) and focus.textInteractionFlags() != Qt.TextInteractionFlag.NoTextInteraction:
            if event.key() == Qt.Key.Key_Escape:
                focus.clearFocus()
                return
            return super().keyPressEvent(event)
        key = event.key()
        plain = event.modifiers() in (Qt.KeyboardModifier.NoModifier, Qt.KeyboardModifier.KeypadModifier)
        if plain and key in (Qt.Key.Key_Delete, Qt.Key.Key_Backspace):
            if self.delete_selected():
                self.win.commit()
            return
        if plain and key == Qt.Key.Key_Escape:
            if self.temp is not None:
                self.scene().removeItem(self.temp)
                self.temp = None
            self.scene().clearSelection()
            return
        if plain and int(key) in TOOL_KEYS:
            self.win.set_tool(TOOL_KEYS[int(key)])
            return
        super().keyPressEvent(event)

    def wheelEvent(self, event):
        if event.modifiers() & (Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.MetaModifier):
            delta = event.angleDelta().y()
            if delta:
                self.zoom_by(1.15 if delta > 0 else 1 / 1.15)
            event.accept()
            return
        super().wheelEvent(event)

    # ---- glisser-déposer d'un fichier image ----
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls() or event.mimeData().hasImage():
            event.acceptProposedAction()
        else:
            super().dragEnterEvent(event)

    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls() or event.mimeData().hasImage():
            event.acceptProposedAction()
        else:
            super().dragMoveEvent(event)

    def dropEvent(self, event):
        mime = event.mimeData()
        for url in mime.urls():
            if url.isLocalFile() and self.win.open_path(url.toLocalFile()):
                event.acceptProposedAction()
                return
        if mime.hasImage():
            image = QImage(mime.imageData())
            if not image.isNull():
                self.win.new_image(image, "image déposée")
                event.acceptProposedAction()


# ======================================================================================
# Fenêtre
# ======================================================================================

class MainWindow(QMainWindow):
    def __init__(self, path=None):
        super().__init__()
        s = settings()
        self.color = QColor(s.value("color", SWATCHES[0][1]))
        self.width = int(s.value("width", 3))
        self.text_size = int(s.value("text_size", 18))
        self.history, self.redo_stack = [], []
        self.dirty = False
        self.source_name = ""
        self.armed_until = 0.0
        self.armed_sig = None
        self.canvas = Canvas(self)
        self._build_ui()
        self.set_tool("select")
        self.setWindowIcon(Icons.get("app", 32))
        geo = s.value("geometry")
        if geo is not None:
            self.restoreGeometry(geo)
        else:
            self.resize(1200, 780)
        self._capture_timer = QTimer(self)
        self._capture_timer.setInterval(400)
        self._capture_timer.timeout.connect(self._poll_capture)
        self.commit(initial=True)
        if path:
            self.open_path(path)
        self.update_title()

    # ---- interface ----
    def _btn(self, icon=None, text=None, tip=None, slot=None, checkable=False, menu=None, with_text=False):
        b = QToolButton()
        if icon:
            b.setIcon(Icons.get(icon) if isinstance(icon, str) else icon)
            b.setIconSize(QSize(18, 18))
        if text:
            b.setText(text)
        if tip:
            b.setToolTip(tip)
        b.setCheckable(checkable)
        b.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon if with_text
                             else Qt.ToolButtonStyle.ToolButtonIconOnly)
        if slot:
            b.clicked.connect(lambda _c=False: slot())
        if menu is not None:
            b.setMenu(menu)
            b.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        b.setMinimumHeight(34)
        if not with_text and menu is None:
            b.setFixedWidth(36)
        b.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        return b

    def _sep(self, layout):
        line = QFrame()
        line.setFixedSize(1, 24)
        line.setStyleSheet(f"background: {C['border']};")
        layout.addSpacing(4)
        layout.addWidget(line)
        layout.addSpacing(4)

    def _build_ui(self):
        body = QWidget()
        body.setObjectName("body")
        root = QVBoxLayout(body)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        bar = QFrame()
        bar.setObjectName("cmdbar")
        h = QHBoxLayout(bar)
        h.setContentsMargins(8, 6, 8, 6)
        h.setSpacing(2)

        h.addWidget(self._btn("capture", " Capturer", "Capturer une zone de l'écran", self.capture, with_text=True))
        h.addWidget(self._btn("open", tip=f"Ouvrir une image ({key_text('Ctrl+O')})", slot=self.open_dialog))
        h.addWidget(self._btn("paste", tip=f"Coller une capture ({key_text('Ctrl+V')})", slot=self.paste))
        self._sep(h)

        self.tool_buttons = {}
        groups = (("select", "crop", "lasso", "transparent"),
                  ("rect", "ellipse", "arrow", "text", "step", "highlight", "pixelate", "redact"))
        tools = {t[0]: t for t in TOOLS}
        for gi, group in enumerate(groups):
            for name in group:
                _k, label, key, icon, hint = tools[name]
                b = self._btn(icon, tip=f"{label} ({key})\n{hint}", slot=lambda n=name: self.set_tool(n),
                              checkable=True)
                self.tool_buttons[name] = b
                h.addWidget(b)
            self._sep(h)

        self.swatch_buttons = []
        for label, value in SWATCHES:
            b = self._btn(Icons.swatch(value), tip=label, slot=lambda v=value: self.set_color(QColor(v)),
                          checkable=True)
            b.setFixedWidth(30)
            b.setProperty("color", value)
            self.swatch_buttons.append(b)
            h.addWidget(b)
        self.custom_color_btn = self._btn("plus", tip="Autre couleur…", slot=self.pick_color)
        self.custom_color_btn.setFixedWidth(30)
        h.addWidget(self.custom_color_btn)
        self._sep(h)

        width_menu = style_menu(QMenu(self))
        self.width_actions = {}
        for label, value in WIDTHS:
            act = QAction(f"{label} ({value} px)", width_menu)
            act.setCheckable(True)
            act.triggered.connect(lambda _c=False, v=value: self.set_width(v))
            width_menu.addAction(act)
            self.width_actions[value] = act
        h.addWidget(self._btn(text="Trait", tip="Épaisseur des cadres, cercles et flèches", menu=width_menu,
                              with_text=True))
        size_menu = style_menu(QMenu(self))
        self.size_actions = {}
        for label, value in TEXT_SIZES:
            act = QAction(f"{label} ({value} px)", size_menu)
            act.setCheckable(True)
            act.triggered.connect(lambda _c=False, v=value: self.set_text_size(v))
            size_menu.addAction(act)
            self.size_actions[value] = act
        h.addWidget(self._btn(text="Texte", tip="Taille des textes et des numéros", menu=size_menu, with_text=True))
        self._sep(h)

        self.undo_btn = self._btn("undo", tip=f"Annuler ({key_text('Ctrl+Z')})", slot=self.undo)
        self.redo_btn = self._btn("redo", tip=f"Rétablir ({key_text('Ctrl+Y')})", slot=self.redo)
        h.addWidget(self.undo_btn)
        h.addWidget(self.redo_btn)
        h.addStretch(1)
        self.copy_btn = self._btn("copy", " Copier", f"Copier l'image finale ({key_text('Ctrl+C')}), "
                                  "à coller dans Confluence, Word, Teams…", self.copy_image, with_text=True)
        self.copy_btn.setObjectName("accent")
        self.copy_btn.setIcon(Icons.get("copy", 16, "#FFFFFF"))
        h.addWidget(self.copy_btn)
        h.addSpacing(4)
        self.save_btn = self._btn("save", " Enregistrer", f"Enregistrer en PNG ({key_text('Ctrl+S')})",
                                  self.save_dialog, with_text=True)
        h.addWidget(self.save_btn)
        root.addWidget(bar)
        root.addWidget(self.canvas, 1)
        self.setCentralWidget(body)

        sb = self.statusBar()
        sb.setSizeGripEnabled(False)
        self.hint_label = QLabel()
        sb.addWidget(self.hint_label, 1)
        self.version_label = QLabel(f"v{VERSION}")
        self.version_label.setToolTip(version_details())
        sb.addPermanentWidget(self.version_label)
        self.size_label = QLabel()
        sb.addPermanentWidget(self.size_label)
        sb.addPermanentWidget(self._btn("minus", tip="Zoom arrière", slot=lambda: self.canvas.zoom_by(1 / 1.25)))
        self.zoom_label = QLabel("100 %")
        self.zoom_label.setMinimumWidth(48)
        self.zoom_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sb.addPermanentWidget(self.zoom_label)
        sb.addPermanentWidget(self._btn("plus", tip="Zoom avant", slot=lambda: self.canvas.zoom_by(1.25)))
        sb.addPermanentWidget(self._btn("fit", tip=f"Ajuster à la fenêtre ({key_text('Ctrl+0')})",
                                        slot=self.canvas.zoom_fit))

        for seq, slot in (("Ctrl+V", self.paste), ("Ctrl+O", self.open_dialog), ("Ctrl+C", self.copy_image),
                          ("Ctrl+S", self.save_dialog), ("Ctrl+Z", self.undo), ("Ctrl+Y", self.redo),
                          ("Ctrl+Shift+Z", self.redo), ("Ctrl+0", self.canvas.zoom_fit),
                          ("Ctrl+1", self.canvas.zoom_100), ("Ctrl+A", self.select_all),
                          ("Ctrl+N", self.capture)):
            act = QAction(self)
            keys = [QKeySequence(seq)]
            if IS_MAC:
                keys.append(QKeySequence(seq.replace("Ctrl+", "Meta+")))
            act.setShortcuts(keys)
            act.triggered.connect(lambda _c=False, f=slot: self._shortcut(f))
            self.addAction(act)
        self.refresh_style_controls()

    def _shortcut(self, fn):
        """Les raccourcis ne s'appliquent pas pendant la saisie d'un texte (Ctrl+C/V/Z y restent du texte)."""
        focus = self.canvas.scene().focusItem()
        if isinstance(focus, TextItem) and focus.textInteractionFlags() != Qt.TextInteractionFlag.NoTextInteraction:
            return
        fn()

    # ---- outils et styles ----
    def set_tool(self, name):
        focus = self.canvas.scene().focusItem()
        if focus is not None:
            focus.clearFocus()
        self.canvas.tool = name
        for n, b in self.tool_buttons.items():
            b.setChecked(n == name)
        self.canvas.setDragMode(QGraphicsView.DragMode.RubberBandDrag if name == "select"
                                else QGraphicsView.DragMode.NoDrag)
        self.canvas.viewport().setCursor(Qt.CursorShape.ArrowCursor if name == "select"
                                         else Qt.CursorShape.IBeamCursor if name == "text"
                                         else Qt.CursorShape.CrossCursor)
        if name != "select":
            self.canvas.scene().clearSelection()
        hint = next(t[4] for t in TOOLS if t[0] == name)
        self.hint_label.setText(hint)
        self.canvas.setFocus()

    def _apply_to_selection(self):
        changed = False
        for it in self.canvas.scene().selectedItems():
            if hasattr(it, "set_style") and not isinstance(it, (PixelateItem, HighlightItem, RedactItem)):
                it.set_style(self.color, self.width, self.text_size)
                changed = True
        if changed:
            self.commit()

    def set_color(self, color):
        self.color = QColor(color)
        settings().setValue("color", self.color.name())
        for it in self.canvas.scene().selectedItems():
            if isinstance(it, HighlightItem):
                it.set_style(self.color, None, None)
        self.refresh_style_controls()
        self._apply_to_selection()

    def pick_color(self):
        color = QColorDialog.getColor(self.color, self, "Choisir une couleur")
        if color.isValid():
            self.set_color(color)

    def set_width(self, value):
        self.width = value
        settings().setValue("width", value)
        self.refresh_style_controls()
        self._apply_to_selection()

    def set_text_size(self, value):
        self.text_size = value
        settings().setValue("text_size", value)
        self.refresh_style_controls()
        self._apply_to_selection()

    def refresh_style_controls(self):
        for b in self.swatch_buttons:
            b.setChecked(QColor(b.property("color")).name() == self.color.name())
        self.custom_color_btn.setIcon(Icons.swatch(self.color.name()) if not any(
            b.isChecked() for b in self.swatch_buttons) else Icons.get("plus"))
        for v, act in self.width_actions.items():
            act.setChecked(v == self.width)
        for v, act in self.size_actions.items():
            act.setChecked(v == self.text_size)

    def select_all(self):
        for it in self.canvas.annotations():
            it.setSelected(True)

    # ---- historique ----
    def commit(self, initial=False):
        st = self.canvas.state()
        if self.history and st["key"] == self.history[-1]["key"] and st["items"] == self.history[-1]["items"]:
            return
        self.history.append(st)
        del self.history[:-60]
        self.redo_stack.clear()
        if not initial:
            self.dirty = True
        self.update_buttons()

    def undo(self):
        if len(self.history) < 2:
            return
        self.redo_stack.append(self.history.pop())
        self.canvas.restore(self.history[-1])
        self.dirty = True
        self.update_buttons()

    def redo(self):
        if not self.redo_stack:
            return
        st = self.redo_stack.pop()
        self.history.append(st)
        self.canvas.restore(st)
        self.dirty = True
        self.update_buttons()

    def update_buttons(self):
        has = self.canvas.has_image()
        self.undo_btn.setEnabled(len(self.history) > 1)
        self.redo_btn.setEnabled(bool(self.redo_stack))
        self.copy_btn.setEnabled(has)
        self.save_btn.setEnabled(has)
        for b in self.tool_buttons.values():
            b.setEnabled(has)
        self.size_label.setText(f"{self.canvas.image.width()} × {self.canvas.image.height()} px" if has else "")
        self.update_zoom()
        self.update_title()

    def update_zoom(self):
        self.zoom_label.setText(f"{round(self.canvas.zoom_level() * 100)} %")

    def update_title(self):
        name = f" — {self.source_name}" if self.source_name else ""
        self.setWindowTitle(f"{APP_NAME}{name}{' •' if self.dirty else ''}")

    # ---- entrées ----
    def new_image(self, image, name):
        if image.isNull():
            return False
        self.canvas.set_image(image, keep_items=False)
        self.source_name = name
        self.commit()
        self.dirty = False
        self.update_title()
        self.set_tool("select")
        return True

    def paste(self):
        mime = QGuiApplication.clipboard().mimeData()
        if mime is not None and mime.hasImage():
            image = QGuiApplication.clipboard().image()
            if self.new_image(image, "capture collée"):
                return
        if mime is not None and mime.hasUrls():
            for url in mime.urls():
                if url.isLocalFile() and self.open_path(url.toLocalFile()):
                    return
        self.statusBar().showMessage("Le presse-papiers ne contient pas d'image.", 4000)

    def open_dialog(self):
        start = settings().value("last_dir", os.path.expanduser("~"))
        exts = " ".join("*" + e for e in IMAGE_FORMATS)
        path, _ = QFileDialog.getOpenFileName(self, "Ouvrir une image", start, f"Images ({exts})")
        if path:
            self.open_path(path)

    def open_path(self, path):
        image = load_image(path)
        if image.isNull():
            self.warn(f"Impossible d'ouvrir cette image :\n{path}")
            return False
        settings().setValue("last_dir", os.path.dirname(path))
        self.current_path = path
        return self.new_image(image, os.path.basename(path))

    # ---- capture ----
    def _clipboard_signature(self):
        mime = QGuiApplication.clipboard().mimeData()
        if mime is None or not mime.hasImage():
            return None
        image = QGuiApplication.clipboard().image()
        if image.isNull():
            return None
        thumb = image.scaled(16, 16).convertToFormat(QImage.Format.Format_RGB32)
        return (image.width(), image.height(), hashlib.sha1(bytes(thumb.constBits())).hexdigest())

    def capture(self):
        self.armed_sig = self._clipboard_signature()
        self.armed_until = time.monotonic() + 120
        self._capture_timer.start()
        if IS_WIN:
            proc = QProcess(self)
            proc.setProgram(os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "explorer.exe"))
            proc.setArguments(["ms-screenclip:"])
            proc.startDetached()
            self.showMinimized()
            self.statusBar().showMessage("Sélectionne la zone à capturer…", 8000)
        else:
            shortcut = "Cmd+Ctrl+Maj+4" if IS_MAC else "ton outil de capture (vers le presse-papiers)"
            self.statusBar().showMessage(
                f"Fais {shortcut} et sélectionne la zone : elle arrivera ici toute seule.", 15000)
            self.showMinimized()

    def _poll_capture(self):
        if time.monotonic() > self.armed_until:
            self._capture_timer.stop()
            return
        sig = self._clipboard_signature()
        if sig is not None and sig != self.armed_sig:
            self._capture_timer.stop()
            if self.new_image(QGuiApplication.clipboard().image(), "capture"):
                self.showNormal()
                self.raise_()
                self.activateWindow()

    # ---- sorties ----
    def final_image(self):
        return self.canvas.flatten()

    def copy_image(self):
        image = self.final_image()
        if image.isNull():
            return
        QGuiApplication.clipboard().setImage(image)
        self.dirty = False
        self.update_title()
        self.statusBar().showMessage("Image copiée : colle-la dans ton document.", 4000)

    def save_dialog(self):
        image = self.final_image()
        if image.isNull():
            return
        start_dir = settings().value("save_dir", os.path.expanduser("~/Desktop"))
        name = time.strftime("capture-%Y%m%d-%H%M%S.png")
        path, _chosen = QFileDialog.getSaveFileName(self, "Enregistrer l'image", os.path.join(start_dir, name),
                                                    "Image PNG (*.png)")
        if not path:
            return
        final = path if path.lower().endswith(".png") else os.path.splitext(path)[0] + ".png"
        if final != path and os.path.exists(final):
            box = QMessageBox(QMessageBox.Icon.Question, APP_NAME,
                              f"« {os.path.basename(final)} » existe déjà.\n\nLe remplacer ?",
                              QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, self)
            box.setTextFormat(Qt.TextFormat.PlainText)
            box.setDefaultButton(QMessageBox.StandardButton.No)
            if box.exec() != QMessageBox.StandardButton.Yes:
                return
        if self.save_to(final, image):
            settings().setValue("save_dir", os.path.dirname(path))
            self.source_name = os.path.basename(path)
            self.dirty = False
            self.update_title()
            self.statusBar().showMessage(f"Enregistré : {path}", 5000)

    def save_to(self, path, image):  # noqa: D401
        # PNG uniquement : format intégré à Qt (aucun module à charger) et net pour les captures,
        # là où le JPEG floute le texte et les traits.
        if os.path.splitext(path)[1].lower() != ".png":
            path = os.path.splitext(path)[0] + ".png"
        ok = image.save(path, "PNG")
        if not ok:
            self.warn(f"Impossible d'enregistrer :\n{path}")
        return ok

    def warn(self, text):
        box = QMessageBox(QMessageBox.Icon.Warning, APP_NAME, text, QMessageBox.StandardButton.Ok, self)
        box.setTextFormat(Qt.TextFormat.PlainText)
        box.exec()

    def closeEvent(self, event):
        if self.dirty and self.canvas.has_image():
            box = QMessageBox(QMessageBox.Icon.Question, APP_NAME,
                              "L'image modifiée n'a été ni copiée ni enregistrée.\n\nQuitter quand même ?",
                              QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, self)
            box.setTextFormat(Qt.TextFormat.PlainText)
            box.setDefaultButton(QMessageBox.StandardButton.No)
            if box.exec() != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
        settings().setValue("geometry", self.saveGeometry())
        super().closeEvent(event)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.update_zoom()


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
        print(f"{APP_NAME} {VERSION} du {VERSION_DATE} — {etat}")
        return 0
    verifier_pyside()
    args = [a for a in sys.argv[1:] if not a.startswith("-psn")]
    app = QApplication([sys.argv[0]])
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(VERSION)
    app.setOrganizationName(ORG_NAME)
    apply_theme(app)
    app.setWindowIcon(Icons.get("app", 64))
    win = MainWindow(args[0] if args else None)
    win.show()
    QTimer.singleShot(500, avertir_si_abime)
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
