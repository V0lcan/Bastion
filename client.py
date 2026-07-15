#!/usr/bin/env python3
"""Bastion Client - PyQt6 GUI with end-to-end encryption and file/image sharing"""

import sys
import json
import asyncio
import base64
import datetime
import os
import mimetypes
import re
import html
import zlib

_missing = []
try:
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QDialog, QSplitter,
        QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit,
        QListWidget, QListWidgetItem, QFrame, QFormLayout,
        QMessageBox, QScrollArea, QFileDialog, QCheckBox, QPlainTextEdit,
    )
    from PyQt6.QtCore import (
        Qt, QThread, QObject, pyqtSignal, pyqtSlot,
        QTimer, QBuffer, QSize,
    )
    from PyQt6.QtGui import QFont, QColor, QPixmap, QMovie, QTextCursor
except ImportError:
    _missing.append("PyQt6")

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:
    _missing.append("cryptography")

try:
    import websockets
    try:  # websockets >= 13: new asyncio implementation (legacy one is deprecated)
        from websockets.asyncio.client import connect as ws_connect
    except ImportError:
        ws_connect = websockets.connect
except ImportError:
    _missing.append("websockets")

if _missing:
    print(f"Missing packages: {', '.join(_missing)}")
    print(f"Install with: pip install {' '.join(_missing)}")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_MAX_FILE_BYTES = 8 * 1024 * 1024   # fallback until server sends its limit
MAX_DISPLAY_PX = 480                # max inline image width
IMAGE_MIME = frozenset({
    "image/jpeg", "image/png", "image/gif",
    "image/webp", "image/bmp", "image/tiff",
})

# File types that get an inline text preview
TEXT_MIME_EXTRA = frozenset({
    "application/json", "application/xml", "application/javascript",
    "application/x-sh", "application/x-yaml", "application/x-python",
})
TEXT_EXTS = frozenset({
    ".txt", ".md", ".markdown", ".py", ".js", ".ts", ".json", ".xml", ".yaml",
    ".yml", ".csv", ".tsv", ".log", ".ini", ".cfg", ".conf", ".toml", ".html",
    ".htm", ".css", ".c", ".cpp", ".cc", ".h", ".hpp", ".java", ".rs", ".go",
    ".rb", ".sh", ".bat", ".ps1", ".sql", ".r", ".php", ".pl", ".lua", ".kt",
})
TEXT_PREVIEW_MAX_LINES = 200
TEXT_PREVIEW_MAX_CHARS = 8000


def is_text_file(mimetype: str, filename: str) -> bool:
    if mimetype.startswith("text/") or mimetype in TEXT_MIME_EXTRA:
        return True
    return os.path.splitext(filename)[1].lower() in TEXT_EXTS

# ── Palette ────────────────────────────────────────────────────────────────
BG        = "#141519"   # app background
PANEL     = "#1b1d22"   # sidebar / dialogs / input bar
ELEV      = "#23262d"   # inputs, cards
BORDER    = "#2c2f37"
TEXT      = "#e4e6ea"
MUTED     = "#8d919b"
ACCENT    = "#6366f1"
ACCENT_H  = "#787af4"
GREEN     = "#4ade80"
RED       = "#f87171"
AMBER     = "#fbbf24"
SELF_NAME  = "#f0b27a"
OTHER_NAME = "#7dc4ff"
SYSTEM     = "#7fb069"

AVATAR_COLORS = [
    "#5865f2", "#3ba55c", "#faa61a", "#ed4245",
    "#eb459e", "#00b0f4", "#9b59b6", "#e67e22",
]


def avatar_color(username: str) -> str:
    return AVATAR_COLORS[zlib.crc32(username.encode()) % len(AVATAR_COLORS)]


def format_timestamp(ts: str | None) -> str:
    """Convert an ISO-8601 UTC timestamp to local HH:MM; pass through old formats."""
    if not ts:
        return ""
    try:
        dt = datetime.datetime.fromisoformat(ts)
        if dt.tzinfo is not None:
            dt = dt.astimezone()
        return dt.strftime("%H:%M")
    except ValueError:
        return ts

# ---------------------------------------------------------------------------
# Discord-style markdown → HTML
# ---------------------------------------------------------------------------

def _md_apply_spans(t: str) -> str:
    """Apply inline styles to a single already-HTML-escaped line."""
    t = re.sub(r'\*\*\*(.+?)\*\*\*',       r'<b><i>\1</i></b>', t)   # ***bold italic***
    t = re.sub(r'\*\*(.+?)\*\*',            r'<b>\1</b>',        t)   # **bold**
    t = re.sub(r'\*(.+?)\*',                r'<i>\1</i>',         t)   # *italic*
    t = re.sub(r'__(.+?)__',                r'<u>\1</u>',         t)   # __underline__
    t = re.sub(r'(?<!\w)_(.+?)_(?!\w)',     r'<i>\1</i>',         t)   # _italic_
    t = re.sub(r'~~(.+?)~~',                r'<s>\1</s>',         t)   # ~~strikethrough~~
    t = re.sub(                                                           # ||spoiler||
        r'\|\|(.+?)\|\|',
        r'<span style="background:#555555;color:#555555;border-radius:2px;">\1</span>',
        t,
    )
    return t


def _md_inline(text: str) -> str:
    """Handle inline code spans, blockquotes (per-line), then inline styles."""
    # Extract inline code so its contents are never reformatted
    tokens: list[tuple[str, str]] = []
    last = 0
    for m in re.finditer(r'`([^`\n]+)`', text):
        if m.start() > last:
            tokens.append(("text", text[last:m.start()]))
        tokens.append(("code", m.group(1)))
        last = m.end()
    if last < len(text):
        tokens.append(("text", text[last:]))

    out: list[str] = []
    for kind, content in tokens:
        if kind == "code":
            e = html.escape(content)
            out.append(
                f'<code style="background:#2a2a2a;padding:1px 5px;'
                f'border-radius:3px;font-family:Consolas,monospace;">{e}</code>'
            )
        else:
            lines = content.split("\n")
            rendered: list[str] = []
            for line in lines:
                if line.startswith("> "):
                    inner = _md_apply_spans(html.escape(line[2:]))
                    rendered.append(
                        f'<span style="border-left:3px solid #555555;'
                        f'padding-left:8px;color:#aaaaaa;">{inner}</span>'
                    )
                else:
                    rendered.append(_md_apply_spans(html.escape(line)))
            out.append("<br>".join(rendered))
    return "".join(out)


def markdown_to_html(text: str) -> str:
    """Convert Discord-style markdown to Qt-compatible HTML."""
    # Split on fenced code blocks first — their contents are left untouched
    segments: list[tuple[str, str]] = []
    last = 0
    for m in re.finditer(r'```(?:\w*\n?)?([\s\S]*?)```', text):
        if m.start() > last:
            segments.append(("text", text[last:m.start()]))
        segments.append(("codeblock", m.group(1).strip()))
        last = m.end()
    if last < len(text):
        segments.append(("text", text[last:]))

    out: list[str] = []
    for kind, content in segments:
        if kind == "codeblock":
            e = html.escape(content)
            out.append(
                f'<pre style="background:#2a2a2a;padding:5px 10px;border-radius:4px;'
                f'font-family:Consolas,monospace;color:#d4d4d4;margin:3px 0;'
                f'white-space:pre-wrap;">{e}</pre>'
            )
        else:
            out.append(_md_inline(content))
    return "".join(out)


# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------

_KDF_SALT = b"chat_platform_v2"
# NOTE: all clients on a server must use the same salt + iteration count,
# otherwise they derive different keys and see "[unable to decrypt]".
_KDF_ITERATIONS = 600_000


def derive_key(server_password: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_KDF_SALT,
        iterations=_KDF_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(server_password.encode()))


# ---------------------------------------------------------------------------
# Stylesheet
# ---------------------------------------------------------------------------

DARK_STYLE = f"""
QWidget {{
    background-color: {BG};
    color: {TEXT};
    font-family: "Segoe UI";
    font-size: 10pt;
}}
QDialog            {{ background-color: {PANEL}; }}
QMainWindow        {{ background-color: {BG}; }}
QScrollArea        {{ border: none; background-color: {BG}; }}
QSplitter::handle  {{ background-color: {BORDER}; width: 1px; height: 1px; }}
QToolTip {{
    background-color: {ELEV}; color: {TEXT};
    border: 1px solid {BORDER}; padding: 4px 8px;
}}

QListWidget {{
    background-color: {PANEL};
    border: none;
    outline: none;
    color: {TEXT};
}}
QListWidget::item                    {{ padding: 6px 10px; border-radius: 6px; margin: 1px 6px; }}
QListWidget::item:selected           {{ background-color: {ACCENT}; color: #ffffff; }}
QListWidget::item:hover:!selected    {{ background-color: {ELEV}; }}

QLineEdit, QPlainTextEdit {{
    background-color: {ELEV};
    border: 1px solid {BORDER};
    border-radius: 8px;
    color: {TEXT};
    padding: 7px 12px;
    selection-background-color: {ACCENT};
}}
QLineEdit:focus, QPlainTextEdit:focus {{ border-color: {ACCENT}; }}

QCheckBox          {{ color: {MUTED}; spacing: 8px; }}
QCheckBox::indicator {{
    width: 16px; height: 16px;
    border: 1px solid {BORDER}; border-radius: 4px;
    background-color: {ELEV};
}}
QCheckBox::indicator:checked {{ background-color: {ACCENT}; border-color: {ACCENT}; }}

QPushButton {{
    background-color: {ACCENT};
    color: #ffffff;
    border: none;
    border-radius: 8px;
    padding: 7px 16px;
    font-weight: 600;
}}
QPushButton:hover   {{ background-color: {ACCENT_H}; }}
QPushButton:pressed {{ background-color: #4f52c9; }}
QPushButton[secondary="true"]        {{ background-color: {ELEV}; color: {TEXT}; font-weight: 400; }}
QPushButton[secondary="true"]:hover  {{ background-color: {BORDER}; }}

QScrollBar:vertical               {{ background: transparent; width: 8px; border: none; }}
QScrollBar::handle:vertical       {{ background: {BORDER}; border-radius: 4px; min-height: 20px; }}
QScrollBar::handle:vertical:hover {{ background: #3d414b; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar:horizontal             {{ background: transparent; height: 8px; border: none; }}
QScrollBar::handle:horizontal     {{ background: {BORDER}; border-radius: 4px; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}

QFormLayout QLabel {{ color: {MUTED}; }}
"""


# ---------------------------------------------------------------------------
# Full-size image viewer dialog
# ---------------------------------------------------------------------------

class ImageViewer(QDialog):
    def __init__(self, pixmap: QPixmap, filename: str, raw: bytes, parent=None):
        super().__init__(parent)
        self.setWindowTitle(filename)
        self.resize(min(pixmap.width() + 40, 1200), min(pixmap.height() + 80, 860))

        lay = QVBoxLayout(self)
        lay.setContentsMargins(8, 8, 8, 8)
        lay.setSpacing(8)

        scroll = QScrollArea()
        scroll.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl = QLabel()
        lbl.setPixmap(pixmap)
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        scroll.setWidget(lbl)
        lay.addWidget(scroll, 1)

        btns = QHBoxLayout()
        btns.addStretch()
        save_btn = QPushButton("Save Image")
        save_btn.clicked.connect(lambda: self._save(raw, filename))
        close_btn = QPushButton("Close")
        close_btn.setProperty("secondary", True)
        close_btn.setStyle(close_btn.style())
        close_btn.clicked.connect(self.accept)
        btns.addWidget(save_btn)
        btns.addSpacing(6)
        btns.addWidget(close_btn)
        lay.addLayout(btns)

    @staticmethod
    def _save(data: bytes, filename: str):
        path, _ = QFileDialog.getSaveFileName(None, "Save Image", filename)
        if path:
            with open(path, "wb") as f:
                f.write(data)


# ---------------------------------------------------------------------------
# Inline content widgets
# ---------------------------------------------------------------------------

class ClickablePixmapLabel(QLabel):
    """Static image shown at MAX_DISPLAY_PX wide; click opens full-size viewer."""

    def __init__(self, full: QPixmap, filename: str, raw: bytes):
        super().__init__()
        self._full = full
        self._filename = filename
        self._raw = raw
        display = (
            full.scaledToWidth(MAX_DISPLAY_PX, Qt.TransformationMode.SmoothTransformation)
            if full.width() > MAX_DISPLAY_PX else full
        )
        self.setPixmap(display)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setToolTip(f"{filename}  —  click to view full size")
        self.setStyleSheet("margin-top: 4px;")

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            ImageViewer(self._full, self._filename, self._raw, self.window()).exec()
        super().mousePressEvent(event)


class AnimatedGifLabel(QLabel):
    """Plays an animated GIF inline. Click to save."""

    def __init__(self, data: bytes, filename: str):
        super().__init__()
        self._data = data
        self._filename = filename
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setToolTip(f"{filename}  —  click to save")
        self.setStyleSheet("margin-top: 4px;")

        self._buf = QBuffer()
        self._buf.setData(data)
        self._buf.open(QBuffer.OpenModeFlag.ReadOnly)

        self._movie = QMovie()
        self._movie.setDevice(self._buf)
        self._movie.setCacheMode(QMovie.CacheMode.CacheAll)

        # Scale oversized GIFs before starting playback
        self._movie.jumpToFrame(0)
        nat = self._movie.currentImage().size()
        if nat.width() > MAX_DISPLAY_PX:
            ratio = MAX_DISPLAY_PX / nat.width()
            self._movie.setScaledSize(QSize(MAX_DISPLAY_PX, int(nat.height() * ratio)))

        self.setMovie(self._movie)
        self._movie.start()

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            path, _ = QFileDialog.getSaveFileName(self.window(), "Save GIF", self._filename)
            if path:
                with open(path, "wb") as f:
                    f.write(self._data)
        super().mousePressEvent(event)


class FileAttachmentWidget(QFrame):
    """Non-image file: icon, name, size, and a Save button."""

    _ICONS: dict[str, str] = {
        "application/pdf":            "📕",
        "application/zip":            "🗜",
        "application/x-zip-compressed": "🗜",
        "application/x-tar":          "🗜",
        "application/x-7z-compressed": "🗜",
        "audio":                      "🎵",
        "video":                      "🎬",
        "text":                       "📄",
        "application":                "⚙",
    }

    def __init__(self, data: bytes, filename: str, mimetype: str):
        super().__init__()
        self._data = data
        self._filename = filename
        self.setStyleSheet(
            f"QFrame {{ background-color: {ELEV}; border: 1px solid {BORDER};"
            " border-radius: 8px; } QLabel { border: none; background: transparent; }"
        )
        self.setFixedHeight(62)
        self.setMaximumWidth(400)

        row = QHBoxLayout(self)
        row.setContentsMargins(12, 0, 12, 0)
        row.setSpacing(10)

        icon_lbl = QLabel(self._pick_icon(mimetype))
        icon_lbl.setStyleSheet("font-size: 24pt; border: none; background: transparent;")
        icon_lbl.setFixedWidth(36)
        row.addWidget(icon_lbl)

        info = QVBoxLayout()
        info.setSpacing(1)
        name_lbl = QLabel(filename)
        name_lbl.setStyleSheet(f"color: {TEXT}; font-weight: bold;")
        size_lbl = QLabel(self._fmt(len(data)))
        size_lbl.setStyleSheet(f"color: {MUTED}; font-size: 8pt;")
        info.addWidget(name_lbl)
        info.addWidget(size_lbl)
        row.addLayout(info, 1)

        save = QPushButton("Save")
        save.setFixedWidth(62)
        save.clicked.connect(self._save)
        row.addWidget(save)

    @classmethod
    def _pick_icon(cls, mime: str) -> str:
        return cls._ICONS.get(mime) or cls._ICONS.get(mime.split("/")[0], "📁")

    @staticmethod
    def _fmt(n: int) -> str:
        if n < 1024:
            return f"{n} B"
        n /= 1024
        if n < 1024:
            return f"{n:.1f} KB"
        n /= 1024
        if n < 1024:
            return f"{n:.1f} MB"
        return f"{n / 1024:.1f} GB"

    def _save(self):
        path, _ = QFileDialog.getSaveFileName(self.window(), "Save File", self._filename)
        if path:
            with open(path, "wb") as f:
                f.write(self._data)


class TextPreviewWidget(QFrame):
    """Non-image text file: filename header + inline scrollable preview + Save."""

    def __init__(self, data: bytes, filename: str):
        super().__init__()
        self._data = data
        self._filename = filename
        self.setStyleSheet(
            f"QFrame {{ background-color: {ELEV}; border: 1px solid {BORDER};"
            " border-radius: 8px; }"
        )
        self.setMaximumWidth(560)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(10, 8, 10, 10)
        lay.setSpacing(6)

        header = QHBoxLayout()
        header.setSpacing(8)
        icon = QLabel("📄")
        icon.setStyleSheet("border: none; background: transparent; font-size: 13pt;")
        name = QLabel(filename)
        name.setStyleSheet(f"color: {TEXT}; font-weight: bold; border: none; background: transparent;")
        size = QLabel(FileAttachmentWidget._fmt(len(data)))
        size.setStyleSheet(f"color: {MUTED}; font-size: 8pt; border: none; background: transparent;")
        save = QPushButton("Save")
        save.setFixedWidth(58)
        save.clicked.connect(self._save)
        header.addWidget(icon)
        header.addWidget(name)
        header.addWidget(size)
        header.addStretch()
        header.addWidget(save)
        lay.addLayout(header)

        text = data.decode("utf-8", errors="replace")
        truncated = False
        lines = text.splitlines()
        if len(lines) > TEXT_PREVIEW_MAX_LINES:
            lines = lines[:TEXT_PREVIEW_MAX_LINES]
            truncated = True
        preview = "\n".join(lines)
        if len(preview) > TEXT_PREVIEW_MAX_CHARS:
            preview = preview[:TEXT_PREVIEW_MAX_CHARS]
            truncated = True

        box = QPlainTextEdit()
        box.setReadOnly(True)
        box.setPlainText(preview)
        box.setFont(QFont("Consolas", 9))
        box.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        box.setStyleSheet(
            f"QPlainTextEdit {{ background-color: {BG}; border: 1px solid {BORDER};"
            f" border-radius: 6px; color: #cfd3da; padding: 6px; }}"
        )
        box.setMaximumHeight(220)
        lay.addWidget(box)

        if truncated:
            note = QLabel("… preview truncated — click Save for the full file")
            note.setStyleSheet(f"color: {MUTED}; font-size: 8pt; border: none; background: transparent;")
            lay.addWidget(note)

    def _save(self):
        path, _ = QFileDialog.getSaveFileName(self.window(), "Save File", self._filename)
        if path:
            with open(path, "wb") as f:
                f.write(self._data)


def make_role_chip(name: str, color: str) -> QLabel:
    """Small rounded colored badge for a role. Fixed height so it never
    stretches to fill a taller layout row; add it with AlignVCenter.
    A subtle light border keeps it visible even over a similarly-colored
    background (e.g. a list row's selection highlight)."""
    chip = QLabel(name)
    chip.setFixedHeight(18)
    chip.setStyleSheet(
        f"background-color: {color}; color: #ffffff; border-radius: 9px;"
        " border: 1px solid rgba(255,255,255,60);"
        " padding: 0px 8px; font-size: 8pt; font-weight: bold;"
    )
    return chip


# ---------------------------------------------------------------------------
# Message row widget
# ---------------------------------------------------------------------------

class MessageWidget(QFrame):
    """Discord-style message row: a top-aligned avatar on the left, then a
    header line (name · role chip · timestamp) with the message body tight
    underneath it."""

    def __init__(self, username: str | None, timestamp: str | None,
                 is_self: bool = False, dim: bool = False,
                 role: tuple[str, str] | None = None):
        super().__init__()
        self.setObjectName("msg")
        self.setStyleSheet(
            "QFrame#msg { border: none; background: transparent; }"
            f"QFrame#msg:hover {{ background-color: {PANEL}; }}"
        )
        outer = QHBoxLayout(self)
        outer.setContentsMargins(16, 3, 16, 3)
        outer.setSpacing(14)

        self._dim = dim          # True for replayed history messages
        self._text_color = MUTED if dim else "#dbdee1"

        if username:
            avatar = QLabel(username[:1].upper())
            avatar.setFixedSize(40, 40)
            avatar.setAlignment(Qt.AlignmentFlag.AlignCenter)
            bg = "#3a3d45" if dim else avatar_color(username)
            avatar.setStyleSheet(
                f"background-color: {bg}; color: #ffffff; border-radius: 20px;"
                " font-weight: bold; font-size: 15pt;"
            )
            outer.addWidget(avatar, 0, Qt.AlignmentFlag.AlignTop)

        self._lay = QVBoxLayout()
        self._lay.setContentsMargins(0, 0, 0, 0)
        self._lay.setSpacing(2)
        outer.addLayout(self._lay, 1)

        if username:
            hrow = QHBoxLayout()
            hrow.setContentsMargins(0, 0, 0, 0)
            hrow.setSpacing(8)
            # Light, bold names like Discord; the coloured avatar and the role
            # chip provide the per-user / per-role differentiation.
            name_color = "#7a7d84" if dim else "#f2f3f5"
            name = QLabel(username)
            name.setStyleSheet(
                f"color: {name_color}; font-weight: 600; font-size: 10pt;"
                " background: transparent;"
            )
            hrow.addWidget(name, 0, Qt.AlignmentFlag.AlignVCenter)
            if role and not dim:
                hrow.addWidget(make_role_chip(role[0], role[1]), 0, Qt.AlignmentFlag.AlignVCenter)
            if timestamp:
                ts = QLabel(format_timestamp(timestamp))
                ts.setStyleSheet(f"color: {MUTED}; font-size: 8pt; background: transparent;")
                hrow.addWidget(ts, 0, Qt.AlignmentFlag.AlignVCenter)
            hrow.addStretch()
            self._lay.addLayout(hrow)

    def add_text(self, text: str) -> "MessageWidget":
        lbl = QLabel()
        lbl.setWordWrap(True)
        lbl.setTextFormat(Qt.TextFormat.RichText)
        lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        lbl.setOpenExternalLinks(False)
        lbl.setStyleSheet(
            f"color: {self._text_color}; background: transparent; line-height: 140%;"
        )
        lbl.setText(markdown_to_html(text))
        self._lay.addWidget(lbl)
        return self

    def add_image(self, data: bytes, filename: str, mimetype: str) -> "MessageWidget":
        if mimetype == "image/gif":
            widget: QWidget = AnimatedGifLabel(data, filename)
        else:
            px = QPixmap()
            if px.loadFromData(data):
                widget = ClickablePixmapLabel(px, filename, data)
            else:
                widget = QLabel(f"[Could not display: {filename}]")
                widget.setStyleSheet("color: #888; background: transparent;")
        self._lay.addWidget(widget)
        return self

    def add_text_preview(self, data: bytes, filename: str) -> "MessageWidget":
        self._lay.addWidget(TextPreviewWidget(data, filename))
        return self

    def add_file(self, data: bytes, filename: str, mimetype: str) -> "MessageWidget":
        self._lay.addWidget(FileAttachmentWidget(data, filename, mimetype))
        return self


# ---------------------------------------------------------------------------
# Scrollable chat area
# ---------------------------------------------------------------------------

class ChatArea(QScrollArea):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWidgetResizable(True)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setFrameShape(QFrame.Shape.NoFrame)

        self._content = QWidget()
        self._content.setStyleSheet(f"background-color: {BG};")
        self._vbox = QVBoxLayout(self._content)
        self._vbox.setAlignment(Qt.AlignmentFlag.AlignTop)
        self._vbox.setSpacing(1)
        self._vbox.setContentsMargins(0, 8, 4, 8)
        self.setWidget(self._content)

    def add_message(self, widget: QWidget):
        at_bottom = self._at_bottom()
        self._vbox.addWidget(widget)
        if at_bottom:
            QTimer.singleShot(0, self._to_bottom)

    def add_system(self, text: str, color: str = SYSTEM):
        at_bottom = self._at_bottom()
        lbl = QLabel(f"  ✦  {text}")
        lbl.setStyleSheet(
            f"color: {color}; font-style: italic; padding: 2px 12px;"
            " background: transparent;"
        )
        lbl.setWordWrap(True)
        self._vbox.addWidget(lbl)
        if at_bottom:
            QTimer.singleShot(0, self._to_bottom)

    def clear_all(self):
        while self._vbox.count():
            item = self._vbox.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

    def _at_bottom(self) -> bool:
        vsb = self.verticalScrollBar()
        # Treat as "at bottom" when within 40 px — handles sub-pixel rounding
        # and the moment just before the layout updates after a new widget is added.
        return vsb.value() >= vsb.maximum() - 40

    def _to_bottom(self):
        self.verticalScrollBar().setValue(self.verticalScrollBar().maximum())


# ---------------------------------------------------------------------------
# Message input (multiline: Enter sends, Shift+Enter inserts a newline)
# ---------------------------------------------------------------------------

class MessageInput(QPlainTextEdit):
    send_requested = pyqtSignal()
    history_prev = pyqtSignal()
    history_next = pyqtSignal()

    _MAX_LINES = 6

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setPlaceholderText("Type a message…   (Shift+Enter for a new line)")
        self.setTabChangesFocus(True)
        # QPlainTextEdit's document margin makes the content report as a
        # hair taller than the viewport even for a single empty line, which
        # trips ScrollBarAsNeeded and draws a scrollbar squeezed into the box
        # (looks like a stray pill). The box already grows up to _MAX_LINES,
        # and wheel/keyboard scrolling still works with the bar hidden.
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.textChanged.connect(self._adjust_height)
        self._adjust_height()

    def text(self) -> str:
        return self.toPlainText()

    def setText(self, text: str):
        self.setPlainText(text)
        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.setTextCursor(cursor)

    def keyPressEvent(self, event):
        key = event.key()
        if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            if event.modifiers() & Qt.KeyboardModifier.ShiftModifier:
                super().keyPressEvent(event)
            else:
                self.send_requested.emit()
            return
        cursor = self.textCursor()
        if key == Qt.Key.Key_Up and cursor.blockNumber() == 0:
            self.history_prev.emit()
            return
        if (key == Qt.Key.Key_Down
                and cursor.blockNumber() == self.document().blockCount() - 1):
            self.history_next.emit()
            return
        super().keyPressEvent(event)

    def _adjust_height(self):
        # document().size().height() is the line count (incl. wrapped lines)
        lines = max(1, min(int(self.document().size().height()), self._MAX_LINES))
        self.setFixedHeight(lines * self.fontMetrics().lineSpacing() + 18)


# ---------------------------------------------------------------------------
# Connect dialog
# ---------------------------------------------------------------------------

class ConnectDialog(QDialog):
    def __init__(self, parent=None, prefill: dict | None = None):
        super().__init__(parent)
        self.setWindowTitle("Connect to Bastion")
        self.setFixedWidth(400)
        self.result_data: dict | None = None

        lay = QVBoxLayout(self)
        lay.setSpacing(12)
        lay.setContentsMargins(28, 24, 28, 22)

        title = QLabel("Bastion")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("font-size: 16pt; font-weight: bold;")
        lay.addWidget(title)

        subtitle = QLabel("Self-hosted encrypted chat")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet(f"color: {MUTED}; padding-bottom: 8px;")
        lay.addWidget(subtitle)

        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        form.setSpacing(10)
        form.setHorizontalSpacing(14)

        self._fields: dict[str, QLineEdit] = {}
        pf = prefill or {}
        for key, label, default, secret in [
            ("host",            "Server IP",       "localhost", False),
            ("port",            "Port",            "8765",      False),
            ("server_password", "Server Password", "",          True),
            ("username",        "Username",        "",          False),
            ("password",        "Your Password",   "",          True),
            ("enc_passphrase",  "Encryption Key",  "",          True),
        ]:
            edit = QLineEdit(pf.get(key, default))
            if secret:
                edit.setEchoMode(QLineEdit.EchoMode.Password)
            form.addRow(f"{label}:", edit)
            self._fields[key] = edit

        self._fields["enc_passphrase"].setPlaceholderText("optional")
        self._fields["enc_passphrase"].setToolTip(
            "Optional shared passphrase for message encryption.\n"
            "When set (same on every client), the server operator cannot\n"
            "derive the message key. Leave empty to use the server password."
        )

        lay.addLayout(form)

        self.tls_check = QCheckBox("Use TLS (wss://)")
        self.tls_check.setToolTip("Requires the server to run with --certfile/--keyfile")
        self.tls_check.setChecked(bool(pf.get("use_tls")))
        lay.addWidget(self.tls_check)
        lay.addSpacing(6)

        btns = QHBoxLayout()
        btns.addStretch()
        cancel = QPushButton("Cancel")
        cancel.setProperty("secondary", True)
        cancel.setStyle(cancel.style())
        cancel.clicked.connect(self.reject)
        connect = QPushButton("Connect")
        connect.setDefault(True)
        connect.clicked.connect(self._on_accept)
        btns.addWidget(cancel)
        btns.addSpacing(8)
        btns.addWidget(connect)
        lay.addLayout(btns)

        self._fields["host"].setFocus()

    def _on_accept(self):
        data = {k: e.text().strip() for k, e in self._fields.items()}
        required = {k: v for k, v in data.items() if k != "enc_passphrase"}
        if not all(required.values()):
            QMessageBox.warning(self, "Missing Fields",
                                "All fields except Encryption Key are required.")
            return
        try:
            int(data["port"])
        except ValueError:
            QMessageBox.warning(self, "Invalid Port", "Port must be a number.")
            return
        data["use_tls"] = self.tls_check.isChecked()
        self.result_data = data
        self.accept()


# ---------------------------------------------------------------------------
# WebSocket worker (background QThread)
# ---------------------------------------------------------------------------

class WebSocketWorker(QObject):
    message_received = pyqtSignal(dict)

    def __init__(self, params: dict):
        super().__init__()
        self.params = params
        self._loop: asyncio.AbstractEventLoop | None = None
        self.ws = None

    @pyqtSlot()
    def run(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._main())
        except Exception as e:
            self.message_received.emit({"type": "_connect_error", "message": str(e)})
        finally:
            self._loop.close()
            self._loop = None

    async def _main(self):
        # wss:// makes websockets use a default SSL context that verifies
        # the server certificate and hostname.
        scheme = "wss" if self.params.get("use_tls") else "ws"
        uri = f"{scheme}://{self.params['host']}:{self.params['port']}"
        try:
            async with ws_connect(uri, max_size=20 * 1024 * 1024) as ws:
                self.ws = ws
                await ws.send(json.dumps({
                    "type":            "auth",
                    "server_password": self.params["server_password"],
                    "username":        self.params["username"],
                    "password":        self.params["password"],
                }))
                async for raw in ws:
                    self.message_received.emit(json.loads(raw))
        except Exception as e:
            self.message_received.emit({"type": "_connection_lost", "message": str(e)})
        finally:
            self.ws = None

    def send_msg(self, msg: dict):
        if self.ws and self._loop:
            asyncio.run_coroutine_threadsafe(self.ws.send(json.dumps(msg)), self._loop)

    def close(self):
        if self.ws and self._loop:
            asyncio.run_coroutine_threadsafe(self.ws.close(), self._loop)


# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------

class ChatWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Bastion")
        self.resize(1040, 700)
        self.setMinimumSize(720, 480)

        self.worker: WebSocketWorker | None = None
        self.thread: QThread | None = None
        self.fernet: Fernet | None = None
        self.username = ""
        self.connect_params: dict = {}
        self.current_room: str | None = None
        self.rooms: list[str] = []
        self.room_users: dict[str, list[str]] = {}
        self.role_colors: dict[str, str] = {}      # role name -> hex color
        self.user_roles: dict[str, list[str]] = {} # username -> [role names]
        self.my_roles: list[str] = []
        self.is_admin = False
        self.max_file_bytes: int = _DEFAULT_MAX_FILE_BYTES
        self._custom_key = False
        self._history: list[str] = []
        self._history_idx = -1

        self._build_ui()
        QTimer.singleShot(120, self._show_connect_dialog)

    # -----------------------------------------------------------------------
    # UI construction
    # -----------------------------------------------------------------------

    def _build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        vbox = QVBoxLayout(root)
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.setSpacing(0)

        # ── Top bar ──────────────────────────────────────────────────────
        topbar = QWidget()
        topbar.setFixedHeight(46)
        topbar.setStyleSheet(f"background:{PANEL}; border-bottom:1px solid {BORDER};")
        tb = QHBoxLayout(topbar)
        tb.setContentsMargins(14, 0, 14, 0)

        app_title = QLabel("Bastion")
        app_title.setStyleSheet(
            "font-size:12pt; font-weight:bold; background:transparent; padding-right:14px;"
        )
        tb.addWidget(app_title)

        self.status_label = QLabel()
        self.status_label.setTextFormat(Qt.TextFormat.RichText)
        self.status_label.setStyleSheet("font-size:9pt; background:transparent;")
        self._set_status("Not connected", MUTED)
        tb.addWidget(self.status_label)
        tb.addStretch()

        self.lock_label = QLabel("🔒 Encrypted")
        self.lock_label.setStyleSheet(f"color:{GREEN}; font-size:9pt; background:transparent;")
        self.lock_label.hide()
        tb.addWidget(self.lock_label)
        tb.addSpacing(20)

        for text, slot, secondary in [
            ("Disconnect", self._disconnect, True),
            ("Connect",    self._show_connect_dialog, False),
        ]:
            btn = QPushButton(text)
            if secondary:
                btn.setProperty("secondary", True)
                btn.setStyle(btn.style())
            btn.clicked.connect(slot)
            tb.addWidget(btn)
            tb.addSpacing(6)

        vbox.addWidget(topbar)

        # ── Splitter ─────────────────────────────────────────────────────
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setHandleWidth(1)
        vbox.addWidget(splitter)

        # ── Sidebar ───────────────────────────────────────────────────────
        sidebar = QWidget()
        sidebar.setFixedWidth(210)
        sidebar.setStyleSheet(f"background:{PANEL};")
        sb = QVBoxLayout(sidebar)
        sb.setContentsMargins(0, 0, 0, 0)
        sb.setSpacing(0)

        for caption, attr, weight in [("ROOMS", "room_list", 2), ("USERS", "user_list", 1)]:
            hdr = QLabel(caption)
            hdr.setStyleSheet(
                f"color:{MUTED}; font-size:8pt; font-weight:bold;"
                " letter-spacing:1px; padding:12px 12px 4px 12px; background:transparent;"
            )
            sb.addWidget(hdr)
            lw = QListWidget()
            lw.setFrameShape(QFrame.Shape.NoFrame)
            lw.setFont(QFont("Segoe UI", 10))
            sb.addWidget(lw, weight)
            setattr(self, attr, lw)

        self.room_list.currentRowChanged.connect(self._on_room_changed)
        # User rows use custom widgets (name + role chips); drop item padding
        # so the widget gets the full row height and isn't clipped.
        self.user_list.setStyleSheet("QListWidget::item { padding: 0px; }")
        splitter.addWidget(sidebar)

        # ── Chat panel ────────────────────────────────────────────────────
        cp = QWidget()
        cp_lay = QVBoxLayout(cp)
        cp_lay.setContentsMargins(0, 0, 0, 0)
        cp_lay.setSpacing(0)

        self.room_title = QLabel("Select a room")
        self.room_title.setStyleSheet("font-size:12pt; font-weight:bold; padding:10px 16px;")
        cp_lay.addWidget(self.room_title)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setFixedHeight(1)
        sep.setStyleSheet(f"background:{BORDER}; border:none;")
        cp_lay.addWidget(sep)

        self.chat_area = ChatArea()
        cp_lay.addWidget(self.chat_area, 1)

        # ── Input bar ─────────────────────────────────────────────────────
        ibar = QWidget()
        ibar.setStyleSheet(f"background:{PANEL}; border-top:1px solid {BORDER};")
        ir = QHBoxLayout(ibar)
        ir.setContentsMargins(10, 8, 10, 8)
        ir.setSpacing(6)
        ir.setAlignment(Qt.AlignmentFlag.AlignBottom)

        self._attach_btn = QPushButton("＋")
        attach = self._attach_btn
        attach.setFixedSize(38, 38)
        attach.setToolTip("Attach image or file  (max 8 MB)")
        attach.setStyleSheet(
            f"QPushButton{{background:{ELEV};color:{MUTED};border-radius:19px;"
            "font-size:15pt;padding:0;border:none;}"
            f"QPushButton:hover{{background:{BORDER};color:{TEXT};}}"
        )
        attach.clicked.connect(self._attach_file)
        ir.addWidget(attach)

        self.msg_entry = MessageInput()
        self.msg_entry.send_requested.connect(self._send_message)
        self.msg_entry.history_prev.connect(self._history_up)
        self.msg_entry.history_next.connect(self._history_down)
        ir.addWidget(self.msg_entry)

        send = QPushButton("Send")
        send.setFixedSize(72, 38)
        send.clicked.connect(self._send_message)
        ir.addWidget(send)

        cp_lay.addWidget(ibar)
        splitter.addWidget(cp)
        splitter.setSizes([210, 830])

    def _set_status(self, text: str, color: str):
        self.status_label.setText(
            f'<span style="color:{color};">●</span>'
            f'<span style="color:{color};">  {html.escape(text)}</span>'
        )

    # -----------------------------------------------------------------------
    # Connection management
    # -----------------------------------------------------------------------

    def _show_connect_dialog(self):
        dlg = ConnectDialog(self, prefill=self.connect_params or None)
        if dlg.exec() == QDialog.DialogCode.Accepted and dlg.result_data:
            self._connect(dlg.result_data)

    def _connect(self, params: dict):
        if self.worker:
            self._disconnect(silent=True)
        self.connect_params = params
        self.username = params["username"]
        # Message key: prefer the dedicated passphrase (never sent to the
        # server) and fall back to the server password for compatibility.
        self._custom_key = bool(params.get("enc_passphrase"))
        secret = params.get("enc_passphrase") or params["server_password"]
        self.fernet = Fernet(derive_key(secret))

        self._set_status(f"Connecting to {params['host']}:{params['port']}…", AMBER)

        self.worker = WebSocketWorker(params)
        self.thread = QThread()
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.message_received.connect(self._handle_message)
        self.thread.start()

    def _disconnect(self, silent: bool = False):
        was_connected = self.worker is not None
        if self.worker:
            self.worker.close()
        if self.thread:
            self.thread.quit()
            self.thread.wait(2000)
        self.worker = None
        self.thread = None
        self.fernet = None
        self._reset_ui()
        if was_connected and not silent:
            self.chat_area.add_system("Disconnected.")

    def _reset_ui(self):
        self.current_room = None
        self.rooms = []
        self.room_users = {}
        self.room_list.clear()
        self.user_list.clear()
        self.room_title.setText("Select a room")
        self._set_status("Not connected", MUTED)
        self.lock_label.hide()
        self._apply_max_file(_DEFAULT_MAX_FILE_BYTES / 1_048_576)

    # -----------------------------------------------------------------------
    # Incoming message dispatch
    # -----------------------------------------------------------------------

    def _handle_message(self, msg: dict):
        t = msg.get("type")

        if t == "auth_result":
            if msg["success"]:
                self._set_status(f"Connected as {self.username}", GREEN)
                if self._custom_key:
                    self.lock_label.setText("🔒 Encrypted (separate passphrase)")
                else:
                    self.lock_label.setText("🔒 Encrypted")
                self.lock_label.show()
                self.rooms = msg.get("rooms", [])
                self.role_colors = msg.get("roles", {})
                self.my_roles = msg.get("your_roles", [])
                self.is_admin = msg.get("is_admin", False)
                self._refresh_rooms()
                self._apply_max_file(msg.get("max_file_mb", _DEFAULT_MAX_FILE_BYTES / 1_048_576))
                self.chat_area.add_system("Connected — messages are encrypted before they leave this device.")
                if self.my_roles:
                    self.chat_area.add_system("Your roles: " + ", ".join(self.my_roles))
            else:
                self._set_status("Not connected", RED)
                QMessageBox.critical(self, "Auth Failed", msg.get("message", "Unknown error"))

        elif t == "rooms_list":
            self.rooms = msg["rooms"]
            if "roles" in msg:
                self.role_colors = msg["roles"]
            if "your_roles" in msg:
                self.my_roles = msg["your_roles"]
            self._refresh_rooms()

        elif t == "users_list":
            self.room_users[msg["room"]] = msg["users"]
            if "roles" in msg:
                self.role_colors.update(msg["roles"])
            self.user_roles.update(msg.get("user_roles", {}))
            if msg["room"] == self.current_room:
                self._refresh_users()

        elif t == "roles_update":
            if "roles" in msg:
                self.role_colors.update(msg["roles"])
            self.user_roles.update(msg.get("user_roles", {}))
            if msg.get("room") == self.current_room:
                self._refresh_users()

        elif t == "room_closed":
            room = msg.get("room")
            self.chat_area.add_system(msg.get("message", f"Access to '{room}' removed"), color=AMBER)
            if room == self.current_room:
                self.current_room = None
                self.chat_area.clear_all()
                self.room_title.setText("Select a room")

        elif t == "room_message":
            self._recv_text(msg, historical=msg.get("historical", False))

        elif t == "file_message":
            self._recv_file(msg)

        elif t == "user_joined":
            room, user = msg["room"], msg["username"]
            if "roles" in msg:
                self.user_roles[user] = msg["roles"]
            self.room_users.setdefault(room, [])
            if user not in self.room_users[room]:
                self.room_users[room].append(user)
            if room == self.current_room:
                self._refresh_users()
                self.chat_area.add_system(f"{user} joined the room")

        elif t == "user_left":
            room, user = msg["room"], msg["username"]
            if room in self.room_users:
                self.room_users[room] = [u for u in self.room_users[room] if u != user]
            if room == self.current_room:
                self._refresh_users()
                self.chat_area.add_system(f"{user} left the room")

        elif t == "system_message":
            self.chat_area.add_system(msg.get("content", ""))

        elif t == "admin_result":
            success = msg.get("success", False)
            color = SYSTEM if success else RED
            self.chat_area.add_system(msg.get("message", ""), color=color)

        elif t == "error":
            self.chat_area.add_system(f"Error: {msg.get('message', 'Unknown')}", color=RED)

        elif t == "config_update":
            if "max_file_mb" in msg:
                self._apply_max_file(msg["max_file_mb"])
                self.chat_area.add_system(
                    f"Server updated max file size to {msg['max_file_mb']} MB"
                )

        elif t == "history_start":
            if msg.get("room") == self.current_room:
                self.chat_area.add_system("─── Chat history ───")

        elif t == "history_end":
            if msg.get("room") == self.current_room:
                self.chat_area.add_system("─── End of history ───")

        elif t == "_connect_error":
            self._set_status("Connection failed", RED)
            QMessageBox.critical(self, "Connection Error", msg.get("message", ""))

        elif t == "_connection_lost":
            self.chat_area.add_system("Disconnected from server.")
            self._reset_ui()

    def _primary_role(self, username: str) -> tuple[str, str] | None:
        """The first role a user holds, as (name, color), for a header chip."""
        for r in self.user_roles.get(username, []):
            if r in self.role_colors:
                return (r, self.role_colors[r])
        return None

    def _recv_text(self, msg: dict, historical: bool = False):
        if msg.get("room") != self.current_room:
            return
        try:
            content = self.fernet.decrypt(msg["content"].encode()).decode()
        except Exception:
            content = "[unable to decrypt]"
        is_self = msg["username"] == self.username
        mw = MessageWidget(msg["username"], msg["timestamp"], is_self, dim=historical,
                           role=self._primary_role(msg["username"]))
        mw.add_text(content)
        self.chat_area.add_message(mw)

    def _recv_file(self, msg: dict):
        if msg.get("room") != self.current_room:
            return
        is_self = msg["username"] == self.username
        historical = msg.get("historical", False)
        role = self._primary_role(msg["username"])
        try:
            payload = json.loads(self.fernet.decrypt(msg["content"].encode()).decode())
            filename = payload["filename"]
            mimetype = payload.get("mimetype", "application/octet-stream")
            raw      = base64.b64decode(payload["data"])
            caption  = payload.get("caption", "")
        except Exception:
            mw = MessageWidget(msg["username"], msg["timestamp"], is_self, dim=historical, role=role)
            mw.add_text("[could not decrypt file]")
            self.chat_area.add_message(mw)
            return

        mw = MessageWidget(msg["username"], msg["timestamp"], is_self, dim=historical, role=role)
        if caption:
            mw.add_text(caption)
        if mimetype in IMAGE_MIME:
            mw.add_image(raw, filename, mimetype)
        elif is_text_file(mimetype, filename):
            mw.add_text_preview(raw, filename)
        else:
            mw.add_file(raw, filename, mimetype)
        self.chat_area.add_message(mw)

    # -----------------------------------------------------------------------
    # UI helpers
    # -----------------------------------------------------------------------

    def _refresh_rooms(self):
        self.room_list.blockSignals(True)
        self.room_list.clear()
        for room in self.rooms:
            self.room_list.addItem(f"#  {room}")
        if self.current_room in self.rooms:
            self.room_list.setCurrentRow(self.rooms.index(self.current_room))
        self.room_list.blockSignals(False)

    def _refresh_users(self):
        self.user_list.clear()
        for user in self.room_users.get(self.current_room, []):
            roles = [r for r in self.user_roles.get(user, []) if r in self.role_colors]
            item = QListWidgetItem()
            row = self._make_user_row(user, roles)
            # Width 0 lets the view stretch the row to the full viewport
            # width instead of trusting row.sizeHint(), which can under-report
            # before the widget has been laid out (causing chips to clip).
            item.setSizeHint(QSize(0, 36))
            if roles:
                item.setToolTip("Roles: " + ", ".join(roles))
            self.user_list.addItem(item)
            self.user_list.setItemWidget(item, row)

    def _make_user_row(self, user: str, roles: list[str]) -> QWidget:
        row = QWidget()
        row.setStyleSheet("background: transparent;")
        lay = QHBoxLayout(row)
        lay.setContentsMargins(10, 0, 10, 0)
        lay.setSpacing(6)
        vc = Qt.AlignmentFlag.AlignVCenter
        is_self = user == self.username
        name = QLabel(("@" if is_self else "") + user)
        name.setStyleSheet(
            f"color: {SELF_NAME if is_self else TEXT}; background: transparent;"
            f"{' font-weight: bold;' if is_self else ''}"
        )
        lay.addWidget(name, 0, vc)
        lay.addStretch()
        # Show up to two role chips to keep the row compact; tooltip lists all
        for r in roles[:2]:
            lay.addWidget(make_role_chip(r, self.role_colors[r]), 0, vc)
        return row

    def _on_room_changed(self, row: int):
        if row < 0 or not self.worker or row >= len(self.rooms):
            return
        room = self.rooms[row]
        if room == self.current_room:
            return
        if self.current_room:
            self.worker.send_msg({"type": "leave_room", "room": self.current_room})
        self.current_room = room
        self.room_title.setText(f"#  {room}")
        self.chat_area.clear_all()
        self.worker.send_msg({"type": "join_room", "room": room})

    # -----------------------------------------------------------------------
    # Sending
    # -----------------------------------------------------------------------

    def _send_message(self):
        content = self.msg_entry.text().strip()
        if not content:
            return
        if content.startswith("/") and "\n" not in content:
            self.msg_entry.clear()
            self._handle_slash_command(content)
            return
        if not self.current_room or not self.worker or not self.fernet:
            return
        self._history.insert(0, content)
        self._history_idx = -1
        self.msg_entry.clear()
        enc = self.fernet.encrypt(content.encode()).decode()
        self.worker.send_msg({"type": "send_message", "room": self.current_room, "content": enc})

    def _handle_slash_command(self, text: str):
        parts = text[1:].split()
        if not parts:
            return
        command = parts[0].lower()
        args = parts[1:]

        if command == "help":
            lines = [
                "Available slash commands:",
                "  /online                           List connected users",
                "  /listusers                        List all registered users",
                "  /listrooms                        List all rooms",
                "  /kick <username>                  Kick a user  [admin]",
                "  /adduser <username> <pass>        Add a new user  [admin]",
                "  /removeuser <username>            Remove a user  [admin]",
                "  /addroom <name>                   Create a room  [admin]",
                "  /removeroom <name>                Remove a room  [admin]",
                "  /setpassword <new_password>       Change server password  [admin]",
                "  /setmaxfile <MB>                  Set max file upload size  [admin]",
                "  /history on|off                   Enable/disable chat history  [admin]",
                "  /makeadmin <username>             Grant admin privileges  [admin]",
                "  /removeadmin <username>           Revoke admin privileges  [admin]",
                "  /role add <name> [#color]         Create a role  [admin]",
                "  /role del <name>                  Delete a role  [admin]",
                "  /role rooms <name> [room ...]     Set rooms a role grants  [admin]",
                "  /role list                        List roles and members  [admin]",
                "  /grantrole <username> <role>      Give a user a role  [admin]",
                "  /revokerole <username> <role>     Remove a role from a user  [admin]",
                "  /blocked                          List blocked IPs  [admin]",
                "  /unblock <ip>                     Unblock an IP address  [admin]",
                "  /ratelimit on|off                 Enable/disable rate limiting  [admin]",
                "  /ratelimit attempts <N>           Set max failed attempts  [admin]",
                "  /ratelimit window <seconds>       Set the failure counting window  [admin]",
                "  /ratelimit block <seconds>        Set block duration  [admin]",
            ]
            for line in lines:
                self.chat_area.add_system(line)
            return

        if not self.worker:
            self.chat_area.add_system("Not connected.", color=RED)
            return

        self.worker.send_msg({"type": "admin_command", "command": command, "args": args})

    def _apply_max_file(self, mb: float):
        self.max_file_bytes = int(mb * 1_048_576)
        self._attach_btn.setToolTip(f"Attach image or file  (max {mb:g} MB)")

    def _attach_file(self):
        if not self.worker or not self.fernet or not self.current_room:
            QMessageBox.information(self, "Not Connected", "Join a room before attaching files.")
            return

        path, _ = QFileDialog.getOpenFileName(self, "Attach File or Image")
        if not path:
            return

        try:
            size = os.path.getsize(path)
        except OSError:
            size = 0

        if size > self.max_file_bytes:
            QMessageBox.warning(
                self, "File Too Large",
                f"Selected file: {size / 1_048_576:.1f} MB\n"
                f"Server limit: {self.max_file_bytes / 1_048_576:g} MB"
            )
            return

        filename = os.path.basename(path)
        mime, _ = mimetypes.guess_type(filename)
        if not mime:
            mime = "application/octet-stream"

        caption = self.msg_entry.text().strip()
        self.msg_entry.clear()

        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            with open(path, "rb") as fh:
                raw = fh.read()

            payload: dict = {
                "filename": filename,
                "mimetype": mime,
                "data":     base64.b64encode(raw).decode(),
            }
            if caption:
                payload["caption"] = caption

            enc = self.fernet.encrypt(json.dumps(payload).encode()).decode()
        except Exception as exc:
            QMessageBox.critical(self, "Error", f"Could not prepare file:\n{exc}")
            return
        finally:
            QApplication.restoreOverrideCursor()

        self.worker.send_msg({"type": "file_message", "room": self.current_room, "content": enc})

    def _history_up(self):
        if self._history:
            self._history_idx = min(self._history_idx + 1, len(self._history) - 1)
            self.msg_entry.setText(self._history[self._history_idx])

    def _history_down(self):
        if self._history_idx > 0:
            self._history_idx -= 1
            self.msg_entry.setText(self._history[self._history_idx])
        elif self._history_idx == 0:
            self._history_idx = -1
            self.msg_entry.clear()

    def closeEvent(self, event):
        self._disconnect(silent=True)
        event.accept()


# ---------------------------------------------------------------------------

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Bastion")
    app.setStyleSheet(DARK_STYLE)
    window = ChatWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
