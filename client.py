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
import time

_missing = []
try:
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QDialog, QSplitter,
        QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit,
        QListWidget, QListWidgetItem, QFrame, QFormLayout,
        QMessageBox, QScrollArea, QFileDialog, QCheckBox, QPlainTextEdit,
        QTabWidget, QMenu, QSystemTrayIcon,
    )
    from PyQt6.QtCore import (
        Qt, QThread, QObject, pyqtSignal, pyqtSlot,
        QTimer, QBuffer, QSize, QPoint, QSettings,
    )
    from PyQt6.QtGui import (
        QFont, QColor, QPixmap, QMovie, QTextCursor, QPainter, QPainterPath,
        QGuiApplication, QIcon, QImage, QShortcut, QKeySequence,
    )
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

# Emoji offered in the message context menu's React submenu
REACTION_EMOJI = ["👍", "❤️", "😂", "😮", "😢", "🎉", "👀", "✅"]


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


# ── Profile images ───────────────────────────────────────────────────────
# Kept intentionally small so profiles fit comfortably in the server's JSON
# config; PROFILE_IMAGE_MAX_B64 below must stay >= what these produce.
PROFILE_AVATAR_PX = 128
PROFILE_BANNER_W = 480
PROFILE_BANNER_H = 160
PROFILE_BIO_MAX_CHARS = 300
PROFILE_IMAGE_MAX_B64 = 400_000


def cropped_pixmap(px: QPixmap, w: int, h: int) -> QPixmap:
    """Scale px to cover a w×h box, then center-crop to exactly that size."""
    scaled = px.scaled(
        w, h, Qt.AspectRatioMode.KeepAspectRatioByExpanding,
        Qt.TransformationMode.SmoothTransformation,
    )
    x = max(0, (scaled.width() - w) // 2)
    y = max(0, (scaled.height() - h) // 2)
    return scaled.copy(x, y, w, h)


def circular_pixmap(px: QPixmap, size: int) -> QPixmap:
    cropped = cropped_pixmap(px, size, size)
    out = QPixmap(size, size)
    out.fill(Qt.GlobalColor.transparent)
    painter = QPainter(out)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    path = QPainterPath()
    path.addEllipse(0, 0, size, size)
    painter.setClipPath(path)
    painter.drawPixmap(0, 0, cropped)
    painter.end()
    return out


def pixmap_to_b64(px: QPixmap, quality: int = 85) -> str:
    buf = QBuffer()
    buf.open(QBuffer.OpenModeFlag.WriteOnly)
    px.save(buf, "JPEG", quality)
    return base64.b64encode(bytes(buf.data())).decode()


_PROFILE_IMAGE_MAX_DIM = 2048   # reject decompression bombs (tiny file, huge canvas)


def b64_to_pixmap(b64: str | None) -> QPixmap | None:
    if not b64 or len(b64) > PROFILE_IMAGE_MAX_B64:
        return None
    try:
        raw = base64.b64decode(b64)
    except Exception:
        return None
    px = QPixmap()
    if not px.loadFromData(raw):
        return None
    if px.width() > _PROFILE_IMAGE_MAX_DIM or px.height() > _PROFILE_IMAGE_MAX_DIM:
        return None
    return px


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


def _insert_soft_breaks(html: str, every: int = 20) -> str:
    """Insert invisible break points (U+200B) into long unbroken runs of
    non-whitespace so QLabel's word-wrap has somewhere to break — otherwise a
    single long token (no spaces, e.g. a wall of the same character or a long
    URL) overflows the label's width instead of wrapping. Skips HTML tags and
    entity references so markup is never split apart."""
    out: list[str] = []
    in_tag = in_entity = False
    run = 0
    for ch in html:
        if in_tag:
            out.append(ch)
            if ch == ">":
                in_tag = False
            continue
        if ch == "<":
            in_tag = True
            out.append(ch)
            run = 0
            continue
        if in_entity:
            out.append(ch)
            if ch == ";":
                in_entity = False
                run += 1
                if run >= every:
                    out.append("​")
                    run = 0
            continue
        if ch == "&":
            in_entity = True
            out.append(ch)
            continue
        if ch.isspace():
            out.append(ch)
            run = 0
            continue
        out.append(ch)
        run += 1
        if run >= every:
            out.append("​")
            run = 0
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

# Fallback salt for servers that predate per-server salts. Newer servers
# send a random per-server salt in auth_result, which prevents cross-server
# rainbow-table precomputation of keys from common passwords.
_LEGACY_KDF_SALT = b"chat_platform_v2"
# NOTE: all clients on a server must use the same salt + iteration count,
# otherwise they derive different keys and see "[unable to decrypt]".
_KDF_ITERATIONS = 600_000


def derive_key(server_password: str, salt: bytes = _LEGACY_KDF_SALT) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_KDF_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(server_password.encode()))


# Message padding: round each plaintext up to a bucket boundary before
# encryption so ciphertext length only reveals a coarse size bucket, not the
# exact message length. 0x80 marks where the real content ends (ISO/IEC
# 7816-4 style), so padding strips unambiguously after decryption.
_PAD_BLOCK = 256


def pad_plaintext(data: bytes) -> bytes:
    n = (-(len(data) + 1)) % _PAD_BLOCK
    return data + b"\x80" + b"\x00" * n


def unpad_plaintext(data: bytes) -> bytes:
    i = data.rfind(b"\x80")
    if i != -1 and not any(data[i + 1:]):
        return data[:i]
    return data  # unpadded message from an older client


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
# Hover profile card
# ---------------------------------------------------------------------------

class ProfileCard(QFrame):
    """Frameless popup shown when hovering a user in the sidebar list:
    banner, avatar, name, role chips, and their bio."""

    CARD_W = 260
    BANNER_H = 74
    AVATAR_SIZE = 56

    def __init__(self):
        super().__init__(None, Qt.WindowType.ToolTip | Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setFixedWidth(self.CARD_W)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        card = QFrame()
        card.setObjectName("card")
        card.setStyleSheet(
            f"QFrame#card {{ background-color: {ELEV}; border: 1px solid {BORDER};"
            " border-radius: 10px; }}"
        )
        outer.addWidget(card)
        cl = QVBoxLayout(card)
        cl.setContentsMargins(0, 0, 0, 0)
        cl.setSpacing(0)

        self._banner = QLabel()
        self._banner.setFixedSize(self.CARD_W, self.BANNER_H)
        self._banner.setScaledContents(False)
        self._banner.setStyleSheet("border-top-left-radius: 10px; border-top-right-radius: 10px;")
        cl.addWidget(self._banner)

        body = QVBoxLayout()
        body.setContentsMargins(14, 10, 14, 12)
        body.setSpacing(8)
        cl.addLayout(body)

        head = QHBoxLayout()
        head.setSpacing(10)
        self._avatar = QLabel()
        self._avatar.setFixedSize(self.AVATAR_SIZE, self.AVATAR_SIZE)
        head.addWidget(self._avatar)

        name_col = QVBoxLayout()
        name_col.setSpacing(4)
        self._name = QLabel()
        self._name.setStyleSheet(
            f"color: {TEXT}; font-weight: 700; font-size: 11pt; background: transparent;"
        )
        name_col.addWidget(self._name)
        self._chips = QHBoxLayout()
        self._chips.setSpacing(4)
        self._chips.addStretch()
        name_col.addLayout(self._chips)
        head.addLayout(name_col, 1)
        body.addLayout(head)

        self._bio = QLabel()
        self._bio.setWordWrap(True)
        # Bios are arbitrary text written by other users — never let QLabel
        # auto-interpret them as rich text (HTML injection).
        self._bio.setTextFormat(Qt.TextFormat.PlainText)
        self._bio.setStyleSheet(f"color: {MUTED}; font-size: 9pt; background: transparent;")
        self._bio.hide()
        body.addWidget(self._bio)

        self.setWindowOpacity(0.98)

    def set_data(self, username: str, avatar_b64: str | None, banner_b64: str | None,
                 bio: str, roles: list[str], role_colors: dict[str, str], is_self: bool):
        banner_px = b64_to_pixmap(banner_b64)
        if banner_px:
            self._banner.setPixmap(cropped_pixmap(banner_px, self.CARD_W, self.BANNER_H))
        else:
            color = avatar_color(username)
            self._banner.setPixmap(QPixmap())
            self._banner.setStyleSheet(
                f"background-color: {color}; border-top-left-radius: 10px;"
                " border-top-right-radius: 10px;"
            )

        avatar_px = b64_to_pixmap(avatar_b64)
        if avatar_px:
            self._avatar.setPixmap(circular_pixmap(avatar_px, self.AVATAR_SIZE))
            self._avatar.setStyleSheet("background: transparent;")
        else:
            self._avatar.setPixmap(QPixmap())
            self._avatar.setText(username[:1].upper())
            self._avatar.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self._avatar.setStyleSheet(
                f"background-color: {avatar_color(username)}; color: #fff;"
                f" border-radius: {self.AVATAR_SIZE // 2}px; font-weight: bold; font-size: 14pt;"
            )

        self._name.setText(("@" if is_self else "") + username)

        while self._chips.count() > 1:  # keep the trailing stretch
            item = self._chips.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()
        for r in roles:
            if r in role_colors:
                self._chips.insertWidget(self._chips.count() - 1, make_role_chip(r, role_colors[r]))

        if bio:
            self._bio.setText(bio)
            self._bio.show()
        else:
            self._bio.hide()

        self.adjustSize()

    def show_near(self, global_pos: QPoint):
        self.adjustSize()
        screen = QGuiApplication.screenAt(global_pos) or QGuiApplication.primaryScreen()
        rect = screen.availableGeometry() if screen else None
        x, y = global_pos.x(), global_pos.y()
        if rect:
            x = min(x, rect.right() - self.width() - 4)
            y = min(y, rect.bottom() - self.height() - 4)
            x = max(rect.left() + 4, x)
            y = max(rect.top() + 4, y)
        self.move(x, y)
        self.show()


class UserRow(QWidget):
    """A single row in the user sidebar list. Emits hover events so the
    parent window can show a ProfileCard for the hovered user."""

    hovered = pyqtSignal(str, QPoint)
    unhovered = pyqtSignal()

    def __init__(self, username: str):
        super().__init__()
        self.username = username

    def enterEvent(self, event):
        self.hovered.emit(self.username, self.mapToGlobal(QPoint(self.width() + 6, -4)))
        super().enterEvent(event)

    def leaveEvent(self, event):
        self.unhovered.emit()
        super().leaveEvent(event)


# ---------------------------------------------------------------------------
# Message row widget
# ---------------------------------------------------------------------------

class MessageWidget(QFrame):
    """Discord-style message row: a top-aligned avatar on the left, then a
    header line (name · role chip · timestamp) with the message body tight
    underneath it."""

    edit_requested = pyqtSignal(str)
    delete_requested = pyqtSignal(str)
    react_requested = pyqtSignal(str, str)   # (msg_id, emoji)
    pin_requested = pyqtSignal(str)
    reply_requested = pyqtSignal(str)

    def __init__(self, username: str | None, timestamp: str | None,
                 is_self: bool = False, dim: bool = False,
                 role: tuple[str, str] | None = None,
                 avatar_b64: str | None = None,
                 msg_id: str | None = None,
                 show_header: bool = True):
        super().__init__()
        self.msg_id = msg_id
        self.author = username or ""
        self.is_self = is_self
        self.plaintext = ""       # decrypted markdown source, for editing
        self._can_edit = False    # set by the window based on type/ownership
        self._can_delete = False
        self._can_pin = False
        self._body_lbl: QLabel | None = None
        self._react_row: QWidget | None = None
        self._my_name = ""
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

        header = bool(username) and show_header
        if header:
            avatar = QLabel()
            avatar.setFixedSize(40, 40)
            avatar_px = None if dim else b64_to_pixmap(avatar_b64)
            if avatar_px:
                avatar.setPixmap(circular_pixmap(avatar_px, 40))
                avatar.setStyleSheet("background: transparent;")
            else:
                avatar.setText(username[:1].upper())
                avatar.setAlignment(Qt.AlignmentFlag.AlignCenter)
                bg = "#3a3d45" if dim else avatar_color(username)
                avatar.setStyleSheet(
                    f"background-color: {bg}; color: #ffffff; border-radius: 20px;"
                    " font-weight: bold; font-size: 15pt;"
                )
            outer.addWidget(avatar, 0, Qt.AlignmentFlag.AlignTop)
        elif username:
            # Grouped continuation row: align the body under the header
            # message's text column (40px avatar + 14px spacing).
            outer.addSpacing(54)

        self._lay = QVBoxLayout()
        self._lay.setContentsMargins(0, 0, 0, 0)
        self._lay.setSpacing(2)
        outer.addLayout(self._lay, 1)

        if header:
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
            self._edited_lbl = QLabel("(edited)")
            self._edited_lbl.setStyleSheet(
                f"color: {MUTED}; font-size: 8pt; font-style: italic; background: transparent;"
            )
            self._edited_lbl.hide()
            hrow.addWidget(self._edited_lbl, 0, Qt.AlignmentFlag.AlignVCenter)
            hrow.addStretch()
            self._lay.addLayout(hrow)
        else:
            self._edited_lbl = None

    def add_text(self, text: str) -> "MessageWidget":
        lbl = QLabel()
        lbl.setWordWrap(True)
        lbl.setTextFormat(Qt.TextFormat.RichText)
        lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        lbl.setOpenExternalLinks(False)
        lbl.setStyleSheet(
            f"color: {self._text_color}; background: transparent; line-height: 140%;"
        )
        lbl.setText(_insert_soft_breaks(markdown_to_html(text)))
        self._lay.addWidget(lbl)
        if self._body_lbl is None:
            self._body_lbl = lbl
            self.plaintext = text
        return self

    def add_quote(self, text: str) -> "MessageWidget":
        """Small quoted-reply header shown above the message body."""
        lbl = QLabel(text)
        lbl.setWordWrap(True)
        lbl.setTextFormat(Qt.TextFormat.PlainText)
        lbl.setStyleSheet(
            f"color: {MUTED}; font-size: 8pt; background: transparent;"
            f" border-left: 2px solid {ACCENT}; padding-left: 6px;"
        )
        self._lay.addWidget(lbl)
        return self

    def mark_edited(self):
        if self._edited_lbl is None:
            # Grouped rows have no header line; add a tiny inline marker
            self._edited_lbl = QLabel("(edited)")
            self._edited_lbl.setStyleSheet(
                f"color: {MUTED}; font-size: 8pt; font-style: italic; background: transparent;"
            )
            self._lay.addWidget(self._edited_lbl)
        self._edited_lbl.show()

    def update_text(self, plaintext: str):
        self.plaintext = plaintext
        if self._body_lbl:
            self._body_lbl.setText(_insert_soft_breaks(markdown_to_html(plaintext)))
        self.mark_edited()

    def set_mentioned(self):
        self.setStyleSheet(
            "QFrame#msg { border: none; border-left: 3px solid " + AMBER + ";"
            " background-color: rgba(251, 191, 36, 18); }"
            f"QFrame#msg:hover {{ background-color: {PANEL}; }}"
        )

    def set_reactions(self, reactions: dict, me: str):
        self._my_name = me
        if self._react_row is None:
            self._react_row = QWidget()
            self._react_row.setStyleSheet("background: transparent;")
            h = QHBoxLayout(self._react_row)
            h.setContentsMargins(0, 2, 0, 0)
            h.setSpacing(4)
            h.addStretch()
            self._lay.addWidget(self._react_row)
        lay = self._react_row.layout()
        while lay.count() > 1:   # keep the trailing stretch
            item = lay.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()
        if not reactions:
            self._react_row.hide()
            return
        for emoji, users in reactions.items():
            mine = me in users
            chip = QPushButton(f"{emoji} {len(users)}")
            chip.setCursor(Qt.CursorShape.PointingHandCursor)
            chip.setFixedHeight(22)
            chip.setToolTip(", ".join(users))
            border = ACCENT if mine else BORDER
            bg = "#2c2a4a" if mine else ELEV
            chip.setStyleSheet(
                f"QPushButton {{ background-color: {bg}; color: {TEXT};"
                f" border: 1px solid {border}; border-radius: 11px;"
                " padding: 0px 8px; font-size: 9pt; font-weight: 400; }}"
                f"QPushButton:hover {{ border-color: {ACCENT_H}; }}"
            )
            if self.msg_id:
                chip.clicked.connect(
                    lambda _=False, e=emoji: self.react_requested.emit(self.msg_id, e)
                )
            lay.insertWidget(lay.count() - 1, chip)
        self._react_row.show()

    def contextMenuEvent(self, event):
        menu = QMenu(self)
        if self.msg_id:
            menu.addAction("Reply", lambda: self.reply_requested.emit(self.msg_id))
            react_menu = menu.addMenu("React")
            for e in REACTION_EMOJI:
                react_menu.addAction(
                    e, lambda em=e: self.react_requested.emit(self.msg_id, em)
                )
        if self.plaintext:
            menu.addAction(
                "Copy Text",
                lambda: QGuiApplication.clipboard().setText(self.plaintext),
            )
        if self._can_edit:
            menu.addAction("Edit", lambda: self.edit_requested.emit(self.msg_id))
        if self._can_pin:
            menu.addAction("Pin", lambda: self.pin_requested.emit(self.msg_id))
        if self._can_delete:
            menu.addAction("Delete", lambda: self.delete_requested.emit(self.msg_id))
        if menu.actions():
            menu.exec(event.globalPos())

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

        # Tracks whether the view should stick to the bottom as new content
        # arrives. Driven off the scrollbar itself rather than recomputed
        # per-insert, so a burst of history messages can't race the layout
        # and leave us reading stale geometry.
        self._pinned = True
        self.verticalScrollBar().valueChanged.connect(self._on_scroll)

        self._notice = QPushButton("↓ New messages", self)
        self._notice.setCursor(Qt.CursorShape.PointingHandCursor)
        self._notice.setStyleSheet(
            f"QPushButton {{ background-color: {ACCENT}; color: white; "
            "border: none; border-radius: 14px; padding: 6px 16px; "
            "font-weight: 600; }}"
            f"QPushButton:hover {{ background-color: {ACCENT_H}; }}"
        )
        self._notice.hide()
        self._notice.clicked.connect(self._on_notice_clicked)

    def add_message(self, widget: QWidget):
        pinned = self._pinned
        self._vbox.addWidget(widget)
        if pinned:
            QTimer.singleShot(0, self._to_bottom)
        else:
            self._show_notice()

    def add_system(self, text: str, color: str = SYSTEM):
        pinned = self._pinned
        lbl = QLabel(f"  ✦  {text}")
        # System lines can embed server-supplied text (error messages, admin
        # results). QLabel auto-detects rich text, so force plain text to
        # keep HTML markup from being interpreted.
        lbl.setTextFormat(Qt.TextFormat.PlainText)
        lbl.setStyleSheet(
            f"color: {color}; font-style: italic; padding: 2px 12px;"
            " background: transparent;"
        )
        lbl.setWordWrap(True)
        self._vbox.addWidget(lbl)
        if pinned:
            QTimer.singleShot(0, self._to_bottom)
        else:
            self._show_notice()

    def clear_all(self):
        while self._vbox.count():
            item = self._vbox.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()
        self._notice.hide()
        self._pinned = True

    def widgets(self) -> list:
        out = []
        for i in range(self._vbox.count()):
            w = self._vbox.itemAt(i).widget()
            if w is not None:
                out.append(w)
        return out

    def _at_bottom(self) -> bool:
        vsb = self.verticalScrollBar()
        # Treat as "at bottom" when within 40 px — handles sub-pixel rounding
        # and the moment just before the layout updates after a new widget is added.
        return vsb.value() >= vsb.maximum() - 40

    def _to_bottom(self):
        self.verticalScrollBar().setValue(self.verticalScrollBar().maximum())

    def scroll_to_bottom(self):
        self._pinned = True
        self._notice.hide()
        QTimer.singleShot(0, self._to_bottom)

    def _on_scroll(self, _value: int):
        self._pinned = self._at_bottom()
        if self._pinned:
            self._notice.hide()

    def _on_notice_clicked(self):
        self.scroll_to_bottom()

    def _show_notice(self):
        self._notice.adjustSize()
        x = (self.width() - self._notice.width()) // 2
        y = self.height() - self._notice.height() - 14
        self._notice.move(max(0, x), max(0, y))
        self._notice.raise_()
        self._notice.show()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self._notice.isVisible():
            self._show_notice()


# ---------------------------------------------------------------------------
# Message input (multiline: Enter sends, Shift+Enter inserts a newline)
# ---------------------------------------------------------------------------

class MessageInput(QPlainTextEdit):
    send_requested = pyqtSignal()
    history_prev = pyqtSignal()
    history_next = pyqtSignal()
    edit_cancelled = pyqtSignal()
    image_pasted = pyqtSignal(QImage)
    files_pasted = pyqtSignal(list)

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

    def insertFromMimeData(self, source):
        if source.hasImage():
            img = source.imageData()
            if isinstance(img, QImage) and not img.isNull():
                self.image_pasted.emit(img)
                return
        if source.hasUrls():
            paths = [u.toLocalFile() for u in source.urls() if u.isLocalFile()]
            if paths:
                self.files_pasted.emit(paths)
                return
        super().insertFromMimeData(source)

    def keyPressEvent(self, event):
        key = event.key()
        if key == Qt.Key.Key_Escape:
            self.edit_cancelled.emit()
            return
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
# Options dialog: profile editor + client preferences
# ---------------------------------------------------------------------------

class OptionsDialog(QDialog):
    def __init__(self, parent, username: str, profile: dict, connected: bool,
                 play_sound: bool, notify_desktop: bool = True):
        super().__init__(parent)
        self.setWindowTitle("Options")
        self.setFixedWidth(420)
        self._username = username
        self._connected = connected
        self._avatar_b64: str | None = profile.get("avatar")
        self._banner_b64: str | None = profile.get("banner")
        self._notify_desktop = notify_desktop
        self.profile_result: dict | None = None
        self.play_sound_result: bool | None = None
        self.notify_result: bool | None = None

        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 18, 20, 16)
        lay.setSpacing(12)

        tabs = QTabWidget()
        lay.addWidget(tabs)
        tabs.addTab(self._build_profile_tab(profile), "Profile")
        tabs.addTab(self._build_preferences_tab(play_sound), "Preferences")

        if not connected:
            note = QLabel("Connect to a server to edit your profile.")
            note.setStyleSheet(f"color: {AMBER}; font-size: 8pt;")
            lay.addWidget(note)

        btns = QHBoxLayout()
        btns.addStretch()
        close = QPushButton("Close")
        close.setProperty("secondary", True)
        close.setStyle(close.style())
        close.clicked.connect(self.reject)
        save = QPushButton("Save")
        save.setDefault(True)
        save.clicked.connect(self._on_save)
        btns.addWidget(close)
        btns.addSpacing(8)
        btns.addWidget(save)
        lay.addLayout(btns)

    # -- Profile tab ---------------------------------------------------

    def _build_profile_tab(self, profile: dict) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setSpacing(10)

        self._banner_lbl = QLabel()
        self._banner_lbl.setFixedSize(ProfileCard.CARD_W, ProfileCard.BANNER_H)
        lay.addWidget(self._banner_lbl, 0, Qt.AlignmentFlag.AlignHCenter)
        self._render_banner()

        banner_btns = QHBoxLayout()
        pick_banner = QPushButton("Choose Background…")
        pick_banner.clicked.connect(self._pick_banner)
        clear_banner = QPushButton("Remove")
        clear_banner.setProperty("secondary", True)
        clear_banner.setStyle(clear_banner.style())
        clear_banner.clicked.connect(self._clear_banner)
        banner_btns.addWidget(pick_banner)
        banner_btns.addWidget(clear_banner)
        lay.addLayout(banner_btns)

        avatar_row = QHBoxLayout()
        self._avatar_lbl = QLabel()
        self._avatar_lbl.setFixedSize(72, 72)
        avatar_row.addWidget(self._avatar_lbl)
        self._render_avatar()

        avatar_btns = QVBoxLayout()
        pick_avatar = QPushButton("Choose Picture…")
        pick_avatar.clicked.connect(self._pick_avatar)
        clear_avatar = QPushButton("Remove")
        clear_avatar.setProperty("secondary", True)
        clear_avatar.setStyle(clear_avatar.style())
        clear_avatar.clicked.connect(self._clear_avatar)
        avatar_btns.addWidget(pick_avatar)
        avatar_btns.addWidget(clear_avatar)
        avatar_row.addLayout(avatar_btns)
        avatar_row.addStretch()
        lay.addLayout(avatar_row)

        bio_hdr = QHBoxLayout()
        bio_hdr.addWidget(QLabel("About me"))
        bio_hdr.addStretch()
        self._bio_counter = QLabel()
        self._bio_counter.setStyleSheet(f"color: {MUTED}; font-size: 8pt;")
        bio_hdr.addWidget(self._bio_counter)
        lay.addLayout(bio_hdr)

        self._bio_edit = QPlainTextEdit(profile.get("bio", ""))
        self._bio_edit.setFixedHeight(80)
        self._bio_edit.setPlaceholderText("Say something about yourself…")
        self._bio_edit.textChanged.connect(self._on_bio_changed)
        lay.addWidget(self._bio_edit)
        self._on_bio_changed()

        return w

    def _on_bio_changed(self):
        text = self._bio_edit.toPlainText()
        if len(text) > PROFILE_BIO_MAX_CHARS:
            cursor = self._bio_edit.textCursor()
            pos = cursor.position()
            self._bio_edit.blockSignals(True)
            self._bio_edit.setPlainText(text[:PROFILE_BIO_MAX_CHARS])
            cursor.setPosition(min(pos, PROFILE_BIO_MAX_CHARS))
            self._bio_edit.setTextCursor(cursor)
            self._bio_edit.blockSignals(False)
            text = text[:PROFILE_BIO_MAX_CHARS]
        self._bio_counter.setText(f"{len(text)}/{PROFILE_BIO_MAX_CHARS}")

    def _render_avatar(self):
        px = b64_to_pixmap(self._avatar_b64)
        if px:
            self._avatar_lbl.setPixmap(circular_pixmap(px, 72))
            self._avatar_lbl.setStyleSheet("background: transparent;")
        else:
            self._avatar_lbl.setPixmap(QPixmap())
            self._avatar_lbl.setText(self._username[:1].upper())
            self._avatar_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self._avatar_lbl.setStyleSheet(
                f"background-color: {avatar_color(self._username)}; color: #fff;"
                " border-radius: 36px; font-weight: bold; font-size: 20pt;"
            )

    def _render_banner(self):
        px = b64_to_pixmap(self._banner_b64)
        if px:
            self._banner_lbl.setPixmap(cropped_pixmap(px, ProfileCard.CARD_W, ProfileCard.BANNER_H))
            self._banner_lbl.setStyleSheet("border-radius: 6px;")
        else:
            self._banner_lbl.setPixmap(QPixmap())
            self._banner_lbl.setStyleSheet(
                f"background-color: {avatar_color(self._username)}; border-radius: 6px;"
            )

    def _pick_avatar(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose Profile Picture", "",
                                               "Images (*.png *.jpg *.jpeg *.bmp *.gif *.webp)")
        if not path:
            return
        px = QPixmap(path)
        if px.isNull():
            QMessageBox.warning(self, "Invalid Image", "Could not load that image.")
            return
        square = cropped_pixmap(px, PROFILE_AVATAR_PX, PROFILE_AVATAR_PX)
        b64 = pixmap_to_b64(square)
        if len(b64) > PROFILE_IMAGE_MAX_B64:
            QMessageBox.warning(self, "Image Too Large", "That image is too large even after resizing.")
            return
        self._avatar_b64 = b64
        self._render_avatar()

    def _clear_avatar(self):
        self._avatar_b64 = None
        self._render_avatar()

    def _pick_banner(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose Background Image", "",
                                               "Images (*.png *.jpg *.jpeg *.bmp *.gif *.webp)")
        if not path:
            return
        px = QPixmap(path)
        if px.isNull():
            QMessageBox.warning(self, "Invalid Image", "Could not load that image.")
            return
        cropped = cropped_pixmap(px, PROFILE_BANNER_W, PROFILE_BANNER_H)
        b64 = pixmap_to_b64(cropped)
        if len(b64) > PROFILE_IMAGE_MAX_B64:
            QMessageBox.warning(self, "Image Too Large", "That image is too large even after resizing.")
            return
        self._banner_b64 = b64
        self._render_banner()

    def _clear_banner(self):
        self._banner_b64 = None
        self._render_banner()

    # -- Preferences tab -------------------------------------------------

    def _build_preferences_tab(self, play_sound: bool) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setSpacing(10)
        lay.setAlignment(Qt.AlignmentFlag.AlignTop)

        self._sound_check = QCheckBox("Play a sound when a new message arrives")
        self._sound_check.setChecked(play_sound)
        lay.addWidget(self._sound_check)

        self._notify_check = QCheckBox("Show desktop notifications when the window is inactive")
        self._notify_check.setChecked(self._notify_desktop)
        lay.addWidget(self._notify_check)

        return w

    # -- Save ------------------------------------------------------------

    def _on_save(self):
        self.play_sound_result = self._sound_check.isChecked()
        self.notify_result = self._notify_check.isChecked()
        if self._connected:
            self.profile_result = {
                "bio": self._bio_edit.toPlainText().strip(),
                "avatar": self._avatar_b64,
                "banner": self._banner_b64,
            }
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
        self._secret = ""
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

        # Profile cards
        self.profile_cache: dict[str, dict] = {}   # username -> {bio, avatar, banner, roles, is_admin}
        self.my_profile: dict = {"bio": "", "avatar": None, "banner": None}
        self.profile_card = ProfileCard()
        self._hover_user: str | None = None
        self._hover_pos: QPoint | None = None
        self._hover_timer = QTimer(self)
        self._hover_timer.setSingleShot(True)
        self._hover_timer.timeout.connect(self._show_profile_popup)

        # Local client preferences (persisted outside the server config)
        self.settings = QSettings("Bastion", "Client")
        self.play_sound_on_message = self.settings.value("play_sound_on_message", False, type=bool)
        self.notify_desktop = self.settings.value("notify_desktop", True, type=bool)

        # Message actions / ambient state
        self._msg_widgets: dict[str, MessageWidget] = {}   # msg id -> widget (current room)
        self._editing_id: str | None = None
        self._reply_to: str | None = None
        # Grouping / day-separator trackers for the current room's render
        self._last_author: str | None = None
        self._last_ts: datetime.datetime | None = None
        self._last_dim: bool | None = None
        self._last_date: datetime.date | None = None
        self.unread: dict[str, int] = {}                   # room -> unread count
        self._typers: dict[str, float] = {}                # username -> expiry time
        self._typing_prune = QTimer(self)
        self._typing_prune.timeout.connect(self._update_typing_label)
        self._typing_prune.start(1000)
        self._last_typing_sent = 0.0

        # Auto-reconnect
        self._manual_disconnect = False
        self._authed = False
        self._reconnect_attempts = 0
        self._rejoin_room: str | None = None
        self._reconnect_timer = QTimer(self)
        self._reconnect_timer.setSingleShot(True)
        self._reconnect_timer.timeout.connect(self._try_reconnect)

        self.setAcceptDrops(True)

        self._build_ui()

        # Desktop notifications via the system tray (needs a visible icon)
        icon = self._make_app_icon()
        self.setWindowIcon(icon)
        self.tray = QSystemTrayIcon(icon, self)
        self.tray.setToolTip("Bastion")
        if self.notify_desktop:
            self.tray.show()
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
            ("⚙ Options",  self._show_options_dialog, True),
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

        header = QWidget()
        hl = QHBoxLayout(header)
        hl.setContentsMargins(0, 0, 10, 0)
        hl.setSpacing(0)
        self.room_title = QLabel("Select a room")
        self.room_title.setStyleSheet("font-size:12pt; font-weight:bold; padding:10px 16px;")
        hl.addWidget(self.room_title)
        hl.addStretch()
        self.pins_btn = QPushButton("📌")
        self.pins_btn.setFixedSize(32, 32)
        self.pins_btn.setToolTip("Pinned messages")
        self.pins_btn.setProperty("secondary", True)
        self.pins_btn.setStyle(self.pins_btn.style())
        self.pins_btn.clicked.connect(self._request_pins)
        hl.addWidget(self.pins_btn)
        cp_lay.addWidget(header)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setFixedHeight(1)
        sep.setStyleSheet(f"background:{BORDER}; border:none;")
        cp_lay.addWidget(sep)

        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Search messages…   (Esc to close)")
        self.search_bar.textChanged.connect(self._apply_search)
        self.search_bar.hide()
        cp_lay.addWidget(self.search_bar)
        QShortcut(QKeySequence.StandardKey.Find, self, activated=self._toggle_search)
        QShortcut(QKeySequence("Escape"), self.search_bar, activated=self._close_search,
                  context=Qt.ShortcutContext.WidgetShortcut)

        self.chat_area = ChatArea()
        cp_lay.addWidget(self.chat_area, 1)

        self.edit_banner = QLabel("  ✏️  Editing message — press Esc to cancel")
        self.edit_banner.setStyleSheet(
            f"background: {ELEV}; color: {AMBER}; font-size: 8pt; padding: 3px 10px;"
        )
        self.edit_banner.hide()
        cp_lay.addWidget(self.edit_banner)

        self.reply_banner = QLabel("")
        self.reply_banner.setStyleSheet(
            f"background: {ELEV}; color: {OTHER_NAME}; font-size: 8pt; padding: 3px 10px;"
        )
        self.reply_banner.hide()
        cp_lay.addWidget(self.reply_banner)

        self.typing_label = QLabel("")
        self.typing_label.setFixedHeight(18)
        self.typing_label.setStyleSheet(
            f"color: {MUTED}; font-size: 8pt; font-style: italic; padding: 0px 16px;"
        )
        cp_lay.addWidget(self.typing_label)

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
        self.msg_entry.edit_cancelled.connect(self._on_input_escape)
        self.msg_entry.image_pasted.connect(self._send_pasted_image)
        self.msg_entry.files_pasted.connect(self._send_dropped_files)
        self.msg_entry.textChanged.connect(self._maybe_send_typing)
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
        # Prefill from this session, else from the last successful connection
        # (host/port/username/TLS only — passwords are never stored).
        prefill = self.connect_params or {
            "host":     str(self.settings.value("last_host", "localhost")),
            "port":     str(self.settings.value("last_port", "8765")),
            "username": str(self.settings.value("last_username", "")),
            "use_tls":  self.settings.value("last_tls", False, type=bool),
        }
        dlg = ConnectDialog(self, prefill=prefill)
        if dlg.exec() == QDialog.DialogCode.Accepted and dlg.result_data:
            self._connect(dlg.result_data)

    def _show_options_dialog(self):
        connected = bool(self.worker) and bool(self.username)
        dlg = OptionsDialog(
            self, self.username or "you", self.my_profile,
            connected=connected, play_sound=self.play_sound_on_message,
            notify_desktop=self.notify_desktop,
        )
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        if dlg.play_sound_result is not None:
            self.play_sound_on_message = dlg.play_sound_result
            self.settings.setValue("play_sound_on_message", self.play_sound_on_message)
        if dlg.notify_result is not None:
            self.notify_desktop = dlg.notify_result
            self.settings.setValue("notify_desktop", self.notify_desktop)
            self.tray.setVisible(self.notify_desktop)
        if dlg.profile_result is not None and self.worker:
            self.worker.send_msg({"type": "update_profile", **dlg.profile_result})

    def _cleanup_connection(self):
        """Tear down the worker thread and key material without touching UI state."""
        if self.worker:
            self.worker.close()
        if self.thread:
            self.thread.quit()
            self.thread.wait(2000)
        self.worker = None
        self.thread = None
        self.fernet = None
        self._secret = ""

    def _try_reconnect(self):
        if self._manual_disconnect or self.worker or not self.connect_params:
            return
        self._set_status("Reconnecting…", AMBER)
        self._connect(self.connect_params)

    def _connect(self, params: dict):
        self._reconnect_timer.stop()
        self._cleanup_connection()
        self._manual_disconnect = False
        self.connect_params = params
        self.username = params["username"]
        self.settings.setValue("last_host", params["host"])
        self.settings.setValue("last_port", params["port"])
        self.settings.setValue("last_username", params["username"])
        self.settings.setValue("last_tls", params.get("use_tls", False))
        # Message key: prefer the dedicated passphrase (never sent to the
        # server) and fall back to the server password for compatibility.
        # The Fernet itself is built on auth_result, once the server has
        # told us its per-server KDF salt.
        self._custom_key = bool(params.get("enc_passphrase"))
        self._secret = params.get("enc_passphrase") or params["server_password"]
        self.fernet = None

        self._set_status(f"Connecting to {params['host']}:{params['port']}…", AMBER)

        self.worker = WebSocketWorker(params)
        self.thread = QThread()
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.message_received.connect(self._handle_message)
        self.thread.start()

    def _disconnect(self, silent: bool = False):
        self._manual_disconnect = True
        self._authed = False
        self._reconnect_timer.stop()
        self._reconnect_attempts = 0
        self._rejoin_room = None
        was_connected = self.worker is not None
        self._cleanup_connection()
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
        self.profile_cache = {}
        self.my_profile = {"bio": "", "avatar": None, "banner": None}
        self._hover_timer.stop()
        self._hover_user = None
        self.profile_card.hide()
        self._msg_widgets.clear()
        self.unread.clear()
        self._typers.clear()
        self.typing_label.setText("")
        self._cancel_edit()
        self._cancel_reply()
        self._reset_message_flow()

    # -----------------------------------------------------------------------
    # Incoming message dispatch
    # -----------------------------------------------------------------------

    def _handle_message(self, msg: dict):
        t = msg.get("type")

        if t == "auth_result":
            if msg["success"]:
                # Derive the message key now that we know the server's KDF
                # salt (older servers don't send one: use the legacy salt).
                salt = _LEGACY_KDF_SALT
                salt_hex = msg.get("kdf_salt")
                if salt_hex:
                    try:
                        salt = bytes.fromhex(salt_hex)
                    except ValueError:
                        pass
                self.fernet = Fernet(derive_key(self._secret, salt))
                self._secret = ""
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
                self._authed = True
                self._reconnect_attempts = 0
                self._refresh_rooms()
                self._apply_max_file(msg.get("max_file_mb", _DEFAULT_MAX_FILE_BYTES / 1_048_576))
                self.chat_area.add_system("Connected — messages are encrypted before they leave this device.")
                if self.my_roles:
                    self.chat_area.add_system("Your roles: " + ", ".join(self.my_roles))
                self.worker.send_msg({"type": "get_profile", "username": self.username})
                # After an auto-reconnect, hop back into the room we were in
                if self._rejoin_room and self._rejoin_room in self.rooms:
                    self.room_list.setCurrentRow(self.rooms.index(self._rejoin_room))
                self._rejoin_room = None
            else:
                self._set_status("Not connected", RED)
                # Don't loop retries against a failing login (changed password, kick)
                self._manual_disconnect = True
                self._authed = False
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
                self._prefetch_profiles(msg["users"])

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
                self._msg_widgets.clear()
                self._cancel_edit()
                self._cancel_reply()
                self._reset_message_flow()
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
                self._prefetch_profiles([user])

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

        elif t == "profile":
            username = msg.get("username")
            if not username:
                return
            data = {
                "bio": msg.get("bio", ""), "avatar": msg.get("avatar"),
                "banner": msg.get("banner"), "roles": msg.get("roles", []),
                "is_admin": msg.get("is_admin", False), "_ts": time.time(),
            }
            self.profile_cache[username] = data
            if username == self.username:
                self.my_profile = {"bio": data["bio"], "avatar": data["avatar"], "banner": data["banner"]}
            if self._hover_user == username and self.profile_card.isVisible():
                self._render_profile_popup(username, data)
            if username in self.room_users.get(self.current_room, []):
                self._refresh_users()

        elif t == "profile_update_result":
            color = SYSTEM if msg.get("success") else RED
            self.chat_area.add_system(msg.get("message", ""), color=color)

        elif t == "message_edited":
            w = self._msg_widgets.get(msg.get("id", ""))
            if w and self.fernet:
                try:
                    new = unpad_plaintext(self.fernet.decrypt(msg["content"].encode())).decode()
                except Exception:
                    new = "[unable to decrypt]"
                w.update_text(new)

        elif t == "message_deleted":
            w = self._msg_widgets.pop(msg.get("id", ""), None)
            if w:
                w.setParent(None)
                w.deleteLater()

        elif t == "reaction_update":
            w = self._msg_widgets.get(msg.get("id", ""))
            if w:
                w.set_reactions(msg.get("reactions", {}), self.username)

        elif t == "typing":
            if msg.get("room") == self.current_room and msg.get("username") != self.username:
                self._typers[msg["username"]] = time.time() + 4
                self._update_typing_label()

        elif t == "room_activity":
            room = msg.get("room")
            if room and room != self.current_room:
                self.unread[room] = self.unread.get(room, 0) + 1
                self._update_room_badges()

        elif t == "pins_list":
            self._show_pins_dialog(msg.get("room", ""), msg.get("pins", []))

        elif t == "_connect_error":
            self._set_status("Connection failed", RED)
            QMessageBox.critical(self, "Connection Error", msg.get("message", ""))

        elif t == "_connection_lost":
            if self._manual_disconnect or not self._authed or not self.connect_params:
                self.chat_area.add_system("Disconnected from server.")
                self._reset_ui()
            else:
                # Unexpected drop after a successful session: retry with backoff
                self._rejoin_room = self.current_room or self._rejoin_room
                self._cleanup_connection()
                self._reset_ui()
                delay = min(30, 2 ** min(self._reconnect_attempts, 5))
                self._reconnect_attempts += 1
                self.chat_area.add_system(
                    f"Connection lost — reconnecting in {delay}s…", color=AMBER
                )
                self._set_status(f"Reconnecting in {delay}s…", AMBER)
                self._reconnect_timer.start(delay * 1000)

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
            content = unpad_plaintext(self.fernet.decrypt(msg["content"].encode())).decode()
        except Exception:
            content = "[unable to decrypt]"
        is_self = msg["username"] == self.username
        mid = msg.get("id")
        sep_added = self._maybe_day_separator(msg.get("timestamp"))
        ts_dt = self._parse_ts(msg.get("timestamp"))
        grouped = (
            not sep_added
            and not msg.get("reply_to")
            and self._last_author == msg["username"]
            and self._last_dim == historical
            and ts_dt is not None and self._last_ts is not None
            and (ts_dt - self._last_ts).total_seconds() < 300
        )
        mw = MessageWidget(msg["username"], msg["timestamp"], is_self, dim=historical,
                           role=self._primary_role(msg["username"]),
                           avatar_b64=self._avatar_for(msg["username"]),
                           msg_id=mid, show_header=not grouped)
        mw.author = msg["username"]
        reply_to = msg.get("reply_to")
        if reply_to:
            orig = self._msg_widgets.get(reply_to)
            if orig is not None:
                excerpt = orig.plaintext.replace("\n", " ")[:100]
                mw.add_quote(f"↩ {orig.author}: {excerpt}")
            else:
                mw.add_quote("↩ (original message unavailable)")
        mw.add_text(content)
        self._last_author = msg["username"]
        self._last_ts = ts_dt
        self._last_dim = historical
        mw._can_edit = is_self and bool(mid)
        mw._can_delete = bool(mid) and (is_self or self.is_admin)
        mw._can_pin = bool(mid) and self.is_admin
        self._wire_message_widget(mw)
        if msg.get("edited"):
            mw.mark_edited()
        if msg.get("reactions"):
            mw.set_reactions(msg["reactions"], self.username)
        mentioned = (not is_self and self.username
                     and re.search(rf"@{re.escape(self.username)}\b", content, re.IGNORECASE))
        if mentioned:
            mw.set_mentioned()
        self.chat_area.add_message(mw)
        if mid:
            self._msg_widgets[mid] = mw
        self._typers.pop(msg["username"], None)
        self._update_typing_label()
        if not historical and not is_self:
            self._notify_message(msg["username"], msg.get("room", ""), mention=bool(mentioned))

    def _avatar_for(self, username: str) -> str | None:
        cached = self.profile_cache.get(username)
        return cached.get("avatar") if cached else None

    def _prefetch_profiles(self, usernames: list[str]):
        """Warm the profile cache for users we don't know about yet, so
        their avatar shows up on messages without needing a hover first."""
        if not self.worker:
            return
        for u in usernames:
            if u not in self.profile_cache:
                self.worker.send_msg({"type": "get_profile", "username": u})

    def _recv_file(self, msg: dict):
        if msg.get("room") != self.current_room:
            return
        is_self = msg["username"] == self.username
        historical = msg.get("historical", False)
        role = self._primary_role(msg["username"])
        avatar_b64 = self._avatar_for(msg["username"])
        try:
            payload = json.loads(unpad_plaintext(self.fernet.decrypt(msg["content"].encode())).decode())
            filename = payload["filename"]
            mimetype = payload.get("mimetype", "application/octet-stream")
            raw      = base64.b64decode(payload["data"])
            caption  = payload.get("caption", "")
        except Exception:
            mw = MessageWidget(msg["username"], msg["timestamp"], is_self, dim=historical,
                                role=role, avatar_b64=avatar_b64)
            mw.add_text("[could not decrypt file]")
            self.chat_area.add_message(mw)
            return

        mid = msg.get("id")
        self._maybe_day_separator(msg.get("timestamp"))
        mw = MessageWidget(msg["username"], msg["timestamp"], is_self, dim=historical,
                           role=role, avatar_b64=avatar_b64, msg_id=mid)
        self._last_author = msg["username"]
        self._last_ts = self._parse_ts(msg.get("timestamp"))
        self._last_dim = historical
        if caption:
            mw.add_text(caption)
        if mimetype in IMAGE_MIME:
            mw.add_image(raw, filename, mimetype)
        elif is_text_file(mimetype, filename):
            mw.add_text_preview(raw, filename)
        else:
            mw.add_file(raw, filename, mimetype)
        mw._can_delete = bool(mid) and (is_self or self.is_admin)
        self._wire_message_widget(mw)
        if msg.get("reactions"):
            mw.set_reactions(msg["reactions"], self.username)
        self.chat_area.add_message(mw)
        if mid:
            self._msg_widgets[mid] = mw
        if not historical and not is_self:
            self._notify_message(msg["username"], msg.get("room", ""))

    def _wire_message_widget(self, mw: MessageWidget):
        mw.edit_requested.connect(self._start_edit)
        mw.delete_requested.connect(self._delete_message)
        mw.react_requested.connect(self._send_react)
        mw.pin_requested.connect(self._pin_message)
        mw.reply_requested.connect(self._start_reply)

    @staticmethod
    def _parse_ts(ts: str | None) -> datetime.datetime | None:
        if not ts:
            return None
        try:
            dt = datetime.datetime.fromisoformat(ts)
            if dt.tzinfo is not None:
                dt = dt.astimezone()
            return dt
        except ValueError:
            return None

    def _maybe_day_separator(self, ts: str | None) -> bool:
        """Insert a '─── Monday, 14 July 2026 ───' line when the day changes."""
        dt = self._parse_ts(ts)
        if dt is None:
            return False
        if dt.date() != self._last_date:
            self._last_date = dt.date()
            self.chat_area.add_system(f"───  {dt:%A, %d %B %Y}  ───", color=MUTED)
            return True
        return False

    def _reset_message_flow(self):
        self._last_author = None
        self._last_ts = None
        self._last_dim = None
        self._last_date = None

    # -----------------------------------------------------------------------
    # Message actions (edit / delete / react / pin)
    # -----------------------------------------------------------------------

    def _start_edit(self, mid: str):
        w = self._msg_widgets.get(mid)
        if not w or not self.worker:
            return
        self._editing_id = mid
        self.msg_entry.setText(w.plaintext)
        self.edit_banner.show()
        self.msg_entry.setFocus()

    def _cancel_edit(self):
        if self._editing_id:
            self._editing_id = None
            self.msg_entry.clear()
        self.edit_banner.hide()

    def _start_reply(self, mid: str):
        w = self._msg_widgets.get(mid)
        if not w or not self.worker:
            return
        self._cancel_edit()
        self._reply_to = mid
        self.reply_banner.setText(f"  ↩  Replying to {w.author} — press Esc to cancel")
        self.reply_banner.show()
        self.msg_entry.setFocus()

    def _cancel_reply(self):
        self._reply_to = None
        self.reply_banner.hide()

    def _on_input_escape(self):
        if self._editing_id:
            self._cancel_edit()
        elif self._reply_to:
            self._cancel_reply()

    # -----------------------------------------------------------------------
    # Client-side message search (Ctrl+F)
    # -----------------------------------------------------------------------

    def _toggle_search(self):
        if self.search_bar.isVisible():
            self._close_search()
        else:
            self.search_bar.show()
            self.search_bar.setFocus()

    def _close_search(self):
        self.search_bar.clear()
        self.search_bar.hide()
        self.msg_entry.setFocus()

    def _apply_search(self, term: str):
        term = term.strip().lower()
        for w in self.chat_area.widgets():
            if isinstance(w, MessageWidget):
                w.setVisible(not term or term in w.plaintext.lower()
                             or term in w.author.lower())
            else:
                # System lines etc. are noise while filtering
                w.setVisible(not term)

    def _delete_message(self, mid: str):
        if not (self.worker and self.current_room):
            return
        answer = QMessageBox.question(
            self, "Delete Message", "Delete this message for everyone?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if answer == QMessageBox.StandardButton.Yes:
            self.worker.send_msg({"type": "delete_message",
                                  "room": self.current_room, "id": mid})

    def _send_react(self, mid: str, emoji: str):
        if self.worker and self.current_room:
            self.worker.send_msg({"type": "react", "room": self.current_room,
                                  "id": mid, "emoji": emoji})

    def _pin_message(self, mid: str):
        if self.worker and self.current_room:
            self.worker.send_msg({"type": "pin_message",
                                  "room": self.current_room, "id": mid})

    def _request_pins(self):
        if self.worker and self.current_room:
            self.worker.send_msg({"type": "get_pins", "room": self.current_room})

    def _show_pins_dialog(self, room: str, pins: list):
        dlg = QDialog(self)
        dlg.setWindowTitle(f"Pinned — #{room}")
        dlg.setMinimumWidth(420)
        lay = QVBoxLayout(dlg)
        lay.setSpacing(8)
        if not pins:
            lay.addWidget(QLabel("No pinned messages in this room."))
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        inner = QWidget()
        ilay = QVBoxLayout(inner)
        ilay.setSpacing(6)
        for pin in pins[:50]:
            try:
                text = unpad_plaintext(self.fernet.decrypt(pin["content"].encode())).decode()
            except Exception:
                text = "[unable to decrypt]"
            row = QFrame()
            row.setStyleSheet(f"background: {ELEV}; border-radius: 6px;")
            rl = QVBoxLayout(row)
            rl.setContentsMargins(10, 6, 10, 8)
            head = QHBoxLayout()
            author = QLabel(pin.get("username", "?"))
            author.setStyleSheet("font-weight: bold; background: transparent;")
            head.addWidget(author)
            ts = QLabel(format_timestamp(pin.get("timestamp")))
            ts.setStyleSheet(f"color: {MUTED}; font-size: 8pt; background: transparent;")
            head.addWidget(ts)
            head.addStretch()
            if self.is_admin:
                unpin = QPushButton("Unpin")
                unpin.setProperty("secondary", True)
                unpin.setStyle(unpin.style())
                unpin.setFixedHeight(24)
                unpin.clicked.connect(
                    lambda _=False, m=pin.get("id"), d=dlg: (self._unpin_message(m), d.accept())
                )
                head.addWidget(unpin)
            rl.addLayout(head)
            body = QLabel(text)
            body.setWordWrap(True)
            body.setTextFormat(Qt.TextFormat.PlainText)
            body.setStyleSheet("background: transparent;")
            rl.addWidget(body)
            ilay.addWidget(row)
        ilay.addStretch()
        scroll.setWidget(inner)
        lay.addWidget(scroll, 1)
        close = QPushButton("Close")
        close.clicked.connect(dlg.accept)
        lay.addWidget(close, 0, Qt.AlignmentFlag.AlignRight)
        dlg.resize(460, 380)
        dlg.exec()

    def _unpin_message(self, mid: str):
        if self.worker and self.current_room and mid:
            self.worker.send_msg({"type": "unpin_message",
                                  "room": self.current_room, "id": mid})

    # -----------------------------------------------------------------------
    # Typing indicator / unread badges / notifications
    # -----------------------------------------------------------------------

    def _maybe_send_typing(self):
        if not (self.worker and self.current_room):
            return
        if not self.msg_entry.text().strip():
            return
        now = time.time()
        if now - self._last_typing_sent > 2.5:
            self._last_typing_sent = now
            self.worker.send_msg({"type": "typing", "room": self.current_room})

    def _update_typing_label(self):
        now = time.time()
        self._typers = {u: exp for u, exp in self._typers.items() if exp > now}
        names = sorted(self._typers)
        if not names:
            text = ""
        elif len(names) == 1:
            text = f"{names[0]} is typing…"
        elif len(names) == 2:
            text = f"{names[0]} and {names[1]} are typing…"
        else:
            text = "Several people are typing…"
        self.typing_label.setText(text)

    def _update_room_badges(self):
        for i, room in enumerate(self.rooms):
            item = self.room_list.item(i)
            if item is None:
                continue
            n = self.unread.get(room, 0)
            item.setText(f"#  {room}" + (f"   ● {n}" if n else ""))

    def _notify_message(self, sender: str, room: str, mention: bool = False):
        if mention or self.play_sound_on_message:
            QApplication.beep()
        if self.notify_desktop and not self.isActiveWindow() and self.tray.isVisible():
            # Content-free on purpose: message text never leaves the chat view
            body = (f"{sender} mentioned you in #{room}" if mention
                    else f"New message from {sender} in #{room}")
            self.tray.showMessage("Bastion", body,
                                  QSystemTrayIcon.MessageIcon.Information, 4000)

    def _make_app_icon(self) -> QIcon:
        px = QPixmap(64, 64)
        px.fill(Qt.GlobalColor.transparent)
        p = QPainter(px)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setBrush(QColor(ACCENT))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(0, 0, 64, 64)
        p.setPen(QColor("#ffffff"))
        p.setFont(QFont("Segoe UI", 28, QFont.Weight.Bold))
        p.drawText(px.rect(), Qt.AlignmentFlag.AlignCenter, "B")
        p.end()
        return QIcon(px)

    # -----------------------------------------------------------------------
    # Paste / drag-and-drop attachments
    # -----------------------------------------------------------------------

    def dragEnterEvent(self, event):
        if (event.mimeData().hasUrls() and self.worker
                and self.fernet and self.current_room):
            event.acceptProposedAction()

    def dropEvent(self, event):
        paths = [u.toLocalFile() for u in event.mimeData().urls() if u.isLocalFile()]
        self._send_dropped_files(paths)

    def _send_dropped_files(self, paths: list):
        if not (self.worker and self.fernet and self.current_room):
            QMessageBox.information(self, "Not Connected", "Join a room before sending files.")
            return
        for path in paths[:5]:
            if os.path.isfile(path):
                self._send_file_path(path)

    def _send_pasted_image(self, image: QImage):
        if not (self.worker and self.fernet and self.current_room):
            QMessageBox.information(self, "Not Connected", "Join a room before sending images.")
            return
        buf = QBuffer()
        buf.open(QBuffer.OpenModeFlag.WriteOnly)
        image.save(buf, "PNG")
        raw = bytes(buf.data())
        if len(raw) > self.max_file_bytes:
            QMessageBox.warning(self, "Image Too Large",
                                f"Pasted image is {len(raw) / 1_048_576:.1f} MB — over the server limit.")
            return
        answer = QMessageBox.question(
            self, "Paste Image", f"Send pasted image ({max(1, len(raw) // 1024)} KB)?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        fname = datetime.datetime.now().strftime("pasted_%H%M%S.png")
        caption = self.msg_entry.text().strip()
        self.msg_entry.clear()
        self._send_file_bytes(raw, fname, "image/png", caption)

    # -----------------------------------------------------------------------
    # UI helpers
    # -----------------------------------------------------------------------

    def _refresh_rooms(self):
        self.room_list.blockSignals(True)
        self.room_list.clear()
        for room in self.rooms:
            self.room_list.addItem(f"#  {room}")
        self._update_room_badges()
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
            self.user_list.addItem(item)
            self.user_list.setItemWidget(item, row)

    def _make_user_row(self, user: str, roles: list[str]) -> QWidget:
        row = UserRow(user)
        row.setStyleSheet("background: transparent;")
        row.hovered.connect(self._on_user_row_hover)
        row.unhovered.connect(self._on_user_row_unhover)
        lay = QHBoxLayout(row)
        lay.setContentsMargins(8, 0, 10, 0)
        lay.setSpacing(6)
        vc = Qt.AlignmentFlag.AlignVCenter
        is_self = user == self.username

        avatar_lbl = QLabel()
        avatar_lbl.setFixedSize(22, 22)
        cached = self.profile_cache.get(user)
        avatar_px = b64_to_pixmap(cached["avatar"]) if cached else None
        if avatar_px:
            avatar_lbl.setPixmap(circular_pixmap(avatar_px, 22))
        else:
            avatar_lbl.setText(user[:1].upper())
            avatar_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            avatar_lbl.setStyleSheet(
                f"background-color: {avatar_color(user)}; color: #fff; border-radius: 11px;"
                " font-weight: bold; font-size: 8pt;"
            )
        lay.addWidget(avatar_lbl, 0, vc)

        name = QLabel(("@" if is_self else "") + user)
        name.setStyleSheet(
            f"color: {SELF_NAME if is_self else TEXT}; background: transparent;"
            f"{' font-weight: bold;' if is_self else ''}"
        )
        lay.addWidget(name, 0, vc)
        lay.addStretch()
        # Show up to two role chips to keep the row compact
        for r in roles[:2]:
            lay.addWidget(make_role_chip(r, self.role_colors[r]), 0, vc)
        return row

    # -----------------------------------------------------------------------
    # Profile hover card
    # -----------------------------------------------------------------------

    def _on_user_row_hover(self, username: str, global_pos: QPoint):
        self._hover_user = username
        self._hover_pos = global_pos
        self._hover_timer.start(350)

    def _on_user_row_unhover(self):
        self._hover_timer.stop()
        self._hover_user = None
        self.profile_card.hide()

    def _show_profile_popup(self):
        username = self._hover_user
        if not username or not self._hover_pos:
            return
        cached = self.profile_cache.get(username)
        self._render_profile_popup(username, cached)
        if self.worker and (not cached or time.time() - cached.get("_ts", 0) > 20):
            self.worker.send_msg({"type": "get_profile", "username": username})

    def _render_profile_popup(self, username: str, data: dict | None):
        roles = [r for r in self.user_roles.get(username, []) if r in self.role_colors]
        bio = (data or {}).get("bio", "")
        avatar_b64 = (data or {}).get("avatar")
        banner_b64 = (data or {}).get("banner")
        self.profile_card.set_data(
            username, avatar_b64, banner_b64, bio, roles, self.role_colors,
            is_self=(username == self.username),
        )
        if self._hover_pos:
            self.profile_card.show_near(self._hover_pos)

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
        self._msg_widgets.clear()
        self._typers.clear()
        self._update_typing_label()
        self._cancel_edit()
        self._cancel_reply()
        self._reset_message_flow()
        self._close_search()
        self.unread.pop(room, None)
        self._update_room_badges()
        self.worker.send_msg({"type": "join_room", "room": room})

    # -----------------------------------------------------------------------
    # Sending
    # -----------------------------------------------------------------------

    def _send_message(self):
        content = self.msg_entry.text().strip()
        if self._editing_id:
            mid = self._editing_id
            if content and self.worker and self.fernet and self.current_room:
                enc = self.fernet.encrypt(pad_plaintext(content.encode())).decode()
                self.worker.send_msg({"type": "edit_message", "room": self.current_room,
                                      "id": mid, "content": enc})
            self._cancel_edit()
            return
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
        enc = self.fernet.encrypt(pad_plaintext(content.encode())).decode()
        out = {"type": "send_message", "room": self.current_room, "content": enc}
        if self._reply_to:
            out["reply_to"] = self._reply_to
            self._cancel_reply()
        self.worker.send_msg(out)

    def _handle_slash_command(self, text: str):
        parts = text[1:].split()
        if not parts:
            return
        command = parts[0].lower()
        args = parts[1:]

        if command == "help":
            self._show_help()
            return

        if not self.worker:
            self.chat_area.add_system("Not connected.", color=RED)
            return

        self.worker.send_msg({"type": "admin_command", "command": command, "args": args})

    def _show_help(self):
        everyone = [
            "  /online                           List connected users",
            "  /listusers                        List all registered users",
            "  /listrooms                        List all rooms",
            "  /setmypassword <new_password>     Change your own password",
        ]
        admin_only = [
            "  /kick <username>                  Kick a user",
            "  /adduser <username> <pass>        Add a new user",
            "  /removeuser <username>            Remove a user",
            "  /addroom <name>                   Create a room",
            "  /removeroom <name>                Remove a room",
            "  /setpassword <new_password>       Change server password",
            "  /setmaxfile <MB>                  Set max file upload size",
            "  /history on|off                   Enable/disable chat history",
            "  /makeadmin <username>             Grant admin privileges",
            "  /removeadmin <username>           Revoke admin privileges",
            "  /role add <name> [#color]         Create a role",
            "  /role del <name>                  Delete a role",
            "  /role rooms <name> [room ...]     Set rooms a role grants",
            "  /role list                        List roles and members",
            "  /grantrole <username> <role>      Give a user a role",
            "  /revokerole <username> <role>     Remove a role from a user",
            "  /blocked                          List blocked IPs",
            "  /unblock <ip>                     Unblock an IP address",
            "  /ratelimit on|off                 Enable/disable rate limiting",
            "  /ratelimit attempts <N>           Set max failed attempts",
            "  /ratelimit window <seconds>       Set the failure counting window",
            "  /ratelimit block <seconds>        Set block duration",
        ]

        self.chat_area.add_system("Available slash commands:")
        for line in everyone:
            self.chat_area.add_system(line)
        if self.is_admin:
            self.chat_area.add_system("Admin commands:", color=AMBER)
            for line in admin_only:
                self.chat_area.add_system(line)

    def _apply_max_file(self, mb: float):
        self.max_file_bytes = int(mb * 1_048_576)
        self._attach_btn.setToolTip(f"Attach image or file  (max {mb:g} MB)")

    def _attach_file(self):
        if not self.worker or not self.fernet or not self.current_room:
            QMessageBox.information(self, "Not Connected", "Join a room before attaching files.")
            return
        path, _ = QFileDialog.getOpenFileName(self, "Attach File or Image")
        if path:
            self._send_file_path(path)

    def _send_file_path(self, path: str):
        """Size-check, read, and send a file from disk (attach/drop/paste path)."""
        if not self.worker or not self.fernet or not self.current_room:
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

        try:
            with open(path, "rb") as fh:
                raw = fh.read()
        except Exception as exc:
            QMessageBox.critical(self, "Error", f"Could not read file:\n{exc}")
            return
        self._send_file_bytes(raw, filename, mime, caption)

    def _send_file_bytes(self, raw: bytes, filename: str, mime: str, caption: str = ""):
        if not self.worker or not self.fernet or not self.current_room:
            return
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            payload: dict = {
                "filename": filename,
                "mimetype": mime,
                "data":     base64.b64encode(raw).decode(),
            }
            if caption:
                payload["caption"] = caption

            enc = self.fernet.encrypt(pad_plaintext(json.dumps(payload).encode())).decode()
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
