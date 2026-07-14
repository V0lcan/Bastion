#!/usr/bin/env python3
"""Bastion Client - PyQt6 GUI with end-to-end encryption and file/image sharing"""

import sys
import json
import asyncio
import base64
import os
import mimetypes
import re
import html

_missing = []
try:
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QDialog, QSplitter,
        QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit,
        QListWidget, QListWidgetItem, QFrame, QFormLayout,
        QMessageBox, QScrollArea, QFileDialog,
    )
    from PyQt6.QtCore import (
        Qt, QThread, QObject, pyqtSignal, pyqtSlot,
        QTimer, QEvent, QBuffer, QSize,
    )
    from PyQt6.QtGui import QFont, QColor, QPixmap, QMovie
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

_KDF_SALT = b"chat_platform_v1"


def derive_key(server_password: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_KDF_SALT,
        iterations=100_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(server_password.encode()))


# ---------------------------------------------------------------------------
# Stylesheet
# ---------------------------------------------------------------------------

DARK_STYLE = """
QWidget {
    background-color: #1e1e1e;
    color: #d4d4d4;
    font-family: "Segoe UI";
    font-size: 10pt;
}
QDialog            { background-color: #252525; }
QMainWindow        { background-color: #1e1e1e; }
QScrollArea        { border: none; background-color: #1e1e1e; }
QSplitter::handle  { background-color: #333; width: 1px; height: 1px; }

QListWidget {
    background-color: #252525;
    border: none;
    outline: none;
    color: #cccccc;
}
QListWidget::item                    { padding: 5px 10px; border-radius: 3px; }
QListWidget::item:selected           { background-color: #094771; color: #fff; }
QListWidget::item:hover:!selected    { background-color: #2a2d2e; }

QLineEdit {
    background-color: #2d2d2d;
    border: 1px solid #3c3c3c;
    border-radius: 4px;
    color: #d4d4d4;
    padding: 6px 10px;
    selection-background-color: #094771;
}
QLineEdit:focus { border-color: #0e639c; }

QPushButton {
    background-color: #0e639c;
    color: #fff;
    border: none;
    border-radius: 4px;
    padding: 6px 14px;
}
QPushButton:hover   { background-color: #1177bb; }
QPushButton:pressed { background-color: #0a4f7e; }
QPushButton[secondary="true"]        { background-color: #3c3c3c; color: #ccc; }
QPushButton[secondary="true"]:hover  { background-color: #4a4a4a; }

QScrollBar:vertical               { background: #1e1e1e; width: 8px; border: none; }
QScrollBar::handle:vertical       { background: #444; border-radius: 4px; min-height: 20px; }
QScrollBar::handle:vertical:hover { background: #555; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar:horizontal             { background: #1e1e1e; height: 8px; border: none; }
QScrollBar::handle:horizontal     { background: #444; border-radius: 4px; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }

QFormLayout QLabel { color: #aaa; }
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
            "QFrame { background-color: #2d2d2d; border: 1px solid #444;"
            " border-radius: 6px; } QLabel { border: none; background: transparent; }"
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
        name_lbl.setStyleSheet("color: #d4d4d4; font-weight: bold;")
        size_lbl = QLabel(self._fmt(len(data)))
        size_lbl.setStyleSheet("color: #888; font-size: 8pt;")
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


# ---------------------------------------------------------------------------
# Message row widget
# ---------------------------------------------------------------------------

class MessageWidget(QFrame):
    """Header (username + timestamp) followed by any number of content items."""

    def __init__(self, username: str | None, timestamp: str | None,
                 is_self: bool = False, dim: bool = False):
        super().__init__()
        self.setStyleSheet(
            "QFrame { border: none; background: transparent; }"
            "QFrame:hover { background-color: #232323; }"
        )
        self._lay = QVBoxLayout(self)
        self._lay.setContentsMargins(10, 4, 10, 4)
        self._lay.setSpacing(3)
        self._dim = dim          # True for replayed history messages
        self._text_color = "#888888" if dim else "#d4d4d4"

        if username and timestamp:
            hrow = QHBoxLayout()
            hrow.setContentsMargins(0, 0, 0, 0)
            hrow.setSpacing(8)
            # Dim the username colour for historical messages
            if dim:
                color = "#8a6a5a" if is_self else "#3a7090"
            else:
                color = "#ce9178" if is_self else "#4fc1ff"
            name = QLabel(username)
            name.setStyleSheet(
                f"color: {color}; font-weight: bold; background: transparent;"
            )
            ts = QLabel(timestamp)
            ts.setStyleSheet("color: #444; font-size: 8pt; background: transparent;")
            hrow.addWidget(name)
            hrow.addWidget(ts)
            hrow.addStretch()
            self._lay.addLayout(hrow)

    def add_text(self, text: str) -> "MessageWidget":
        lbl = QLabel()
        lbl.setWordWrap(True)
        lbl.setTextFormat(Qt.TextFormat.RichText)
        lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        lbl.setOpenExternalLinks(False)
        lbl.setStyleSheet(
            f"color: {self._text_color}; padding-left: 2px; background: transparent;"
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
        self._content.setStyleSheet("background-color: #1e1e1e;")
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

    def add_system(self, text: str, color: str = "#608b4e"):
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
# Connect dialog
# ---------------------------------------------------------------------------

class ConnectDialog(QDialog):
    def __init__(self, parent=None, prefill: dict | None = None):
        super().__init__(parent)
        self.setWindowTitle("Connect to Bastion")
        self.setFixedSize(360, 320)
        self.result_data: dict | None = None

        lay = QVBoxLayout(self)
        lay.setSpacing(12)
        lay.setContentsMargins(28, 22, 28, 22)

        title = QLabel("Connect to Bastion")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("font-size: 13pt; font-weight: bold; padding-bottom: 6px;")
        lay.addWidget(title)

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
        ]:
            edit = QLineEdit(pf.get(key, default))
            if secret:
                edit.setEchoMode(QLineEdit.EchoMode.Password)
            form.addRow(f"{label}:", edit)
            self._fields[key] = edit

        lay.addLayout(form)
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
        if not all(data.values()):
            QMessageBox.warning(self, "Missing Fields", "All fields are required.")
            return
        try:
            int(data["port"])
        except ValueError:
            QMessageBox.warning(self, "Invalid Port", "Port must be a number.")
            return
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
        uri = f"ws://{self.params['host']}:{self.params['port']}"
        try:
            async with websockets.connect(uri, max_size=20 * 1024 * 1024) as ws:
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
        self.max_file_bytes: int = _DEFAULT_MAX_FILE_BYTES
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
        topbar.setFixedHeight(42)
        topbar.setStyleSheet("background:#2d2d2d; border-bottom:1px solid #383838;")
        tb = QHBoxLayout(topbar)
        tb.setContentsMargins(14, 0, 14, 0)

        self.status_label = QLabel("Not connected")
        self.status_label.setStyleSheet("color:#888; font-size:9pt;")
        tb.addWidget(self.status_label)
        tb.addStretch()

        self.lock_label = QLabel("  🔒 Encrypted")
        self.lock_label.setStyleSheet("color:#4ec94e; font-size:9pt;")
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
        sidebar.setFixedWidth(200)
        sidebar.setStyleSheet("background:#252525;")
        sb = QVBoxLayout(sidebar)
        sb.setContentsMargins(0, 0, 0, 0)
        sb.setSpacing(0)

        for caption, attr, weight in [("ROOMS", "room_list", 2), ("USERS", "user_list", 1)]:
            hdr = QLabel(caption)
            hdr.setStyleSheet("color:#777; font-size:8pt; font-weight:bold; padding:10px 10px 3px 10px;")
            sb.addWidget(hdr)
            lw = QListWidget()
            lw.setFrameShape(QFrame.Shape.NoFrame)
            lw.setFont(QFont("Segoe UI", 10))
            sb.addWidget(lw, weight)
            setattr(self, attr, lw)

        self.room_list.currentRowChanged.connect(self._on_room_changed)
        splitter.addWidget(sidebar)

        # ── Chat panel ────────────────────────────────────────────────────
        cp = QWidget()
        cp_lay = QVBoxLayout(cp)
        cp_lay.setContentsMargins(0, 0, 0, 0)
        cp_lay.setSpacing(0)

        self.room_title = QLabel("Select a room")
        self.room_title.setStyleSheet("font-size:13pt; font-weight:bold; padding:8px 14px;")
        cp_lay.addWidget(self.room_title)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setFixedHeight(1)
        sep.setStyleSheet("background:#383838; border:none;")
        cp_lay.addWidget(sep)

        self.chat_area = ChatArea()
        cp_lay.addWidget(self.chat_area, 1)

        # ── Input bar ─────────────────────────────────────────────────────
        ibar = QWidget()
        ibar.setStyleSheet("background:#252525; border-top:1px solid #383838;")
        ir = QHBoxLayout(ibar)
        ir.setContentsMargins(10, 8, 10, 8)
        ir.setSpacing(6)

        self._attach_btn = QPushButton("＋")
        attach = self._attach_btn
        attach.setFixedSize(36, 36)
        attach.setToolTip("Attach image or file  (max 8 MB)")
        attach.setStyleSheet(
            "QPushButton{background:#3a3a3a;color:#aaa;border-radius:18px;"
            "font-size:15pt;padding:0;border:none;}"
            "QPushButton:hover{background:#4a4a4a;color:#ddd;}"
        )
        attach.clicked.connect(self._attach_file)
        ir.addWidget(attach)

        self.msg_entry = QLineEdit()
        self.msg_entry.setPlaceholderText("Type a message…")
        self.msg_entry.returnPressed.connect(self._send_message)
        self.msg_entry.installEventFilter(self)
        ir.addWidget(self.msg_entry)

        send = QPushButton("Send")
        send.setFixedWidth(72)
        send.clicked.connect(self._send_message)
        ir.addWidget(send)

        cp_lay.addWidget(ibar)
        splitter.addWidget(cp)
        splitter.setSizes([200, 840])

    # -----------------------------------------------------------------------
    # Key events (Up/Down history in input)
    # -----------------------------------------------------------------------

    def eventFilter(self, obj, event):
        if obj is self.msg_entry and event.type() == QEvent.Type.KeyPress:
            k = event.key()
            if k == Qt.Key.Key_Up:   self._history_up();   return True
            if k == Qt.Key.Key_Down: self._history_down(); return True
        return super().eventFilter(obj, event)

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
        self.fernet = Fernet(derive_key(params["server_password"]))

        self.status_label.setText(f"Connecting to {params['host']}:{params['port']}…")
        self.status_label.setStyleSheet("color:#e8a030; font-size:9pt;")

        self.worker = WebSocketWorker(params)
        self.thread = QThread()
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.message_received.connect(self._handle_message)
        self.thread.start()

    def _disconnect(self, silent: bool = False):
        if self.worker:
            self.worker.close()
        if self.thread:
            self.thread.quit()
            self.thread.wait(2000)
        self.worker = None
        self.thread = None
        self.fernet = None
        self._reset_ui()

    def _reset_ui(self):
        self.current_room = None
        self.rooms = []
        self.room_users = {}
        self.room_list.clear()
        self.user_list.clear()
        self.room_title.setText("Select a room")
        self.status_label.setText("Not connected")
        self.status_label.setStyleSheet("color:#888; font-size:9pt;")
        self.lock_label.hide()
        self._apply_max_file(_DEFAULT_MAX_FILE_BYTES / 1_048_576)

    # -----------------------------------------------------------------------
    # Incoming message dispatch
    # -----------------------------------------------------------------------

    def _handle_message(self, msg: dict):
        t = msg.get("type")

        if t == "auth_result":
            if msg["success"]:
                self.status_label.setText(f"Connected as {self.username}")
                self.status_label.setStyleSheet("color:#4ec94e; font-size:9pt;")
                self.lock_label.show()
                self.rooms = msg.get("rooms", [])
                self._refresh_rooms()
                self._apply_max_file(msg.get("max_file_mb", _DEFAULT_MAX_FILE_BYTES / 1_048_576))
                self.chat_area.add_system("Connected — messages are end-to-end encrypted.")
            else:
                self.status_label.setText("Not connected")
                self.status_label.setStyleSheet("color:#cc4444; font-size:9pt;")
                QMessageBox.critical(self, "Auth Failed", msg.get("message", "Unknown error"))

        elif t == "rooms_list":
            self.rooms = msg["rooms"]
            self._refresh_rooms()

        elif t == "users_list":
            self.room_users[msg["room"]] = msg["users"]
            if msg["room"] == self.current_room:
                self._refresh_users()

        elif t == "room_message":
            self._recv_text(msg, historical=msg.get("historical", False))

        elif t == "file_message":
            self._recv_file(msg)

        elif t == "user_joined":
            room, user = msg["room"], msg["username"]
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
            color = "#608b4e" if success else "#cc4444"
            self.chat_area.add_system(msg.get("message", ""), color=color)

        elif t == "error":
            self.chat_area.add_system(f"Error: {msg.get('message', 'Unknown')}")

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
            self.status_label.setText("Connection failed")
            self.status_label.setStyleSheet("color:#cc4444; font-size:9pt;")
            QMessageBox.critical(self, "Connection Error", msg.get("message", ""))

        elif t == "_connection_lost":
            self.chat_area.add_system("Disconnected from server.")
            self._reset_ui()

    def _recv_text(self, msg: dict, historical: bool = False):
        if msg.get("room") != self.current_room:
            return
        try:
            content = self.fernet.decrypt(msg["content"].encode()).decode()
        except Exception:
            content = "[unable to decrypt]"
        is_self = msg["username"] == self.username
        mw = MessageWidget(msg["username"], msg["timestamp"], is_self, dim=historical)
        mw.add_text(content)
        self.chat_area.add_message(mw)

    def _recv_file(self, msg: dict):
        if msg.get("room") != self.current_room:
            return
        is_self = msg["username"] == self.username
        try:
            payload = json.loads(self.fernet.decrypt(msg["content"].encode()).decode())
            filename = payload["filename"]
            mimetype = payload.get("mimetype", "application/octet-stream")
            raw      = base64.b64decode(payload["data"])
            caption  = payload.get("caption", "")
        except Exception:
            mw = MessageWidget(msg["username"], msg["timestamp"], is_self)
            mw.add_text("[could not decrypt file]")
            self.chat_area.add_message(mw)
            return

        mw = MessageWidget(msg["username"], msg["timestamp"], is_self)
        if caption:
            mw.add_text(caption)
        if mimetype in IMAGE_MIME:
            mw.add_image(raw, filename, mimetype)
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
            self.room_list.addItem(f"  {room}")
        if self.current_room in self.rooms:
            self.room_list.setCurrentRow(self.rooms.index(self.current_room))
        self.room_list.blockSignals(False)

    def _refresh_users(self):
        self.user_list.clear()
        for user in self.room_users.get(self.current_room, []):
            item = QListWidgetItem(f"{'@' if user == self.username else '  '}{user}")
            if user == self.username:
                item.setForeground(QColor("#ce9178"))
            self.user_list.addItem(item)

    def _on_room_changed(self, row: int):
        if row < 0 or not self.worker or row >= len(self.rooms):
            return
        room = self.rooms[row]
        if room == self.current_room:
            return
        if self.current_room:
            self.worker.send_msg({"type": "leave_room", "room": self.current_room})
        self.current_room = room
        self.room_title.setText(f"  # {room}")
        self.chat_area.clear_all()
        self.worker.send_msg({"type": "join_room", "room": room})

    # -----------------------------------------------------------------------
    # Sending
    # -----------------------------------------------------------------------

    def _send_message(self):
        content = self.msg_entry.text().strip()
        if not content:
            return
        if content.startswith("/"):
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
                "  /online                       List connected users",
                "  /listusers                    List all registered users",
                "  /listrooms                    List all rooms",
                "  /kick <username>              Kick a user  [admin]",
                "  /adduser <username> <pass>    Add a new user  [admin]",
                "  /removeuser <username>        Remove a user  [admin]",
                "  /addroom <name>               Create a room  [admin]",
                "  /removeroom <name>            Remove a room  [admin]",
                "  /setpassword <new_password>   Change server password  [admin]",
                "  /setmaxfile <MB>              Set max file upload size  [admin]",
                "  /history on|off               Enable/disable chat history  [admin]",
                "  /makeadmin <username>         Grant admin privileges  [admin]",
                "  /removeadmin <username>       Revoke admin privileges  [admin]",
            ]
            for line in lines:
                self.chat_area.add_system(line)
            return

        if not self.worker:
            self.chat_area.add_system("Not connected.", color="#cc4444")
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
