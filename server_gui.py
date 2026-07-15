#!/usr/bin/env python3
"""
Bastion Server GUI — a graphical admin console for the chat server.

Launched via `python server.py --gui`. Runs the asyncio WebSocket server in a
background thread and drives all administration (users, rooms, roles, settings)
through the same ChatServer methods the CLI uses. Every mutation is scheduled on
the server's event loop with run_coroutine_threadsafe, so the GUI thread never
touches server state directly.
"""

import asyncio
import logging
import sys
import time

try:
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QTabWidget, QVBoxLayout, QHBoxLayout,
        QLabel, QPushButton, QListWidget, QListWidgetItem, QPlainTextEdit,
        QMessageBox, QInputDialog, QCheckBox, QDoubleSpinBox, QDialog, QFormLayout,
        QLineEdit, QComboBox, QFrame, QGroupBox,
    )
    from PyQt6.QtCore import Qt, QObject, QThread, pyqtSignal, pyqtSlot, QTimer, QSize
    from PyQt6.QtGui import QFont
except ImportError as e:  # surfaced by server.py with an install hint
    raise

try:  # match the server's websockets selection
    from websockets.asyncio.server import serve as ws_serve
except ImportError:
    import websockets
    ws_serve = websockets.serve

log = logging.getLogger("bastion")

# ── Palette (kept in sync with the client) ──────────────────────────────────
BG, PANEL, ELEV, BORDER = "#141519", "#1b1d22", "#23262d", "#2c2f37"
TEXT, MUTED, ACCENT, ACCENT_H = "#e4e6ea", "#8d919b", "#6366f1", "#787af4"
GREEN, RED, AMBER = "#4ade80", "#f87171", "#fbbf24"
ADMIN_BADGE = "#2f9e6e"  # deliberately distinct from ACCENT (row selection colour)

LEVEL_COLORS = {"WARNING": AMBER, "ERROR": RED, "CRITICAL": RED, "INFO": MUTED, "DEBUG": "#6b7280"}

DARK_STYLE = f"""
QWidget {{ background-color: {BG}; color: {TEXT}; font-family: "Segoe UI"; font-size: 10pt; }}
QMainWindow, QDialog {{ background-color: {BG}; }}
QTabWidget::pane {{ border: none; background: {BG}; }}
QTabBar::tab {{ background: {PANEL}; color: {MUTED}; padding: 8px 18px; border: none;
    border-top-left-radius: 6px; border-top-right-radius: 6px; margin-right: 2px; }}
QTabBar::tab:selected {{ background: {ELEV}; color: {TEXT}; }}
QListWidget {{ background-color: {PANEL}; border: 1px solid {BORDER}; border-radius: 8px;
    outline: none; color: {TEXT}; }}
QListWidget::item {{ padding: 5px 8px; border-radius: 6px; margin: 1px 4px; }}
QListWidget::item:selected {{ background-color: {ACCENT}; color: #fff; }}
QListWidget::item:hover:!selected {{ background-color: {ELEV}; }}
QPlainTextEdit, QLineEdit {{ background-color: {PANEL}; border: 1px solid {BORDER};
    border-radius: 8px; color: {TEXT}; padding: 6px 10px; selection-background-color: {ACCENT}; }}
QLineEdit:focus, QPlainTextEdit:focus {{ border-color: {ACCENT}; }}
QComboBox, QDoubleSpinBox {{ background-color: {ELEV}; border: 1px solid {BORDER};
    border-radius: 6px; color: {TEXT}; padding: 4px 8px; }}
QComboBox::drop-down {{ border: none; background: transparent; width: 22px; }}
QComboBox QAbstractItemView {{ background: {ELEV}; color: {TEXT}; border: 1px solid {BORDER};
    outline: none; selection-background-color: {ACCENT}; }}
QPushButton {{ background-color: {ACCENT}; color: #fff; border: none; border-radius: 8px;
    padding: 7px 14px; font-weight: 600; }}
QPushButton:hover {{ background-color: {ACCENT_H}; }}
QPushButton:disabled {{ background-color: {ELEV}; color: {MUTED}; }}
QPushButton[secondary="true"] {{ background-color: {ELEV}; color: {TEXT}; font-weight: 400; }}
QPushButton[secondary="true"]:hover {{ background-color: {BORDER}; }}
QPushButton[danger="true"] {{ background-color: #7f2a2a; color: #ffdede; }}
QPushButton[danger="true"]:hover {{ background-color: #9c3838; }}
QCheckBox {{ color: {TEXT}; spacing: 8px; }}
QCheckBox::indicator {{ width: 16px; height: 16px; border: 1px solid {BORDER};
    border-radius: 4px; background-color: {ELEV}; }}
QCheckBox::indicator:checked {{ background-color: {ACCENT}; border-color: {ACCENT}; }}
QGroupBox {{ border: 1px solid {BORDER}; border-radius: 8px; margin-top: 10px; padding: 10px; }}
QGroupBox::title {{ subcontrol-origin: margin; left: 10px; color: {MUTED}; }}
QScrollBar:vertical {{ background: transparent; width: 8px; }}
QScrollBar::handle:vertical {{ background: {BORDER}; border-radius: 4px; min-height: 20px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
"""


# ---------------------------------------------------------------------------
# Log bridge: forwards "bastion" log records to the GUI thread via a signal
# ---------------------------------------------------------------------------

class _LogEmitter(QObject):
    line = pyqtSignal(str, str)  # levelname, formatted message


class QtLogHandler(logging.Handler):
    def __init__(self, emitter: _LogEmitter):
        super().__init__()
        self._emitter = emitter

    def emit(self, record):
        try:
            self._emitter.line.emit(record.levelname, self.format(record))
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Server worker: owns the asyncio loop and the running WebSocket server
# ---------------------------------------------------------------------------

class ServerWorker(QObject):
    started = pyqtSignal(str)   # address string
    stopped = pyqtSignal()
    failed = pyqtSignal(str)

    def __init__(self, server):
        super().__init__()
        self.server = server
        self.loop: asyncio.AbstractEventLoop | None = None
        self._stop: asyncio.Event | None = None

    @pyqtSlot()
    def run(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_until_complete(self._serve())
        except Exception as e:
            self.failed.emit(str(e))
        finally:
            if self.loop:
                self.loop.close()
            self.loop = None
            self.stopped.emit()

    async def _serve(self):
        self._stop = asyncio.Event()
        s = self.server
        try:
            async with ws_serve(s.handler, s.host, s.port,
                                max_size=16 * 1024 * 1024, ssl=s.ssl_context):
                scheme = "wss" if s.ssl_context else "ws"
                log.info("Server listening on %s://%s:%s", scheme, s.host, s.port)
                self.started.emit(f"{scheme}://{s.host}:{s.port}")
                await self._stop.wait()
        except OSError as e:
            self.failed.emit(f"Could not bind {s.host}:{s.port} — {e}")

    def submit(self, coro):
        """Schedule a coroutine on the server loop; returns a concurrent Future."""
        if self.loop is None:
            raise RuntimeError("Server is not running")
        return asyncio.run_coroutine_threadsafe(coro, self.loop)

    def stop(self):
        if self.loop and self._stop and not self._stop.is_set():
            self.loop.call_soon_threadsafe(self._stop.set)


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _chip(text: str, color: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setFixedHeight(18)
    # A subtle light border keeps the chip visible even when its fill colour
    # is close to (or identical to) the row's selection-highlight colour.
    lbl.setStyleSheet(
        f"background-color: {color}; color: #fff; border-radius: 9px;"
        " border: 1px solid rgba(255,255,255,60);"
        " padding: 0 8px; font-size: 8pt; font-weight: bold;"
    )
    return lbl


def _btn(text: str, slot, kind: str | None = None) -> QPushButton:
    b = QPushButton(text)
    if kind:
        b.setProperty(kind, True)
    b.clicked.connect(slot)
    return b


class AddUserDialog(QDialog):
    """Collects a username + password in one dialog."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add User")
        self.setFixedWidth(320)
        lay = QVBoxLayout(self)
        form = QFormLayout()
        self.user = QLineEdit()
        self.pw = QLineEdit()
        self.pw.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Username:", self.user)
        form.addRow("Password:", self.pw)
        lay.addLayout(form)
        row = QHBoxLayout()
        row.addStretch()
        cancel = _btn("Cancel", self.reject, "secondary")
        ok = _btn("Add", self.accept)
        ok.setDefault(True)
        row.addWidget(cancel)
        row.addWidget(ok)
        lay.addLayout(row)


# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------

class ServerGuiWindow(QMainWindow):
    def __init__(self, server):
        super().__init__()
        self.server = server
        self.setWindowTitle("Bastion — Server Console")
        self.resize(880, 640)
        self.setMinimumSize(720, 520)

        self._snap: dict = {}
        self._running = False
        self._start_time = 0.0

        # Logging bridge
        self._emitter = _LogEmitter()
        self._emitter.line.connect(self._on_log)
        handler = QtLogHandler(self._emitter)
        handler.setFormatter(logging.Formatter("%(asctime)s  %(message)s", "%H:%M:%S"))
        log.setLevel(logging.INFO)
        log.addHandler(handler)

        self._build_ui()

        # Worker thread
        self.worker = ServerWorker(server)
        self.thread = QThread()
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.started.connect(self._on_started)
        self.worker.stopped.connect(self._on_stopped)
        self.worker.failed.connect(self._on_failed)
        self.thread.start()

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)
        self._timer.start(2000)

    # ---- UI construction ----

    def _build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(14, 12, 14, 12)
        outer.setSpacing(10)
        outer.addWidget(self._build_header())

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_dashboard_tab(), "Dashboard")
        self.tabs.addTab(self._build_users_tab(), "Users")
        self.tabs.addTab(self._build_rooms_tab(), "Rooms")
        self.tabs.addTab(self._build_roles_tab(), "Roles")
        self.tabs.addTab(self._build_settings_tab(), "Settings")
        outer.addWidget(self.tabs, 1)

    def _build_header(self) -> QWidget:
        bar = QFrame()
        bar.setStyleSheet(f"QFrame {{ background: {PANEL}; border: 1px solid {BORDER}; border-radius: 8px; }}")
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(14, 10, 14, 10)

        title = QLabel("Bastion")
        title.setStyleSheet("font-size: 13pt; font-weight: bold; background: transparent;")
        lay.addWidget(title)

        self.addr_label = QLabel("starting…")
        self.addr_label.setStyleSheet(f"color: {MUTED}; background: transparent; padding-left: 10px;")
        lay.addWidget(self.addr_label)
        lay.addStretch()

        self.online_label = QLabel("0 online")
        self.online_label.setStyleSheet(f"color: {TEXT}; background: transparent; padding-right: 12px;")
        lay.addWidget(self.online_label)

        self.status_dot = QLabel("● starting")
        self.status_dot.setStyleSheet(f"color: {AMBER}; background: transparent; padding-right: 12px;")
        lay.addWidget(self.status_dot)

        self.toggle_btn = _btn("Stop", self._toggle_server, "danger")
        self.toggle_btn.setFixedWidth(90)
        lay.addWidget(self.toggle_btn)
        return bar

    def _build_dashboard_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 8, 0, 0)
        cap = QLabel("Server log")
        cap.setStyleSheet(f"color: {MUTED}; font-weight: bold;")
        lay.addWidget(cap)
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setFont(QFont("Consolas", 9))
        self.log_view.setMaximumBlockCount(2000)
        lay.addWidget(self.log_view, 1)
        return w

    def _build_users_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 8, 0, 0)
        self.users_list = QListWidget()
        # Rows use custom widgets (name + chips); drop item padding so the
        # widget gets the full row height and isn't clipped.
        self.users_list.setStyleSheet("QListWidget::item { padding: 0px; }")
        lay.addWidget(self.users_list, 1)

        row1 = QHBoxLayout()
        row1.addWidget(_btn("Add User", self._add_user))
        row1.addWidget(_btn("Set Password", self._set_user_password, "secondary"))
        row1.addWidget(_btn("Kick", self._kick_user, "secondary"))
        row1.addWidget(_btn("Remove", self._remove_user, "danger"))
        row1.addStretch()
        lay.addLayout(row1)

        row2 = QHBoxLayout()
        row2.addWidget(_btn("Grant Role", self._grant_role, "secondary"))
        row2.addWidget(_btn("Revoke Role", self._revoke_role, "secondary"))
        row2.addWidget(_btn("Toggle Admin", self._toggle_admin, "secondary"))
        row2.addStretch()
        lay.addLayout(row2)
        return w

    def _build_rooms_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 8, 0, 0)
        self.rooms_list = QListWidget()
        lay.addWidget(self.rooms_list, 1)
        row = QHBoxLayout()
        row.addWidget(_btn("Add Room", self._add_room))
        row.addWidget(_btn("Remove Room", self._remove_room, "danger"))
        row.addStretch()
        lay.addLayout(row)
        return w

    def _build_roles_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 8, 0, 0)
        hint = QLabel("A room becomes access-restricted once any role grants it. "
                      "Rooms no role mentions stay open to everyone.")
        hint.setStyleSheet(f"color: {MUTED};")
        hint.setWordWrap(True)
        lay.addWidget(hint)
        self.roles_list = QListWidget()
        lay.addWidget(self.roles_list, 1)
        row = QHBoxLayout()
        row.addWidget(_btn("New Role", self._add_role))
        row.addWidget(_btn("Set Rooms", self._set_role_rooms, "secondary"))
        row.addWidget(_btn("Delete Role", self._delete_role, "danger"))
        row.addStretch()
        lay.addLayout(row)
        return w

    def _build_settings_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 8, 0, 0)
        lay.setSpacing(10)

        general = QGroupBox("General")
        g = QVBoxLayout(general)
        self.cb_history = QCheckBox("Keep text chat history (replayed on join)")
        self.cb_history.clicked.connect(lambda v: self._set_config("history_enabled", v))
        self.cb_files = QCheckBox("Keep shared files (survive disconnects, replayed on join)")
        self.cb_files.clicked.connect(lambda v: self._set_config("persist_files", v))
        self.cb_ratelimit = QCheckBox("Rate-limit failed logins (brute-force protection)")
        self.cb_ratelimit.clicked.connect(lambda v: self._set_config("rate_limit_enabled", v))
        g.addWidget(self.cb_history)
        g.addWidget(self.cb_files)
        g.addWidget(self.cb_ratelimit)

        file_row = QHBoxLayout()
        file_row.addWidget(QLabel("Max file size (MB):"))
        self.spin_file = QDoubleSpinBox()
        self.spin_file.setRange(0.1, 512.0)
        self.spin_file.setDecimals(1)
        self.spin_file.setFixedWidth(90)
        apply_file = _btn("Apply", lambda: self._set_config("max_file_mb", self.spin_file.value()), "secondary")
        file_row.addWidget(self.spin_file)
        file_row.addWidget(apply_file)
        file_row.addStretch()
        g.addLayout(file_row)

        pw_btn = _btn("Change Server Password…", self._change_server_password, "secondary")
        g.addWidget(pw_btn, alignment=Qt.AlignmentFlag.AlignLeft)
        lay.addWidget(general)

        blocked = QGroupBox("Blocked IPs")
        b = QVBoxLayout(blocked)
        self.blocked_list = QListWidget()
        self.blocked_list.setMaximumHeight(140)
        b.addWidget(self.blocked_list)
        brow = QHBoxLayout()
        brow.addWidget(_btn("Block IP…", self._block_ip))
        brow.addWidget(_btn("Unblock Selected", self._unblock_ip, "secondary"))
        brow.addStretch()
        b.addLayout(brow)
        lay.addWidget(blocked)
        lay.addStretch()
        return w

    # ---- worker signal handlers ----

    @pyqtSlot(str)
    def _on_started(self, address: str):
        self._running = True
        self._start_time = time.time()
        self.addr_label.setText(f"Listening on {address}")
        self.status_dot.setText("● running")
        self.status_dot.setStyleSheet(f"color: {GREEN}; background: transparent; padding-right: 12px;")
        self.toggle_btn.setText("Stop")
        self.toggle_btn.setProperty("danger", True)
        self.toggle_btn.setStyle(self.toggle_btn.style())
        self._refresh()

    @pyqtSlot()
    def _on_stopped(self):
        self._running = False
        self.status_dot.setText("● stopped")
        self.status_dot.setStyleSheet(f"color: {MUTED}; background: transparent; padding-right: 12px;")
        self.addr_label.setText("stopped")
        self.toggle_btn.setText("Start")
        self.toggle_btn.setProperty("danger", False)
        self.toggle_btn.setStyle(self.toggle_btn.style())

    @pyqtSlot(str)
    def _on_failed(self, message: str):
        self._running = False
        self.status_dot.setText("● error")
        self.status_dot.setStyleSheet(f"color: {RED}; background: transparent; padding-right: 12px;")
        QMessageBox.critical(self, "Server Error", message)

    @pyqtSlot(str, str)
    def _on_log(self, level: str, message: str):
        color = LEVEL_COLORS.get(level, MUTED)
        self.log_view.appendHtml(f'<span style="color:{color};">{message}</span>')

    # ---- operation plumbing ----

    def _op(self, coro) -> str | None:
        """Run a ChatServer coroutine on the loop and return its string result."""
        if not self._running:
            QMessageBox.warning(self, "Server Stopped", "Start the server before making changes.")
            return None
        try:
            return self.worker.submit(coro).result(timeout=10)
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
            return None

    def _do(self, coro):
        result = self._op(coro)
        if result:
            self.statusBar().showMessage(result, 5000)
        self._refresh()

    def _selected(self, widget: QListWidget) -> str | None:
        item = widget.currentItem()
        return item.data(Qt.ItemDataRole.UserRole) if item else None

    # ---- refresh ----

    def _refresh(self):
        if not self._running:
            return
        try:
            self._snap = self.worker.submit(self.server.gui_snapshot()).result(timeout=5)
        except Exception:
            return
        snap = self._snap
        self.online_label.setText(f"{len(snap['online'])} online")

        self._fill_users(snap)
        self._fill_rooms(snap)
        self._fill_roles(snap)
        self._fill_settings(snap)

    def _fill_users(self, snap):
        keep = self._selected(self.users_list)
        self.users_list.clear()
        for uname, info in sorted(snap["users"].items()):
            item = QListWidgetItem()
            item.setData(Qt.ItemDataRole.UserRole, uname)
            row = QWidget()
            row.setStyleSheet("background: transparent;")
            r = QHBoxLayout(row)
            r.setContentsMargins(12, 0, 12, 0)
            r.setSpacing(8)
            vc = Qt.AlignmentFlag.AlignVCenter
            dot = QLabel("●")
            dot.setStyleSheet(f"color: {GREEN if info['online'] else '#555'}; background: transparent;")
            r.addWidget(dot, 0, vc)
            name = QLabel(uname)
            name.setStyleSheet(f"color: {TEXT}; background: transparent;")
            r.addWidget(name, 0, vc)
            if info["admin"]:
                r.addWidget(_chip("admin", ADMIN_BADGE), 0, vc)
            for role in info["roles"]:
                r.addWidget(_chip(role, snap["roles"].get(role, {}).get("color", MUTED)), 0, vc)
            r.addStretch()
            # Width 0 lets the view stretch the row to the full viewport
            # width instead of trusting row.sizeHint(), which can under-report
            # before the widget has been laid out (causing the last chip to clip).
            item.setSizeHint(QSize(0, 36))
            self.users_list.addItem(item)
            self.users_list.setItemWidget(item, row)
            if uname == keep:
                self.users_list.setCurrentItem(item)

    def _fill_rooms(self, snap):
        keep = self._selected(self.rooms_list)
        self.rooms_list.clear()
        restricted = set()
        for rd in snap["roles"].values():
            restricted.update(rd["rooms"])
        for room in snap["rooms"]:
            here = len(snap["room_members"].get(room, []))
            tag = "restricted" if room in restricted else "open"
            item = QListWidgetItem(f"#  {room}    ·  {here} here  ·  {tag}")
            item.setData(Qt.ItemDataRole.UserRole, room)
            self.rooms_list.addItem(item)
            if room == keep:
                self.rooms_list.setCurrentItem(item)

    def _fill_roles(self, snap):
        keep = self._selected(self.roles_list)
        self.roles_list.clear()
        for name, rd in sorted(snap["roles"].items()):
            rooms = ", ".join(rd["rooms"]) or "no rooms"
            members = ", ".join(rd["members"]) or "nobody"
            item = QListWidgetItem(f"{name}   grants: {rooms}   —   members: {members}")
            item.setData(Qt.ItemDataRole.UserRole, name)
            item.setForeground(_qcolor(rd["color"]))
            self.roles_list.addItem(item)
            if name == keep:
                self.roles_list.setCurrentItem(item)

    def _fill_settings(self, snap):
        for cb, key in [(self.cb_history, "history_enabled"),
                        (self.cb_files, "persist_files"),
                        (self.cb_ratelimit, "rate_limit_enabled")]:
            cb.blockSignals(True)
            cb.setChecked(snap[key])
            cb.blockSignals(False)
        if not self.spin_file.hasFocus():
            self.spin_file.blockSignals(True)
            self.spin_file.setValue(float(snap["max_file_mb"]))
            self.spin_file.blockSignals(False)
        keep = self._selected(self.blocked_list)
        self.blocked_list.clear()
        for ip, secs in snap["blocked"]:
            m, s = divmod(secs, 60)
            item = QListWidgetItem(f"{ip}  —  {m}m {s}s remaining")
            item.setData(Qt.ItemDataRole.UserRole, ip)
            self.blocked_list.addItem(item)
            if ip == keep:
                self.blocked_list.setCurrentItem(item)

    # ---- user actions ----

    def _add_user(self):
        dlg = AddUserDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self._do(self.server.gui_add_user(dlg.user.text().strip(), dlg.pw.text()))

    def _set_user_password(self):
        u = self._selected(self.users_list)
        if not u:
            return
        pw, ok = QInputDialog.getText(self, "Set Password", f"New password for '{u}':",
                                      QLineEdit.EchoMode.Password)
        if ok and pw:
            self._do(self.server.gui_set_user_password(u, pw))

    def _remove_user(self):
        u = self._selected(self.users_list)
        if not u:
            return
        if QMessageBox.question(self, "Remove User", f"Delete user '{u}'?") == QMessageBox.StandardButton.Yes:
            self._do(self.server.gui_remove_user(u))

    def _kick_user(self):
        u = self._selected(self.users_list)
        if u:
            self._do(self.server.gui_kick(u))

    def _toggle_admin(self):
        u = self._selected(self.users_list)
        if not u:
            return
        is_admin = self._snap.get("users", {}).get(u, {}).get("admin", False)
        self._do(self.server.gui_set_admin(u, not is_admin))

    def _grant_role(self):
        u = self._selected(self.users_list)
        if not u:
            return
        roles = sorted(self._snap.get("roles", {}))
        if not roles:
            QMessageBox.information(self, "No Roles", "Create a role first (Roles tab).")
            return
        role, ok = QInputDialog.getItem(self, "Grant Role", f"Give '{u}' the role:", roles, editable=False)
        if ok and role:
            self._do(self.server.gui_role("grant", u, role))

    def _revoke_role(self):
        u = self._selected(self.users_list)
        if not u:
            return
        held = self._snap.get("users", {}).get(u, {}).get("roles", [])
        if not held:
            QMessageBox.information(self, "No Roles", f"'{u}' has no roles.")
            return
        role, ok = QInputDialog.getItem(self, "Revoke Role", f"Remove from '{u}':", held, editable=False)
        if ok and role:
            self._do(self.server.gui_role("revoke", u, role))

    # ---- room actions ----

    def _add_room(self):
        name, ok = QInputDialog.getText(self, "Add Room", "Room name:")
        if ok and name.strip():
            self._do(self.server.gui_add_room(name.strip()))

    def _remove_room(self):
        room = self._selected(self.rooms_list)
        if not room:
            return
        if QMessageBox.question(self, "Remove Room", f"Delete room '{room}'?") == QMessageBox.StandardButton.Yes:
            self._do(self.server.gui_remove_room(room))

    # ---- role actions ----

    def _add_role(self):
        name, ok = QInputDialog.getText(self, "New Role", "Role name:")
        if not (ok and name.strip()):
            return
        color, ok = QInputDialog.getText(self, "New Role", "Color (hex, e.g. #eb459e) — blank for auto:")
        if not ok:
            return
        self._do(self.server.gui_role("create", name.strip(), color.strip() or None))

    def _delete_role(self):
        role = self._selected(self.roles_list)
        if not role:
            return
        if QMessageBox.question(self, "Delete Role", f"Delete role '{role}'?") == QMessageBox.StandardButton.Yes:
            self._do(self.server.gui_role("delete", role))

    def _set_role_rooms(self):
        role = self._selected(self.roles_list)
        if not role:
            return
        current = ", ".join(self._snap.get("roles", {}).get(role, {}).get("rooms", []))
        text, ok = QInputDialog.getText(
            self, "Set Rooms",
            f"Rooms '{role}' grants (comma-separated, blank = none):", text=current)
        if ok:
            rooms = [r.strip() for r in text.split(",") if r.strip()]
            self._do(self.server.gui_role("rooms", role, rooms))

    # ---- settings actions ----

    def _set_config(self, key, value):
        self._do(self.server.gui_set_config(key, value))

    def _change_server_password(self):
        pw, ok = QInputDialog.getText(self, "Server Password", "New server password:",
                                      QLineEdit.EchoMode.Password)
        if ok and pw:
            self._do(self.server.gui_set_config("server_password", pw))

    def _block_ip(self):
        ip, ok = QInputDialog.getText(self, "Block IP", "IP address to block:")
        if ok and ip.strip():
            self._do(self.server.gui_block_ip(ip.strip()))

    def _unblock_ip(self):
        ip = self._selected(self.blocked_list)
        if ip:
            self._do(self.server.gui_unblock(ip))

    # ---- server toggle / shutdown ----

    def _toggle_server(self):
        if self._running:
            self.worker.stop()
        else:
            # Restart worker thread
            self.worker = ServerWorker(self.server)
            self.thread = QThread()
            self.worker.moveToThread(self.thread)
            self.thread.started.connect(self.worker.run)
            self.worker.started.connect(self._on_started)
            self.worker.stopped.connect(self._on_stopped)
            self.worker.failed.connect(self._on_failed)
            self.thread.start()

    def closeEvent(self, event):
        self.worker.stop()
        self.thread.quit()
        self.thread.wait(2000)
        event.accept()


def _qcolor(hex_str: str):
    from PyQt6.QtGui import QColor
    return QColor(hex_str)


def run(server):
    """Entry point called by server.py --gui."""
    app = QApplication(sys.argv)
    app.setApplicationName("Bastion Server")
    app.setStyleSheet(DARK_STYLE)
    window = ServerGuiWindow(server)
    window.show()
    sys.exit(app.exec())
