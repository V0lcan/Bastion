#!/usr/bin/env python3
"""
Bastion Server - server for hosting chat rooms (CLI or GUI).
Usage: python server.py [--host HOST] [--port PORT] [--config CONFIG]
                        [--certfile CERT --keyfile KEY] [--gui]
"""

import asyncio
import json
import hashlib
import hmac
import logging
import os
import re
import secrets
import ssl
import sys
import datetime
import time
import argparse

try:
    import websockets
except ImportError:
    print("Error: 'websockets' package not found. Install it with: pip install websockets")
    sys.exit(1)

try:  # websockets >= 13: new asyncio implementation (legacy one is deprecated)
    from websockets.asyncio.server import serve as ws_serve
except ImportError:
    ws_serve = websockets.serve

try:  # optional: argon2id password hashing (pip install argon2-cffi)
    from argon2 import PasswordHasher as _Argon2Hasher
    _ARGON2 = _Argon2Hasher()
except ImportError:
    _ARGON2 = None

log = logging.getLogger("bastion")

PBKDF2_ITERATIONS = 600_000

USERNAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,32}")
ROOM_NAME_RE = re.compile(r"[A-Za-z0-9_.\- ]{1,50}")


def valid_username(name: str) -> bool:
    return bool(USERNAME_RE.fullmatch(name))


def valid_room_name(name: str) -> bool:
    return bool(ROOM_NAME_RE.fullmatch(name)) and name == name.strip()


def hash_password(password: str) -> str:
    if _ARGON2 is not None:
        return "argon2:" + _ARGON2.hash(password)
    salt = secrets.token_bytes(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2:{PBKDF2_ITERATIONS}:{salt.hex()}:{h.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        if stored.startswith("argon2:"):
            # Verifiable only while argon2-cffi is installed; raises on mismatch
            return _ARGON2 is not None and _ARGON2.verify(stored[len("argon2:"):], password)
        if stored.startswith("pbkdf2:"):
            _, iterations, salt_hex, h_hex = stored.split(":", 3)
            calc = hashlib.pbkdf2_hmac(
                "sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations)
            )
            return hmac.compare_digest(calc.hex(), h_hex)
        # Legacy v0.1 format: "<salt_hex>:<sha256(salt + password)>"
        salt, h = stored.split(":", 1)
        calc = hashlib.sha256(f"{salt}{password}".encode()).hexdigest()
        return hmac.compare_digest(calc, h)
    except Exception:
        return False


def password_needs_rehash(stored: str) -> bool:
    try:
        if stored.startswith("argon2:"):
            return _ARGON2 is not None and _ARGON2.check_needs_rehash(stored[len("argon2:"):])
        if _ARGON2 is not None:
            return True  # upgrade pbkdf2/legacy hashes to argon2id
        return not stored.startswith(f"pbkdf2:{PBKDF2_ITERATIONS}:")
    except Exception:
        return False


class ChatServer:
    def __init__(self, host: str, port: int, config_file: str,
                 ssl_context: ssl.SSLContext | None = None):
        self.host = host
        self.port = port
        self.ssl_context = ssl_context
        self.config_file = config_file
        self.history_file = os.path.splitext(config_file)[0] + "_history.json"
        self.data = self._load_data()
        self.connected_clients: dict = {}  # websocket -> {"username": str, "rooms": set}
        self.room_clients: dict = {}       # room_name -> set of websockets
        self.room_history: dict = {}       # room_name -> list of message dicts
        self._failed_attempts: dict = {}   # ip -> [timestamp, ...]
        self._blocked_ips: dict = {}       # ip -> unblock_timestamp
        self._init_rooms()
        self._load_history()

    def _load_data(self) -> dict:
        if os.path.exists(self.config_file):
            with open(self.config_file) as f:
                data = json.load(f)
            # Backfill keys added in later versions so old configs keep working
            data.setdefault("admins", [])
            data.setdefault("roles", {})
            data.setdefault("user_roles", {})
            data.setdefault("persist_files", True)
            return data
        data = {
            "server_password": hash_password("changeme"),
            "users": {},
            "rooms": ["General"],
            "admins": [],
            "roles": {},          # role_name -> {"color": "#hex", "rooms": [granted rooms]}
            "user_roles": {},     # username -> [role_name, ...]
            "max_file_mb": 8,
            "history_enabled": False,
            "persist_files": True,   # keep shared files in history so they survive disconnects
            "history_limit": 100,
            "rate_limit": {
                "enabled": True,
                "max_attempts": 5,
                "window_seconds": 60,
                "block_seconds": 300,
            },
            "flood": {
                "max_messages": 15,
                "window_seconds": 10,
            },
            "max_message_chars": 20000,
        }
        self._save_data(data)
        print("Created new server config. Default server password: changeme")
        print("Change it with: setpassword <new_password>")
        return data

    @staticmethod
    def _atomic_write_json(path: str, obj):
        """Write to a temp file then rename, so a crash can't corrupt the file."""
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(obj, f, indent=2)
        os.replace(tmp, path)

    def _save_data(self, data=None):
        if data is None:
            data = self.data
        self._atomic_write_json(self.config_file, data)

    def _init_rooms(self):
        for room in self.data["rooms"]:
            if room not in self.room_clients:
                self.room_clients[room] = set()

    def _load_history(self):
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file) as f:
                    self.room_history = json.load(f)
            except Exception:
                self.room_history = {}
        for room in self.data["rooms"]:
            self.room_history.setdefault(room, [])

    def _save_history(self):
        self._atomic_write_json(self.history_file, self.room_history)

    def _append_history(self, room: str, entry: dict):
        is_file = entry.get("type") == "file_message"
        # Files persist independently of the text-history toggle so shared
        # files survive after the sender disconnects.
        if is_file:
            if not self.data.get("persist_files", True):
                return
        elif not self.data.get("history_enabled"):
            return
        self.room_history.setdefault(room, [])
        self.room_history[room].append(entry)
        limit = self.data.get("history_limit", 100)
        if limit > 0 and len(self.room_history[room]) > limit:
            self.room_history[room] = self.room_history[room][-limit:]
        self._save_history()

    # -------------------------------------------------------------------------
    # Rate limiting
    # -------------------------------------------------------------------------

    def _is_blocked(self, ip: str) -> float | None:
        """Return seconds remaining in block, or None if not blocked.

        Explicit blocks (added by an admin) are always enforced; the
        rate_limit.enabled flag only governs *automatic* blocking from
        repeated failed logins (see _record_failure).
        """
        until = self._blocked_ips.get(ip)
        if until is None:
            return None
        remaining = until - time.time()
        if remaining <= 0:
            del self._blocked_ips[ip]
            self._failed_attempts.pop(ip, None)
            return None
        return remaining

    def _record_failure(self, ip: str):
        """Record a failed auth attempt; block the IP if the threshold is reached."""
        cfg = self.data.get("rate_limit", {})
        if not cfg.get("enabled", True):
            return
        now = time.time()
        window = cfg.get("window_seconds", 60)
        threshold = cfg.get("max_attempts", 5)
        block_dur = cfg.get("block_seconds", 300)

        attempts = self._failed_attempts.setdefault(ip, [])
        attempts.append(now)
        # Prune entries older than the window
        cutoff = now - window
        self._failed_attempts[ip] = [t for t in attempts if t > cutoff]

        if len(self._failed_attempts[ip]) >= threshold:
            self._blocked_ips[ip] = now + block_dur
            log.warning("IP %s blocked for %ss after %s failed attempts", ip, block_dur, threshold)

    def _clear_failures(self, ip: str):
        """Clear failure history for an IP on successful login."""
        self._failed_attempts.pop(ip, None)

    def _flood_allow(self, client_info: dict) -> bool:
        """Sliding-window flood limiter for an authenticated connection."""
        cfg = self.data.get("flood", {})
        limit = cfg.get("max_messages", 15)
        window = cfg.get("window_seconds", 10)
        if limit <= 0:
            return True
        now = time.time()
        times = client_info.setdefault("msg_times", [])
        times[:] = [t for t in times if t > now - window]
        if len(times) >= limit:
            return False
        times.append(now)
        return True

    # -------------------------------------------------------------------------
    # Roles & room access
    # -------------------------------------------------------------------------

    def _restricted_rooms(self) -> set:
        """Rooms gated behind a role (any room named by at least one role)."""
        gated = set()
        for role in self.data.get("roles", {}).values():
            gated.update(role.get("rooms", []))
        return gated

    def _is_admin(self, username: str) -> bool:
        return username in self.data.get("admins", [])

    def _accessible_rooms(self, username: str) -> list:
        """Rooms this user may see/join, in config order. Admins see everything."""
        rooms = self.data["rooms"]
        if self._is_admin(username):
            return list(rooms)
        gated = self._restricted_rooms()
        granted = set()
        for role in self.data.get("user_roles", {}).get(username, []):
            rdef = self.data.get("roles", {}).get(role)
            if rdef:
                granted.update(rdef.get("rooms", []))
        return [r for r in rooms if r not in gated or r in granted]

    def _can_access(self, username: str, room: str) -> bool:
        return room in self._accessible_rooms(username)

    def _user_roles(self, username: str) -> list:
        """A user's role names, dropping any that no longer exist."""
        roles = self.data.get("roles", {})
        return [r for r in self.data.get("user_roles", {}).get(username, []) if r in roles]

    def _role_colors(self) -> dict:
        return {name: rd.get("color", "#8d919b") for name, rd in self.data.get("roles", {}).items()}

    def _roles_snapshot_for_room(self, room: str) -> dict:
        """{username: [roles]} for the connected users currently in a room."""
        out = {}
        for ws in self.room_clients.get(room, set()):
            uname = self.connected_clients.get(ws, {}).get("username")
            if uname:
                out[uname] = self._user_roles(uname)
        return out

    # ---- role mutations (shared by CLI, admin commands, and GUI) ----
    # Each returns (success, message); callers persist + push updates.

    _DEFAULT_ROLE_COLORS = [
        "#eb459e", "#faa61a", "#3ba55c", "#00b0f4",
        "#9b59b6", "#e67e22", "#ed4245", "#5865f2",
    ]

    def role_create(self, name: str, color: str | None = None) -> tuple[bool, str]:
        if not valid_username(name):
            return False, "Role name must be 1-32 chars: letters, digits, _ . -"
        roles = self.data.setdefault("roles", {})
        if name in roles:
            return False, f"Role '{name}' already exists"
        if not color:
            color = self._DEFAULT_ROLE_COLORS[len(roles) % len(self._DEFAULT_ROLE_COLORS)]
        if not re.fullmatch(r"#[0-9a-fA-F]{6}", color):
            return False, "Color must be a hex value like #eb459e"
        roles[name] = {"color": color, "rooms": []}
        return True, f"Role '{name}' created ({color})"

    def role_delete(self, name: str) -> tuple[bool, str]:
        roles = self.data.get("roles", {})
        if name not in roles:
            return False, f"Role '{name}' not found"
        del roles[name]
        for uname in list(self.data.get("user_roles", {})):
            self.data["user_roles"][uname] = [
                r for r in self.data["user_roles"][uname] if r != name
            ]
            if not self.data["user_roles"][uname]:
                del self.data["user_roles"][uname]
        return True, f"Role '{name}' deleted"

    def role_set_rooms(self, name: str, rooms: list) -> tuple[bool, str]:
        roles = self.data.get("roles", {})
        if name not in roles:
            return False, f"Role '{name}' not found"
        unknown = [r for r in rooms if r not in self.data["rooms"]]
        if unknown:
            return False, f"Unknown room(s): {', '.join(unknown)}"
        roles[name]["rooms"] = list(dict.fromkeys(rooms))  # dedupe, keep order
        granted = ", ".join(roles[name]["rooms"]) or "(none)"
        return True, f"Role '{name}' now grants: {granted}"

    def role_grant(self, username: str, role: str) -> tuple[bool, str]:
        if username not in self.data["users"]:
            return False, f"User '{username}' not found"
        if role not in self.data.get("roles", {}):
            return False, f"Role '{role}' not found"
        assigned = self.data.setdefault("user_roles", {}).setdefault(username, [])
        if role in assigned:
            return False, f"'{username}' already has role '{role}'"
        assigned.append(role)
        return True, f"Granted '{role}' to '{username}'"

    def role_revoke(self, username: str, role: str) -> tuple[bool, str]:
        assigned = self.data.get("user_roles", {}).get(username, [])
        if role not in assigned:
            return False, f"'{username}' does not have role '{role}'"
        assigned.remove(role)
        if not assigned:
            del self.data["user_roles"][username]
        return True, f"Revoked '{role}' from '{username}'"

    def _prune_room_from_roles(self, room: str):
        for rd in self.data.get("roles", {}).values():
            if room in rd.get("rooms", []):
                rd["rooms"].remove(room)

    def _roles_report(self) -> str:
        roles = self.data.get("roles", {})
        if not roles:
            return "No roles defined"
        members: dict = {}
        for uname, rlist in self.data.get("user_roles", {}).items():
            for r in rlist:
                members.setdefault(r, []).append(uname)
        lines = ["Roles:"]
        for name, rd in roles.items():
            rooms = ", ".join(rd.get("rooms", [])) or "(no rooms)"
            who = ", ".join(members.get(name, [])) or "(nobody)"
            lines.append(f"  {name} [{rd.get('color', '')}]  grants: {rooms}  —  members: {who}")
        return "\n".join(lines)

    async def _push_access_update(self):
        """After a role/access change: re-send each client their room list,
        push updated role colours, and evict anyone from now-forbidden rooms."""
        role_colors = self._role_colors()
        for ws, info in list(self.connected_clients.items()):
            uname = info.get("username")
            if not uname:
                continue
            accessible = self._accessible_rooms(uname)
            # Evict from any room the user can no longer access
            for room in list(info["rooms"]):
                if room not in accessible:
                    info["rooms"].discard(room)
                    self.room_clients.get(room, set()).discard(ws)
                    await self._broadcast_room(room, {
                        "type": "user_left", "room": room, "username": uname
                    }, exclude=ws)
                    try:
                        await ws.send(json.dumps({
                            "type": "room_closed", "room": room,
                            "message": f"Your access to '{room}' was removed"
                        }))
                    except Exception:
                        pass
            try:
                await ws.send(json.dumps({
                    "type": "rooms_list", "rooms": accessible,
                    "roles": role_colors, "your_roles": self._user_roles(uname),
                }))
            except Exception:
                pass
        # Refresh role badges for everyone in each room the callers may have touched
        for room in list(self.room_clients):
            await self._broadcast_room(room, {
                "type": "roles_update", "room": room,
                "user_roles": self._roles_snapshot_for_room(room),
                "roles": role_colors,
            })

    # -------------------------------------------------------------------------
    # WebSocket handler
    # -------------------------------------------------------------------------

    async def handler(self, websocket):
        client_info = {"username": None, "rooms": set()}
        self.connected_clients[websocket] = client_info
        ip = websocket.remote_address[0]
        try:
            # Reject before even reading the auth message if the IP is blocked
            remaining = self._is_blocked(ip)
            if remaining is not None:
                mins, secs = divmod(int(remaining), 60)
                time_str = f"{mins}m {secs}s" if mins else f"{secs}s"
                await websocket.send(json.dumps({
                    "type": "auth_result", "success": False,
                    "message": f"Too many failed login attempts. Try again in {time_str}."
                }))
                return

            raw = await asyncio.wait_for(websocket.recv(), timeout=30)
            auth_data = json.loads(raw)

            if auth_data.get("type") != "auth":
                await websocket.send(json.dumps({
                    "type": "auth_result", "success": False,
                    "message": "Expected auth message"
                }))
                return

            server_password = auth_data.get("server_password", "")
            # PBKDF2 is deliberately slow — verify in a thread so the event loop keeps serving
            if not await asyncio.to_thread(verify_password, server_password, self.data["server_password"]):
                self._record_failure(ip)
                await websocket.send(json.dumps({
                    "type": "auth_result", "success": False,
                    "message": "Invalid server password"
                }))
                return

            username = auth_data.get("username", "").strip()
            password = auth_data.get("password", "")

            if not username:
                await websocket.send(json.dumps({
                    "type": "auth_result", "success": False, "message": "Username required"
                }))
                return

            # Same message for unknown user and wrong password so usernames
            # can't be enumerated through the auth endpoint.
            stored = self.data["users"].get(username)
            if stored is None or not await asyncio.to_thread(verify_password, password, stored):
                self._record_failure(ip)
                await websocket.send(json.dumps({
                    "type": "auth_result", "success": False,
                    "message": "Invalid username or password"
                }))
                return

            # Upgrade any legacy/weaker hashes now that the plaintext is available
            upgraded = False
            if password_needs_rehash(self.data["server_password"]):
                self.data["server_password"] = hash_password(server_password)
                upgraded = True
            if password_needs_rehash(stored):
                self.data["users"][username] = hash_password(password)
                upgraded = True
            if upgraded:
                self._save_data()

            for ws, info in self.connected_clients.items():
                if ws != websocket and info["username"] == username:
                    await websocket.send(json.dumps({
                        "type": "auth_result", "success": False,
                        "message": "User already connected"
                    }))
                    return

            self._clear_failures(ip)
            client_info["username"] = username
            await websocket.send(json.dumps({
                "type": "auth_result",
                "success": True,
                "message": f"Welcome, {username}!",
                "rooms": self._accessible_rooms(username),
                "max_file_mb": self.data.get("max_file_mb", 8),
                "is_admin": self._is_admin(username),
                "roles": self._role_colors(),
                "your_roles": self._user_roles(username),
            }))
            log.info("%s connected from %s", username, ip)

            async for raw_msg in websocket:
                try:
                    msg = json.loads(raw_msg)
                    await self._handle_message(websocket, client_info, msg)
                except json.JSONDecodeError:
                    await websocket.send(json.dumps({"type": "error", "message": "Invalid JSON"}))

        except asyncio.TimeoutError:
            pass
        except websockets.exceptions.ConnectionClosed:
            pass
        except Exception as e:
            log.error("Client error: %s", e)
        finally:
            username = client_info.get("username")
            if username:
                log.info("%s disconnected", username)
                for room in list(client_info["rooms"]):
                    self.room_clients[room].discard(websocket)
                    await self._broadcast_room(room, {
                        "type": "user_left", "room": room, "username": username
                    }, exclude=websocket)
            del self.connected_clients[websocket]

    async def _handle_message(self, websocket, client_info, msg):
        msg_type = msg.get("type")
        username = client_info["username"]

        if msg_type == "list_rooms":
            await websocket.send(json.dumps({
                "type": "rooms_list", "rooms": self._accessible_rooms(username)
            }))

        elif msg_type == "join_room":
            room = msg.get("room")
            if room not in self.data["rooms"]:
                await websocket.send(json.dumps({"type": "error", "message": f"Room '{room}' does not exist"}))
                return
            if not self._can_access(username, room):
                await websocket.send(json.dumps({
                    "type": "error", "message": f"You don't have access to '{room}'"
                }))
                return
            if room in client_info["rooms"]:
                return  # already joined; don't re-broadcast user_joined
            client_info["rooms"].add(room)
            self.room_clients[room].add(websocket)
            await self._broadcast_room(room, {
                "type": "user_joined", "room": room, "username": username,
                "roles": self._user_roles(username),
            }, exclude=websocket)
            users = [
                self.connected_clients[ws]["username"]
                for ws in self.room_clients[room]
                if self.connected_clients[ws]["username"]
            ]
            await websocket.send(json.dumps({
                "type": "users_list", "room": room, "users": users,
                "user_roles": self._roles_snapshot_for_room(room),
                "roles": self._role_colors(),
            }))
            # Replay stored history: text if history is on, files if persist_files is on
            show_text = self.data.get("history_enabled")
            show_files = self.data.get("persist_files", True)
            replay = [
                e for e in self.room_history.get(room, [])
                if (e.get("type") == "file_message" and show_files)
                or (e.get("type") == "room_message" and show_text)
            ]
            if replay:
                await websocket.send(json.dumps({"type": "history_start", "room": room}))
                for entry in replay:
                    await websocket.send(json.dumps({**entry, "historical": True}))
                await websocket.send(json.dumps({"type": "history_end", "room": room}))

        elif msg_type == "leave_room":
            room = msg.get("room")
            if room in client_info["rooms"]:
                client_info["rooms"].discard(room)
                self.room_clients[room].discard(websocket)
                await self._broadcast_room(room, {
                    "type": "user_left", "room": room, "username": username
                }, exclude=websocket)

        elif msg_type in ("send_message", "file_message"):
            room = msg.get("room")
            content = msg.get("content", "")
            if msg_type == "send_message":
                content = content.strip()
            if not content:
                return
            if room not in client_info["rooms"]:
                await websocket.send(json.dumps({"type": "error", "message": "You are not in that room"}))
                return
            if not self._flood_allow(client_info):
                await websocket.send(json.dumps({
                    "type": "error",
                    "message": "You're sending messages too fast — slow down"
                }))
                return
            if msg_type == "send_message":
                max_chars = self.data.get("max_message_chars", 20000)
                if max_chars > 0 and len(content) > max_chars:
                    await websocket.send(json.dumps({
                        "type": "error", "message": "Message is too long"
                    }))
                    return
            # Server-side file size guard (content is base64+encrypted, ~2× raw size)
            if msg_type == "file_message":
                max_mb = self.data.get("max_file_mb", 8)
                if len(content) > max_mb * 1024 * 1024 * 2:
                    await websocket.send(json.dumps({
                        "type": "error",
                        "message": f"File exceeds the server limit of {max_mb} MB"
                    }))
                    return
            # ISO-8601 UTC; clients convert to local time for display
            timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
            out_type = "room_message" if msg_type == "send_message" else "file_message"
            entry = {
                "type": out_type,
                "room": room,
                "username": username,
                "content": content,
                "timestamp": timestamp,
            }
            await self._broadcast_room(room, entry)
            # Persist text (when history is on) and files (when persist_files is on)
            self._append_history(room, entry)

        elif msg_type == "list_users":
            room = msg.get("room")
            if room in self.room_clients:
                users = [
                    self.connected_clients[ws]["username"]
                    for ws in self.room_clients[room]
                    if self.connected_clients[ws]["username"]
                ]
                await websocket.send(json.dumps({
                    "type": "users_list", "room": room, "users": users,
                    "user_roles": self._roles_snapshot_for_room(room),
                    "roles": self._role_colors(),
                }))

        elif msg_type == "admin_command":
            command = msg.get("command", "").lower()
            args = msg.get("args", [])
            await self._handle_admin_command(websocket, username, command, args)

    async def _handle_admin_command(self, websocket, requester: str, command: str, args: list):
        INFO_COMMANDS = {"online", "listusers", "listrooms"}
        is_admin = requester in self.data.get("admins", [])

        if command not in INFO_COMMANDS and not is_admin:
            await websocket.send(json.dumps({
                "type": "admin_result", "success": False,
                "message": "Permission denied: you are not an admin"
            }))
            return

        async def ok(msg):
            await websocket.send(json.dumps({"type": "admin_result", "success": True, "message": msg}))

        async def err(msg):
            await websocket.send(json.dumps({"type": "admin_result", "success": False, "message": msg}))

        if command == "online":
            online = [i["username"] for i in self.connected_clients.values() if i["username"]]
            await ok("Online: " + (", ".join(online) if online else "(nobody)"))

        elif command == "listusers":
            users = list(self.data["users"].keys())
            await ok("Users: " + (", ".join(users) if users else "(none)"))

        elif command == "listrooms":
            rooms = self.data["rooms"]
            await ok("Rooms: " + (", ".join(rooms) if rooms else "(none)"))

        elif command == "kick":
            if not args:
                await err("Usage: /kick <username>"); return
            target = args[0]
            for ws, info in list(self.connected_clients.items()):
                if info["username"] == target:
                    await ws.send(json.dumps({
                        "type": "system_message",
                        "content": f"You have been kicked by {requester}"
                    }))
                    await ws.close()
                    await ok(f"Kicked '{target}'")
                    log.info(f"[Admin] {requester} kicked {target}")
                    return
            await err(f"User '{target}' is not online")

        elif command == "adduser":
            if len(args) < 2:
                await err("Usage: /adduser <username> <password>"); return
            uname, pwd = args[0], args[1]
            if not valid_username(uname):
                await err("Username must be 1-32 chars: letters, digits, _ . -"); return
            if uname in self.data["users"]:
                await err(f"User '{uname}' already exists"); return
            self.data["users"][uname] = hash_password(pwd)
            self._save_data()
            await ok(f"User '{uname}' added")
            log.info(f"[Admin] {requester} added user '{uname}'")

        elif command == "removeuser":
            if not args:
                await err("Usage: /removeuser <username>"); return
            uname = args[0]
            if uname not in self.data["users"]:
                await err(f"User '{uname}' not found"); return
            del self.data["users"][uname]
            self._save_data()
            await ok(f"User '{uname}' removed")
            log.info(f"[Admin] {requester} removed user '{uname}'")

        elif command == "addroom":
            if not args:
                await err("Usage: /addroom <name>"); return
            room = " ".join(args)
            if not valid_room_name(room):
                await err("Room name must be 1-50 chars: letters, digits, spaces, _ . -"); return
            if room in self.data["rooms"]:
                await err(f"Room '{room}' already exists"); return
            self.data["rooms"].append(room)
            self.room_clients[room] = set()
            self.room_history.setdefault(room, [])
            self._save_data()
            await self._push_access_update()
            await ok(f"Room '{room}' created")
            log.info(f"[Admin] {requester} created room '{room}'")

        elif command == "removeroom":
            if not args:
                await err("Usage: /removeroom <name>"); return
            room = " ".join(args)
            if room not in self.data["rooms"]:
                await err(f"Room '{room}' not found"); return
            if room in self.room_clients:
                await self._broadcast_room(room, {
                    "type": "system_message",
                    "content": f"Room '{room}' has been deleted by {requester}"
                })
                for ws in list(self.room_clients[room]):
                    if ws in self.connected_clients:
                        self.connected_clients[ws]["rooms"].discard(room)
                del self.room_clients[room]
            self.data["rooms"].remove(room)
            self._prune_room_from_roles(room)
            self._save_data()
            await self._push_access_update()
            await ok(f"Room '{room}' removed")
            log.info(f"[Admin] {requester} removed room '{room}'")

        elif command == "role":
            sub = (args[0].lower() if args else "")
            if sub == "add":
                if len(args) < 2:
                    await err("Usage: /role add <name> [#color]"); return
                color = args[2] if len(args) > 2 else None
                success, message = self.role_create(args[1], color)
            elif sub in ("del", "delete", "remove"):
                if len(args) < 2:
                    await err("Usage: /role del <name>"); return
                success, message = self.role_delete(args[1])
            elif sub == "rooms":
                if len(args) < 2:
                    await err("Usage: /role rooms <name> [room ...]"); return
                success, message = self.role_set_rooms(args[1], args[2:])
            elif sub == "list":
                await ok(self._roles_report()); return
            else:
                await err("Usage: /role add|del|rooms|list"); return
            if success:
                self._save_data()
                await self._push_access_update()
                await ok(message)
                log.info(f"[Admin] {requester} role {' '.join(args)}")
            else:
                await err(message)

        elif command in ("grantrole", "revokerole"):
            if len(args) < 2:
                await err(f"Usage: /{command} <username> <role>"); return
            if command == "grantrole":
                success, message = self.role_grant(args[0], args[1])
            else:
                success, message = self.role_revoke(args[0], args[1])
            if success:
                self._save_data()
                await self._push_access_update()
                await ok(message)
                log.info(f"[Admin] {requester} {command} {args[0]} {args[1]}")
            else:
                await err(message)

        elif command == "setpassword":
            if not args:
                await err("Usage: /setpassword <new_password>"); return
            self.data["server_password"] = hash_password(args[0])
            self._save_data()
            await ok("Server password updated")
            log.info(f"[Admin] {requester} changed server password")

        elif command == "setmaxfile":
            if not args:
                await err("Usage: /setmaxfile <MB>"); return
            try:
                mb = float(args[0])
                if mb <= 0:
                    raise ValueError
            except ValueError:
                await err("Size must be a positive number (e.g. 8 or 0.5)"); return
            self.data["max_file_mb"] = mb
            self._save_data()
            await self._broadcast_all({"type": "config_update", "max_file_mb": mb})
            await ok(f"Max file size set to {mb} MB")
            log.info(f"[Admin] {requester} set max file size to {mb} MB")

        elif command == "history":
            if not args:
                await err("Usage: /history on|off"); return
            sub = args[0].lower()
            if sub == "on":
                self.data["history_enabled"] = True
                self._save_data()
                await ok("Chat history enabled")
            elif sub == "off":
                self.data["history_enabled"] = False
                self._save_data()
                await ok("Chat history disabled")
            else:
                await err("Usage: /history on|off")
            log.info(f"[Admin] {requester} set history {sub}")

        elif command == "makeadmin":
            if not args:
                await err("Usage: /makeadmin <username>"); return
            uname = args[0]
            if uname not in self.data["users"]:
                await err(f"User '{uname}' not found"); return
            admins = self.data.setdefault("admins", [])
            if uname not in admins:
                admins.append(uname)
                self._save_data()
            await ok(f"'{uname}' is now an admin")
            log.info(f"[Admin] {requester} made '{uname}' an admin")

        elif command == "removeadmin":
            if not args:
                await err("Usage: /removeadmin <username>"); return
            uname = args[0]
            admins = self.data.get("admins", [])
            if uname not in admins:
                await err(f"'{uname}' is not an admin"); return
            admins.remove(uname)
            self._save_data()
            await ok(f"'{uname}' is no longer an admin")
            log.info(f"[Admin] {requester} removed '{uname}' from admins")

        elif command == "blocked":
            now = time.time()
            active = [(ip, until) for ip, until in self._blocked_ips.items() if until > now]
            if active:
                lines = ["Blocked IPs:"]
                for ip, until in active:
                    remaining = int(until - now)
                    mins, secs = divmod(remaining, 60)
                    time_str = f"{mins}m {secs}s" if mins else f"{secs}s"
                    lines.append(f"  {ip}  —  {time_str} remaining")
                await ok("\n".join(lines))
            else:
                await ok("No IPs currently blocked")

        elif command == "unblock":
            if not args:
                await err("Usage: /unblock <ip>"); return
            ip = args[0]
            if ip in self._blocked_ips:
                del self._blocked_ips[ip]
                self._failed_attempts.pop(ip, None)
                await ok(f"IP {ip} unblocked")
                log.info(f"[Admin] {requester} unblocked {ip}")
            else:
                await err(f"IP {ip} is not blocked")

        elif command == "ratelimit":
            if not args:
                await err("Usage: /ratelimit on|off|attempts <N>|window <S>|block <S>"); return
            sub = args[0].lower()
            cfg = self.data.setdefault("rate_limit", {})

            if sub == "on":
                cfg["enabled"] = True
                self._save_data()
                await ok("Rate limiting enabled")
            elif sub == "off":
                cfg["enabled"] = False
                self._save_data()
                await ok("Rate limiting disabled")
            elif sub == "attempts":
                if len(args) < 2:
                    await err("Usage: /ratelimit attempts <N>"); return
                try:
                    n = int(args[1])
                    if n < 1: raise ValueError
                except ValueError:
                    await err("Must be a positive integer"); return
                cfg["max_attempts"] = n
                self._save_data()
                await ok(f"Max failed attempts set to {n}")
            elif sub == "window":
                if len(args) < 2:
                    await err("Usage: /ratelimit window <seconds>"); return
                try:
                    s = int(args[1])
                    if s < 1: raise ValueError
                except ValueError:
                    await err("Must be a positive integer"); return
                cfg["window_seconds"] = s
                self._save_data()
                await ok(f"Failure window set to {s}s")
            elif sub == "block":
                if len(args) < 2:
                    await err("Usage: /ratelimit block <seconds>"); return
                try:
                    s = int(args[1])
                    if s < 1: raise ValueError
                except ValueError:
                    await err("Must be a positive integer"); return
                cfg["block_seconds"] = s
                self._save_data()
                await ok(f"Block duration set to {s}s")
            else:
                await err("Usage: /ratelimit on|off|attempts <N>|window <S>|block <S>")
            if sub in ("on", "off", "attempts", "window", "block"):
                log.info(f"[Admin] {requester} ran /ratelimit {' '.join(args)}")

        else:
            await err(f"Unknown command: /{command}  —  type /help for a list")

    async def _broadcast_room(self, room: str, message: dict, exclude=None):
        if room not in self.room_clients:
            return
        msg_str = json.dumps(message)
        dead = set()
        for ws in self.room_clients[room]:
            if ws == exclude:
                continue
            try:
                await ws.send(msg_str)
            except Exception:
                dead.add(ws)
        for ws in dead:
            self.room_clients[room].discard(ws)

    async def _broadcast_all(self, message: dict):
        msg_str = json.dumps(message)
        # Iterate over a copy: handler() mutates connected_clients on disconnect
        for ws in list(self.connected_clients):
            try:
                await ws.send(msg_str)
            except Exception:
                pass  # dead connections are cleaned up by their handler()

    # -------------------------------------------------------------------------
    # GUI operations (invoked on the event loop via run_coroutine_threadsafe)
    # -------------------------------------------------------------------------

    async def gui_snapshot(self) -> dict:
        """A consistent read of everything the admin GUI displays."""
        online = {i["username"] for i in self.connected_clients.values() if i["username"]}
        members: dict = {}
        for uname, rlist in self.data.get("user_roles", {}).items():
            for r in rlist:
                members.setdefault(r, []).append(uname)
        roles = {
            name: {
                "color": rd.get("color", "#8d919b"),
                "rooms": list(rd.get("rooms", [])),
                "members": members.get(name, []),
            }
            for name, rd in self.data.get("roles", {}).items()
        }
        users = {
            uname: {
                "admin": self._is_admin(uname),
                "roles": self._user_roles(uname),
                "online": uname in online,
            }
            for uname in self.data["users"]
        }
        now = time.time()
        blocked = [(ip, int(until - now)) for ip, until in self._blocked_ips.items() if until > now]
        return {
            "online": sorted(online),
            "users": users,
            "rooms": list(self.data["rooms"]),
            "roles": roles,
            "room_members": {r: sorted(
                self.connected_clients[ws]["username"]
                for ws in self.room_clients.get(r, set())
                if self.connected_clients.get(ws, {}).get("username")
            ) for r in self.data["rooms"]},
            "history_enabled": bool(self.data.get("history_enabled")),
            "persist_files": bool(self.data.get("persist_files", True)),
            "max_file_mb": self.data.get("max_file_mb", 8),
            "rate_limit_enabled": bool(self.data.get("rate_limit", {}).get("enabled", True)),
            "blocked": blocked,
        }

    async def gui_add_user(self, uname: str, pwd: str) -> str:
        if not valid_username(uname):
            return "Username must be 1-32 chars: letters, digits, _ . -"
        if not pwd:
            return "Password cannot be empty"
        if uname in self.data["users"]:
            return f"User '{uname}' already exists"
        self.data["users"][uname] = hash_password(pwd)
        self._save_data()
        return f"User '{uname}' added"

    async def gui_set_user_password(self, uname: str, pwd: str) -> str:
        if uname not in self.data["users"]:
            return f"User '{uname}' not found"
        self.data["users"][uname] = hash_password(pwd)
        self._save_data()
        return f"Password updated for '{uname}'"

    async def gui_remove_user(self, uname: str) -> str:
        if uname not in self.data["users"]:
            return f"User '{uname}' not found"
        del self.data["users"][uname]
        self.data.get("user_roles", {}).pop(uname, None)
        if uname in self.data.get("admins", []):
            self.data["admins"].remove(uname)
        self._save_data()
        await self.gui_kick(uname)
        return f"User '{uname}' removed"

    async def gui_kick(self, uname: str) -> str:
        for ws, info in list(self.connected_clients.items()):
            if info["username"] == uname:
                try:
                    await ws.send(json.dumps({
                        "type": "system_message",
                        "content": "You have been kicked from the server"
                    }))
                    await ws.close()
                except Exception:
                    pass
                return f"Kicked '{uname}'"
        return f"User '{uname}' is not online"

    async def gui_set_admin(self, uname: str, make_admin: bool) -> str:
        if uname not in self.data["users"]:
            return f"User '{uname}' not found"
        admins = self.data.setdefault("admins", [])
        if make_admin and uname not in admins:
            admins.append(uname)
        elif not make_admin and uname in admins:
            admins.remove(uname)
        self._save_data()
        await self._push_access_update()
        return f"'{uname}' is {'now' if make_admin else 'no longer'} an admin"

    async def gui_add_room(self, room: str) -> str:
        if not valid_room_name(room):
            return "Room name must be 1-50 chars: letters, digits, spaces, _ . -"
        if room in self.data["rooms"]:
            return f"Room '{room}' already exists"
        self.data["rooms"].append(room)
        self.room_clients[room] = set()
        self.room_history.setdefault(room, [])
        self._save_data()
        await self._push_access_update()
        return f"Room '{room}' created"

    async def gui_remove_room(self, room: str) -> str:
        if room not in self.data["rooms"]:
            return f"Room '{room}' not found"
        if room in self.room_clients:
            await self._broadcast_room(room, {
                "type": "system_message",
                "content": f"Room '{room}' has been deleted"
            })
            for ws in list(self.room_clients[room]):
                if ws in self.connected_clients:
                    self.connected_clients[ws]["rooms"].discard(room)
            del self.room_clients[room]
        self.data["rooms"].remove(room)
        self._prune_room_from_roles(room)
        self._save_data()
        await self._push_access_update()
        return f"Room '{room}' removed"

    async def gui_role(self, action: str, *args) -> str:
        ops = {
            "create": self.role_create, "delete": self.role_delete,
            "rooms": self.role_set_rooms, "grant": self.role_grant,
            "revoke": self.role_revoke,
        }
        if action not in ops:
            return "Unknown role action"
        success, message = ops[action](*args)
        if success:
            self._save_data()
            await self._push_access_update()
        return message

    async def gui_set_config(self, key: str, value) -> str:
        if key == "history_enabled":
            self.data["history_enabled"] = bool(value)
        elif key == "persist_files":
            self.data["persist_files"] = bool(value)
        elif key == "rate_limit_enabled":
            self.data.setdefault("rate_limit", {})["enabled"] = bool(value)
        elif key == "max_file_mb":
            try:
                mb = float(value)
                if mb <= 0:
                    raise ValueError
            except (TypeError, ValueError):
                return "Max file size must be a positive number"
            self.data["max_file_mb"] = mb
            await self._broadcast_all({"type": "config_update", "max_file_mb": mb})
        elif key == "server_password":
            if not value:
                return "Password cannot be empty"
            self.data["server_password"] = hash_password(value)
        else:
            return f"Unknown setting '{key}'"
        self._save_data()
        return "Setting updated"

    async def gui_block_ip(self, ip: str) -> str:
        ip = (ip or "").strip()
        if not ip:
            return "Enter an IP address"
        dur = self.data.get("rate_limit", {}).get("block_seconds", 300)
        self._blocked_ips[ip] = time.time() + dur
        dropped = 0
        for ws, info in list(self.connected_clients.items()):
            try:
                if ws.remote_address and ws.remote_address[0] == ip:
                    await ws.close()
                    dropped += 1
            except Exception:
                pass
        extra = f", {dropped} connection(s) dropped" if dropped else ""
        return f"Blocked {ip} for {dur}s{extra}"

    async def gui_unblock(self, ip: str) -> str:
        if ip in self._blocked_ips:
            del self._blocked_ips[ip]
            self._failed_attempts.pop(ip, None)
            return f"Unblocked {ip}"
        return f"{ip} is not blocked"

    # -------------------------------------------------------------------------
    # CLI
    # -------------------------------------------------------------------------

    async def start(self):
        scheme = "wss" if self.ssl_context else "ws"
        log.info("Starting chat server on %s://%s:%s", scheme, self.host, self.port)
        if not self.ssl_context:
            log.warning("Running without TLS — pass --certfile/--keyfile to encrypt traffic (wss://)")
        if _ARGON2 is None:
            log.info("argon2-cffi not installed — using PBKDF2 for password hashing "
                     "(pip install argon2-cffi for argon2id)")
        async with ws_serve(self.handler, self.host, self.port,
                            max_size=16 * 1024 * 1024, ssl=self.ssl_context):
            print("Server running. Type 'help' for commands.")
            await self._cli_loop()

    async def _cli_loop(self):
        loop = asyncio.get_event_loop()
        while True:
            try:
                line = await loop.run_in_executor(None, input, "> ")
            except EOFError:
                break
            await self._handle_cli(line.strip())

    async def _handle_cli(self, line: str):
        if not line:
            return
        parts = line.split()
        cmd = parts[0].lower()
        args = parts[1:]

        if cmd == "help":
            print(
                "Commands:\n"
                "  adduser <username> <password>   Add a user\n"
                "  removeuser <username>           Remove a user\n"
                "  listusers                       List all registered users\n"
                "  addroom <name>                  Add a chat room\n"
                "  removeroom <name>               Remove a chat room\n"
                "  listrooms                       List all rooms\n"
                "  online                          Show online users\n"
                "  kick <username>                 Kick a user\n"
                "  makeadmin <username>            Grant in-chat admin privileges\n"
                "  removeadmin <username>          Revoke in-chat admin privileges\n"
                "  listadmins                      List all admins\n"
                "  role add <name> [#color]        Create a role\n"
                "  role del <name>                 Delete a role\n"
                "  role rooms <name> [room ...]    Set which rooms a role grants access to\n"
                "  role list                       List roles, granted rooms, and members\n"
                "  grantrole <username> <role>     Give a user a role\n"
                "  revokerole <username> <role>    Remove a role from a user\n"
                "  setpassword <new_password>      Change server password\n"
                "  setmaxfile <MB>                 Set max file upload size in MB\n"
                "  history on|off                  Enable or disable chat history\n"
                "  history limit <N>               Keep last N messages per room (0 = unlimited)\n"
                "  history clear [room]            Clear history for one room or all rooms\n"
                "  history status                  Show history settings\n"
                "  blocked                         List currently blocked IPs\n"
                "  unblock <ip>                    Unblock an IP address\n"
                "  ratelimit on|off                Enable or disable rate limiting\n"
                "  ratelimit attempts <N>          Max failed attempts before block\n"
                "  ratelimit window <seconds>      Rolling window for counting failures\n"
                "  ratelimit block <seconds>       How long to block an IP\n"
                "  ratelimit status                Show rate-limit settings\n"
                "  quit / exit                     Stop the server"
            )

        elif cmd == "adduser":
            if len(args) < 2:
                print("Usage: adduser <username> <password>")
                return
            username, password = args[0], args[1]
            if not valid_username(username):
                print("Username must be 1-32 chars: letters, digits, _ . -")
                return
            if username in self.data["users"]:
                print(f"User '{username}' already exists")
                return
            self.data["users"][username] = hash_password(password)
            self._save_data()
            print(f"User '{username}' added")

        elif cmd == "removeuser":
            if not args:
                print("Usage: removeuser <username>")
                return
            username = args[0]
            if username not in self.data["users"]:
                print(f"User '{username}' not found")
                return
            del self.data["users"][username]
            self._save_data()
            print(f"User '{username}' removed")

        elif cmd == "listusers":
            if self.data["users"]:
                print("Registered users:", ", ".join(self.data["users"].keys()))
            else:
                print("No users registered")

        elif cmd == "addroom":
            if not args:
                print("Usage: addroom <name>")
                return
            room = " ".join(args)
            if not valid_room_name(room):
                print("Room name must be 1-50 chars: letters, digits, spaces, _ . -")
                return
            if room in self.data["rooms"]:
                print(f"Room '{room}' already exists")
                return
            self.data["rooms"].append(room)
            self.room_clients[room] = set()
            self.room_history.setdefault(room, [])
            self._save_data()
            await self._push_access_update()
            print(f"Room '{room}' created")

        elif cmd == "removeroom":
            if not args:
                print("Usage: removeroom <name>")
                return
            room = " ".join(args)
            if room not in self.data["rooms"]:
                print(f"Room '{room}' not found")
                return
            if room in self.room_clients:
                await self._broadcast_room(room, {
                    "type": "system_message",
                    "content": f"Room '{room}' has been deleted by the server"
                })
                for ws in list(self.room_clients[room]):
                    if ws in self.connected_clients:
                        self.connected_clients[ws]["rooms"].discard(room)
                del self.room_clients[room]
            self.data["rooms"].remove(room)
            self._prune_room_from_roles(room)
            self._save_data()
            await self._push_access_update()
            print(f"Room '{room}' removed")

        elif cmd == "role":
            sub = args[0].lower() if args else ""
            if sub == "add":
                if len(args) < 2:
                    print("Usage: role add <name> [#color]"); return
                success, message = self.role_create(args[1], args[2] if len(args) > 2 else None)
            elif sub in ("del", "delete", "remove"):
                if len(args) < 2:
                    print("Usage: role del <name>"); return
                success, message = self.role_delete(args[1])
            elif sub == "rooms":
                if len(args) < 2:
                    print("Usage: role rooms <name> [room ...]"); return
                success, message = self.role_set_rooms(args[1], args[2:])
            elif sub == "list":
                print(self._roles_report()); return
            else:
                print("Usage: role add <name> [#color] | del <name> | rooms <name> [room ...] | list")
                return
            print(message)
            if success:
                self._save_data()
                await self._push_access_update()

        elif cmd in ("grantrole", "revokerole"):
            if len(args) < 2:
                print(f"Usage: {cmd} <username> <role>")
                return
            if cmd == "grantrole":
                success, message = self.role_grant(args[0], args[1])
            else:
                success, message = self.role_revoke(args[0], args[1])
            print(message)
            if success:
                self._save_data()
                await self._push_access_update()

        elif cmd == "listrooms":
            if self.data["rooms"]:
                print("Rooms:", ", ".join(self.data["rooms"]))
            else:
                print("No rooms")

        elif cmd == "online":
            online = [info["username"] for info in self.connected_clients.values() if info["username"]]
            print("Online:", ", ".join(online) if online else "(nobody)")

        elif cmd == "kick":
            if not args:
                print("Usage: kick <username>")
                return
            username = args[0]
            for ws, info in list(self.connected_clients.items()):
                if info["username"] == username:
                    await ws.send(json.dumps({
                        "type": "system_message",
                        "content": "You have been kicked from the server"
                    }))
                    await ws.close()
                    print(f"Kicked '{username}'")
                    return
            print(f"User '{username}' is not online")

        elif cmd == "makeadmin":
            if not args:
                print("Usage: makeadmin <username>")
                return
            uname = args[0]
            if uname not in self.data["users"]:
                print(f"User '{uname}' not found")
                return
            admins = self.data.setdefault("admins", [])
            if uname in admins:
                print(f"'{uname}' is already an admin")
                return
            admins.append(uname)
            self._save_data()
            print(f"'{uname}' is now an admin")

        elif cmd == "removeadmin":
            if not args:
                print("Usage: removeadmin <username>")
                return
            uname = args[0]
            admins = self.data.get("admins", [])
            if uname not in admins:
                print(f"'{uname}' is not an admin")
                return
            admins.remove(uname)
            self._save_data()
            print(f"'{uname}' is no longer an admin")

        elif cmd == "listadmins":
            admins = self.data.get("admins", [])
            print("Admins:", ", ".join(admins) if admins else "(none)")

        elif cmd == "setpassword":
            if not args:
                print("Usage: setpassword <new_password>")
                return
            self.data["server_password"] = hash_password(args[0])
            self._save_data()
            print("Server password updated")

        elif cmd == "setmaxfile":
            if not args:
                print("Usage: setmaxfile <megabytes>")
                return
            try:
                mb = float(args[0])
                if mb <= 0:
                    raise ValueError
            except ValueError:
                print("Size must be a positive number (e.g. 8 or 0.5)")
                return
            self.data["max_file_mb"] = mb
            self._save_data()
            await self._broadcast_all({"type": "config_update", "max_file_mb": mb})
            print(f"Max file size set to {mb} MB")

        elif cmd == "blocked":
            now = time.time()
            active = [(ip, until) for ip, until in self._blocked_ips.items() if until > now]
            if active:
                for ip, until in active:
                    remaining = int(until - now)
                    mins, secs = divmod(remaining, 60)
                    time_str = f"{mins}m {secs}s" if mins else f"{secs}s"
                    print(f"  {ip}  —  {time_str} remaining")
            else:
                print("No IPs currently blocked")

        elif cmd == "unblock":
            if not args:
                print("Usage: unblock <ip>")
                return
            ip = args[0]
            if ip in self._blocked_ips:
                del self._blocked_ips[ip]
                self._failed_attempts.pop(ip, None)
                print(f"IP {ip} unblocked")
            else:
                print(f"IP {ip} is not blocked")

        elif cmd == "ratelimit":
            sub = args[0].lower() if args else ""
            cfg = self.data.setdefault("rate_limit", {})

            if sub == "on":
                cfg["enabled"] = True
                self._save_data()
                print("Rate limiting enabled")

            elif sub == "off":
                cfg["enabled"] = False
                self._save_data()
                print("Rate limiting disabled")

            elif sub == "attempts":
                if len(args) < 2:
                    print("Usage: ratelimit attempts <N>"); return
                try:
                    n = int(args[1])
                    if n < 1: raise ValueError
                except ValueError:
                    print("Must be a positive integer"); return
                cfg["max_attempts"] = n
                self._save_data()
                print(f"Max failed attempts set to {n}")

            elif sub == "window":
                if len(args) < 2:
                    print("Usage: ratelimit window <seconds>"); return
                try:
                    s = int(args[1])
                    if s < 1: raise ValueError
                except ValueError:
                    print("Must be a positive integer"); return
                cfg["window_seconds"] = s
                self._save_data()
                print(f"Failure window set to {s}s")

            elif sub == "block":
                if len(args) < 2:
                    print("Usage: ratelimit block <seconds>"); return
                try:
                    s = int(args[1])
                    if s < 1: raise ValueError
                except ValueError:
                    print("Must be a positive integer"); return
                cfg["block_seconds"] = s
                self._save_data()
                print(f"Block duration set to {s}s")

            elif sub == "status":
                enabled = cfg.get("enabled", True)
                print(f"Rate limiting: {'ON' if enabled else 'OFF'}")
                print(f"Max attempts:  {cfg.get('max_attempts', 5)} failures "
                      f"within {cfg.get('window_seconds', 60)}s")
                print(f"Block duration: {cfg.get('block_seconds', 300)}s")
                now = time.time()
                count = sum(1 for t in self._blocked_ips.values() if t > now)
                print(f"Blocked IPs: {count}")

            else:
                print("Usage: ratelimit on|off|attempts <N>|window <S>|block <S>|status")

        elif cmd == "history":
            sub = args[0].lower() if args else ""

            if sub == "on":
                self.data["history_enabled"] = True
                self._save_data()
                print("Chat history enabled")

            elif sub == "off":
                self.data["history_enabled"] = False
                self._save_data()
                print("Chat history disabled (existing history kept on disk)")

            elif sub == "limit":
                if len(args) < 2:
                    print("Usage: history limit <N>")
                    return
                try:
                    n = int(args[1])
                    if n < 0:
                        raise ValueError
                except ValueError:
                    print("Limit must be a non-negative integer")
                    return
                self.data["history_limit"] = n
                self._save_data()
                desc = f"last {n} messages" if n > 0 else "unlimited messages"
                print(f"History limit set to {desc} per room")

            elif sub == "clear":
                room = " ".join(args[1:]) if len(args) > 1 else None
                if room:
                    # Check against stored history, not the live room list, so
                    # history left behind by deleted rooms can still be cleared
                    if room not in self.room_history:
                        print(f"Room '{room}' has no stored history")
                        return
                    self.room_history[room] = []
                    print(f"History cleared for '{room}'")
                else:
                    for r in self.room_history:
                        self.room_history[r] = []
                    print("History cleared for all rooms")
                self._save_history()

            elif sub == "status":
                enabled = self.data.get("history_enabled", False)
                limit   = self.data.get("history_limit", 100)
                print(f"History: {'ON' if enabled else 'OFF'}")
                print(f"Limit:   {limit} messages per room (0 = unlimited)")
                for room in self.data["rooms"]:
                    count = len(self.room_history.get(room, []))
                    print(f"  {room}: {count} stored message(s)")

            else:
                print("Usage: history on|off|limit <N>|clear [room]|status")

        elif cmd in ("quit", "exit"):
            print("Shutting down...")
            sys.exit(0)

        else:
            print(f"Unknown command: '{cmd}'. Type 'help' for help.")


def main():
    parser = argparse.ArgumentParser(description="Bastion Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8765, help="Port (default: 8765)")
    parser.add_argument("--config", default="server_data.json", help="Config file (default: server_data.json)")
    parser.add_argument("--certfile", help="TLS certificate chain (PEM). Enables wss://")
    parser.add_argument("--keyfile", help="TLS private key (PEM)")
    parser.add_argument("--gui", action="store_true", help="Launch the graphical admin console")
    args = parser.parse_args()

    if not args.gui:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%H:%M:%S",
        )

    ssl_context = None
    if args.certfile:
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            ssl_context.load_cert_chain(args.certfile, args.keyfile)
        except (OSError, ssl.SSLError) as e:
            print(f"Error loading TLS certificate/key: {e}")
            sys.exit(1)
    elif args.keyfile:
        print("Error: --keyfile requires --certfile")
        sys.exit(1)

    server = ChatServer(args.host, args.port, args.config, ssl_context=ssl_context)

    if args.gui:
        try:
            import server_gui
        except ImportError as e:
            print(f"The --gui option requires PyQt6. Install it with: pip install PyQt6\n({e})")
            sys.exit(1)
        server_gui.run(server)
    else:
        asyncio.run(server.start())


if __name__ == "__main__":
    main()
