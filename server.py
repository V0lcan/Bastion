#!/usr/bin/env python3
"""
Bastion Server - CLI-based server for hosting chat rooms
Usage: python server.py [--host HOST] [--port PORT] [--config CONFIG]
"""

import asyncio
import json
import hashlib
import os
import sys
import datetime
import argparse

try:
    import websockets
except ImportError:
    print("Error: 'websockets' package not found. Install it with: pip install websockets")
    sys.exit(1)


def hash_password(password: str) -> str:
    salt = os.urandom(16).hex()
    h = hashlib.sha256(f"{salt}{password}".encode()).hexdigest()
    return f"{salt}:{h}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, h = stored.split(":", 1)
        return hashlib.sha256(f"{salt}{password}".encode()).hexdigest() == h
    except Exception:
        return False


class ChatServer:
    def __init__(self, host: str, port: int, config_file: str):
        self.host = host
        self.port = port
        self.config_file = config_file
        self.history_file = os.path.splitext(config_file)[0] + "_history.json"
        self.data = self._load_data()
        self.connected_clients: dict = {}  # websocket -> {"username": str, "rooms": set}
        self.room_clients: dict = {}       # room_name -> set of websockets
        self.room_history: dict = {}       # room_name -> list of message dicts
        self._init_rooms()
        self._load_history()

    def _load_data(self) -> dict:
        if os.path.exists(self.config_file):
            with open(self.config_file) as f:
                return json.load(f)
        data = {
            "server_password": hash_password("changeme"),
            "users": {},
            "rooms": ["General"],
            "admins": [],
            "max_file_mb": 8,
            "history_enabled": False,
            "history_limit": 100,
        }
        self._save_data(data)
        print("Created new server config. Default server password: changeme")
        print("Change it with: setpassword <new_password>")
        return data

    def _save_data(self, data=None):
        if data is None:
            data = self.data
        with open(self.config_file, "w") as f:
            json.dump(data, f, indent=2)

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
        with open(self.history_file, "w") as f:
            json.dump(self.room_history, f, indent=2)

    def _append_history(self, room: str, entry: dict):
        if not self.data.get("history_enabled"):
            return
        self.room_history.setdefault(room, [])
        self.room_history[room].append(entry)
        limit = self.data.get("history_limit", 100)
        if limit > 0 and len(self.room_history[room]) > limit:
            self.room_history[room] = self.room_history[room][-limit:]
        self._save_history()

    # -------------------------------------------------------------------------
    # WebSocket handler
    # -------------------------------------------------------------------------

    async def handler(self, websocket):
        client_info = {"username": None, "rooms": set()}
        self.connected_clients[websocket] = client_info
        try:
            raw = await asyncio.wait_for(websocket.recv(), timeout=30)
            auth_data = json.loads(raw)

            if auth_data.get("type") != "auth":
                await websocket.send(json.dumps({
                    "type": "auth_result", "success": False,
                    "message": "Expected auth message"
                }))
                return

            if not verify_password(auth_data.get("server_password", ""), self.data["server_password"]):
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

            if username not in self.data["users"]:
                await websocket.send(json.dumps({
                    "type": "auth_result", "success": False, "message": "User not found"
                }))
                return

            if not verify_password(password, self.data["users"][username]):
                await websocket.send(json.dumps({
                    "type": "auth_result", "success": False, "message": "Invalid password"
                }))
                return

            for ws, info in self.connected_clients.items():
                if ws != websocket and info["username"] == username:
                    await websocket.send(json.dumps({
                        "type": "auth_result", "success": False,
                        "message": "User already connected"
                    }))
                    return

            client_info["username"] = username
            await websocket.send(json.dumps({
                "type": "auth_result",
                "success": True,
                "message": f"Welcome, {username}!",
                "rooms": self.data["rooms"],
                "max_file_mb": self.data.get("max_file_mb", 8),
            }))
            print(f"[+] {username} connected")

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
            print(f"[!] Client error: {e}")
        finally:
            username = client_info.get("username")
            if username:
                print(f"[-] {username} disconnected")
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
            await websocket.send(json.dumps({"type": "rooms_list", "rooms": self.data["rooms"]}))

        elif msg_type == "join_room":
            room = msg.get("room")
            if room not in self.data["rooms"]:
                await websocket.send(json.dumps({"type": "error", "message": f"Room '{room}' does not exist"}))
                return
            client_info["rooms"].add(room)
            self.room_clients[room].add(websocket)
            await self._broadcast_room(room, {
                "type": "user_joined", "room": room, "username": username
            }, exclude=websocket)
            users = [
                self.connected_clients[ws]["username"]
                for ws in self.room_clients[room]
                if self.connected_clients[ws]["username"]
            ]
            await websocket.send(json.dumps({"type": "users_list", "room": room, "users": users}))
            # Replay history if enabled
            if self.data.get("history_enabled") and self.room_history.get(room):
                await websocket.send(json.dumps({"type": "history_start", "room": room}))
                for entry in self.room_history[room]:
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
            # Server-side file size guard (content is base64+encrypted, ~2× raw size)
            if msg_type == "file_message":
                max_mb = self.data.get("max_file_mb", 8)
                if len(content) > max_mb * 1024 * 1024 * 2:
                    await websocket.send(json.dumps({
                        "type": "error",
                        "message": f"File exceeds the server limit of {max_mb} MB"
                    }))
                    return
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            out_type = "room_message" if msg_type == "send_message" else "file_message"
            entry = {
                "type": out_type,
                "room": room,
                "username": username,
                "content": content,
                "timestamp": timestamp,
            }
            await self._broadcast_room(room, entry)
            # Persist text messages; skip file_message to avoid huge history files
            if msg_type == "send_message":
                self._append_history(room, entry)

        elif msg_type == "list_users":
            room = msg.get("room")
            if room in self.room_clients:
                users = [
                    self.connected_clients[ws]["username"]
                    for ws in self.room_clients[room]
                    if self.connected_clients[ws]["username"]
                ]
                await websocket.send(json.dumps({"type": "users_list", "room": room, "users": users}))

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
                    print(f"[Admin] {requester} kicked {target}")
                    return
            await err(f"User '{target}' is not online")

        elif command == "adduser":
            if len(args) < 2:
                await err("Usage: /adduser <username> <password>"); return
            uname, pwd = args[0], args[1]
            if uname in self.data["users"]:
                await err(f"User '{uname}' already exists"); return
            self.data["users"][uname] = hash_password(pwd)
            self._save_data()
            await ok(f"User '{uname}' added")
            print(f"[Admin] {requester} added user '{uname}'")

        elif command == "removeuser":
            if not args:
                await err("Usage: /removeuser <username>"); return
            uname = args[0]
            if uname not in self.data["users"]:
                await err(f"User '{uname}' not found"); return
            del self.data["users"][uname]
            self._save_data()
            await ok(f"User '{uname}' removed")
            print(f"[Admin] {requester} removed user '{uname}'")

        elif command == "addroom":
            if not args:
                await err("Usage: /addroom <name>"); return
            room = " ".join(args)
            if room in self.data["rooms"]:
                await err(f"Room '{room}' already exists"); return
            self.data["rooms"].append(room)
            self.room_clients[room] = set()
            self.room_history.setdefault(room, [])
            self._save_data()
            await self._broadcast_all({"type": "rooms_list", "rooms": self.data["rooms"]})
            await ok(f"Room '{room}' created")
            print(f"[Admin] {requester} created room '{room}'")

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
            self._save_data()
            await self._broadcast_all({"type": "rooms_list", "rooms": self.data["rooms"]})
            await ok(f"Room '{room}' removed")
            print(f"[Admin] {requester} removed room '{room}'")

        elif command == "setpassword":
            if not args:
                await err("Usage: /setpassword <new_password>"); return
            self.data["server_password"] = hash_password(args[0])
            self._save_data()
            await ok("Server password updated")
            print(f"[Admin] {requester} changed server password")

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
            print(f"[Admin] {requester} set max file size to {mb} MB")

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
            print(f"[Admin] {requester} set history {sub}")

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
            print(f"[Admin] {requester} made '{uname}' an admin")

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
            print(f"[Admin] {requester} removed '{uname}' from admins")

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
        dead = set()
        for ws in self.connected_clients:
            try:
                await ws.send(msg_str)
            except Exception:
                dead.add(ws)

    # -------------------------------------------------------------------------
    # CLI
    # -------------------------------------------------------------------------

    async def start(self):
        print(f"Starting chat server on {self.host}:{self.port}")
        async with websockets.serve(self.handler, self.host, self.port, max_size=16 * 1024 * 1024):
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
                "  setpassword <new_password>      Change server password\n"
                "  setmaxfile <MB>                 Set max file upload size in MB\n"
                "  history on|off                  Enable or disable chat history\n"
                "  history limit <N>               Keep last N messages per room (0 = unlimited)\n"
                "  history clear [room]            Clear history for one room or all rooms\n"
                "  history status                  Show history settings\n"
                "  quit / exit                     Stop the server"
            )

        elif cmd == "adduser":
            if len(args) < 2:
                print("Usage: adduser <username> <password>")
                return
            username, password = args[0], args[1]
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
            if room in self.data["rooms"]:
                print(f"Room '{room}' already exists")
                return
            self.data["rooms"].append(room)
            self.room_clients[room] = set()
            self._save_data()
            await self._broadcast_all({"type": "rooms_list", "rooms": self.data["rooms"]})
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
            self._save_data()
            await self._broadcast_all({"type": "rooms_list", "rooms": self.data["rooms"]})
            print(f"Room '{room}' removed")

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
                    if room not in self.data["rooms"]:
                        print(f"Room '{room}' not found")
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
    args = parser.parse_args()

    server = ChatServer(args.host, args.port, args.config)
    asyncio.run(server.start())


if __name__ == "__main__":
    main()
