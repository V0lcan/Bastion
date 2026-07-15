# Bastion

A two-program self-hosted chat platform: a server (`server.py`, CLI or GUI) and a PyQt6 GUI client (`client.py`). Communication uses WebSockets with JSON-encoded messages. All persistent state lives in a JSON config file on the server, plus a companion history file that stores text messages and shared files.

---

## Requirements

Python 3.10 or newer. Install third-party packages once:

```
pip install -r requirements.txt
```

or manually:

```
pip install websockets PyQt6 cryptography
```

| Package | Purpose | Built-in? |
|---|---|---|
| `websockets` | WebSocket server and client | No |
| `PyQt6` | GUI framework (client, and the server's `--gui` console) | No |
| `cryptography` | Fernet encryption + PBKDF2 key derivation (client only) | No |
| `argon2-cffi` | **Optional.** argon2id password hashing on the server; PBKDF2 is used if absent | No |
| `asyncio` | Async I/O event loop | Yes |
| `hashlib` / `hmac` | Password hashing (PBKDF2-HMAC-SHA256) and constant-time comparison (server only) | Yes |
| `ssl` | Optional TLS (`wss://`) support | Yes |
| `json` | Config and message serialisation | Yes |

The headless CLI server needs only `websockets` (plus optional `argon2-cffi`). `PyQt6` is required for the client and for the server's graphical console.

---

## File Structure

```
Chat/
├── server.py                # Server (CLI + entry point)
├── server_gui.py            # Server admin console (used by --gui)
├── client.py                # GUI client
├── requirements.txt         # Dependency list
├── tests/
│   └── test_server.py       # Unit tests (python -m unittest discover tests)
├── server_data.json         # Auto-generated on first server run
├── server_data_history.json # Persisted text messages and shared files
├── README.md                # This file
└── GUIDE.md                 # End-user guide
```

---

## server.py

### Entry point

```
python server.py [--host HOST] [--port PORT] [--config CONFIG] [--certfile CERT --keyfile KEY] [--gui]
```

| Flag | Default | Description |
|---|---|---|
| `--host` | `0.0.0.0` | Interface to bind on. Use `0.0.0.0` for all interfaces. |
| `--port` | `8765` | TCP port to listen on. |
| `--config` | `server_data.json` | Path to the persistent config file. |
| `--certfile` | — | TLS certificate chain (PEM). When set, the server speaks `wss://`. |
| `--keyfile` | — | TLS private key (PEM). Used together with `--certfile`. |
| `--gui` | off | Launch the graphical admin console (`server_gui.py`) instead of the CLI. |

### Graphical admin console (`--gui`)

`python server.py --gui` opens a PyQt6 console that runs the WebSocket server in a background thread and exposes all administration through tabs:

- **Dashboard** — live server log, listening address, online count, and a Start/Stop button.
- **Users** — every registered user with an online indicator, admin/role badges; add, remove, kick, set password, grant/revoke roles, toggle admin.
- **Rooms** — all rooms with live occupancy and whether each is *open* or *restricted*; add and remove rooms.
- **Roles** — create/delete roles (with colours), set which rooms each grants, see members.
- **Settings** — toggle text history, file persistence, and login rate-limiting; set the max file size; change the server password; view, add, and remove blocked IPs.

All mutations run on the server's event loop via `run_coroutine_threadsafe`, so the GUI never touches server state directly. The same operations remain available from the CLI and from client slash-commands.

### Roles and room access

Roles gate access to rooms:

- A room becomes **restricted** as soon as *any* role lists it. Rooms that no role mentions stay **open** to everyone.
- A user may see and join a restricted room only if one of their roles grants it (admins always see every room).
- Roles carry a colour and are shown to users as badges next to their name in the user list and in chat.
- Granting or revoking a role updates affected clients live: their room list refreshes, badges update, and anyone sitting in a room they just lost access to is removed from it.

Manage roles from the CLI, the GUI Roles tab, or admin slash-commands:

```
role add <name> [#color]        Create a role
role del <name>                 Delete a role (also unassigns it)
role rooms <name> [room ...]    Set the rooms a role grants (replaces the list)
role list                       Show roles, granted rooms, and members
grantrole <username> <role>     Give a user a role
revokerole <username> <role>    Remove a role from a user
```

### `ChatServer` class

Owns all server state and logic.

| Attribute | Type | Description |
|---|---|---|
| `host` | `str` | Bound host |
| `port` | `int` | Bound port |
| `config_file` | `str` | Path to JSON config |
| `history_file` | `str` | Path to history JSON (derived from `config_file`) |
| `data` | `dict` | In-memory mirror of config file |
| `connected_clients` | `dict[WebSocket, dict]` | Maps each live connection to `{"username": str \| None, "rooms": set[str]}` |
| `room_clients` | `dict[str, set[WebSocket]]` | Maps each room name to the set of connections currently in it |
| `room_history` | `dict[str, list[dict]]` | In-memory message history per room |

| Method | Description |
|---|---|
| `_load_data()` | Reads config file, or creates it with defaults on first run |
| `_save_data()` | Writes `self.data` to the config file |
| `_init_rooms()` | Populates `room_clients` from the loaded room list |
| `_load_history()` | Loads `history_file` into `room_history` |
| `_save_history()` | Persists `room_history` to `history_file` |
| `_append_history(room, entry)` | Appends an entry and trims to `history_limit`; no-op when history is off |
| `handler(websocket)` | Async coroutine called per connection — handles auth, then dispatches messages |
| `_handle_message(ws, info, msg)` | Routes a single incoming client message by `type` field |
| `_handle_admin_command(ws, requester, command, args)` | Executes an in-chat admin command on behalf of `requester` |
| `_broadcast_room(room, msg, exclude)` | Sends `msg` to every connection in `room`, optionally skipping one |
| `_broadcast_all(msg)` | Sends `msg` to every connected client |
| `start()` | Starts the WebSocket server and the CLI loop |
| `_cli_loop()` | Reads stdin lines in an executor so the event loop is never blocked |
| `_handle_cli(line)` | Dispatches a CLI command string |

### Password hashing

Passwords are hashed with **argon2id** when `argon2-cffi` is installed, otherwise **PBKDF2-HMAC-SHA256** (600 000 iterations, 16-byte random salt). Stored values are self-describing by prefix:

```
argon2:$argon2id$v=19$m=...           (when argon2-cffi is available)
pbkdf2:<iterations>:<salt-hex>:<hash-hex>
```

`hash_password(password)` and `verify_password(password, stored)` implement both; PBKDF2 comparisons use `hmac.compare_digest` (constant time). The legacy v0.1 format (`<salt>:<sha256(salt + password)>`) is still accepted. Any hash weaker than the current scheme — legacy, PBKDF2 when argon2 is available, or an argon2 hash whose parameters have changed — is transparently re-hashed the first time that user logs in successfully. Because these functions are deliberately slow, verification runs in a worker thread (`asyncio.to_thread`) so the event loop keeps serving other clients.

Failed logins for an unknown username and a wrong password return the same message (`Invalid username or password`) so valid usernames cannot be enumerated.

### Config file (`server_data.json`)

```json
{
  "server_password": "argon2:$argon2id$... (or pbkdf2:<iterations>:<salt>:<hash>)",
  "users": {
    "alice": "argon2:$argon2id$...",
    "bob":   "argon2:$argon2id$..."
  },
  "rooms": ["General", "Gaming", "Staff"],
  "admins": ["alice"],
  "roles": {
    "moderator": { "color": "#eb459e", "rooms": ["Staff"] }
  },
  "user_roles": { "bob": ["moderator"] },
  "max_file_mb": 8,
  "history_enabled": false,
  "persist_files": true,
  "history_limit": 100,
  "max_message_chars": 20000,
  "rate_limit": { "enabled": true, "max_attempts": 5, "window_seconds": 60, "block_seconds": 300 },
  "flood": { "max_messages": 15, "window_seconds": 10 }
}
```

The file is written atomically (temp file + rename) on every mutating command. Missing keys are backfilled on load, so configs from older versions keep working. The history file (`server_data_history.json`) stores both persisted text messages (when `history_enabled`) and shared files (when `persist_files`), trimmed to `history_limit` entries per room.

### Authentication flow

1. Client connects via WebSocket.
2. Server waits up to **30 seconds** for the first message.
3. First message must be `{"type": "auth", ...}`.
4. Server checks server password → username existence → user password → duplicate session.
5. On success, responds with `auth_result` including the rooms the user may access, `max_file_mb`, `is_admin`, the role→colour map (`roles`), and the user's own roles (`your_roles`).
6. On any failure, responds with an error message and closes the handler.

### CLI commands

| Command | Arguments | Description |
|---|---|---|
| `help` | — | Print command list |
| `adduser` | `<username> <password>` | Register a new user |
| `removeuser` | `<username>` | Delete a user |
| `listusers` | — | Print all registered usernames |
| `addroom` | `<name>` | Create a room and notify all online clients |
| `removeroom` | `<name>` | Delete a room, notifying clients inside it first |
| `listrooms` | — | Print all room names |
| `online` | — | Print usernames of all currently connected users |
| `kick` | `<username>` | Send a system message then close that user's connection |
| `makeadmin` | `<username>` | Grant in-chat admin privileges to a user |
| `removeadmin` | `<username>` | Revoke in-chat admin privileges |
| `listadmins` | — | Print all users with admin privileges |
| `role add` | `<name> [#color]` | Create a role |
| `role del` | `<name>` | Delete a role (and unassign it from all users) |
| `role rooms` | `<name> [room ...]` | Set which rooms a role grants access to |
| `role list` | — | List roles, granted rooms, and members |
| `grantrole` | `<username> <role>` | Give a user a role |
| `revokerole` | `<username> <role>` | Remove a role from a user |
| `setpassword` | `<new_password>` | Replace the server password |
| `setmaxfile` | `<MB>` | Set the maximum file upload size; broadcasts `config_update` to all clients |
| `history on\|off` | — | Enable or disable message persistence |
| `history limit` | `<N>` | Keep the last N messages per room (0 = unlimited) |
| `history clear` | `[room]` | Clear history for one room or all rooms |
| `history status` | — | Show history settings and stored message counts |
| `quit` / `exit` | — | `sys.exit(0)` |

Room names support spaces: `addroom Lo-fi Music` creates a room called `Lo-fi Music`.

---

## client.py

### Entry point

```
python client.py
```

No command-line arguments. The connect dialog opens automatically on launch.

### Encryption

Message content is encrypted client-side with **Fernet** (AES-128-CBC + HMAC-SHA256). The key is derived deterministically from the server password via **PBKDF2-HMAC-SHA256**:

```
key = PBKDF2HMAC(SHA256, length=32, salt=b"chat_platform_v2", iterations=600_000)
      → base64url-encode → Fernet key
```

All clients on a server must run the same client version: the salt and iteration count are part of the key derivation, so mixed versions derive different keys and show `[unable to decrypt]`.

By default the key is derived from the **server password**, so all clients that can log in share it. The connect dialog also has an optional **Encryption Key** field: when set (and identical on every client), the key is derived from that passphrase instead, which is never sent to the server — so the operator, who knows the server password, still cannot derive the message key. The server only ever sees ciphertext either way.

Encrypted message types: `room_message` content and `file_message` content (entire payload JSON). Metadata (room name, username, timestamp) and server-originated system messages remain plaintext.

`derive_key(secret)` and the `Fernet` instance are created in `ChatWindow._connect()` once per session.

### Markdown

Messages support Discord-style inline markdown, processed by `markdown_to_html(text)`:

| Syntax | Output |
|---|---|
| `` ```code block``` `` | Monospace pre block |
| `` `inline` `` | Inline monospace span |
| `***bold italic***` | Bold italic |
| `**bold**` | Bold |
| `*italic*` or `_italic_` | Italic (snake_case protected) |
| `__underline__` | Underline |
| `~~strikethrough~~` | Strikethrough |
| `\|\|spoiler\|\|` | Hidden text (revealed on selection) |
| `> quote` | Blockquote styling |

### File sharing

The attach button (＋) opens a file picker. Images are displayed inline; GIFs play animated; text files (by MIME type or extension) get a scrollable inline preview; other files show as a card with a Save button. The maximum file size is enforced client-side (from `max_file_mb` in `auth_result`) and again server-side before broadcast.

Shared files are **persisted** in the room history (controlled by `persist_files`, on by default) and re-sent to anyone who joins the room later — so a file stays available after the sender disconnects. This is independent of the text-history toggle (`history_enabled`), which controls persistence of ordinary chat messages.

File payload structure (encrypted before sending):
```json
{
  "filename": "photo.jpg",
  "mimetype": "image/jpeg",
  "data": "<base64-encoded bytes>",
  "caption": "optional caption text"
}
```

### Admin slash commands

Typing `/command` in the message input sends an `admin_command` message to the server instead of a chat message. Info commands are available to all users; all others require the sender to be in the `admins` list.

| Command | Who can use | Description |
|---|---|---|
| `/help` | Everyone | Show this list (handled locally, no server round-trip) |
| `/online` | Everyone | List currently connected users |
| `/listusers` | Everyone | List all registered users |
| `/listrooms` | Everyone | List all rooms |
| `/kick <username>` | Admins | Kick a user from the server |
| `/adduser <username> <pass>` | Admins | Register a new user |
| `/removeuser <username>` | Admins | Delete a user |
| `/addroom <name>` | Admins | Create a room (spaces allowed in name) |
| `/removeroom <name>` | Admins | Delete a room |
| `/setpassword <new_password>` | Admins | Change the server password |
| `/setmaxfile <MB>` | Admins | Set max file upload size |
| `/history on\|off` | Admins | Enable or disable message history |
| `/makeadmin <username>` | Admins | Grant admin privileges to a user |
| `/removeadmin <username>` | Admins | Revoke admin privileges |
| `/role add\|del\|rooms\|list …` | Admins | Manage roles and the rooms they grant |
| `/grantrole <username> <role>` | Admins | Give a user a role |
| `/revokerole <username> <role>` | Admins | Remove a role from a user |

The server responds with `admin_result`. Success is shown in green; failure in red.

Admin privileges are granted by the server host via the CLI (`makeadmin <username>`) and persist in `server_data.json`.

### Classes

#### `ImageViewer(QDialog)`

Full-size image viewer opened when clicking an inline image. Contains a `QScrollArea` and a Save button.

#### `ClickablePixmapLabel(QLabel)`

Displays a static image scaled to `MAX_DISPLAY_PX` (480 px) wide. Click opens `ImageViewer`.

#### `AnimatedGifLabel(QLabel)`

Plays an animated GIF inline using `QMovie` + `QBuffer` from raw bytes. GIFs wider than `MAX_DISPLAY_PX` are scaled via `setScaledSize`. Click to save.

#### `FileAttachmentWidget(QFrame)`

Dark card widget for non-image files: mime-based icon, filename, human-readable size, and a Save button.

#### `MessageWidget(QFrame)`

A message row containing a username/timestamp header and any number of content items (text, image, file). `dim=True` uses muted colours for replayed history messages.

| Method | Description |
|---|---|
| `add_text(text)` | Appends a markdown-rendered `QLabel` |
| `add_image(data, filename, mimetype)` | Appends `AnimatedGifLabel` or `ClickablePixmapLabel` |
| `add_file(data, filename, mimetype)` | Appends `FileAttachmentWidget` |

#### `ChatArea(QScrollArea)`

Scrollable message container. Auto-scrolls to the bottom on new content only if the user was already at the bottom (within 40 px) before the widget was inserted.

| Method | Description |
|---|---|
| `add_message(widget)` | Appends a `MessageWidget`; smart-scrolls |
| `add_system(text, color)` | Appends a green italic system line; smart-scrolls; `color` defaults to `#608b4e` |
| `clear_all()` | Removes all widgets |

#### `ConnectDialog(QDialog)`

Modal dialog collecting five fields (`host`, `port`, `server_password`, `username`, `password`) plus a **Use TLS (wss://)** checkbox. Pre-fills from the previous session when reopened.

#### `WebSocketWorker(QObject)`

Runs inside a background `QThread`. Owns the asyncio event loop and the live WebSocket connection.

| Method | Description |
|---|---|
| `run()` (slot) | Thread entry: creates asyncio loop, runs `_main()` |
| `_main()` | Async: opens WS, sends auth, reads messages, emits `message_received` |
| `send_msg(msg)` | Thread-safe send via `run_coroutine_threadsafe` |
| `close()` | Thread-safe close via `run_coroutine_threadsafe` |

Signal: `message_received(dict)` — emitted for every incoming JSON message.

#### `ChatWindow(QMainWindow)`

The main application window.

| Attribute | Type | Description |
|---|---|---|
| `worker` | `WebSocketWorker \| None` | Active worker |
| `thread` | `QThread \| None` | Thread running the worker |
| `fernet` | `Fernet \| None` | Encryption instance for the current session |
| `username` | `str` | Authenticated username |
| `current_room` | `str \| None` | Room shown in the chat panel |
| `rooms` | `list[str]` | Ordered room list from server |
| `room_users` | `dict[str, list[str]]` | Users per room |
| `max_file_bytes` | `int` | Current file size cap (updated from server) |

| Method | Description |
|---|---|
| `_build_ui()` | Constructs all Qt widgets |
| `_show_connect_dialog()` | Opens `ConnectDialog`, calls `_connect` on accept |
| `_connect(params)` | Derives Fernet key, creates worker + thread |
| `_disconnect(silent)` | Closes WS, stops thread, resets UI |
| `_handle_message(msg)` | Dispatches incoming message dict |
| `_recv_text(msg, historical)` | Decrypts and renders a `room_message` |
| `_recv_file(msg)` | Decrypts and renders a `file_message` |
| `_refresh_rooms()` | Redraws the room `QListWidget` |
| `_refresh_users()` | Redraws the user `QListWidget` |
| `_on_room_changed(row)` | Handles room selection: leave old, join new, clear chat area |
| `_send_message()` | Routes to slash-command handler or encrypts and sends `send_message` |
| `_handle_slash_command(text)` | Handles `/help` locally; sends all others as `admin_command` |
| `_apply_max_file(mb)` | Updates `max_file_bytes` and attach-button tooltip |
| `_attach_file()` | File picker → size check → encrypt payload → send `file_message` |
| `_history_up/down()` | Cycles sent-message history via Up/Down arrow keys |
| `eventFilter(obj, event)` | Intercepts Up/Down in the input field |

### Threading model

Qt's event loop and the WebSocket asyncio loop run on separate threads, communicating via a Qt signal with an **auto (queued) connection**:

```
Worker thread:  asyncio loop → json.loads → message_received.emit(dict)
Qt main thread: signal delivery → _handle_message(dict) → UI update
```

`run_coroutine_threadsafe` is used in the other direction (Qt thread → asyncio) for sending messages and closing the connection.

---

## WebSocket Protocol

All messages are UTF-8 JSON objects. Every object has a `"type"` field.

### Client → Server

| `type` | Additional fields | Description |
|---|---|---|
| `auth` | `server_password`, `username`, `password` | Must be the first message sent |
| `join_room` | `room` | Enter a room and receive its user list (and replayed history/files); rejected if the user lacks access |
| `leave_room` | `room` | Leave a room |
| `send_message` | `room`, `content` | Broadcast an encrypted text message to a room |
| `file_message` | `room`, `content` | Broadcast an encrypted file payload to a room |
| `list_rooms` | — | Request the current room list |
| `list_users` | `room` | Request the user list for a room |
| `admin_command` | `command`, `args` | Execute an admin command; server responds with `admin_result` |

### Server → Client

| `type` | Additional fields | Description |
|---|---|---|
| `auth_result` | `success` (bool), `message`, and on success `rooms`, `max_file_mb`, `is_admin`, `roles` (name→colour), `your_roles` | Response to `auth` |
| `rooms_list` | `rooms` (list); optionally `roles`, `your_roles` | Room list the user may access, sent on request or when rooms/roles change |
| `users_list` | `room`, `users` (list), `user_roles` (name→roles), `roles` (name→colour) | User list for a room, with role badges |
| `room_message` | `room`, `username`, `content`, `timestamp`, `historical` (bool) | Encrypted text message |
| `file_message` | `room`, `username`, `content`, `timestamp`, `historical` (bool) | Encrypted file payload (replayed on join when persisted) |
| `user_joined` | `room`, `username`, `roles` | Someone entered a room |
| `user_left` | `room`, `username` | Someone left a room or disconnected |
| `roles_update` | `room`, `user_roles`, `roles` | Role assignments/colours changed; refresh badges |
| `room_closed` | `room`, `message` | The user's access to a room was removed; they are dropped from it |
| `system_message` | `content` | Server-originated notice (kick, room deletion, etc.) |
| `config_update` | `max_file_mb` | Server configuration changed |
| `history_start` | `room` | Signals the start of replayed history for a room |
| `history_end` | `room` | Signals the end of replayed history for a room |
| `admin_result` | `success` (bool), `message` | Response to `admin_command` |
| `error` | `message` | Protocol error response |

Timestamps are ISO-8601 UTC (e.g. `2026-07-15T14:09:57+00:00`); the client converts them to local time for display.

---

## Security notes

- Passwords are hashed at rest with argon2id (if `argon2-cffi` is installed) or PBKDF2-HMAC-SHA256 (600 000 iterations, per-hash random salt), compared in constant time. Weaker/legacy hashes are upgraded automatically on the next successful login.
- The auth message travels inside the WebSocket connection. **Without TLS it is plaintext on the wire** — run the server with `--certfile`/`--keyfile` and tick *Use TLS* in the client, or tunnel over a VPN (Tailscale/WireGuard) or SSH.
- Failed logins return a uniform `Invalid username or password`, so the auth endpoint does not reveal which usernames exist.
- Brute-force protection: repeated failed logins from one IP are blocked for a configurable period (`ratelimit` commands; default 5 failures / 60 s window / 300 s block).
- The server password acts as a gate preventing unknown clients from even attempting user authentication.
- **Message content is encrypted client-side** with Fernet (AES-128-CBC + HMAC-SHA256). The server never sees plaintext message bodies or file contents.
- The encryption key is symmetric and shared among all clients who know the server password, derived via PBKDF2-HMAC-SHA256 (600 000 iterations). This is **group encryption, not per-user end-to-end encryption**: anyone who knows the server password (including the server operator) can derive the key. Metadata (usernames, room names, timestamps) is visible to the server.
- Usernames (1–32 chars: letters, digits, `_ . -`) and room names (1–50 chars, spaces allowed) are validated server-side.
- A user can only have one active session at a time; a second login with the same username is rejected.
- In-chat admin privileges are stored in `server_data.json` and must be granted by the server host via the CLI or GUI. A non-admin user who sends an `admin_command` receives a "Permission denied" error and the command is not executed.
- **Roles and room access are enforced server-side**, not merely hidden in the UI: the server filters each user's room list and rejects `join_room` for rooms the user cannot access. A restricted room is invisible to users without a granting role. Note that access controls *who can read a room*, but the message key is still shared (see group-encryption caveat above) — access control is not a substitute for per-room encryption.
- Admin slash-command arguments (e.g. the password in `/adduser`) are **not** Fernet-encrypted — they are only protected by TLS. Prefer running user management from the server CLI/GUI, or enable TLS.
- Chat history (`server_data_history.json`) stores text messages (when enabled) and shared files (when `persist_files` is on) as ciphertext, replayed as-is to joining clients. Persisted files are held in plaintext-on-disk-as-ciphertext form and count toward `history_limit`; on a busy server with large files this file can grow, so lower `history_limit` or disable `persist_files` if disk is a concern.
