# Bastion

A two-program self-hosted chat platform: a CLI server (`server.py`) and a PyQt6 GUI client (`client.py`). Communication uses WebSockets with JSON-encoded messages. All persistent state lives in a single JSON config file on the server.

---

## Requirements

Python 3.10 or newer. Install third-party packages once:

```
pip install websockets PyQt6 cryptography
```

| Package | Purpose | Built-in? |
|---|---|---|
| `websockets` | WebSocket server and client | No |
| `PyQt6` | GUI framework (client only) | No |
| `cryptography` | Fernet encryption + PBKDF2 key derivation (client only) | No |
| `asyncio` | Async I/O event loop | Yes |
| `hashlib` | Password hashing (SHA-256, server only) | Yes |
| `json` | Config and message serialisation | Yes |

---

## File Structure

```
Chat/
├── server.py                # CLI server
├── client.py                # GUI client
├── server_data.json         # Auto-generated on first server run
├── server_data_history.json # Auto-generated when history is enabled
├── README.md                # This file
└── GUIDE.md                 # End-user guide
```

---

## server.py

### Entry point

```
python server.py [--host HOST] [--port PORT] [--config CONFIG]
```

| Flag | Default | Description |
|---|---|---|
| `--host` | `0.0.0.0` | Interface to bind on. Use `0.0.0.0` for all interfaces. |
| `--port` | `8765` | TCP port to listen on. |
| `--config` | `server_data.json` | Path to the persistent config file. |

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

Passwords are hashed with **SHA-256 + random salt**:

```
stored_value = "<16-byte-hex-salt>:<sha256(salt + password)>"
```

`hash_password(password)` and `verify_password(password, stored)` implement this. Passwords are never stored or transmitted in plaintext after the initial auth message.

### Config file (`server_data.json`)

```json
{
  "server_password": "<salt>:<hash>",
  "users": {
    "alice": "<salt>:<hash>",
    "bob":   "<salt>:<hash>"
  },
  "rooms": ["General", "Gaming"],
  "admins": ["alice"],
  "max_file_mb": 8,
  "history_enabled": false,
  "history_limit": 100
}
```

The file is rewritten on every mutating CLI command. The history file (`server_data_history.json`) is written separately on every new message when history is enabled.

### Authentication flow

1. Client connects via WebSocket.
2. Server waits up to **30 seconds** for the first message.
3. First message must be `{"type": "auth", ...}`.
4. Server checks server password → username existence → user password → duplicate session.
5. On success, responds with `auth_result` including the full room list and `max_file_mb`.
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
key = PBKDF2HMAC(SHA256, length=32, salt=b"chat_platform_v1", iterations=100_000)
      → base64url-encode → Fernet key
```

Because all clients connecting to the same server share the same server password, they all derive the same Fernet key and can decrypt each other's messages. The server only ever sees ciphertext and requires no changes to support encryption.

Encrypted message types: `room_message` content and `file_message` content (entire payload JSON). Metadata (room name, username, timestamp) and server-originated system messages remain plaintext.

`derive_key(server_password)` and the `Fernet` instance are created in `ChatWindow._connect()` once per session.

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

The attach button (＋) opens a file picker. Images are displayed inline; GIFs play animated; other files show as a card with a Save button. The maximum file size is enforced client-side (from `max_file_mb` in `auth_result`) and again server-side before broadcast.

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

Modal dialog collecting five fields: `host`, `port`, `server_password`, `username`, `password`. Pre-fills from the previous session when reopened.

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
| `join_room` | `room` | Enter a room and receive its user list (and history if enabled) |
| `leave_room` | `room` | Leave a room |
| `send_message` | `room`, `content` | Broadcast an encrypted text message to a room |
| `file_message` | `room`, `content` | Broadcast an encrypted file payload to a room |
| `list_rooms` | — | Request the current room list |
| `list_users` | `room` | Request the user list for a room |
| `admin_command` | `command`, `args` | Execute an admin command; server responds with `admin_result` |

### Server → Client

| `type` | Additional fields | Description |
|---|---|---|
| `auth_result` | `success` (bool), `message`, `rooms`, `max_file_mb` (on success) | Response to `auth` |
| `rooms_list` | `rooms` (list) | Full room list, sent on request or when rooms change |
| `users_list` | `room`, `users` (list) | User list for a room |
| `room_message` | `room`, `username`, `content`, `timestamp`, `historical` (bool) | Encrypted text message |
| `file_message` | `room`, `username`, `content`, `timestamp` | Encrypted file payload |
| `user_joined` | `room`, `username` | Someone entered a room |
| `user_left` | `room`, `username` | Someone left a room or disconnected |
| `system_message` | `content` | Server-originated notice (kick, room deletion, etc.) |
| `config_update` | `max_file_mb` | Server configuration changed |
| `history_start` | `room` | Signals the start of replayed history for a room |
| `history_end` | `room` | Signals the end of replayed history for a room |
| `admin_result` | `success` (bool), `message` | Response to `admin_command` |
| `error` | `message` | Protocol error response |

Timestamps are formatted as `HH:MM:SS` in the server's local time.

---

## Security notes

- Passwords are salted-SHA256 hashed at rest. They are transmitted in plaintext inside the WebSocket handshake — use a VPN or SSH tunnel when connecting over the public internet.
- The server password acts as a gate preventing unknown clients from even attempting user authentication.
- **Message content is end-to-end encrypted** with Fernet (AES-128-CBC + HMAC-SHA256). The server never sees plaintext message bodies or file contents.
- The encryption key is symmetric and shared among all clients who know the server password. It is derived via PBKDF2-HMAC-SHA256 (100 000 iterations). This is group encryption, not per-user E2E.
- A user can only have one active session at a time; a second login with the same username is rejected.
- In-chat admin privileges are stored in `server_data.json` and must be granted by the server host via the CLI. A non-admin user who sends an `admin_command` receives a "Permission denied" error and the command is not executed.
- There is no rate limiting or brute-force protection on authentication attempts.
- Chat history (`server_data_history.json`) stores only text messages, not file payloads. History entries are stored as ciphertext and replayed as-is to joining clients.
