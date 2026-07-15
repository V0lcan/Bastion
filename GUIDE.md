# Bastion — User Guide

## Requirements

- Python 3.10 or newer
- Three third-party packages (install once):
  ```
  pip install websockets PyQt6 cryptography
  ```

`websockets` is used by both programs. `PyQt6` and `cryptography` are used only by the client.

---

## First-time setup (server host)

### 1. Start the server

Open a terminal in the `Chat` folder and run:

```
python server.py
```

> **Prefer a graphical console?** Run `python server.py --gui` instead for a point-and-click admin window (users, rooms, roles, settings, and a live log). See [Using the server GUI](#using-the-server-gui) below. Everything in this CLI walkthrough has an equivalent there.

On first run the server creates `server_data.json` with one room (`General`) and a default server password of `changeme`. You will see:

```
Created new server config. Default server password: changeme
Change it with: setpassword <new_password>
Starting chat server on 0.0.0.0:8765
Server running. Type 'help' for commands.
>
```

### 2. Change the server password

At the `>` prompt, set a real password before sharing the server with anyone:

```
> setpassword mySecretPass123
Server password updated
```

### 3. Add user accounts

Add one account per person who will connect:

```
> adduser alice hunter2
User 'alice' added
> adduser bob p@ssw0rd
User 'bob' added
```

### 4. Add more rooms (optional)

```
> addroom Gaming
Room 'Gaming' created
> addroom Lo-fi Music
Room 'Lo-fi Music' created
```

That is all the server needs. Share the following with your friends:

- Your public IP address (or local IP if on the same network)
- The port (`8765` by default)
- The server password
- Their individual username and password

---

## Connecting with the client

### 1. Launch the client

```
python client.py
```

The connect dialog opens automatically.

### 2. Fill in the connection details

| Field | What to enter |
|---|---|
| Server IP | The server's IP address (e.g. `192.168.1.10` or a public IP) |
| Port | The port the server is running on (default `8765`) |
| Server Password | The password set with `setpassword` on the server |
| Username | Your account name (must be added by the server host) |
| Your Password | Your account password |
| Encryption Key | *Optional.* A shared passphrase for message encryption. Leave blank to use the server password. If your group sets one, **everyone must type the exact same value** — and the server operator then cannot read your messages. |
| Use TLS (wss://) | Tick if the server was started with `--certfile`/`--keyfile` |

Press **Enter** or click **Connect**.

### 3. Using the chat window

```
+------------------------------------------------------------------+
| Connected as alice         🔒 Encrypted   [Disconnect] [Connect] |
+----------+-------------------------------------------------------+
| ROOMS    |  # General                                            |
|          |  ----------------------------------------------------- |
|  General |  [10:30:01] alice: hey everyone!                      |
|  Gaming  |  [10:30:05] bob: hi!                                  |
|  Lo-fi   |  *** charlie joined the room                          |
|          |                                                       |
| USERS    |                                                       |
|          |                                                       |
| @alice   |                                                       |
|   bob    |                                                       |
|   charlie|                                                       |
+----------+-------------------------------------------------------+
| Type a message…                                         [Send]   |
+------------------------------------------------------------------+
```

The **🔒 Encrypted** indicator in the top bar confirms that messages are being encrypted before they leave your machine.

- **ROOMS panel** — click a room to join it. Your current room is highlighted.
- **USERS panel** — shows everyone currently in the active room. Your name is prefixed with `@`.
- **Chat area** — messages appear in real time. Your username is shown in a different colour from others'.
- **System messages** — shown in green italics (joins, leaves, server notices).
- **Roles** — if the server host has given you or others a role, it appears as a small coloured badge next to the name in the user list and in chat. Some rooms may only be visible to certain roles.
- **Send** — type in the box and press **Enter** or click **Send**. Use **Shift+Enter** for a new line within a message.
- **Attachments** — click **＋** to send an image or file. Images preview inline, text files show a scrollable preview, and everything else appears as a card with a **Save** button. Shared files remain in the room for people who join later.
- **Message history** — press **Up / Down** arrow (on the first/last line) in the message box to cycle through previously sent messages.

### 4. Switching rooms

Click any room in the sidebar. The client automatically leaves the previous room and joins the new one. Chat history from before you joined is not shown — only messages sent while you are in the room appear.

### 5. Disconnecting

Click **Disconnect** in the top bar, or close the window. You can click **Connect** to open the dialog and reconnect.

---

## Server administration

All admin commands are typed at the `>` prompt in the terminal where the server is running.

### User management

```
> adduser <username> <password>     Create a user
> removeuser <username>             Delete a user
> listusers                         List all registered users
```

Removing a user does not kick them if they are currently online — they will be disconnected the next time they try to authenticate (i.e. after a reconnect).

### Room management

```
> addroom <name>                    Create a room (spaces allowed in name)
> removeroom <name>                 Delete a room and notify anyone inside
> listrooms                         List all rooms
```

When a room is removed, anyone currently in it receives a system message and the room disappears from all connected clients' sidebar immediately.

### Online users

```
> online                            Show who is connected right now
```

### Kicking a user

```
> kick <username>
```

Sends the user a "you have been kicked" system message and closes their connection. They can reconnect immediately — there is no ban.

### Roles and private rooms

By default every room is open to everyone who can log in. To make a room private, create a **role** and give it access to that room — only users with the role (and admins) will see or be able to join it.

```
> addroom Staff                 Create the room
> role add moderator #eb459e    Create a role (colour is optional)
> role rooms moderator Staff     Let the role into the Staff room
> grantrole alice moderator      Give alice the role
```

Now `Staff` is hidden from everyone except admins and users with the `moderator` role. Alice sees it appear in her sidebar the moment you run `grantrole` — no reconnect needed. Roles show up as coloured badges next to a user's name in the user list and in chat.

```
> role list                      Show roles, their rooms, and members
> revokerole alice moderator     Remove the role (alice loses access immediately)
> role del moderator             Delete the role entirely
```

A room stops being private if no role grants it (for example after `role del`), reverting to open access.

### Shared files stay in the chat

Files and images people send are saved on the server and shown again to anyone who joins the room later, so they don't vanish when the sender disconnects. This is on by default. To turn it off (or manage text history), use the GUI Settings tab or:

```
> history status                 Show what is being kept
```

### Changing the server password

```
> setpassword <new_password>
```

Takes effect for the next connection attempt. Existing sessions are not affected.

---

## Using the server GUI

Launch the graphical admin console instead of the CLI:

```
python server.py --gui
```

The server starts immediately and a window opens with five tabs:

| Tab | What you can do |
|---|---|
| **Dashboard** | Watch the live server log; see the listening address and how many users are online; Stop/Start the server. |
| **Users** | See every account with an online dot and admin/role badges. Add or remove users, set a password, kick, grant/revoke roles, toggle admin. |
| **Rooms** | See all rooms with live occupancy and whether each is *open* or *restricted*. Add or remove rooms. |
| **Roles** | Create and delete roles (with a colour), choose which rooms each role grants, and see who has it. |
| **Settings** | Toggle text history, file persistence, and login rate-limiting; set the max file size; change the server password; block and unblock IPs. |

Select a user or role first, then use the buttons underneath the list to act on it. Changes take effect immediately and are pushed to connected clients live, exactly like the CLI commands.

The `--gui` option needs `PyQt6` installed (the same package the client uses). The headless `python server.py` needs only `websockets`.

### Stopping the server

```
> quit
```

or

```
> exit
```

All connected clients will lose their connection when the server stops.

---

## Running on a custom port or host

```
python server.py --host 0.0.0.0 --port 9000
```

The client's **Port** field must match whatever port the server uses.

To bind only to a specific interface (e.g. localhost-only for testing):

```
python server.py --host 127.0.0.1
```

---

## Using a different config file

Useful if you want to run multiple separate servers on the same machine:

```
python server.py --config friends_server.json --port 8765
python server.py --config work_server.json   --port 8766
```

Each config file is independent — separate user lists, passwords, and rooms.

---

## Connecting over the internet

If the server is running on a home network, you need to:

1. Forward the server port (default `8765`) on your router to the machine running `server.py`.
2. Share your **public** IP address (not your local `192.168.x.x` one) with friends.
3. Make sure the port is allowed in Windows Firewall.

For a more secure setup, do one (or both) of the following:

### Option A — TLS (wss://)

If you have a domain name and a certificate (e.g. from Let's Encrypt), start the server with:

```
python server.py --certfile fullchain.pem --keyfile privkey.pem
```

Clients then tick **Use TLS (wss://)** in the connect dialog and enter the domain name as the Server IP. The certificate must be valid for the hostname the clients type in — self-signed certificates will be rejected unless the clients install your CA.

### Option B — VPN

Run the server over a VPN (e.g. Tailscale or WireGuard) so all traffic is encrypted at the network layer without needing a certificate.

---

## Troubleshooting

| Problem | Likely cause | Fix |
|---|---|---|
| "Connection Error" on connect | Wrong IP, port, or server not running | Double-check IP and port; confirm server is running |
| "Invalid server password" | Wrong server password | Ask the server host for the correct password |
| "Invalid username or password" | Account not created, or wrong user password | Check with the server host; they can create accounts with `adduser` |
| "Too many failed login attempts" | Your IP was temporarily blocked after repeated failures | Wait for the block to expire, or ask the host to run `unblock <ip>` |
| "User already connected" | You have another session open | Disconnect the other client first |
| Server prints `[!] Client error` | Usually a network drop | Generally safe to ignore |
| `websockets` not found | Package not installed | Run `pip install websockets PyQt6 cryptography` |
| `PyQt6` not found | Package not installed | Run `pip install PyQt6` |
| `cryptography` not found | Package not installed | Run `pip install cryptography` |
| `[unable to decrypt]` shown in chat | Client connected with a different server password than the sender used | All clients must use the same server password |
| Client window is blank after connecting | No room selected | Click a room in the sidebar |
