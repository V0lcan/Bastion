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
- **Send** — type in the box and press **Enter** or click **Send**.
- **Message history** — press **Up / Down** arrow in the message box to cycle through previously sent messages.

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

### Changing the server password

```
> setpassword <new_password>
```

Takes effect for the next connection attempt. Existing sessions are not affected.

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

For a more secure setup, run the server over a VPN (e.g. Tailscale or WireGuard) so the traffic is encrypted end-to-end.

---

## Troubleshooting

| Problem | Likely cause | Fix |
|---|---|---|
| "Connection Error" on connect | Wrong IP, port, or server not running | Double-check IP and port; confirm server is running |
| "Invalid server password" | Wrong server password | Ask the server host for the correct password |
| "User not found" | Account not created | Ask the server host to run `adduser` |
| "Invalid password" | Wrong user password | Check with the server host |
| "User already connected" | You have another session open | Disconnect the other client first |
| Server prints `[!] Client error` | Usually a network drop | Generally safe to ignore |
| `websockets` not found | Package not installed | Run `pip install websockets PyQt6 cryptography` |
| `PyQt6` not found | Package not installed | Run `pip install PyQt6` |
| `cryptography` not found | Package not installed | Run `pip install cryptography` |
| `[unable to decrypt]` shown in chat | Client connected with a different server password than the sender used | All clients must use the same server password |
| Client window is blank after connecting | No room selected | Click a room in the sidebar |
