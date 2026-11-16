# Mildly Server

The personal server the app pairs with: one command installs it on any Linux machine the
user controls, it prints a 12-digit code and a QR code, and from then on it runs the user's
containers, keeps their encrypted files and chats, and (with their own domain) serves sites
over HTTPS and runs mail. `ServerService` and `ContextService` in the app's
`app/src/services/contracts.ts` are its API from the app's side; this document is the
server's side, and the wire format both must keep to.

Contents

1. [Pieces](#1-pieces)
2. [Trust and transport](#2-trust-and-transport)
3. [Pairing](#3-pairing)
4. [The API](#4-the-api)
5. [Containers](#5-containers)
6. [Files and chats](#6-files-and-chats)
7. [Addresses and HTTPS](#7-addresses-and-https)
8. [Install](#8-install)
9. [Order of work and state](#9-order-of-work-and-state)
10. [Decisions for the owner](#10-decisions-for-the-owner)

---

## 1. Pieces

| Piece | Where | What |
| --- | --- | --- |
| Engine | this repository (Rust, binary `mildly-server`) | HTTP API, pairing, devices, containers, storage, chat sync, metrics. Runs as a systemd service |
| Container runtime | Docker Engine or Podman, chosen at install | Runs the user's containers. The engine speaks the Docker API, which Podman also serves |
| HTTPS front | Caddy in a container (`mildly-front`), configured by the engine | Sites of web containers under the server's address, certificates from Let's Encrypt |
| Free names | deSEC (`name.dedyn.io`), through an account of the server's own | `mildly-server free-names`; the installer offers it |
| Mail | Stalwart in a container (add-on) | Only with the user's own domain |
| Installer | `install.sh` | `curl … | sh`: runtime, engine, service, free names, first code |
| Client side | the app's `app/src/services/live/server.ts`, `server-wire.ts`, `server-tools.ts` | Speak the API below |

State lives in `/var/lib/mildly` (`state.json`, `blobs/`, `snapshots/`), configuration in
`/etc/mildly/config.toml`.

## 2. Trust and transport

The promise on screen: *only your devices can open what is stored, and whoever hosts the
server cannot read chats, files or backups.* It must also work on a bare IP address with no
certificate, from a webview that cannot pin certificates. So the API does not rely on TLS:
every request is sealed end to end.

- The engine has a long-lived **P-256 key** (the server key). Its fingerprint is in the QR
  code and in every announcement (section 3).
- Each paired device has its own **P-256 signing key**, created on the device, never
  exported (a non-extractable WebCrypto key kept by the vault). This is the "passkey" the
  wizard talks about: WebAuthn passkeys are not available in every webview (WIRING.md, open
  decision 8), so the fallback the screens promise is used everywhere — a key that never
  leaves the device and is required to reach the server. `passkeyId` is its fingerprint.
- A request is one `POST /v1/rpc` (or `/v1/blob` for file bytes). The app makes a fresh
  ephemeral P-256 key, derives an AES-256-GCM key with ECDH against the server key and
  HKDF-SHA-256, and encrypts `{method, params, deviceId, time, nonce, signature}`. The
  signature is the device key's ECDSA over the method, time, nonce and a hash of the params.
  The answer is encrypted with the same key. Nothing on the wire is readable, a request
  cannot be replayed (time window of two minutes, nonces remembered), and only a paired
  device can call anything but `pair`.
- What the engine cannot read: personal files, chats, memory and backups are encrypted on
  the device with the **space key** before they are sent (section 6). The engine can read
  what it must act on: container settings and logs, device names, the domain.

## 3. Pairing

The installer (and `mildly-server pair` later) prints a **12-digit code** and a **QR code**.
The code works once, for ten minutes, and five wrong tries end it.

The app has to find the server from those 12 digits alone (the wizard has no address field):

1. `codeKey = PBKDF2-SHA-256(code, "mildly-pair-v1", 300 000 rounds)`. Slow on purpose: an
   eavesdropper who sees an announcement cannot try 10¹² codes in ten minutes.
2. While a code is valid the engine **announces** itself: `{addresses, serverKey}`
   encrypted with AES-GCM under a key derived from `codeKey`, published
   - on the local network: an answer to a UDP broadcast on port 7681 (the desktop and
     phone shells send it; a browser cannot);
   - at a **rendezvous**: a topic named from `codeKey` on an ntfy server (`ntfy.sh` by
     default, configurable on both sides, self-hostable). The topic name and the content
     mean nothing without the code.
3. The QR code skips the search: `mildly://pair?c=<code>&k=<server key fingerprint>&a=<address>`.
4. The app sends `pair` sealed to the announced server key: a **proof** that it knows the code
   (`HMAC(codeKey, "proof")`, never the code itself), the device name and kind, the device's
   public signing key, and a one-off ECDH **box** key with its tag `HMAC(codeKey, "box" ‖ box)`.
   The first device becomes the owner. The answer is the `ServerInfo`, the device record, and
   whether the code was an invite.
5. The first device creates the space key on the device (section 6).

**Invites.** A further device joins with a code made on a device that is already paired
(Personal server → Add a device), so the engine never learns it:

1. The inviting device picks the twelve digits, derives `codeKey`, and sends `invite.create`
   with the topic, the announcement key and the proof. None of them reveals the code; the
   engine announces the invite exactly like its own codes.
2. The joining device pairs as above. The engine records it on the invite with its box key
   and tag.
3. The inviting device, waiting on `invite.status`, checks the tag with the code (the engine
   cannot forge it), then seals the space key to the box: ECDH with a fresh key,
   HKDF-SHA-256 with salt `HMAC(codeKey, "space")` and info `mildly-space-v1`, AES-256-GCM
   with AAD `mildly-space`, and sends it with `invite.deliver`. A tag that does not match
   removes the joined device instead.
4. The joining device collects it with `space.receive`, opens it, and keeps it in its vault.

A device paired later with an installer code (for example after losing every device) can
manage the server but has no space key, so it cannot open stored files or chats; the app
says so. A wrong proof counts against every open code.

## 4. The API

All methods go through `/v1/rpc`; names follow the contract.

| Method | Contract | Notes |
| --- | --- | --- |
| `hello` | — | Unsealed. Engine version and server key, for the QR path |
| `pair` | `pair` | Code, device, signing key → `ServerInfo`, `DeviceInfo` |
| `setup` | `setup` | Quota and address choice from the wizard → snapshot |
| `load` | `load` | Everything the server pages show |
| `unpair` | `unpair` | Removes the calling device |
| `metrics` | `watchMetrics` | The last 24 samples; the app polls every 1.5 s |
| `containers.list` / `.create` / `.action` / `.remove` / `.logs` | containers | `create` returns at once with `building`; the app polls for updates. Names are unique |
| `containers.inspect` / `.read` | the model's tools | Any container, apps already on the machine included. No environment values |
| `containers.write` / `.exec` / `.configure` | the model's tools | The engine's own containers only |
| `terminal.open` / `.read` / `.write` / `.resize` / `.close` | `openTerminal` | `read` is a long poll (up to 25 s); sessions belong to the device that opened them |
| `domain.search` / `.check` / `.set`, `quota.set` | address, space | `set` and `quota.set` are owner only |
| `invite.create` / `.status` / `.deliver` / `.cancel`, `space.receive` | invites | `create` is owner only; the others belong to the device that made the invite, or that joined |
| `devices.remove` | `removeDevice` | Owner only, not the calling device (that is `unpair`) |
| `storage.list` / `.begin` / `.put` / `.end` / `.get` / `.remove` | storage | Pieces of up to 8 MB; `begin` checks the quota |
| `context.put` / `.list` / `.drop`, `memory.put` / `.get` | chat sync | `list` returns what changed since a time |
| `server.restart`, `update.check` | upkeep | `restart` is owner only; the engine exits and its service starts it again. `update.check` reads the latest release of `TheMildly/server` |
| `storage.*`, `context.*` | storage, chat sync | Sealed blobs (section 6) |
| `invite.*`, `devices.remove` | devices | Owner only |
| `notify.set`, `addon.set`, `mail.*`, snapshots, moving | server settings | Not yet |

Errors come back as `{code}`: `bad-code`, `expired`, `not-owner`, `not-found`, `exists`,
`external`, `bad-name`, `bad-path`, `too-large`, `no-free-names`, `name-taken`,
`no-public-address`, `not-pointing`, `ports-busy`, `dns`, `quota`, `runtime`,
`unavailable`. The app turns them into translated sentences.

## 5. Containers

The engine talks to the runtime's Docker-compatible socket (`/var/run/docker.sock`, or
Podman's `/run/podman/podman.sock`). Every container it makes carries `ai.mildly.*` labels
and joins the `mildly` network, where the others reach it by its plain name (`db`, `shop`).

**Apps already on the machine.** Containers the engine did not make are listed too
(`external`, id `x` + the runtime's short id), with a kind guessed from the image. The user
can start, stop and restart them, and the owner can open a shell in them. Nothing else
changes them: the engine refuses to remove them, write into them, run commands in them or
recreate them. The model can read their files, logs and settings and join their networks,
so a new app can be built next to an old one and talk to it without risk to it.

| Kind | Starts from | Reached at |
| --- | --- | --- |
| `web`, `miniapp` | `nginx:alpine`, files in a volume | a port on the server; `name.<domain>` once Caddy and a domain are there |
| `logic` | `node:22-alpine`, a placeholder API on port 3000 | same |
| `worker` | `node:22-alpine`, idle until code arrives | — |
| `database` | `postgres:17-alpine`, generated password | the `mildly` network only |

Images can be overridden in the config. A snapshot is the container committed to an image
plus its volume as a tarball, kept in `snapshots/`; moving sends that to another server
paired by the same user.

**The model builds.** The agent loop stays on the device, where the provider keys are; the
app gives models that take tools nine `server_*` tools (the app's `app/src/services/live/server-tools.ts`)
and a short brief: look first and reuse, one container per part, reach parts by name,
install and check the logs before saying it works, never change apps that were already
there. Each tool is one sealed call:

| Tool | Call | Notes |
| --- | --- | --- |
| `server_list_containers` | `containers.list` | |
| `server_create_container` | `containers.create`, then polls | Kind, name; optional image, command, port, networks to join. Waits until it runs |
| `server_write_file` / `server_read_file` | `containers.write` / `.read` | Relative to the app folder; reading also takes absolute paths, in any container |
| `server_run` | `containers.exec` | `sh -c` in the app folder; exit code and the last 64 KB of output; up to 300 s |
| `server_logs`, `server_inspect` | `containers.logs` / `.inspect` | |
| `server_configure_container` | `containers.configure` | Recreated with a new image, command, port or networks; files and host port stay |
| `server_restart_container` | `containers.action` | |

**Terminals.** `terminal.open` starts a shell (bash when there is one) in a container with a
pseudo-terminal, or a login shell on the machine itself for the owner. Output is buffered
(512 KB) and read with long polls through the sealed API; keystrokes go back the same way.
Sessions end after fifteen idle minutes.

## 6. Files and chats

The space key (AES-256-GCM) is made on the first device and travels only sealed between the
user's devices (section 3, invites). Everything below is encrypted with it on the device, as
`iv ‖ ciphertext` with an AAD that names what it is, so one sealed thing cannot pass for
another:

| What | On the device | On the server |
| --- | --- | --- |
| A file | Split into 4 MiB pieces, each sealed with AAD `mildly-file:<fid>:<n>` (`fid` random per file). Its name, kind, type, size and piece count are sealed as the description (`mildly-desc`) | `blobs/<id>.bin` and `blobs/<id>.json`: origin, stored size, time, the sealed description |
| A chat | The whole chat as JSON, AAD `mildly-chat:<id>` | `chats/<id>.bin`; its file time is when it last arrived |
| The memory list | JSON, AAD `mildly-memory` | `memory.bin` |

The engine knows sizes, times and the chat ids the app makes, nothing more. Personal files
count against the quota chosen in setup (by their stored size); generated media do not.
Chats are pulled at start-up and when the server pages open: `context.list` with the time of
the newest copy seen, and the app keeps the newer of each.

Removing a device stops it reaching the server; it still knows the space key it was given.
Changing the space key when a device is removed (and re-sealing what is stored) is for a
later version.

## 7. Addresses and HTTPS

- **IP address:** works from the start; sites open on their ports.
- **Free name (`name.dedyn.io`):** deSEC, a non-profit DNS service, gives one free name
  under `dedyn.io` per account, and `dedyn.io` is on the Public Suffix List, so each name has
  its own Let's Encrypt limits. The server holds an account of its own: `mildly-server
  free-names --email ADDRESS` signs it up (deSEC sends one email to confirm; the command
  waits) and keeps a long-lived token in `state.json`, or `--token TOKEN` takes an account the
  user already has. The installer offers this. The wizard's search then looks names up over
  DNS-over-HTTPS (a taken name has name servers), and choosing one registers it and points
  it and `*.name` at the server's public IPv4. Choosing another name lets the old one go.
- **Own domain:** the user points `name` (and `*.name`, so each site gets its own name) at the
  server. `domain.check` resolves both over DNS-over-HTTPS and compares with the server's
  public address; the answer says what is missing.
- **HTTPS:** with an address set, the engine runs Caddy as `mildly-front` on ports 80 and
  443, on the `mildly` network, and writes its configuration: the bare name opens the first
  site, `<site>.<name>` each web, mini-app and logic container. Certificates come from
  Let's Encrypt (`front_tls = "internal"` uses Caddy's own authority, for servers the
  internet cannot reach). The engine rewrites the configuration within seconds when sites
  are made, changed or removed. If another app already holds 80 or 443, the address is not
  changed and the app says why. Back to the IP address removes the front.

## 8. Install

```bash
curl -fsSL https://github.com/TheMildly/server/releases/latest/download/install.sh | sudo sh -s -- --runtime docker   # or podman
```

Without `--runtime` the installer asks (when it can) or keeps whatever runtime is already
there. It installs the runtime from its official source, the engine binary (from
`github.com/TheMildly/server` releases by default, `MILDLY_DOWNLOAD` or `--binary` otherwise),
a systemd unit, opens the API port (7680), discovery (7681/udp) and the web (80, 443) when a
firewall is on, starts the service, offers a free name (`--free-names EMAIL`,
`--no-free-names`) and prints the first code and QR code.

| Command | What |
| --- | --- |
| `mildly-server run` | The engine (what the service runs) |
| `mildly-server pair` | A fresh pairing code and QR code |
| `mildly-server free-names --email ADDRESS` / `--token TOKEN` | Free names through deSEC |
| `mildly-server version` | |

**Releases.** Running `.github/workflows/build.yml` with "Publish a release" ticked (or pushing
a tag such as `v0.1.0`, the `version` in `Cargo.toml`) builds `mildly-server-x86_64` and `mildly-server-aarch64`
on Ubuntu 22.04, so they also run on older distributions, and publishes them with
`install.sh` as a GitHub release, which is where the installer downloads from. Running it
without the box ticked only builds them and attaches them to the run.

## 9. Order of work and state

| Slice | What | State |
| --- | --- | --- |
| 1 | Engine skeleton, sealed RPC, pairing (code, QR, LAN, rendezvous), load, metrics, containers, installer; app side for the same | **done** — paired from the browser by the twelve digits through the rendezvous, set up, made a site container on Docker, started, stopped, read its log, removed it. The installer has not run on a real machine yet |
| 2 | The model builds on the server (tools), apps already on the machine, terminals, free names, own domain, the HTTPS front | **done** — a scripted model listed, inspected, was refused writing into and restarting an app that was already there, made a site container joined to that app's network, wrote into it, ran a command that reached the old app, read files and logs; terminals in a container, in the old app and on the machine; the own domain and a free name (against a stand-in deSEC) served the site over HTTPS through Caddy, a site made later appeared under the address by itself, a taken name was refused. Not yet against the real deSEC or with real Let's Encrypt certificates |
| 3 | Space key, storage, chat and memory sync, invites and device removal; restart, update check | **done** — two devices (separate browser profiles) on one engine: the first paired, uploaded a 5 MB file in two pieces, synced a chat and the memory list, and made an invite; the second joined with the typed code, got the space key, opened the file byte for byte and found the chat and memory. Nothing readable on the server's disk; quota refused an oversize file; a made-up code found no server; a removed device was shut out; restart came back with everything; removing the file deleted it |
| 4 | Snapshots and moving, add-ons, mail (Stalwart), backups on the server, changing the space key when a device is removed | |
| 5 | Directory for typed codes without the rendezvous; push | needs a project domain |

## 10. Decisions for the owner

1. ~~Where installs and binaries are served from~~ — decided: the releases of
   `github.com/TheMildly/server`, private for now. Until it is public, anonymous downloads
   fail and installs need `MILDLY_DOWNLOAD` or `--binary`. The wizard still shows
   `get.mildly.example/install.sh`, a placeholder in the frozen screens.
2. **A project domain** for the directory and a short install address. Free names no longer
   need it (deSEC, section 7).
3. ~~The rendezvous~~ — decided: `ntfy.sh`; a self-hosted ntfy can replace it with one setting.
   ntfy.sh limits free messages per address and day. A server sends about five per code, so
   that is far away for one server, but a machine on a shared address can hit it; codes then
   still work on the local network and by QR code, and the engine's log says so.
