# hyKBridge

```
== HyKBridge by HYrecovery & HoshinoSumi from teko.IO SisTemS! ==
== Under MIT Open Source License ==
```

**A LAN bridge that lets your computer reach an e-reader that spends most of its life
asleep.** The device polls *you*: it wakes on a timer, finds your machine on the local
network, pulls one command, runs it, and goes back to sleep.

No cloud. No accounts. No third-party server. Two machines on the same LAN are enough.

Tested on a jailbroken Kindle Paperwhite 3 (KUAL + Kindle Python 3.9).

---

## Why it is built this way

A suspended device has **no network stack** — nothing can connect to it while it sleeps.
So the direction has to be inverted:

* the **device is the active party**: it wakes, discovers the host, and pulls work;
* the **host is a passive server**: it waits, authenticates, and answers.

Every response from the host is signed; the device **verifies the signature before
running anything**, because commands execute as `root` on the device. A rogue server on
the LAN is the real threat, and that is exactly what the signature stops.

## How it works

```
        pair once                    then, forever
   ┌──────────────────┐        ┌────────────────────────────────────┐
   │ device: KUAL     │        │ device wakes (RTC alarm)           │
   │  "Show Pairing   │        │   → finds host (remembered IP,     │
   │   Code" → 6 digits│       │     else UDP beacon on :8093)      │
   │        ↓         │        │   → GET /next?dev=…&hold=25        │
   │ host: pair --code│        │   → verifies X-Host-Sig (HMAC)     │
   │        ↓         │        │   → runs it / saves the file       │
   │ shared secret    │        │   → POST /result                   │
   │ + device_id      │        │   → arms the next alarm, sleeps    │
   └──────────────────┘        └────────────────────────────────────┘
```

* **Discovery** — the device first tries the host address it learned at pairing time
  (the host never has to be configured by hand), then listens for the host's UDP
  broadcast (`255.255.255.255:8093`, one packet every 2 s). LAN only, short timeouts.
* **The response body *is* the command.** No envelope, no JSON wrapper for commands.
* **Airplane mode short-circuits the loop** — wireless off means no poll, no alarm, no
  wake. It is judged by the explicit wireless switch, never by `wlan0` state (right
  after resume the interface is not associated yet, and reading that as "airplane mode"
  would mean the device never arms another alarm and never wakes again).

## Security model

| Direction | Credential | Protects against |
|---|---|---|
| host → device | `X-Host-Sig = HMAC-SHA256(secret, body)` | a rogue "host" on the LAN feeding the device root commands |
| device → host | `X-Dev`, `X-Ts`, `X-Sig = HMAC(secret, dev\|ts\|method\|path)` | rogue devices draining your queue; `X-Ts` gives replay protection (±300 s) |
| first contact | 6-digit code shown on the device screen, **single use**, 5-minute TTL, max 5 attempts, constant-time compare | someone racing you to pair |

File transfers are signed over `sha256(content)` and written to a `.part` file before an
atomic rename. Secrets are never printed — only lengths/fingerprints.

## Install

### 1. Device (jailbroken Kindle with KUAL + Kindle Python 3)

Copy the `device/` folder to the Kindle as `extensions/hyKBridge/`, e.g. over USB:

```
<kindle>/extensions/hyKBridge/{config.xml,menu.json,bin/,server/}
```

Then, in KUAL: **hyKBridge → Shell: Start** (this also opens the port in the firewall —
Kindle's `INPUT` policy is `DROP`, so a new port needs an explicit rule; the rule is
runtime-only and disappears on reboot). The device service listens on **8090**.

The menu also offers **Shell: Stop / Restart**, **Show Status**, **Show Log** and the
pulse / keep-awake switches.

### 2. Host (any machine with Node 18+)

```bash
node host/hyKBridge.mjs serve        # HTTP on 8091/8092 + UDP beacon
```

### 3. Pair once

| | |
|---|---|
| on the device | KUAL → **hyKBridge → Show Pairing Code** (6 digits appear on screen) |
| on the host | `node host/hyKBridge.mjs pair --kindle <device-ip> --code 123456` |

### 4. Use it

```bash
node host/hyKBridge.mjs exec "df -h /mnt/us"      # run a command on the device
node host/hyKBridge.mjs push ./book.mobi           # deliver a file to /documents
node host/hyKBridge.mjs list                       # queue / results
node host/hyKBridge.mjs result <job-id>            # read a result
node host/hyKBridge.mjs status                     # paired devices, ports, counters
```

On the device, **hyKBridge → Pulse: Start** begins the wake-poll-sleep loop
(`state/pulse-interval`, default 120 s). Pulse never forces a suspend: it only arms an
RTC alarm and lets the system sleep when it wants, so using the device is never
interrupted.

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/__hello` | none | discovery marker (`{"app":"hyKBridge",…}`) |
| GET | `/next?dev=&hold=25` | HMAC | long-poll; **200 + command body**, or 204 |
| POST | `/result?job=` | HMAC | return output, clears the job |
| GET | `/file/<job>` | HMAC | download a queued file (signed over its sha256) |
| POST | `/api/pair` | 6-digit code | bootstrap: exchange the code for a device secret |

## Verify it yourself

```bash
node host/selftest.mjs
```

Plays both sides locally: 401 without credentials, 401 on a stale timestamp, 401 with the
wrong secret, long-poll really holds, the body is the command, a one-byte change breaks
the signature, results are stored and jobs cleared.

Expected: `RESULT: 10 passed, 0 failed`.

The banner goes to **stderr** for `exec` / `push` / `result`, so stdout stays pipeable;
set `HYKBRIDGE_QUIET=1` to drop it entirely.

### Updating a device that is already set up

Nothing stops you from pushing new files while the service runs -- the device
service exposes `POST /api/put?path=...` (token-authenticated, writes confined to
`/mnt/us`), and **Shell: Restart** applies them. That is exactly how this package was
built: edit here, push, restart, re-run `selftest.mjs`.

## Layout

```
host/hyKBridge.mjs        host application (single file, zero npm dependencies)
host/selftest.mjs         protocol test
device/config.xml         KUAL extension manifest
device/menu.json          KUAL menu
device/server/hyKBridge.py    device service: exec / files / books / plugins / pairing
device/bin/hyKBridge-pulse.py the wake-poll-sleep client
device/bin/banner.sh          the copyright banner (sourced by every script)
device/bin/*.sh               start / stop / restart / status / log / pairing code / keep-awake
```

## License

MIT — see [LICENSE](LICENSE).

*Simplified Chinese: [README.chs.md](README.chs.md)*
