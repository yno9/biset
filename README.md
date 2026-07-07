# biset

The ubiquitous pigeon, de facto like HTTP.

**biset is a single HTML file: a JMAP client with a Markdown vault.** It connects to your accounts, aggregates every message into one local vault, and renders it as Markdown you can read and reply to from any editor. Each account lives behind a *relay* — a small server that bridges an external protocol (SMTP, IMAP, …) into JMAP — and biset is the client that reads them all.

```
External events
       ↕
  Relays (per-protocol client & JMAP server)
   ├── jmapsmtp        SMTP send/receive, DeltaChat/chatmail E2EE
   ├── jmapimap        IMAP mailbox
   ├── jmapclaude      Claude CLI as an inbox
   └── ...
       ↕ JMAP over HTTP (+ SSE push)
  biset — JMAP client (single HTML file)
   ├── E2EE            OpenPGP + DeltaChat securejoin
   └── Vault          JSON source-of-truth + Markdown (FSAA)
       ↕
  Your editor / Obsidian / any Markdown tool
```

---

## Features

- **Single HTML file** — biset builds to one inlined [`dist/index.html`](https://github.com/yno9/biset/blob/main/dist/index.html). No dev server, no runtime dependencies; it runs from `file://` (local-first) or any static host.
- **JMAP client** — connects directly to any JMAP relay/server. Multi-account.
- **Relays** — each account sits behind an independent JMAP HTTP server bridging one external protocol (SMTP, IMAP, …). biset aggregates them all into one view.
- **End-to-end encryption** — OpenPGP messaging with full **DeltaChat / chatmail interoperability**, including QR-less securejoin (setup-contact) via an invite link. See [`ARC.md`](ARC.md).
- **Encrypted accounts** — password-derived envelope (Argon2id) provisioned to the server; the private key never leaves the client in the clear.
- **Markdown vault** — biset's identity. Opt into a folder and biset mirrors every thread as Markdown via the File System Access API. Edit a file to reply, archive, or delete — changes are watched and pushed back through the relay.

---

## Requirements

- A Chromium-based browser (Chrome/Edge/Brave). The Markdown vault — biset's identity — needs the File System Access API + `FileSystemObserver`, which are Chromium-only.
- At least one JMAP relay to connect to (e.g. a [jmapsmtp](https://github.com/yno9/go-jmapsmtp) / chatmail account).
- [Bun](https://bun.sh) — only if building from source.

---

## Getting started

You can run biset three ways:

**1. Use the hosted instance** — open <https://biset.non.md> and create an account.

**2. Use the prebuilt file** — the repo ships a built `dist/index.html`. Open it locally (`file://`) or drop it on any static host.

**3. Build from source**

```sh
git clone https://github.com/yno9/biset
cd biset
bun install
bun run build      # → dist/index.html
```

Then open `dist/index.html`.

> `bun build` alone only refreshes `dist/app.js`. Always use `bun run build`, which also runs `scripts/inline.mjs` to inline the JS + CSS into `dist/index.html`. See [`ARC.md`](ARC.md#build-flow).

First launch with no accounts drops you on `#new`, where you can create an account on the configured host. Existing users add accounts from the in-app `/account` page.

---

## Config

`config.json` (next to `index.html`) sets the default host used for account creation:

```json
{
  "hostname": "non.md"
}
```

New accounts are provisioned as `username@hostname` against `https://hostname`.

---

## Vault structure

Enable a vault from `/config` → **Vault**. biset then writes:

```
vault/
├── .data/                                   ← JSON, source of truth
│   ├── messages/<account>/<id>.json         ← JMAP Email objects
│   ├── threads/<threadId>.json              ← thread index
│   ├── mailboxes.json
│   ├── identities.json
│   └── submissions/<id>.json                ← queued outgoing
└── you@example.com/
    ├── _new.md                              ← compose new messages here
    ├── _bob@example.com_01151100.md         ← unread thread (_ prefix)
    └── bob@example.com_01151100.md          ← read thread
```

Filenames: `{contact}_{mmddHHMM}.md` — the timestamp comes from the thread's first message (immutable). A leading `_` marks an unread thread.

The `.data/` JSON is authoritative; Markdown files are rendered from it. Only the `status:` frontmatter field (and the `!b` marker) is read back to trigger actions.

---

## Thread format

```markdown
---
subject: "Re: hello"
contact: bob@example.com
id: abc123
status: 
---


- - -
2024-01-15-11:30 you@example.com

Sounds good, see you then!

- - -
2024-01-15-11:00 bob@example.com

Hey, are you free tomorrow?
```

**Frontmatter fields:**

| Field | Description |
|---|---|
| `subject` | Thread subject |
| `contact` | The other party's address |
| `id` | Thread ID |
| `status` | Set to trigger an action (see below) |

Messages are separated by a `- - -` line, newest first. The **compose area** is everything between the frontmatter and the first `- - -`.

---

## Replying

Write in the compose area, then either set `status: send` or append `!b` anywhere in the text:

```markdown
---
subject: "Re: hello"
contact: bob@example.com
id: abc123
status: 
---

Thanks, sounds good.!b

- - -
2024-01-15-11:00 bob@example.com

Hey, are you free tomorrow?
```

biset watches the file, detects the change, and sends automatically.

---

## New message

Edit `_new.md` in an account directory:

```markdown
---
contact: bob@example.com
status: send
---

Hi Bob, just wanted to reach out.
```

---

## Actions

Set `status:` in the frontmatter to trigger an action on the next sync:

| status | action |
|---|---|
| `send` | send the compose area (also triggered by `!b` in the body) |
| `seen` | mark thread as read |
| `follow` | follow / keep the thread |
| `archived` | archive the thread |
| `deleted` | delete the thread |
| `spam` | mark as spam |

---

## Relays

| Relay | Protocols | Description |
|---|---|---|
| [jmapsmtp](https://github.com/yno9/go-jmapsmtp) | SMTP | Self-hosted SMTP send/receive; wraps outgoing mail as PGP/MIME and injects Autocrypt for DeltaChat/chatmail E2EE |
| jmapimap | IMAP | Email via a standard IMAP mailbox |
| jmapclaude | Claude CLI | AI assistant as an inbox (per-project mailbox) |

Each relay is an independent JMAP HTTP server. It owns its config and state, handles reconnection, and exposes an SSE endpoint so biset gets push notifications on new data.

---

## Architecture

See [`ARC.md`](ARC.md) for the build flow, source layout, hash routing, and the DeltaChat / chatmail interoperability notes (securejoin v3, protected headers, and the byte-level chatmail traps).

---

## License

GNU Affero General Public License v3.0 (AGPL-3.0)
