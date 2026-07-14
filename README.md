# biset

The ubiquitous pigeon, de facto like HTTP.

**biset is a single HTML file: a JMAP client with a Markdown vault, built on a portable identity.** It connects to your accounts, aggregates every message into one local vault, and renders it as Markdown you can read and reply to from any editor. Each account lives behind a *relay* — a small server that bridges an external protocol (SMTP, ActivityPub, IMAP, …) into JMAP — and biset is the client that reads them all.

Underneath, every identity is a **did:dht** — a client-generated, rotation-less key, not an address. Addresses (`you@relay.example`) are discoverable *pointers* to that key, published as a signed record on the Mainline DHT and (for human-readable lookup) a DNS TXT record. Lose a relay, move to another operator, or bring your own domain, and contacts still find you — the address can change, the identity doesn't. See [`DID.md`](DID.md) for the full design and [`ARC.md`](ARC.md#identity-layer-did) for the current architecture.

```
External events
       ↕
  Relays (per-protocol client & JMAP server)
   ├── jmapsmtp        SMTP send/receive, DeltaChat/chatmail E2EE
   ├── jmapap          ActivityPub federation (fediverse)
   ├── jmapimap        IMAP mailbox
   ├── jmapclaude      Claude CLI as an inbox
   └── ...
       ↕ JMAP over HTTP (+ SSE push)         ↕ DID resolution (DHT + DNS)
  biset — JMAP client (single HTML file)     anchor — optional identity registry
   ├── DID             portable root identity, per-relay scoped credentials
   ├── E2EE            OpenPGP + DeltaChat securejoin
   └── Vault           JSON source-of-truth + Markdown (FSAA)
       ↕
  Your editor / Obsidian / any Markdown tool
```

---

## Features

- **Single HTML file** — biset builds to one inlined [`dist/index.html`](https://github.com/yno9/biset/blob/main/dist/index.html). No dev server, no runtime dependencies; it runs from `file://` (local-first) or any static host.
- **Portable identity (DID)** — a rotation-less `did:dht` root, generated client-side, backed up as a 24-word recovery phrase. Move relays, add a relay run by a different operator, or bring your own domain, and your identity — keys, contacts, discoverability — comes with you. DID is layered on top of, not instead of, real protocols: biset still speaks plain SMTP/JMAP/ActivityPub, so nothing about interop is sacrificed for portability. Fully optional — a relay/account can run with no DID at all ("anchorless"). See [`DID.md`](DID.md).
- **JMAP client** — connects directly to any JMAP relay/server. Multi-account, multi-protocol (mail + ActivityPub) merged into one identity.
- **Relays** — each account sits behind an independent JMAP HTTP server bridging one external protocol (SMTP, ActivityPub, IMAP, …). biset aggregates them all into one view. Relays are independent processes that share libraries, not state — no core server.
- **End-to-end encryption** — OpenPGP messaging with full **DeltaChat / chatmail interoperability**, including QR-less securejoin (setup-contact) via an invite link. See [`ARC.md`](ARC.md).
- **Encrypted accounts** — password-derived envelope (Argon2id) provisioned to the server; the private key never leaves the client in the clear. Recovery-phrase login works without ever touching a password.
- **Bring your own domain** — host mail on your own domain, served by an existing relay, with no server to run yourself: prove domain ownership via a DNS TXT record, biset relay handles the rest. See [`DID.md`](DID.md#custom-byo-domains--implemented-2026-07-13).
- **Markdown vault** — Opt into a folder and biset mirrors every thread as Markdown via the File System Access API. Edit a file to reply, archive, or delete — changes are watched and pushed back through the relay.

---

## Requirements

- Any Chromium-based browser (Brave/Vivaldi/Edge). The Markdown vault needs the File System Access API + `FileSystemObserver`, which are Chromium-only.
- At least one JMAP relay to connect to (e.g. a [jmapsmtp](https://github.com/yno9/go-jmapsmtp) / chatmail account).
- [Bun](https://bun.sh) — only if building from source.

---

## Getting started

You can run biset three ways:

**1. Use the hosted instance** — open <https://t.biset.md> and create an account.

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

`config.json` (next to `index.html`, inlined into the build) sets the relays used for account creation:

```json
{
  "hostname": "t.biset.md",
  "mail_url": "https://mail.biset.md",
  "ap_url": "https://ap.biset.md"
}
```

New accounts get **both** a mail identity (`username@hostname` on `mail_url`) and an ActivityPub identity (on `ap_url`), sharing one DID — see [`DID.md`](DID.md). `hostname` alone (no explicit `mail_url`/`ap_url`) falls back to `mail.<hostname>` / `ap.<hostname>`.

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
| [jmapsmtp](https://github.com/yno9/go-jmap-smtp) | SMTP | Self-hosted SMTP send/receive; wraps outgoing mail as PGP/MIME and injects Autocrypt for DeltaChat/chatmail E2EE |
| [jmapap](https://github.com/yno9/go-jmapap) | ActivityPub | Fediverse federation — WebFinger, actor documents, inbox/outbox; a JMAP↔AP bridge, sibling of jmapsmtp |
| jmapimap | IMAP | Email via a standard IMAP mailbox |
| jmapclaude | Claude CLI | AI assistant as an inbox (per-project mailbox) |

Each relay is an independent JMAP HTTP server. It owns its config and state, handles reconnection, and exposes an SSE endpoint so biset gets push notifications on new data. Relays that opt into DID also share [`go-jmapserver`](https://github.com/yno9/go-jmapserver) (common JMAP/DID library code, not shared state) and, optionally, [`go-didanchor`](https://github.com/yno9/go-didanchor) — a small, standalone identity registry (address↔DID claims, DNS anchor records) that any relay can point at, or none at all ("anchorless" mode). See [`DID.md`](DID.md) for how these fit together.

---

## Architecture

See [`ARC.md`](ARC.md) for the build flow, source layout, hash routing, and the DeltaChat / chatmail interoperability notes (securejoin v3, protected headers, and the byte-level chatmail traps).

---

## License

GNU Affero General Public License v3.0 (AGPL-3.0)
