# biset Architecture Notes

## Build flow

biset is distributed as a **single HTML file**. `dist/app.js` is inlined into `dist/index.html` at build time, so the app runs directly via `file://` with no dev server required (local-first design).

### Build and deploy

```sh
bun run build
```

This runs the `build` script in `package.json`:
```
bun build src/main.ts --outfile=dist/app.js --target=browser --minify-syntax --minify-whitespace --define ... && bun run scripts/inline.mjs
```

`scripts/inline.mjs` reads `src/style.css` and `dist/app.js` and splices them into `dist/index.html` replacing the placeholder comments. Running `bun build` alone updates `dist/app.js` but leaves `dist/index.html` with the old inlined code — always use `bun run build`.

**Deploy** to production (`v1`) with `./deploy.sh [app|landing|all]`. Two **separate artifacts** are served from the same jmapap host — never conflate them:

| Artifact | Source | Server dir | Served at | Config |
|---|---|---|---|---|
| **app** (chat client) | `dist/index.html` (built) | `/root/jmapap/app/` | `t.biset.md` | jmapap `web_root:"app"` |
| **landing** (public site) | `home/*` (index + assets + `tos.html`) | `/root/jmapap/apex/` | `biset.md` apex | Caddy `root * /root/jmapap/apex` |

`deploy.sh` builds (app only), uploads, then verifies via **sha match + live URL** so a wrong-directory or stale deploy fails loudly. Do not `scp` by hand — deploying the app over the landing dir (or vice versa) silently breaks one of the two sites, and file mtimes alone won't reveal it.

### Source layout

| Path | Role |
|---|---|
| `src/index.html` | Shell HTML; CSS/JS placeholders replaced at build |
| `src/style.css` | All styles; inlined into `<style>` by `inline.mjs` |
| `src/main.ts` | Entry point — routing, global event wiring |
| `src/ui/left-pane.ts` | Left column, LP_COMMANDS (account/config/compose), inbox list |
| `src/ui/thread.ts` | Right column — thread render, reply dock, scroll |
| `src/ui/shell.ts` | `showApp`, `startPolling`, `fetchMessages`, `showSysMsg` |
| `src/ui/account-create.ts` | New-user onboarding page (`#new`), account-create overlay |
| `src/context.ts` | Global state — sessions, current inbox, stored accounts |
| `src/app.ts` | Session init, PGP init, inbox summary loading |
| `src/jmap/` | JMAP client, email builder, querystate |
| `src/deltachat/` | DeltaChat protocol knowledge (see below) |
| `src/pgp/` | E2EE / symmetric crypto primitives |

## Layout

Two-pane app (`#app`):
- **`#left-pane`** — card with margin, collapsible. Contains search, inbox list, LP_COMMANDS.
- **`#right-col`** — flex column containing `#outer` (scrollable) and `#reply-dock` (sticky bottom).
  - `#outer` contains `#thread-title-row` (sticky top), `#right-pane` (thread/cmd content).

### Mobile (`≤720px`)

Left pane is hidden by default. `#app.lp-enabled.show-left` shows the left pane full-screen and hides `#right-col`. `#right-pane` gets `width: 100%` to override the desktop calc.

### Single-col mode

`#app.single-col.lp-enabled` collapses the left pane to `width: 0` via CSS transition (shrinks from the right). Triggered by Cmd+B or the toggle button.

## Routing

Hash-based:
- `#new` → new-user onboarding page (no app chrome, full-screen)
- `#account`, `#config`, `#compose` → LP_COMMANDS pages inside the normal app shell
- `#user/mailbox/contact` → opens a specific inbox thread

`init()` in `main.ts` reads `location.hash` on load and dispatches accordingly. After account creation on the `#new` page, `showApp()` + `setupLeftPane()` + `startPolling()` run before navigating to `#account`.

## Hamburger menu

One shared `#lp-hamburger-menu` element (`position: fixed`), triggered by two buttons:
- `#lp-hamburger` — top-right of the right column header (desktop)
- `#lp-hamburger-left` — top-right of the left pane header (mobile `show-left` mode)

`main.ts` attaches mouseenter/mouseleave/click handlers to both buttons via a loop. The menu is positioned via `getBoundingClientRect()` of the triggering button.

---

# DeltaChat / chatmail interoperability

biset is a JMAP mail client that interoperates with DeltaChat / chatmail via group chat, E2EE, and securejoin. DeltaChat-specific protocol knowledge is isolated in one place.

## Layer structure

- **`src/deltachat/protocol.ts`** — all `Chat-*` header knowledge, Autocrypt/Gossip, protected header generation, grpid generation. No `Chat-*` magic strings anywhere else.
- **`src/deltachat/securejoin.ts`** — securejoin v3 (setup-contact), inviter (Alice) side.
- **`src/pgp/crypto.ts`** — E2EE / symmetric crypto primitives. Symmetric message construction for securejoin lives here.
- **`src/sync/session.ts`** — on receive: decrypts PGP, promotes protected headers, learns Autocrypt keys, drives securejoin handshake (`maybeHandleSecurejoin`).

## Message model

- **DeltaChat hides all headers inside the ciphertext** (recipients as `To: hidden-recipients:;`, Autocrypt inside). The receiver must decrypt before it can read Chat-Group-ID or the sender's Autocrypt key. `session.ts` decrypts and promotes inner headers.
- **biset sending**: the plaintext body contains armored PGP. `go-jmapsmtp` wraps it as PGP/MIME (RFC 3156), injects Autocrypt + Chat-Version headers on the outside, and DKIM-signs. The outer Autocrypt enables opportunistic E2EE even before securejoin completes.
- **Protected headers**: `Chat-*` / `Secure-Join*` / `Autocrypt(-Gossip)` go inside the ciphertext. DeltaChat ignores cleartext copies and trusts only the inner values (RFC 9788 family). `buildProtectedHeaders` handles this.

## securejoin v3 (biset = inviter Alice)

Invite URL (no QR needed, `newInviteUrl`):
```
https://i.delta.chat/#<FP uppercase 40hex>&v=3&i=<invitenumber>&s=<auth>&a=<addr>&n=<name>
```
invitenumber/auth are `create_id()`-equivalent (18 bytes URL-safe base64), persisted in localStorage.

Handshake (driven by `maybeHandleSecurejoin` on receive sync):
1. Bob→biset **`vc-request-pubkey`** (symmetric / no key). password=`securejoin/<biset FP>/<auth>`. biset tries symmetric decrypt against all active invite auth values.
2. biset→Bob **`vc-pubkey`** (symmetric + signed, inner Autocrypt = biset key). Bob learns biset's key.
3. Bob→biset **`vc-request-with-auth`** (normal E2E/PKESK, Bob key in Autocrypt, Secure-Join-Auth/Fingerprint). biset learns Bob's key and verifies auth/FP.
4. biset→Bob **`vc-contact-confirm`** (E2E, Bob key in gossip to pass Bob's self-gossip guard). Bob fires `SecurejoinJoinerProgress::Succeeded` → UI advances from "Establishing connection" to compose.

Processed securejoin messages are not stored — they are destroyed via JMAP.

## Three non-obvious interop traps (confirmed at byte level)

1. **Read-only group**: if the grpid doesn't satisfy DeltaChat's `validate_id` (URL-safe base64, 11–32 chars), Chat-Group-ID is ignored and the chat becomes a read-only ad-hoc group. `crypto.randomUUID()` (36 chars) fails this. → `newGroupId()` produces 18-byte base64url (24 chars).

2. **Missing CRC24 → `523 Encryption Needed`**: chatmail's filtermail expects an `=CRC24` suffix on armored PGP and strips everything from the last `=` onward. openpgp.js **omits CRC24 for AEAD (SEIPDv2)**, so without a checksum the base64 padding `=` gets stripped, causing decode failure → "not encrypted" rejection. → `ensureArmorChecksum` appends RFC 9580 §6.1 CRC-24 (init `0xB704CE` / poly `0x1864CFB`).

3. **S2K iterated → rPGP decrypt rejection**: DeltaChat's `check_symmetric_encryption` (core `decrypt.rs`) only accepts **`Salted` S2K** in symmetric SKESKs. openpgp.js only produces `Iterated` for password encryption and ignores `config.s2kType: salted`. → `symmEncryptSignMime` builds a **manual Salted-S2K SKESK**: derives `K = SHA256(salt‖password)[:16]` as session key, lets openpgp.js produce SEIPDv1, then strips the Iterated SKESK and prepends a hand-crafted v4 SKESK (AES-128, Salted type 1, SHA-256, no ESK).

## Current status (2026-07-05)

- ✅ biset ⇔ DeltaChat/chatmail **securejoin v3 full handshake** (invite URL only, no QR / manual key extraction). Verified against multiple chatmail servers (d.gaufr.es family).
- ✅ Group chat (valid Chat-Group-ID), bidirectional E2EE, threading.
- ✅ Peer key auto-learning from inner Autocrypt on receive (no manual key installation).
- ⚠️ Known minor issues:
  - `[pgp] decrypt failed ... No public key encrypted session key` log noise when trying PK decrypt on symmetric messages (expected, harmless).
  - Handshake steps (vc-request-with-auth etc.) occasionally remain in inbox. Robust swallowing not yet implemented.
- ⚠️ **nine.testrun.org** does not deliver to non.md addresses (testrun-specific issue). Use another chatmail server (d.gaufr.es etc.).

## Reference material used

- DeltaChat core: `securejoin.rs` / `securejoin/bob.rs` / `qrinvite.rs` / `mimefactory.rs` / `mimeparser.rs` / `decrypt.rs` / `tools.rs`
- chatmail filtermail (Rust): `src/message.rs` (check_encrypted / is_securejoin) / `src/openpgp.rs` (check_armored_payload) / `src/inbound.rs`
- go side: `go-jmapsmtp/main.go` (sendEmail/wrap), `autocrypt.go` (pgpMIMEWrapInline/peerkey), `go-jmapserver/email.go` (BuildRFC5322)

---

# ActivityPub federation & E2EE roadmap

biset federates over ActivityPub through the **`go-jmapap`** relay (a JMAP↔AP bridge, sibling of `go-jmapsmtp`). Relays are independent and share libraries, not state — there is no core server. One identity (`email`) can be served by both the mail relay and the AP relay; biset merges them into one inbox client-side (`_identity` = email, `_relay` = serverUrl, `accountKey` = email+" "+serverUrl to avoid JMAP id collisions across relays).

## Identity anchor (split-identity prevention)

Because the relays are independent, each owns its `<localpart>` namespace on its own disk — so the same address (`dab0@non.md`) could be provisioned by two different people on the two relays (different cryptenv envelopes), a **split identity** exploitable for fediverse impersonation. The apex (already `jmapap`, which answers WebFinger for the domain) plays a minimal **identity-anchor** role to collapse the two independent first-come points into one:

- **Registry** (`go-jmapap/anchor.go`): `localpart → envelope fingerprint`, where fingerprint = `SHA-256(cryptenv envelope canonical bytes)`. biset sends the *identical* envelope to every relay, so a matching fingerprint proves same-owner.
- `GET/POST /identity/<localpart>` — POST claims/verifies: unclaimed → 201, same fingerprint → 200 (idempotent), different → **409** (split rejected).
- **Provision consults the anchor**: `jmapap` claims in-process; `jmapsmtp` claims over HTTP via its `anchor_url` config (internal `http://127.0.0.1:8768`) and rejects on 409.
- **Graceful / fail-closed**: empty `anchor_url` = single-relay mode (skip, no guarantee); configured-but-unreachable = **503 fail-closed** (refuse rather than risk a split). The anchor is control-plane only — runtime message flow never touches it, it's consulted at provision time alone.
- **Backfill** on startup records fingerprints for pre-anchor accounts (`jmapap` in-process + `jmapsmtp` push); a push conflict logs `[anchor] SPLIT DETECTED`.

This keeps the no-core philosophy (no new server; the apex role jmapap already plays gains a tiny registry) while making an identity coherent across relays. See also the identity/MLS discussion — the anchor fingerprint/key is a natural root for MLS credentials later.

## Two-language crypto model

E2EE is **per-protocol**, matching the "one relay bridges one protocol" architecture:

| Transport | E2EE scheme | Rationale |
|---|---|---|
| **mail** (jmapsmtp) | **PGP** (openpgp.js) | DeltaChat / chatmail interop — non-negotiable |
| **ActivityPub** (jmapap) | **MLS** (target; see below) | fediverse-standard E2EE, interoperable |

These key models cannot be unified — PGP is a stateless static key, MLS is a stateful per-device ratchet. What *is* unified is the surface: same `email` identity, same WebFinger/actor + WKD discovery, same cryptenv envelope/login. **PGP is never used over AP** — a PGP-wrapped Note is unreadable to Mastodon/Emissary/other fediverse clients and would defeat federation. AP is either plaintext (fediverse interop) or MLS (standard E2EE). The send path skips PGP entirely for AP relays (`isApRelay()` in `context.ts` gates `encryptText` and `prefetchRecipientKey`).

## MLS-in-ActivityPub — decision & design (decided 2026-07-06, timing TBD, not yet implemented)

**Decision:** biset↔biset AP E2EE uses **MLS**, per the SWICG spec *"Messaging Layer Security in ActivityPub"* + **RFC 9420**, via the **`ts-mls`** TypeScript library (in-browser). Reference implementation: **Emissary** (emissary.dev/e2ee — Social Web Foundation project, Sovereign Tech Fund funded, same `ts-mls`, targeting mid-2026).

**Why MLS over PGP for AP:** forward secrecy + post-compromise security, real group semantics at scale (efficient add/remove rekey), and — decisively — it is the emerging fediverse standard, so encrypted messages still *federate* (interop with Emissary et al.). PGP over AP gives none of this and breaks interop.

**Services already provided by `go-jmapap` (reused, not rebuilt):**
- MLS **directory service** ← WebFinger + Actor profiles (locate users / their key material).
- MLS **delivery service** ← AP inbox/outbox (route opaque MLS ciphertext to clients).
- To add: **KeyPackage publishing** at the actor, and **routing of opaque MLS message types** to the client (server treats contents as opaque).

**Identity / device design (recommended; final ratification pending):**

| Axis | Decision |
|---|---|
| **Credential** | AP **actor URI** (resolved from `email` via WebFinger), `basic` credential. Unifies with the merge model (email = identity = actor). |
| **Trust** | KeyPackage fetched from the actor's own server over HTTPS — the AP-MLS directory-service trust model (honest-but-curious server, no CA). Key transparency is future work. |
| **Multi-device** | **Per-device leaf** (true MLS): each browser has its own signing key + KeyPackages and is an independent group member. Private keys never leave the device. |
| **State storage** | MLS group state (ratchet/secrets) in **IndexedDB (device-local)**, *not* the synced vault. |
| **History** | **Not shared across a user's own devices** (MLS default; Emissary behaves the same). A new device joins fresh. |
| **Device management** | Publish a KeyPackage set (device list) at the actor; future **revoke** UI removes a leaf from all groups. |

**Rejected: shared identity key across devices.** MLS group state is a *mutating* ratchet; syncing it across devices via the vault means concurrent epoch mutation → corrupted group state, plus copying private keys destroys per-device PCS. It looks like the PGP one-key-per-email model but is a trap. Per-device leaves are how AP-MLS/Emissary work, so it is also the interoperable choice.

**Accepted UX costs of per-device:** adding a contact adds *all* of their devices; a freshly-added device cannot read prior history; revoking a device is a group operation.

**Near-term stance:** AP stays plaintext (fediverse interop); E2EE remains mail/PGP only until MLS work begins.


