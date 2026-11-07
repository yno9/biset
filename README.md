# oui

Oui is a communication client that keeps mail and DIDComm data encrypted on the user's own
devices, so no server holds a permanent mailbox or message history.

## How it is put together

- **Identity lives elsewhere.** did:vh identities are issued and hosted by an external
  provider (did.md). Oui resolves public documents and never writes them.
- **The log is the source of truth.** Each device keeps an encrypted Vault in IndexedDB:
  signed immutable events, content-addressed ciphertext objects, and segment key wraps.
- **The projection is derived.** The JMAP read model the UI renders is recomputed from that
  log per entity, last-writer-wins, and can be thrown away and rebuilt at any time.
- **Devices sync over DIDComm.** Multi-device synchronisation carries those same records
  through the ordinary DIDComm mediator queue — there is no dedicated sync server.
- **History travels as files.** Export and import use plain JMAP with a single extension
  property for ordering, so several partial exports converge on one complete set.
- **Mail can live on disk.** With the File System Access API, threads are mirrored into a
  local folder as Markdown that the user can edit and reply from.

## Documentation

[ARC.md](ARC.md) describes the architecture as implemented: trust boundaries, keys, storage,
delivery, verification status, and what is still missing. Start there.

## Building and checking

Node 26 and pnpm (`.nvmrc`, `packageManager`); there is no Bun.

```bash
pnpm install
pnpm build      # vite: one self-contained dist/index.html, plus dist/sw.js and dist/fonts/
pnpm dev        # vite dev server on :3000 (/mock.html renders the UI on made-up data)
pnpm check      # typecheck + knip + reachability + tests (vitest)
```

The client needs the sibling checkout `../lft` (linked in `package.json`).
Verify the client by opening `dist/index.html` over `file://`.

Servers are each bundled into one `.mjs` that runs on Node 26 (`dist-server/`):

```bash
pnpm build:didcomm-mediator   # the DIDComm mediator
pnpm build:mimi               # MIMI delivery service
```

Mail is not part of Oui: a mail address is reached as the DID a mail bridge
([didmail](https://github.com/yno9/didmail)) gives it, looked up by WebFinger
(`mailGateways` in `config.json`).

Deployment targets are in `deploy.sh`; the application and the landing page are two separate
targets and must not be confused.

> Installation and user-facing documentation will be added with the first working milestone.
