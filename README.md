# biset

Biset is a communication client that keeps mail and DIDComm data encrypted on the user's own
devices, so no server holds a permanent mailbox or message history.

## How it is put together

- **Identity lives elsewhere.** did:webvh identities are issued and hosted by an external
  provider (did.md). Biset resolves public documents and never writes them.
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

| Document | Contents |
|---|---|
| [ARC.md](ARC.md) | The architecture as implemented: trust boundaries, keys, storage, delivery, verification status, and what is still missing. Start here. |
| [PLAN_vault-sync-redesign.md](PLAN_vault-sync-redesign.md) | The design decisions and implementation checklist behind the current two-layer sync (log layer / projection layer). |
| [PLAN.md](PLAN.md) | did.md Wallet login design. |
| [PLAN_biset-mimi-server.md](PLAN_biset-mimi-server.md) | The MIMI delivery service that ships in this repository. It runs, but the current client does not call it. |
| `tasks/` | Per-task working notes. |

> `REPORT.md`, `NOTE.md`, `WORKSHEET_vault-sync.md`, and `PLAN-simplify.md` predate the
> 2026-09-15 sync redesign and describe removed designs. They are kept as records only and
> contradict the current code.

The previous implementation is retained locally in `src.bak/` and `jmapsmtp.bak/`.

## Building and checking

```bash
bun run build      # bundles the client AND inlines it into dist/index.html
bun run check      # typecheck + knip + reachability + tests
```

`bun build` on its own is not enough — `bun run build` is what produces `dist/index.html`.
Verify the client by opening that file over `file://`.

Server binaries are built separately:

```bash
bun run build:mail-plugin        # mediator with the SMTP bridge (production)
bun run build:didcomm-mediator   # plain mediator (mutually exclusive with the above)
bun run build:mimi               # MIMI delivery service
```

Deployment targets are in `deploy.sh`; the application and the landing page are two separate
targets and must not be confused.

> Installation and user-facing documentation will be added with the first working milestone.
