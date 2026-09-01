# Biset MIMI client routing

> Status: implemented for route selection / 2026-09-01
> Scope: room creation in `biset-client`.  This is intentionally separate from the MIMI provider/server plan.

## Inputs trusted by the selector

The client receives each remote participant's MIMI capability from its normal, authenticated capability-discovery path.  Before the selector sees it, the client must verify the document issuer and its binding to `peerId`; an unverified document is rejected, rather than treated as a hint.  The relevant capability fields are `supportsNormal` and `anonymousMmrVersion: 1`.

The local configuration supplies two independently deployed HTTPS origins: normal and anon.  The selector does not accept a provider origin supplied by a remote peer, and it rejects credentials, query strings, fragments, and non-HTTPS origins.

## Route choice for a new room

`selectMimiRoomRoute()` in `src/mls/mimi-client-routing.ts` applies the following rules to every intended remote participant:

- `require-anon`: create only when every participant advertises verified anonymous MMR v1; otherwise fail explicitly.
- `prefer-anon`: use anon when every participant supports it.  Otherwise use normal only when every participant advertises verified normal-mode support.
- `normal`: use normal only when every participant advertises verified normal-mode support.

Missing, unsupported, or unverified capability data is not a basis for interoperability and makes the selection fail.  A client may offer a normal-room retry only after the user selected the non-mandatory `prefer-anon` policy; it must not silently downgrade `require-anon`.

## Persistence and non-migration

The room-creation flow persists the returned `{ mode, baseUrl }` alongside its local room record and includes the selected mode in the invitation/initial commit metadata.  Existing rooms use that persisted route directly.  They are never re-selected or migrated: normal and anon rooms use different credential forms and run against separate provider processes and databases.  To change a room's mode, create a new room and perform an application-level transition.

The selector is pure and creation-only by design.  `MimiClientTransport` consumes the persisted mode/origin for later requests; capability discovery must not cause an existing room to switch provider processes.
