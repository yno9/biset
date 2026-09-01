# Biset MIMI transition and Self Group isolation

> Status: design proposal / 2026-09-01
> Scope: the exit criteria for `biset-mls-ds` and the possible replacement of the Coordinator's Self Group MLS delivery path.  This document does not authorize data migration or service retirement.

## Decision

`biset-mls-ds` is not converted in place.  A `GroupLocalId` and a MIMI `PseudonymousCredential` belong to different authentication schemes, while an MLS group binds its member credentials into its cryptographic state.  Rewriting either the provider database or an MLS group state would invalidate those bindings.  Therefore the only safe migration unit is a **new anon MIMI room**, with freshly generated MLS state, room-scoped pseudonyms, and KeyPackages.

Likewise, a Self Group must not share the normal or anon MIMI process.  If it is adopted, it is a third, owner-only deployment (`self`), with a separate listener, DB, resource limits, credentials, and operational alerts.  Sharing source code is useful; sharing a failure domain is not.

## Preconditions for declaring anon MIMI a replacement

The declaration requires all of the following, recorded in a release review rather than inferred from a unit test:

1. **Process boundary:** normal, anon, and Self Group deployments have distinct service accounts, SQLite paths, network listeners, TLS identities, backups, log sinks, and rate-limit budgets.  A normal-process compromise must not grant filesystem or database access to anon data.
2. **Schema and request audit:** the anon database, logs, metrics labels, error reports, and ingress API must contain neither a real DID/client identifier nor an old `GroupLocalId`.  The only member identifiers visible to the anon provider are room-scoped pseudonyms and their signing public keys.
3. **End-to-end capability:** a pseudonymous client can create, add/remove, publish/claim KeyPackages, submit a franked application message, and pull/watch its deliveries without using the normal provider.  Mixed credential types and cross-mode routes are rejected.
4. **Cryptographic properties:** every current member can decrypt the current epoch's identity links; an erased previous exporter secret cannot decrypt a later epoch's links; a removed member cannot decrypt post-removal links.  The pseudonymous credential's origin/binding validation must be specified and independently reviewed before this gate can pass.
5. **Metadata comparison:** review confirms the remaining provider-visible metadata (room-scoped pseudonym, membership/epoch timing, ciphertext size and timing, franking evidence) is no broader than the explicitly accepted replacement threat model.  MIMI cannot claim to hide traffic analysis, and that limitation must be disclosed.
6. **Operational readiness:** two independent anon deployments complete the federation gate under capacity limits, backup/restore exercises pass, and a fail-closed configuration test rejects accidental normal/anon co-location.

Current code satisfies only portions of 3 and 4; specifically, it now carries pseudonymous update, message, pull, and watch requests, but it does not yet define or independently validate the pseudonymous-credential origin/binding.  Consequently **no decommission decision is authorized**.

## Conversation-room migration protocol

1. Ship the anon-capable client and complete the prerequisite review above.  The old identity-blind room remains authoritative during the rollout.
2. An existing member sends an E2E migration offer in the old room.  It identifies a local migration operation, not the old room ID, to the new provider.  Each participant explicitly accepts or declines.
3. Accepted clients generate fresh MIMI KeyPackages, fresh room-scoped pseudonyms, and a new MLS group.  The new anon provider receives no old group ID, `GroupLocalId`, real DID, or copied history.
4. Each client verifies the new group roster through its authenticated old-room offer, persists a local-only mapping between old and new rooms, and sends an E2E cutover acknowledgement in both rooms.  No server-side table links the rooms.
5. The old room becomes read-only after a user-visible grace period.  It remains available for pull/recovery until every accepted member has acknowledged or the migration is cancelled.  Ciphertext history is not copied; the client may offer a separately encrypted local export.
6. The service may retire `biset-mls-ds` only after all rooms are migrated, deliberately retained, or expired under a published retention policy; a rollback means resuming the old room, never merging two MLS histories.

## Self Group replacement shape

The existing `biset-coordinator` owns Vault/OIDC state and its Self Group DS in one deployment.  A replacement must preserve its owner-only authorization, device-add/external-join recovery, durable ordered delivery, checkpoint semantics, and availability under third-party load.

The proposed `biset-mimi-self` deployment has an allowlist of exactly one owner identity per room, accepts only that owner's device credentials, disables federation, identifier discovery, public asset proxy, and third-party consent endpoints, and has independent capacity controls.  The Coordinator remains the Vault/OIDC authority; it does not share its SQLite database or listener with this deployment.  A client performs a new-room handoff only after all of its devices have demonstrated delivery and recovery from the candidate Self Group.  The old Coordinator path stays live until that proof and a rollback window are complete.

## Follow-up implementation tasks

- **5.1b operational anonymity gate:** audit service accounts, paths, log sinks, backups, and rate limits in the deployment environment, then run the two-process release review.  The completed 5.1 code guard already binds a SQLite database to one mode and rejects mixed credential types.
- **5.2 pseudonymous credential binding:** specify the issuer and verification rule, then implement and independently test it before accepting anon credentials as a replacement guarantee.
- **5.3 conversation migration client flow:** implement the E2E offer/accept/cutover state machine and local-only old/new mapping; do not copy server history.
- **5.4 self deployment spike:** implement a separate `biset-mimi-self` process behind owner-only authorization and prove Vault recovery and third-party-load isolation before any Coordinator retirement plan.
