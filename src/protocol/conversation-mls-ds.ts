/**
 * Signed control messages for the Conversation Group MLS Delivery Service
 * (`docs/protocols/mls-ds-1.0.md`, RFC 9750 §5), carried over plain HTTP/
 * JSON (mls-ds/http.ts) -- no DIDComm binding (dropped, see this file's own
 * revision note below). Parallels `mls-ds.ts` (the Self Group DS)
 * field-for-field EXCEPT it drops `identityId` entirely -- membership is
 * `(groupId, senderId)`, judged by this DS's own opaque roster, never by a
 * single-owner identity concept (PLAN_biset-mls-ds.md §7). Self Group's
 * `mls-ds.ts` is unmodified by this file's existence -- this is a parallel
 * module, not a generalization of it.
 *
 * **Revision (identity-blind DS, PLAN_biset-mls-ds.md §7 rewrite)**: every
 * `*Kid: DeviceId` field from this file's first version has been replaced
 * with a `GroupLocalId` -- a fresh, single-group, throwaway Ed25519
 * keypair's public key, generated at invite/create time and never reused
 * across groups. The public key itself IS the id: authorization is "does
 * this signature verify against the pubkey the id names", nothing more --
 * no DID resolution, no `deviceCredential` payload, no way for the DS to
 * ever learn a member's real identity from a control message. Three
 * concrete leaks this closes (found in review, 2026-08-31):
 *
 *   1. GroupInfo's ratchet tree carries every member's real DID-bound MLS
 *      credential in the clear (RFC 9420 requires this for a joiner to
 *      validate it) -- `group.ts`'s own `groupInfoMemberKids` proves it's
 *      trivially extractable with no Authentication Service involved, and
 *      the first version's `groupInfoFor` had no membership gate at all
 *      ("knowing groupId is the invitation"), so this was world-readable,
 *      not just DS-exclusive knowledge. Fixed by dropping GroupInfo/
 *      external-join entirely -- `ConversationGroupInfoPullV1`,
 *      `ConversationExternalCommitSubmitV1`, and the `groupInfo`/
 *      `welcomeTo` fields on commit-submit no longer exist. Joining is
 *      Welcome-only now (an existing member must Add you); Welcome is
 *      HPKE-encrypted to the joiner's own KeyPackage init key and stays
 *      opaque to the DS.
 *   2. Every signed request's own `deviceCredential` field self-declared
 *      the sender's real DID -- gone; there is no credential field left to
 *      attach.
 *   3. Push delivery (message-notify) required resolving a real DID to
 *      know where to send it -- gone; the DIDComm binding (fanout.ts,
 *      didcomm.ts, didcomm-types.ts) is deleted, not just unwired. A
 *      member catches up via `deliveries-pull` only (poll-based).
 *
 * `ConversationGroupsForPullV1` is also gone: it asked "every group this
 * kid belongs to", which is structurally meaningless once ids are
 * per-group and throwaway by design -- a client already has the answer
 * locally (mls/conversation-group-store.ts's own `listGroupIds`).
 *
 * `ConversationCommitSubmitV1.roster` (a full claimed-roster snapshot) is
 * now `addedIds`/`removedIds` (a delta): the DS already owns the
 * authoritative roster Set server-side, so a submitter only needs to know
 * who THEY are adding or removing, never the entire current membership.
 *
 * As with mls-ds.ts, every field the DS uses to decide anything is
 * authenticated; the DS itself never inspects the opaque
 * `commit`/`proposal`/`privateMessage` bytes.
 */

/** A group-local control-plane identifier: hex of a 32-byte Ed25519 public
 * key, freshly generated per group and never reused across groups (the
 * property that makes cross-group correlation structurally impossible --
 * see this file's header). Verifying a request is nothing more than "does
 * `signature` verify against `hexToBytes(id)`" -- no resolution step, no
 * registry, no network call. Distinct from `DeviceId` (`did#fragment`,
 * used only at the MLS layer now -- members still recognize each other by
 * their real, DID-bound MLS credential inside the E2E-encrypted group;
 * only the DS must not). */
export type GroupLocalId = string

export type ConversationLogEntryKind = 'commit' | 'welcome' | 'proposal' | 'application'

/** One delivered object, as the DS holds it: opaque payload plus the
 * ordering it was given. `application` is the one kind Self Group's
 * MlsLogEntry doesn't have -- PLAN-mimi.md's finding that Self Group's DS
 * never carries application data (Vault sync uses a separate ordered log)
 * but a Conversation Group's does, since fanning that out IS the DS's job here. */
export interface ConversationLogEntry {
  seq: number
  kind: ConversationLogEntryKind
  payload: Uint8Array
  epoch: string
  at: string
}

export interface ConversationGroupCreateV1 {
  version: 1
  groupId: string
  /** The creator's own freshly-minted group-local id -- generated for
   * THIS group, on the spot, by the creator themself. `store.ts`'s
   * `createGroup` has no prior roster to check membership against, so
   * this needs no proof beyond the signature itself. */
  creatorId: GroupLocalId
  createdAt: string
  signature: Uint8Array
}

export interface ConversationCommitSubmitV1 {
  version: 1
  groupId: string
  /** The committing device's own group-local id for this group. */
  senderId: GroupLocalId
  /** The epoch this commit was made FROM. */
  epoch: string
  commit: Uint8Array
  /** New members this commit's Welcome is for, as the sender claims --
   * DS bookkeeping only, never cryptographically verified against
   * `commit` (same disclaimer mls-ds.ts's own roster field carries). */
  addedIds?: GroupLocalId[]
  /** Members this commit removes, as the sender claims. */
  removedIds?: GroupLocalId[]
  welcome?: Uint8Array
  submittedAt: string
  signature: Uint8Array
}

export interface ConversationKeyPackagePublishV1 {
  version: 1
  id: GroupLocalId
  packages: Uint8Array[]
  publishedAt: string
  signature: Uint8Array
}

/** Unlike Self Group's MlsKeyPackageTakeV1 (which always means "give me a
 * spare for MY OWN new device"), a Conversation Group take is always FOR
 * someone else -- `targetId` names whose KeyPackage the requester wants,
 * since there's no "this identity's own devices" concept here
 * (mls-ds-1.0.md §4.6). Neither side needs to already be a group member:
 * a prospective joiner publishes under a group-local id before anyone has
 * added them (see this file's header on the new bootstrap flow). */
export interface ConversationKeyPackageTakeV1 {
  version: 1
  requesterId: GroupLocalId
  targetId: GroupLocalId
  requestedAt: string
  signature: Uint8Array
}

export interface ConversationSelfRemoveSubmitV1 {
  version: 1
  groupId: string
  senderId: GroupLocalId
  epoch: string
  proposal: Uint8Array
  /** The group-local id declaring its own removal -- MUST equal `senderId`. */
  removedId: GroupLocalId
  submittedAt: string
  signature: Uint8Array
}

export interface ConversationPendingRemovalsClearV1 {
  version: 1
  groupId: string
  /** Must be the group's last accepted commit's sender -- the DS enforces this itself. */
  requesterId: GroupLocalId
  clearedIds: GroupLocalId[]
  clearedAt: string
  signature: Uint8Array
}

export interface ConversationDeliveriesPullV1 {
  version: 1
  groupId: string
  requesterId: GroupLocalId
  afterSeq: number
  requestedAt: string
  signature: Uint8Array
}

/** Mints a short-lived watch token for `GET /v1/conversation-mls/deliveries/stream`
 * (mls-ds/http.ts) -- an SSE connection the requester opens itself, so the
 * DS never needs to resolve or store a delivery address (contrast the
 * deleted `message-notify` push, conversation-mls-ds.ts's own header). Same
 * fields and same everMembers gate as `ConversationDeliveriesPullV1`, minus
 * `afterSeq` -- that becomes the `/stream` request's own query param, not
 * part of this signed mint request, since one token may be used to resume
 * a connection at whatever seq the client last saw. */
export interface ConversationDeliveriesWatchV1 {
  version: 1
  groupId: string
  requesterId: GroupLocalId
  requestedAt: string
  signature: Uint8Array
}

export interface ConversationKeyPackageDropV1 {
  version: 1
  id: GroupLocalId
  droppedAt: string
  signature: Uint8Array
}

export interface ConversationKeyPackageCountPullV1 {
  version: 1
  id: GroupLocalId
  requestedAt: string
  signature: Uint8Array
}

/** mls-ds-1.0.md §5.1: application message fan-out is gone (see this
 * file's header) -- `message-submit` still exists (a member still needs to
 * hand the DS an encrypted application message to log), but nothing PUSHES
 * it anywhere; every recipient learns of it via `deliveries-pull`. */
export interface ConversationMessageSubmitV1 {
  version: 1
  groupId: string
  senderId: GroupLocalId
  epoch: string
  privateMessage: Uint8Array
  submittedAt: string
  signature: Uint8Array
}
