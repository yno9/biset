// biset's MLS transport protocol over DIDComm — PLANMLS.md Phase 0's "MLS
// オブジェクト転送用の独自DIDComm PIURIプロトコル".
//
// There is no standard DIDComm protocol for carrying MLS objects, so this
// defines one, in the same `https://biset.md/…` namespace as the Web Push
// extension the mediator already speaks (`push/1.0`). It is deliberately thin:
// every body is a small JSON object whose MLS fields are base64url'd MLS wire
// bytes, and nothing here interprets those bytes. Encoding lives here and
// nowhere else so the client (`src/mls/`) and the DS (`anchor/mediator/`)
// cannot drift on the wire format.
//
// ## The roles
//
//   - **member** — a client device. Publishes key packages, submits commits
//     and application messages, receives deliveries.
//   - **delivery-service** — the Mediator that owns a group's ORDER
//     (PLANMLS.md §2). Server fanout: one DS per group, normally the home
//     mediator of whoever created it.
//   - **key-package-store** — a Mediator holding its own users' published key
//     packages, so a stranger can invite a device that is currently offline.
//     Answered by the same mediator process, but a separate role: a mediator
//     may serve key packages without ever being anyone's DS.
//
// ## What the DS does and does not learn
//
// Server fanout means the DS necessarily knows **who is in the group** — it
// cannot address copies otherwise. That is the cost PLANMLS.md §5 records for
// choosing server fanout, and it is worth being exact about the boundary:
//
//   - The DS **can** see: the group id, the roster of member DIDs, message
//     sizes and timing, and the epoch counter.
//   - The DS **cannot** see: message content (MLS PrivateMessage), who inside
//     the group sent a given message (MLS hides the sender in the encrypted
//     content), or the application metadata layer (encrypted under the group's
//     exporter secret, PLANMLS.md §3.3).
//   - Every OTHER mediator on the path — the members' home mediators — sees
//     only an ordinary Forward, exactly as for a 1:1 message.
import { b64url, b64urlToBytes } from './crypto.ts'

export const MLS_PROTOCOL = 'https://biset.md/mls/1.0'

/** member → key-package-store. Publish (replace) this device's pool of unused
 * key packages. Idempotent: the store keeps exactly what the latest publish
 * listed, so a client that regenerates its pool doesn't accumulate stale ones. */
export const KEY_PACKAGE_PUBLISH = `${MLS_PROTOCOL}/key-package-publish`
/** member → key-package-store. "Give me one key package per device of this
 * DID", to add them to a group. */
export const KEY_PACKAGE_REQUEST = `${MLS_PROTOCOL}/key-package-request`
/** key-package-store → member. The answer to a request. */
export const KEY_PACKAGE_RESPONSE = `${MLS_PROTOCOL}/key-package-response`
/** member → delivery-service. "Be the DS for this group", sent once by the
 * creator. Carries the initial roster so the DS can fan out. */
export const GROUP_CREATE = `${MLS_PROTOCOL}/group-create`
/** delivery-service → member. Acknowledges the DS role for a group. */
export const GROUP_CREATED = `${MLS_PROTOCOL}/group-created`
/** member → delivery-service. A commit, with the Welcome it produced (if any)
 * and the roster it results in. The DS decides whether this commit wins its
 * epoch, then fans it out. */
export const COMMIT = `${MLS_PROTOCOL}/commit`
/** member → delivery-service. A commit submitted by a device that is NOT yet
 * in the group, committing itself in (RFC 9420 external commit). Separate from
 * `commit` because the DS authorizes it by a different rule: the submitter is
 * not a member of the MLS group yet, but its IDENTITY must already be in the
 * roster — this is how a new device of an existing member joins without any of
 * that member's other devices being online. */
export const EXTERNAL_COMMIT = `${MLS_PROTOCOL}/external-commit`
/** member → delivery-service. "Give me the GroupInfo for this group", which is
 * what an external commit is built against. */
export const GROUP_INFO_REQUEST = `${MLS_PROTOCOL}/group-info-request`
/** delivery-service → member. The current GroupInfo, or none published yet. */
export const GROUP_INFO = `${MLS_PROTOCOL}/group-info`
/** member → delivery-service. A Remove proposal a device made for ITSELF.
 *
 * Separate from `commit` because nothing is ordered by it: a proposal changes
 * no epoch, and the DS both fans it out (so a sibling can commit it) and
 * REMEMBERS it, so a device that joins later learns that a leaf still in the
 * tree has already asked to be gone. See mls-ds.ts's pendingRemovals. */
export const SELF_REMOVE = `${MLS_PROTOCOL}/self-remove`
/** member → delivery-service. "That declared departure is done" — the DS
 * cannot tell on its own, since it never sees the tree. */
export const CLEAR_REMOVALS = `${MLS_PROTOCOL}/clear-removals`
/** member → delivery-service. An application message to fan out. */
export const APPLICATION = `${MLS_PROTOCOL}/application`
/** delivery-service → member. One ordered MLS object. */
export const DELIVER = `${MLS_PROTOCOL}/deliver`
/** member → delivery-service. "Give me this group's deliveries after seq N."
 *
 * The counterpart to `deliver`, and the reason it exists is that push alone
 * cannot be trusted to be complete. The DS fans out to the roster the last
 * committer DECLARED, and it cannot check that declaration — the commit is
 * encrypted (mls-ds.ts's everMembers). Pull is what makes that harmless: a
 * member left out of someone's roster, or one whose copy was simply lost,
 * fetches what it is missing itself.
 *
 * Authorized by having ever been in the roster rather than by being in it now,
 * so a member cannot be shut out of the pull by the same act that shut it out
 * of the push. */
export const DELIVERIES_REQUEST = `${MLS_PROTOCOL}/deliveries-request`
/** delivery-service → member. Zero or more ordered MLS objects, in seq order. */
export const DELIVERIES = `${MLS_PROTOCOL}/deliveries`
/** member → delivery-service. "Which of your groups am I in?"
 *
 * The way INTO a group is a Welcome, and a Welcome is pushed exactly once. A
 * device that fails to use the one it was sent — an old build that did not
 * understand it, a key package whose private half was lost, a crash between
 * receiving and joining — is then invited to a group it will never see, while
 * everyone else sees it as a member. Both sides are silently wrong, and no
 * amount of waiting fixes it.
 *
 * So membership is askable. The answer lets a device notice a group it belongs
 * to and has no state for, pull that group's log, and join from the Welcome
 * still sitting in it. */
export const GROUPS_REQUEST = `${MLS_PROTOCOL}/groups-request`
/** delivery-service → member. The groups this DS holds that the asker is in. */
export const GROUPS = `${MLS_PROTOCOL}/groups`

/** The problem-report code for "no GroupInfo has been published for this
 * group's current epoch yet", the one thing an external join needs and cannot
 * produce itself. Distinct from a conflict: waiting (or asking a member to
 * commit once) fixes it, retrying immediately does not. */
export const NO_GROUP_INFO = 'e.p.msg.mls.no-group-info'

/** The problem-report code a DS answers a commit with when someone else's
 * commit already took that epoch. Not an error in any real sense — MLS's own
 * remedy is to apply the winning commit and re-propose, which is what the
 * receiving client does (PLANMLS.md Phase 1: "競合commitはMLS作法通り次epochで
 * リトライさせる"). */
export const EPOCH_CONFLICT = 'e.p.msg.mls.epoch-conflict'

/** What a delivered object is. The DS treats all three as opaque bytes and
 * orders them together; the label only tells the receiving client which MLS
 * entry point to hand the bytes to. */
export type MlsObjectKind = 'commit' | 'welcome' | 'application' | 'proposal'

export interface KeyPackagePublishBody {
  /** The publishing device's key id (`did#kN`) — its key packages are stored
   * under it, so a request for the DID gets one per device. */
  kid: string
  /** base64url MLS wire key packages. Replaces whatever was stored for `kid`. */
  key_packages: string[]
}

export interface KeyPackageRequestBody {
  /** The identity to be invited. Bare DID: the requester doesn't know, and
   * shouldn't have to know, how many devices it has. */
  did: string
}

export interface KeyPackageResponseBody {
  did: string
  /** Answering a PUBLISH: how many unused key packages the store now holds for
   * that device. The publisher cannot count them itself — it keeps every
   * private half until a Welcome consumes one, so its local count never falls
   * — which is why the pool has to be topped up from this number and not from
   * anything the client knows. Absent when answering a request. */
  remaining?: number
  /** One entry per device that has an unused key package left. A device with
   * an exhausted pool is simply absent — it can be added later, and inviting
   * the rest now beats failing the whole invitation. */
  packages: Array<{ kid: string; key_package: string }>
}

export interface GroupCreateBody {
  /** Hex MLS group id. */
  group_id: string
  /** Member DIDs, creator included. The DS's fan-out list, nothing more. */
  roster: string[]
}

export interface GroupCreatedBody {
  group_id: string
  /** The DID now acting as this group's DS — the same mediator answering. */
  ds_did: string
}

export interface CommitBody {
  group_id: string
  /** The epoch the sender committed FROM. The DS admits exactly one commit per
   * epoch, which is the entirety of what "ordering" means here — it never
   * looks inside the commit to check anything. */
  epoch: string
  /** base64url MLS wire commit. */
  commit: string
  /** base64url MLS wire Welcome, when this commit added someone. */
  welcome?: string
  /** DIDs the Welcome is for — they are not in the roster yet at the time the
   * commit is sent, so they can't be derived from it. */
  welcome_to?: string[]
  /** The roster AFTER this commit. Sent rather than inferred: the DS does not
   * parse MLS, so an Add/Remove is invisible to it. */
  roster: string[]
  /** base64url GroupInfo for the epoch this commit produces, so a new device
   * of a member can commit itself in later without anyone being online.
   * Optional: a group whose members never publish one simply cannot be joined
   * externally. */
  group_info?: string
}

export interface ExternalCommitBody {
  group_id: string
  /** The epoch of the GroupInfo this was built against. */
  epoch: string
  /** base64url MLS wire commit — a PublicMessage, unlike an ordinary commit. */
  commit: string
  /** base64url GroupInfo for the epoch this commit produces.
   *
   * Carried here for the same reason as on an ordinary commit, but it matters
   * more: an external join CONSUMES the GroupInfo it used (the DS drops it, as
   * it now describes a past epoch), so without one attached, the first device
   * to join externally would leave the group unjoinable for the next one until
   * some other device happened to commit. A third device would then be stuck
   * behind exactly the "another device must be online" requirement external
   * commits exist to remove. */
  group_info?: string
}

export interface GroupInfoRequestBody { group_id: string }

export interface GroupInfoBody {
  group_id: string
  /** base64url GroupInfo, absent when none has been published yet. */
  group_info?: string
  /** Device kids that have declared their own removal and are still in the
   * tree. A joiner acts on these once it is a member — see mls-ds.ts. */
  pending_removals?: string[]
}

export interface ClearRemovalsBody {
  group_id: string
  kids: string[]
}

export interface SelfRemoveBody {
  group_id: string
  /** The epoch the proposal was made in. A proposal is only committable in
   * its own epoch; the DS keeps the DECLARATION beyond that. */
  epoch: string
  /** base64url MLS wire proposal (a PublicMessage). */
  proposal: string
  /** The device kid removing itself. Redundant with the proposal's own leaf
   * index for a member that can read it, and necessary for one that cannot:
   * a device joining later cannot decrypt a proposal from an epoch it was
   * never in, but can still act on the kid. */
  kid: string
}

export interface ApplicationBody {
  group_id: string
  /** base64url MLS PrivateMessage. */
  message: string
}

export interface DeliverBody {
  group_id: string
  /** The DS's own sequence number for this group, from 1 and gapless. A client
   * that receives seq n+2 while holding n knows it is missing one and can ask
   * for a resend rather than trying to apply it out of order — MLS state
   * advances strictly in order and an out-of-order apply fails. */
  seq: number
  kind: MlsObjectKind
  /** base64url MLS wire bytes of the object named by `kind`. */
  payload: string
  /** For `commit`/`application`: the epoch the object belongs to. Advisory —
   * MLS itself is authoritative — but lets a client discard a delivery for an
   * epoch it has already passed without a decrypt attempt. */
  epoch?: string
}

export interface GroupsRequestBody { /** No fields: the asker is the envelope's sender. */ }

export interface GroupsBody {
  /** Group ids the asker is a member of, as this DS sees it. A device
   * compares them against what it holds and pulls anything missing. */
  groups: Array<{ group_id: string; epoch: string }>
}

export interface DeliveriesRequestBody {
  group_id: string
  /** The highest seq this device has APPLIED. Everything after it is what the
   * device is missing — which is why it must be the applied one and not the
   * highest seen: a delivery that arrived but could not be applied is still
   * missing in every sense that matters. */
  after_seq: number
}

export interface DeliveriesBody {
  group_id: string
  /** In seq order, and possibly a prefix of what is missing — the DS bounds
   * one answer. A client that gets a full batch asks again from the last seq
   * it applied. */
  deliveries: DeliverBody[]
}

/** MLS bytes → the wire form used in every body above. */
export function encodeMlsField(bytes: Uint8Array): string { return b64url(bytes) }

/** Inverse of `encodeMlsField`, with the type check a body's field needs
 * before it is handed to MLS. */
export function decodeMlsField(value: unknown, what: string): Uint8Array {
  if (typeof value !== 'string' || !value) throw new Error(`mls-transport: ${what} is missing or not a string`)
  return b64urlToBytes(value)
}

/** True for every message type of this protocol — the dispatcher's one check. */
export function isMlsTransport(msg: { type?: string }): boolean {
  return (msg.type ?? '').startsWith(`${MLS_PROTOCOL}/`)
}
