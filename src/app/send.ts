// The app's outbound send path, lifted out of main.ts's bootClient()
// (PLAN-simplify.md §2 S4 stage 1). Nothing here is new: these are the
// same handlers bootClient() used to define as closures inside its
// `if (apexDomain && identity.deviceKid)` block, with the dependencies
// they used to read off that closure now named explicitly in SendContext
// below. That type IS the documentation of what a send actually needs.
import type { IdentityRecord } from '../identity/record-store.ts'
import type { LocalJmapReadModel, LocalJmapTransport } from '../local-jmap/gateway.ts'
import type { VaultBackedLocalJmapMutationSink } from '../local-jmap/vault-mutation-sink.ts'
import type { ContactKeyReader } from '../vault/contact-key-reader.ts'
import type { ContactKeyV1 } from '../vault/contact-key.ts'
import type { IndexedDbDidCommGroupChatStore } from '../didcomm/group-chat-store.ts'
import type { ReplySendInput } from '../ui/thread.ts'
import { initiateRelationship, sendDidCommMessage, sendGroupInvite, type PendingRelationship } from '../didcomm/send-message.ts'
import { didCommThreadId } from '../didcomm/basicmessage.ts'
import { didcommGroupAddress, parseDidCommGroupAddress, randomDidCommGroupId } from '../didcomm/group-chat.ts'
import { buildOutboundRfc5322 } from '../mail/rfc5322-builder.ts'
import { fromHex } from '../identity/bootstrap.ts'
import { refreshInbox, showSysMsg } from '../ui/shell.ts'

export interface PendingHandshake {
  pending: PendingRelationship
  promise: Promise<ContactKeyV1>
  resolve(value: ContactKeyV1): void
}

/**
 * Everything the send handlers below read out of bootClient()'s scope.
 *
 * `identity` is a GETTER, not a value, and that is load-bearing:
 * bootClient()'s own `identity` is a `let` that enableDidComm REASSIGNS at
 * boot (see its declaration's comment there), and every handler that reads
 * `didCommKid`/`didCommX25519PrivateKey` has to see the new record without
 * a page reload. Copying the record into this context at wiring time would
 * hand these functions the pre-enableDidComm identity forever -- i.e. a
 * send right after DIDComm is enabled would sign with a key that no longer
 * describes this device. Each function calls `ctx.identity()` once, at
 * entry, exactly where the closure version used to first dereference it.
 *
 * `startRelationshipPoll`, `flushDidCommTransportOutbox` and
 * `triggerMimiVaultSync` are the same story one level further out: all
 * three are forward-declared `let`s in bootClient() that get their real
 * implementation further down the boot sequence, so they are methods here
 * (dispatching live) rather than captured function values. The two
 * optional ones (`flushDidCommTransportOutbox`,`triggerMimiVaultSync`)
 * keep their "nothing to nudge, don't throw" behaviour on the main.ts side
 * of the wiring, which is where the `?.` used to live.
 */
export interface SendContext {
  identity(): IdentityRecord
  readModel: LocalJmapReadModel
  mutationSink: Pick<VaultBackedLocalJmapMutationSink, 'commitMailMessage'>
  contactKeyReader: Pick<ContactKeyReader, 'currentFor'>
  groupChatStore: Pick<IndexedDbDidCommGroupChatStore, 'load' | 'save'>
  transport: Pick<LocalJmapTransport, 'call'>
  /** This identity's own mail address (mailFromForIdentity) -- the From of
   * every plain-mail send below. */
  mailFrom: string
  pendingByOwnKid: Map<string, PendingHandshake>
  pendingByCounterparty: Map<string, PendingHandshake>
  startRelationshipPoll(xKid: string, xPriv: Uint8Array, did: string, mediatorUrl: string): void
  flushDidCommTransportOutbox(): Promise<void>
  /** Fire-and-forget by contract, matching the `void trigger?.()` call
   * shape these handlers used to have inline. */
  triggerMimiVaultSync(): void
}

// A `to` of exactly one DID (not an email address) dispatches over
// DIDComm instead of mail -- the same "to" field both transports share
// (thread.ts/compose-page.ts have no separate DID input), branching
// here rather than in the UI layer. Multiple DIDs at once isn't
// supported: 1:1 chat only (confirmed with the user, 2026-08-25), and
// mixing a DID with a real email address in one send has no sane
// meaning either.
export async function ensureDidCommContact(ctx: SendContext, toDid: string): Promise<ContactKeyV1> {
  const identity = ctx.identity()
  if (!identity.didCommKid || !identity.didCommX25519PrivateKey) {
    throw new Error('Enable DIDComm in account settings before messaging a DID')
  }
  let contactKey = await ctx.contactKeyReader.currentFor(toDid)
  if (!contactKey) {
    let handshake = ctx.pendingByCounterparty.get(toDid)
    if (!handshake) {
      const initiated = await initiateRelationship(toDid, {
        fromKid: identity.didCommKid,
        x25519PrivateKey: fromHex(identity.didCommX25519PrivateKey),
      })
      if (!initiated.ok) throw new Error(initiated.error)
      let resolve!: (value: ContactKeyV1) => void
      const promise = new Promise<ContactKeyV1>((resolvePromise) => {
        resolve = resolvePromise
      })
      handshake = { pending: initiated.pending, promise, resolve }
      ctx.pendingByOwnKid.set(initiated.pending.peer.xKid, handshake)
      ctx.pendingByCounterparty.set(toDid, handshake)
      ctx.startRelationshipPoll(initiated.pending.peer.xKid, initiated.pending.peer.xPriv, initiated.pending.peer.did, initiated.pending.mediatorUrl)
    }
    contactKey = await Promise.race([
      handshake.promise,
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error(`relationship handshake with ${toDid} timed out`)), 60_000)),
    ])
  }
  return contactKey
}

async function sendDidCommChat(ctx: SendContext, toDid: string, input: ReplySendInput): Promise<void> {
  const identity = ctx.identity()
  if (!identity.didCommKid || !identity.didCommX25519PrivateKey) {
    throw new Error('Enable DIDComm in account settings before messaging a DID')
  }
  // A did.md Wallet starts a conversation from its public DIDComm leaf.
  // It deliberately has no Biset-private relationship credential, so a
  // reply to that inbound public message must use the same public route.
  // Keep the normal private relationship path for every conversation
  // that already has one, and for a newly composed Biset conversation.
  const snapshotBeforeSend = await ctx.readModel.snapshot()
  const repliedMessage = input.inReplyTo
    ? snapshotBeforeSend.emails.find(email => email.id === input.inReplyTo)
    : undefined
  const currentContact = await ctx.contactKeyReader.currentFor(toDid)
  const isPublicInboundReply = currentContact === null
    && repliedMessage?.mailboxIds.inbox === true
    && repliedMessage.from?.some(address => address.email === toDid) === true
  if (isPublicInboundReply) {
    const direct = await sendDidCommMessage(toDid, input.body, {
      fromKid: identity.didCommKid,
      x25519PrivateKey: fromHex(identity.didCommX25519PrivateKey),
      ...(input.subject ? { subject: input.subject } : {}),
    })
    if (!direct.ok) throw new Error(direct.error)
    const now = new Date().toISOString()
    await ctx.mutationSink.commitMailMessage({
      email: {
        id: crypto.randomUUID(),
        threadId: didCommThreadId(identity.did, toDid),
        mailboxIds: { sent: true },
        keywords: { '$seen': true },
        receivedAt: now,
        sentAt: now,
        from: [{ email: identity.did }],
        to: [{ email: toDid }],
        ...(input.subject ? { subject: input.subject } : {}),
      },
      rawRfc5322: new TextEncoder().encode(input.body),
    }, snapshotBeforeSend)
    await refreshInbox(ctx.readModel)
    ctx.triggerMimiVaultSync()
    return
  }
  const now = new Date().toISOString()
  const emailId = crypto.randomUUID()
  const messageId = crypto.randomUUID()
  const snapshot = await ctx.readModel.snapshot()
  await ctx.mutationSink.commitMailMessage({
    email: {
      id: emailId,
      threadId: didCommThreadId(identity.did, toDid),
      mailboxIds: { outbox: true },
      keywords: { '$seen': true },
      receivedAt: now,
      sentAt: now,
      from: [{ email: identity.did }],
      to: [{ email: toDid }],
      ...(input.subject ? { subject: input.subject } : {}),
    },
    rawRfc5322: new TextEncoder().encode(input.body),
    didComm: [{ messageId, toDid }],
  }, snapshot)
  await refreshInbox(ctx.readModel)
  await ctx.flushDidCommTransportOutbox()
  await refreshInbox(ctx.readModel)
  ctx.triggerMimiVaultSync()
}

// Shared "commit local echo + fan out via the outbox" tail for DIDComm
// group chat -- used by BOTH group creation (after inviting) and
// ordinary replies to an existing group thread. Reads the roster fresh
// from groupChatStore rather than taking `toDids` as an argument, so
// both call sites converge on one path.
async function sendDidCommGroupMessage(ctx: SendContext, groupId: string, input: ReplySendInput): Promise<void> {
  const identity = ctx.identity()
  const roster = await ctx.groupChatStore.load(groupId)
  if (!roster) throw new Error(`No local roster for DIDComm group ${groupId}`)
  const toDids = roster.members.filter(m => m !== identity.did)
  const messageId = crypto.randomUUID()
  const emailId = crypto.randomUUID()
  const now = new Date().toISOString()
  const snapshot = await ctx.readModel.snapshot()
  await ctx.mutationSink.commitMailMessage({
    email: {
      id: emailId,
      threadId: didcommGroupAddress(groupId),
      mailboxIds: { outbox: true },
      keywords: { '$seen': true },
      receivedAt: now,
      sentAt: now,
      from: [{ email: identity.did }],
      to: toDids.map(email => ({ email })),
      ...(input.subject ? { subject: input.subject } : {}),
    },
    rawRfc5322: new TextEncoder().encode(input.body),
    didComm: toDids.map(toDid => ({ messageId, toDid })),
  }, snapshot)
  await refreshInbox(ctx.readModel)
  await ctx.flushDidCommTransportOutbox()
  await refreshInbox(ctx.readModel)
  ctx.triggerMimiVaultSync()
}

// Compose's "2+ DID recipients" branch (sendReply's dispatch, below):
// full-mesh group creation, no MLS. Every member needs a pairwise
// ContactKeyV1 with every OTHER member (group-chat.ts's own header) --
// this device already has one with itself's not needed, and with each
// invitee via ensureDidCommContact below; the invitees mesh-complete
// with EACH OTHER on their own once they receive the invite
// (handleDidCommGroupInvite above).
async function createAndSendDidCommGroup(ctx: SendContext, toDids: string[], input: ReplySendInput): Promise<void> {
  const identity = ctx.identity()
  if (!identity.didCommKid || !identity.didCommX25519PrivateKey) throw new Error('Enable DIDComm in account settings before starting a group')
  const groupId = randomDidCommGroupId()
  const members = [identity.did, ...toDids]
  const now = new Date().toISOString()
  await ctx.groupChatStore.save({ groupId, members, ...(input.subject ? { name: input.subject } : {}), createdAt: now, updatedAt: now })

  const unreachable: string[] = []
  for (const toDid of toDids) {
    try {
      const contactKey = await ensureDidCommContact(ctx, toDid)
      const sent = await sendGroupInvite(contactKey, { groupId, members, ...(input.subject ? { name: input.subject } : {}) })
      if (!sent.ok) throw new Error(sent.error)
    } catch (error) {
      unreachable.push(toDid)
      console.warn(`[didcomm-group/invite] ${toDid}:`, error instanceof Error ? error.message : error)
    }
  }
  if (unreachable.length) showSysMsg(`Could not invite: ${unreachable.join(', ')} -- they'll receive this once reachable`)

  // Queue the founding message for EVERY member regardless of invite
  // success above -- flushDidCommTransportOutbox's own
  // ensureDidCommContact retries the handshake again on every poll, so
  // an unreachable member still eventually gets it. No forward-secrecy
  // concern here (unlike MLS), so no separate "wait for join" step is
  // needed either.
  await sendDidCommGroupMessage(ctx, groupId, input)
}

export async function sendReply(ctx: SendContext, input: ReplySendInput): Promise<void> {
  if (input.toAddrs.length === 1 && input.toAddrs[0]!.startsWith('did:')) {
    await sendDidCommChat(ctx, input.toAddrs[0]!, input)
    return
  }
  if (input.toAddrs.length === 1 && input.toAddrs[0]!.startsWith('didcomm-group:')) {
    await sendDidCommGroupMessage(ctx, parseDidCommGroupAddress(input.toAddrs[0]!), input)
    return
  }
  // 2+ DID recipients (never mixed with mail -- same rule the 1-DID
  // branch above already applies) starts a new DIDComm group chat,
  // full-mesh, no MLS (mirroring src.bak's own "visible.length >= 2"
  // compose branch).
  if (input.toAddrs.length >= 2 && input.toAddrs.every(addr => addr.startsWith('did:'))) {
    await createAndSendDidCommGroup(ctx, input.toAddrs, input)
    return
  }
  const { rawRfc5322 } = buildOutboundRfc5322({
    from: ctx.mailFrom,
    to: input.toAddrs,
    subject: input.subject,
    body: input.body,
    inReplyTo: input.inReplyTo,
    references: input.references,
  })
  const emailId = crypto.randomUUID()
  const now = new Date().toISOString()
  const snapshot = await ctx.readModel.snapshot()
  await ctx.mutationSink.commitMailMessage({
    email: {
      id: emailId,
      threadId: crypto.randomUUID(),
      mailboxIds: { outbox: true },
      keywords: {},
      receivedAt: now,
      sentAt: now,
      from: [{ email: ctx.mailFrom }],
      to: input.toAddrs.map(email => ({ email })),
      subject: input.subject,
    },
    rawRfc5322,
  }, snapshot)
  await ctx.transport.call([{ name: 'EmailSubmission/set', callId: 's1', arguments: { create: { s1: { emailId } } } }])
  await refreshInbox(ctx.readModel)
  ctx.triggerMimiVaultSync()
}
