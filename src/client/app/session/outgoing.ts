// What this identity writes: a DIDComm chat message (to one counterparty, or a group), and a note to itself.
//
// A message is committed locally first (the durable outbox), then sent to each recipient's public DID from this device's own
// key. `thid` makes it part of a group conversation: the same message, addressed to every participant (group-chat.ts).
import { mailAddressOfBridgeDid } from '../../pgp/autocrypt.ts'
import { newDidCommId } from '../../../protocol/didcomm/message.ts'
import { resolveRecipient } from '../../didcomm/address-resolver.ts'
import { didCommThidOf, didCommThreadOf } from '../../didcomm/basicmessage.ts'
import { didcommGroupAddress, groupConversation, parseDidCommGroupAddress } from '../../didcomm/group-chat.ts'
import type { WalletDidCommOutbox } from '../../identity/wallet/didcomm-outbox.ts'
import { rotationReader } from '../../store/projection/contacts.ts'
import { sameIdentity } from '../../../protocol/vh/identifier.ts'
import { readBisetConfig } from '../ui/config.ts'
import type { ReplySendInput } from '../ui/reply-box.tsx'
import { NOTEPAD_THREAD_ID } from '../ui/thread-model.ts'
import type { AccountVault } from './account-vault.ts'

export interface Outgoing {
  send(input: ReplySendInput): Promise<void>
  /** The Notepad: a message to oneself, written into the vault like any message (so every device of the identity has it) and
   * queued for nobody, since there is no one to send it to. */
  writeNote(body: string): Promise<void>
  /** A group conversation is whatever its messages say: its participants are those of its latest message. */
  groupConversation(thid: string): Promise<ReturnType<typeof groupConversation>>
}

export function createOutgoing(options: {
  vault: AccountVault
  /** This identity's DID, as it is written to others. */
  did: string
  /** There is none until the mediator is connected. */
  outbox(): WalletDidCommOutbox | undefined
}): Outgoing {
  const { vault } = options
  const conversationOf = async (thid: string) => {
    const snapshot = await vault.snapshot()
    return groupConversation(thid, snapshot.emails, rotationReader(snapshot.contactCards))
  }
  const queue = async (recipients: string[], input: ReplySendInput, group?: { thid: string }, answered?: { id: string; threadId: string; messageId?: string }): Promise<void> => {
    const outbox = options.outbox()
    if (!outbox) throw new Error('DIDComm is still connecting for this Wallet session')
    if (recipients.length === 0) throw new Error('A DIDComm message needs a recipient')
    const now = new Date().toISOString()
    const messageId = newDidCommId()
    // A 1:1 message with a DID is a thread of the conversation: a reply is in the thread it answers (named by the id of its first
    // message), and anything else starts one, named by its own id. A reply in a conversation from before threads starts one at the
    // message it answers. With a mail address (a bridge DID) every message is a thread of its own and a reply is chained to the
    // message it answers by `inReplyTo`, as a mail client does: the bridge sends that message's id as In-Reply-To (didmail
    // PROTOCOL.md §6.2), and mail coming back names its parent the same way.
    const mail = !group && mailAddressOfBridgeDid(recipients[0]!) !== undefined
    const thid = group ? undefined : mail || !answered ? messageId : (didCommThidOf(answered.threadId) ?? answered.messageId ?? messageId)
    await vault.mutationSink.commitMailMessage({
      email: {
        id: crypto.randomUUID(),
        // A group conversation is its `thid`, carried by every message of it.
        threadId: group ? didcommGroupAddress(group.thid) : didCommThreadOf(vault.identityId, recipients[0]!, thid!),
        mailboxIds: { outbox: true }, keywords: { '$seen': true },
        receivedAt: now, sentAt: now, from: [{ email: vault.identityId }], to: recipients.map(email => ({ email })),
        ...(input.subject ? { subject: input.subject } : {}),
        messageId,
        ...(answered ? { inReplyTo: answered.messageId ?? answered.id } : {}),
      },
      rawRfc5322: new TextEncoder().encode(input.body),
      didComm: recipients.map(toDid => ({ messageId, toDid })),
    }, await vault.snapshot())
    await vault.refresh()
    await outbox.flush()
    await vault.refresh()
  }

  return {
    groupConversation: conversationOf,
    async send(input) {
      if (!options.outbox()) throw new Error('DIDComm is still connecting for this Wallet session')
      const snapshot = await vault.snapshot()
      const answered = input.inReplyTo ? snapshot.emails.find(email => email.messageId === input.inReplyTo || email.id === input.inReplyTo) : undefined
      // A reply in a group conversation goes to every participant of its latest message but this identity (reply-all).
      if (answered?.threadId.startsWith('didcomm-group:')) {
        const thid = parseDidCommGroupAddress(answered.threadId)
        const conversation = await conversationOf(thid)
        if (!conversation) throw new Error('This DIDComm group conversation is unavailable on this device')
        await queue(conversation.participants.filter(participant => !sameIdentity(participant, options.did)), input, { thid })
        return
      }
      // A mail address is another name for a DID (address-resolver.ts).
      const toDids = await Promise.all(input.toAddrs.map(address => resolveRecipient(address, readBisetConfig().mailGateways)))
      if (toDids.length === 0 || !toDids.every(address => address.startsWith('did:'))) throw new Error('A did.md Wallet session composes to DID recipients or mail addresses only')
      const recipients = [...new Set(toDids)].filter(address => !sameIdentity(address, options.did))
      // Several recipients start a group conversation of its own.
      if (recipients.length >= 2) return queue(recipients, input, { thid: newDidCommId() })
      // A reply to the one counterparty answers the message it replies to.
      await queue(recipients, input, undefined, recipients.length === 1 ? answered : undefined)
    },
    async writeNote(body) {
      const now = new Date().toISOString()
      await vault.mutationSink.commitMailMessage({
        email: {
          id: crypto.randomUUID(), threadId: NOTEPAD_THREAD_ID, mailboxIds: { sent: true }, keywords: { '$seen': true },
          receivedAt: now, sentAt: now, from: [{ email: vault.identityId }], to: [{ email: vault.identityId }], messageId: crypto.randomUUID(),
        },
        rawRfc5322: new TextEncoder().encode(body),
      }, await vault.snapshot())
      await vault.refresh()
    },
  }
}
