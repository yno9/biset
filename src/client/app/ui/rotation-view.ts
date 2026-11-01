// A received message as shown (PLAN-refactor.md §14.4). It is stored under the DID that authenticated it; here that DID
// reads as the person it stands for, from the contact cards. Pure: the screens call it with a `rotationReader` of the cards.
import type { RotationReader } from '../../store/projection/contacts.ts'
import { labelForDid } from './did-display.ts'
import type { MailMessageView } from './message/message-view.ts'

/** `msg` with each DID of it read as its counterparty's public DID (`from`, `to_addrs`, the 1:1 thread), or `null` for a message
 * from a DID its counterparty has since left: it is kept in the Vault but not shown (§14.5). */
export function readRotated(msg: MailMessageView, reader: RotationReader): MailMessageView | null {
  if (reader.superseded(msg.from)) return null
  const from = reader.party(msg.from)
  return {
    ...msg,
    from,
    // The name the message came with stays; the one made from the DID is made from the person's DID instead.
    from_name: from !== msg.from && msg.from_name === labelForDid(msg.from) ? labelForDid(from) : msg.from_name,
    ...(msg.to_addrs ? { to_addrs: msg.to_addrs.map(reader.party) } : {}),
    thread_id: reader.thread(msg.thread_id),
  }
}
