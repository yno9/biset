// Which of a bridged message's reply tokens (didmail PROTOCOL.md §7.1) may be kept, and for whom. One rule for every way a message is
// taken in: the ingress projector (a mail), and the Secure-Join steps, which are answered before they reach it.
import { sameIdentity } from '../../protocol/vh/identifier.ts'
import { mailAddressOfBridgeDid } from '../pgp/autocrypt.ts'
import type { BasicMessageBody } from './basicmessage.ts'

/** The tokens of `body` that may be kept: only from a bridge's mail that passed DMARC, and only for the DIDs of the sender and of its
 * `Reply-To` -- what a sender can touch is its own card and the one it names as the place to answer. */
export function trustedReplyTokens(body: Pick<BasicMessageBody, 'replyTokens' | 'auth' | 'replyTo'>, senderDid: string): Record<string, string> {
  if (!body.replyTokens || body.auth?.dmarc !== 'pass' || !mailAddressOfBridgeDid(senderDid)) return {}
  return Object.fromEntries(Object.entries(body.replyTokens).filter(([did]) => sameIdentity(did, senderDid) || (body.replyTo !== undefined && sameIdentity(did, body.replyTo))))
}
