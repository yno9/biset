// Writing an encrypted mail for a mail address: the inner MIME the way Delta Chat and other OpenPGP mail clients read it
// (the real Subject, Date, Message-ID and References inside; our key in an Autocrypt header), encrypted to the
// recipient's key and ours, signed. The mail bridge (didmail PROTOCOL.md §7.4) wraps the armor into PGP/MIME.
import { encryptMessage } from './message-crypto.ts'
import { avatarLine, buildInnerMime, fromLine, keydataHeader } from './mime.ts'

export interface ComposeInput {
  /** The DIDComm message id and thread, which the bridge turns into Message-ID and In-Reply-To (PROTOCOL.md §6.1). */
  id: string
  thid?: string
  /** The host of the bridge DID (`did:web:{host}:{domain}:{local}`): `<id@host>` is the Message-ID of an id with no `@`. */
  bridgeHost: string
  subject?: string
  content: string
  sentAt: string
  fromAddress: string
  fromName?: string
  /** The picture to send along (base64 of the image), when the recipient has not got this one yet. */
  avatarBase64?: string
  toAddress: string
  own: { privateKey: Uint8Array; keydata: string }
  /** The recipient's binary public key. */
  peerKey: Uint8Array
}

/** Same rule as the bridge's `messageIdFromDidcommId`: an id with an `@` already is a Message-ID. */
export function messageIdOf(id: string, bridgeHost: string): string {
  return id.includes('@') ? `<${id}>` : `<${id}@${bridgeHost}>`
}

/** What a hidden subject looks like outside (the same stand-in Delta Chat uses). */
export const HIDDEN_SUBJECT = '[...]'

export async function composeEncryptedMail(input: ComposeInput): Promise<{ armored: string; outerSubject: string }> {
  const parent = input.thid ? messageIdOf(input.thid, input.bridgeHost) : undefined
  const date = new Date(input.sentAt)
  const inner = buildInnerMime({
    headers: [
      ['To', input.toAddress],
      ['Subject', input.subject ?? ''],
      ['Date', (Number.isNaN(date.getTime()) ? new Date() : date).toUTCString()],
      ['Message-ID', messageIdOf(input.id, input.bridgeHost)],
      // Without it Delta Chat takes the message for ordinary mail and shows "<subject> – <text>"; with it, the text alone.
      ['Chat-Version', '1.0'],
      ...(parent ? [['In-Reply-To', parent], ['References', parent]] as Array<[string, string]> : []),
    ],
    lines: [fromLine(input.fromAddress, input.fromName), keydataHeader('Autocrypt', input.fromAddress, input.own.keydata, true), ...(input.avatarBase64 ? [avatarLine(input.avatarBase64)] : [])],
    text: input.content,
  })
  const armored = await encryptMessage({ plaintext: inner, recipients: [input.peerKey], signer: input.own.privateKey })
  return { armored, outerSubject: HIDDEN_SUBJECT }
}
