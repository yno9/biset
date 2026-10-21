// Delta Chat's Secure-Join v3 ("setup contact"), the side that is invited: someone opens our invite link in Delta Chat, and
// the two end up knowing each other's keys. That is what makes us a key-contact there: Delta Chat tells contacts by the
// fingerprint of their key, and writes encrypted only to those (chatmail/core `Chat::is_encrypted`).
//
//   Delta Chat -> us   vc-request-pubkey       encrypted to a password, the shared secret `securejoin/<our fingerprint>/<auth>`
//   us -> Delta Chat   vc-pubkey               same password, signed by us, our key in an Autocrypt header
//   Delta Chat -> us   vc-request-with-auth    encrypted to our key, signed by theirs, its Autocrypt header, Secure-Join-Fingerprint
//   us -> Delta Chat   vc-contact-confirm      encrypted to its key, signed, its key in an Autocrypt-Gossip header
//
// All the Secure-Join headers are inside the encryption; Delta Chat ignores any outside. The invite (its number and auth token)
// is not stored: it follows from the generation seed and the day, and is valid for INVITE_DAYS days, so any device of the
// identity can answer for any invite another one gave.
import * as openpgp from 'openpgp'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToBase64url } from '../../protocol/canonical.ts'
import type { PgpKey } from './keyring.ts'
import { autocryptKeydata } from './keyring.ts'
import { decryptMessage, encryptMessage, NotEncryptedToUsError } from './message-crypto.ts'
import { buildInnerMime, keydataHeader, parseInnerMime, parseKeydataHeader } from './mime.ts'
import { symmetricDecrypt, symmetricEncryptSigned } from './symmetric.ts'

export const INVITE_DAYS = 30
export const SECURE_JOIN_SUBJECT = 'Secure-Join'

const DAY_MS = 24 * 60 * 60 * 1000
const utf8 = (text: string) => new TextEncoder().encode(text)

/** 18 random-looking bytes as base64url, the 24 characters Delta Chat's `create_id()` makes. */
function token(seed: Uint8Array, label: string, day: number): string {
  return bytesToBase64url(hkdf(sha256, seed, undefined, utf8(`biset/securejoin/${label}/v1/${day}`), 18))
}

export function inviteOfDay(seed: Uint8Array, day: number): { invitenumber: string; auth: string } {
  return { invitenumber: token(seed, 'invitenumber', day), auth: token(seed, 'auth', day) }
}

/** The auth tokens of the invites that are still valid at `now`. */
export function validAuths(seed: Uint8Array, now: number): string[] {
  const today = Math.floor(now / DAY_MS)
  return Array.from({ length: INVITE_DAYS }, (_, back) => inviteOfDay(seed, today - back).auth)
}

export const sharedSecret = (fingerprint: string, auth: string) => `securejoin/${fingerprint.toUpperCase()}/${auth}`

/** The link to give to Delta Chat (as text, or as the QR code it would scan). */
export function inviteUrl(input: { seed: Uint8Array; key: Pick<PgpKey, 'fingerprint'>; address: string; name?: string; now: number }): string {
  const { invitenumber, auth } = inviteOfDay(input.seed, Math.floor(input.now / DAY_MS))
  const name = encodeURIComponent(input.name || input.address).replace(/%20/g, '+')
  return `https://i.delta.chat/#${input.key.fingerprint.toUpperCase()}&v=3&i=${invitenumber}&s=${auth}&a=${encodeURIComponent(input.address)}&n=${name}`
}

export interface SecureJoinParty {
  /** The bridge DID of the other side, which the answers go to. */
  did: string
  address: string
}

export interface SecureJoinContext {
  seed: Uint8Array
  /** Our key of the current generation; the invites are for it. */
  key: PgpKey
  address: string
  now: number
  /** Sends an answer: an armored OpenPGP message, as a mail with the subject `Secure-Join`. */
  send(to: SecureJoinParty, armored: string): Promise<void>
  /** Keeps the key of the other side, which the handshake has vouched for. */
  learn(party: SecureJoinParty, keydata: string): Promise<void>
}

export type SecureJoinOutcome = 'vc-request-pubkey' | 'vc-request-with-auth'

/** Answers `armored` (an encrypted mail from `from`) if it is a Secure-Join step for one of our invites; undefined for any
 * other message (which is just mail). A step that is not valid (an old or unknown invite, a key that is not the one named, a
 * signature that does not hold) is not answered, and is not mail either: it is dropped with an error. */
export async function handleSecureJoin(armored: string, from: SecureJoinParty, context: SecureJoinContext): Promise<SecureJoinOutcome | undefined> {
  const auths = validAuths(context.seed, context.now)

  // 1. Delta Chat asks for our key, in a message only someone who has the invite can make.
  const symmetric = await symmetricDecrypt(armored, auths.map(auth => sharedSecret(context.key.fingerprint, auth)))
  if (symmetric) {
    const mime = parseInnerMime(symmetric.plaintext)
    const auth = mime.headers['secure-join-auth']
    if (mime.headers['secure-join'] !== 'vc-request-pubkey' || !auth || !auths.includes(auth)) throw new Error('a password message that is not a valid vc-request-pubkey')
    const inner = buildInnerMime({
      lines: [keydataHeader('Autocrypt', context.address, await autocryptKeydata(context.key.privateKey, context.address), true), 'Chat-Version: 1.0', 'Secure-Join: vc-pubkey', `Secure-Join-Auth: ${auth}`],
      text: SECURE_JOIN_SUBJECT,
    })
    await context.send(from, await symmetricEncryptSigned(inner, sharedSecret(context.key.fingerprint, auth), context.key.privateKey))
    return 'vc-request-pubkey'
  }

  // 2. Delta Chat proves it has the invite, and names its key.
  let opened
  try { opened = await decryptMessage({ armored, privateKey: context.key.privateKey }) } catch (error) {
    if (error instanceof NotEncryptedToUsError) return undefined
    throw error
  }
  const mime = parseInnerMime(opened.plaintext)
  if (mime.headers['secure-join'] !== 'vc-request-with-auth') return undefined
  const auth = mime.headers['secure-join-auth']
  const named = mime.headers['secure-join-fingerprint']?.replace(/\s+/g, '').toUpperCase()
  if (!auth || !auths.includes(auth)) throw new Error('vc-request-with-auth with an auth token that is not one of our invites')
  const held = parseKeydataHeader(mime.headers.autocrypt)
  if (!named || !held || held.addr.toLowerCase() !== from.address.toLowerCase()) throw new Error('vc-request-with-auth without the sender\'s key for the sender\'s address')
  const keyBytes = Uint8Array.from(atob(held.keydata), char => char.charCodeAt(0))
  const theirs = await openpgp.readKey({ binaryKey: keyBytes })
  if (theirs.getFingerprint().toUpperCase() !== named) throw new Error('the key sent is not the one the fingerprint names')
  // The message must have been signed by that key: only its owner can claim it.
  const checked = await decryptMessage({ armored, privateKey: context.key.privateKey, senderKeys: [keyBytes] })
  if (checked.signature?.verified !== true) throw new Error('vc-request-with-auth is not signed by the key it names')

  await context.learn(from, held.keydata)
  const confirm = buildInnerMime({ lines: ['Chat-Version: 1.0', 'Secure-Join: vc-contact-confirm', keydataHeader('Autocrypt-Gossip', from.address, held.keydata)], text: SECURE_JOIN_SUBJECT })
  await context.send(from, await encryptMessage({ plaintext: confirm, recipients: [keyBytes], signer: context.key.privateKey }))
  return 'vc-request-with-auth'
}
