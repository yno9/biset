// Delta Chat's Secure-Join v3 ("setup contact"), the side that joins: we open an invite someone gave us (a link or the text of a
// QR code), and the two end up knowing each other's keys, which makes them a verified contact. The other side of this is
// securejoin.ts; the steps are the same ones, read from Delta Chat's own joiner (chatmail/core `securejoin/bob.rs`).
//
//   us -> them   vc-request-pubkey       encrypted to a password, the shared secret `securejoin/<their fingerprint>/<auth>`;
//                                        neither signed nor carrying our key (Delta Chat sends it so)
//   them -> us   vc-pubkey               same password, signed by them, their key in an Autocrypt header
//   us -> them   vc-request-with-auth    encrypted to their key, signed by us, our Autocrypt header, our fingerprint, and their
//                                        own key in an Autocrypt-Gossip header: Delta Chat ignores the step without it (it
//                                        takes the gossip for the proof that we encrypted to the key we were meant to)
//   them -> us   vc-contact-confirm      encrypted to our key, signed by them
//
// The answers are matched to the join by what only the invite gives (the password, and the fingerprint of the key), not by the
// sender's address: the account that made the invite may answer from another of its addresses.
//
// The state between the steps (which invite we opened for which address, and the key they sent) is the pending join: it is
// kept on this device only, for PENDING_HOURS.
import * as openpgp from 'openpgp'
import type { PgpKey } from './keyring.ts'
import { autocryptKeydata } from './keyring.ts'
import { decryptMessage, encryptMessage, NotEncryptedToUsError } from './message-crypto.ts'
import { buildInnerMime, keydataHeader, parseInnerMime, parseKeydataHeader } from './mime.ts'
import { symmetricDecrypt, symmetricEncryptSigned } from './symmetric.ts'
import { SECURE_JOIN_SUBJECT, sharedSecret, type SecureJoinParty } from './securejoin.ts'

export const PENDING_HOURS = 24

export class InviteError extends Error {}

export interface Invite {
  /** The inviter's key, 40 (v4) or 64 (v6) hex characters, upper case. */
  fingerprint: string
  auth: string
  address: string
  name: string
}

/** What Delta Chat shows for "setup contact": `https://i.delta.chat/#<FP>&a=…&n=…&i=…&s=…&v=3`, or the same as `OPENPGP4FPR:<FP>#a=…`. */
export function parseInvite(text: string): Invite {
  const value = text.trim()
  let fingerprintPart: string, rest: string
  const uri = /^OPENPGP4FPR:([^#]+)#(.*)$/is.exec(value)
  const link = /^https:\/\/(?:i\.delta\.chat|[^/#]*)\/?[^#]*#([^&]+)&?(.*)$/is.exec(value)
  if (uri) { fingerprintPart = uri[1]!; rest = uri[2]! } else if (link) { fingerprintPart = link[1]!; rest = link[2]! } else throw new InviteError('this is not a Delta Chat invite')
  const fingerprint = decodeURIComponent(fingerprintPart).replace(/\s+/g, '').toUpperCase()
  if (!/^(?:[0-9A-F]{40}|[0-9A-F]{64})$/.test(fingerprint)) throw new InviteError('the invite has no valid key fingerprint')
  const params = new URLSearchParams(rest.replace(/#/g, '&'))
  if (params.has('x') || params.has('g') || params.has('b')) throw new InviteError('group and channel invites are not supported')
  if (params.get('v') !== '3') throw new InviteError('this invite is from an older Delta Chat (only version 3 invites are supported)')
  const auth = params.get('s') ?? ''
  if (!/^[A-Za-z0-9_-]{8,64}$/.test(auth)) throw new InviteError('the invite has no valid auth token')
  const address = params.get('a') ?? ''
  if (!/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(address)) throw new InviteError('the invite has no valid address')
  return { fingerprint, auth, address, name: params.get('n') ?? address }
}

export interface PendingJoin extends Invite {
  stage: 'requested' | 'auth-sent'
  /** Their key (Autocrypt keydata) once vc-pubkey has brought it. */
  keydata?: string
  at: number
}

export interface PendingJoins {
  list(): Promise<PendingJoin[]>
  put(join: PendingJoin): Promise<void>
  remove(address: string): Promise<void>
}

export interface JoinContext {
  key: PgpKey
  address: string
  now: number
  pending: PendingJoins
  /** Sends an armored OpenPGP message as a mail with the subject `Secure-Join`. `introduction` marks the first message to an
   * address that has not written to us (didmail's reply-only mode; PROTOCOL.md §7.1). */
  send(to: SecureJoinParty, armored: string, options: { introduction?: boolean }): Promise<void>
  /** Keeps their key, which the handshake has vouched for. */
  learn(party: SecureJoinParty, keydata: string): Promise<void>
}

const fromBase64 = (value: string) => Uint8Array.from(atob(value), char => char.charCodeAt(0))

/** Step 1: asks the inviter for their key. */
export async function beginJoin(invite: Invite, to: SecureJoinParty, context: JoinContext): Promise<void> {
  const inner = buildInnerMime({ lines: ['Secure-Join: vc-request-pubkey', `Secure-Join-Auth: ${invite.auth}`], text: SECURE_JOIN_SUBJECT })
  const armored = await symmetricEncryptSigned(inner, sharedSecret(invite.fingerprint, invite.auth))
  await context.pending.put({ ...invite, stage: 'requested', at: context.now })
  await context.send(to, armored, { introduction: true })
}

export type JoinOutcome = 'vc-pubkey' | 'vc-contact-confirm'

/** Takes `armored` (an encrypted mail from `from`) if it is the next step of a join we began with that address; undefined for
 * any other message (which is just mail). A step that does not hold (a key that is not the invite's, a signature that fails) is
 * an error, and the join stays pending. */
export async function handleJoinStep(armored: string, from: SecureJoinParty, context: JoinContext): Promise<JoinOutcome | undefined> {
  const horizon = context.now - PENDING_HOURS * 60 * 60 * 1000
  // Not only the invite's own address: a Delta Chat account may have several relays, and answer from another one (the invite
  // names chtml.ca, the answer comes from chat.vim.wtf). The password (the invite's) and the key (its fingerprint) are the proof.
  const mine = (await context.pending.list()).filter(join => join.at >= horizon)
  for (const join of mine) {
    if (join.stage === 'requested') {
      // 2. They send their key, under the password only the invite gives.
      const opened = await symmetricDecrypt(armored, [sharedSecret(join.fingerprint, join.auth)])
      if (!opened) continue
      const mime = parseInnerMime(opened.plaintext)
      if (mime.headers['secure-join'] !== 'vc-pubkey' || mime.headers['secure-join-auth'] !== join.auth) throw new Error('a password message that is not a valid vc-pubkey')
      const held = parseKeydataHeader(mime.headers.autocrypt)
      if (!held || held.addr.toLowerCase() !== from.address.toLowerCase()) throw new Error('vc-pubkey without the sender\'s key for the sender\'s address')
      const theirs = await openpgp.readKey({ binaryKey: fromBase64(held.keydata) })
      if (theirs.getFingerprint().toUpperCase() !== join.fingerprint) throw new Error('the key sent is not the one the invite names')
      const signed = await symmetricDecrypt(armored, [sharedSecret(join.fingerprint, join.auth)], [fromBase64(held.keydata)])
      if (!signed || signed.signedBy.length === 0) throw new Error('vc-pubkey is not signed by the key the invite names')

      const reply = buildInnerMime({
        lines: [keydataHeader('Autocrypt', context.address, await autocryptKeydata(context.key.privateKey, context.address), true), 'Chat-Version: 1.0', 'Secure-Join: vc-request-with-auth', `Secure-Join-Auth: ${join.auth}`, `Secure-Join-Fingerprint: ${context.key.fingerprint}`, keydataHeader('Autocrypt-Gossip', held.addr, held.keydata)],
        text: SECURE_JOIN_SUBJECT,
      })
      await context.send(from, await encryptMessage({ plaintext: reply, recipients: [fromBase64(held.keydata)], signer: context.key.privateKey }), {})
      await context.pending.put({ ...join, stage: 'auth-sent', keydata: held.keydata })
      return 'vc-pubkey'
    }

    // 4. They confirm, in a message encrypted to us and signed by the key we have been given.
    let checked
    try { checked = await decryptMessage({ armored, privateKey: context.key.privateKey, senderKeys: [fromBase64(join.keydata!)] }) } catch (error) {
      if (error instanceof NotEncryptedToUsError) continue
      throw error
    }
    if (parseInnerMime(checked.plaintext).headers['secure-join'] !== 'vc-contact-confirm') continue
    if (checked.signature?.verified !== true) throw new Error('vc-contact-confirm is not signed by the key the invite names')
    await context.learn(from, join.keydata!)
    await context.pending.remove(join.address)
    return 'vc-contact-confirm'
  }
  return undefined
}

/** The pending joins of one identity, kept in this browser (they live minutes; a join answered on another device is not followed). */
export function localPendingJoins(identityId: string, storage: Pick<Storage, 'getItem' | 'setItem'> | undefined = globalThis.localStorage): PendingJoins {
  const key = `biset.securejoin.pending.${identityId}`
  const read = (): PendingJoin[] => { try { const value = JSON.parse(storage?.getItem(key) ?? '[]') as unknown; return Array.isArray(value) ? value as PendingJoin[] : [] } catch { return [] } }
  const write = (joins: PendingJoin[]) => { try { storage?.setItem(key, JSON.stringify(joins)) } catch { /* no storage: the join is not followed */ } }
  return {
    list: async () => read(),
    put: async join => write([...read().filter(entry => entry.address.toLowerCase() !== join.address.toLowerCase()), join]),
    remove: async address => write(read().filter(entry => entry.address.toLowerCase() !== address.toLowerCase())),
  }
}
