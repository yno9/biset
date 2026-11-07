// Delta Chat's Secure-Join, both sides, over DIDComm to a mail bridge: an invite link (the account page) opened in Delta Chat,
// which then sends two messages only someone with the invite can make; and an invite Delta Chat gave, opened here. The answers
// make this identity a key-contact there, and its key a verified one on this identity's card.
import { resolveMailAddressDid } from '../../didcomm/address-resolver.ts'
import { basicMessageBodyOf, pgpArmorOf } from '../../didcomm/basicmessage.ts'
import { trustedReplyTokens } from '../../didcomm/reply-tokens.ts'
import type { RotationManager } from '../../didcomm/rotation-manager.ts'
import { sendDidCommMessage } from '../../didcomm/send-message.ts'
import { mailAddressOfBridgeDid } from '../../pgp/autocrypt.ts'
import type { OwnProfile } from '../../pgp/mime.ts'
import { handleSecureJoin, SECURE_JOIN_SUBJECT } from '../../pgp/securejoin.ts'
import { beginJoin, handleJoinStep, localPendingJoins, parseInvite, type JoinContext } from '../../pgp/securejoin-join.ts'
import { autocryptKeyPatch, contactNamePatch, replyTokenOf, contactCardForDid } from '../../store/projection/contacts.ts'
import type { DidCommPlaintext } from '../../../protocol/didcomm/message.ts'
import { errorMessage } from '../../../protocol/error-message.ts'
import { readBisetConfig } from '../ui/config.ts'
import type { AccountVault } from './account-vault.ts'
import type { GenerationSeeds, OwnMail } from './own-identity.ts'

export interface SecureJoin {
  /** Opens an invite Delta Chat gave: the first step of the handshake, to the address the invite names. */
  joinInvite(text: string): Promise<{ name: string; address: string }>
  /** Answers a step of the handshake; false when `message` is not one (an ordinary mail, which goes on to be shown). */
  answer(message: DidCommPlaintext): Promise<boolean>
}

export function createSecureJoin(options: {
  vault: AccountVault
  mail: OwnMail | undefined
  seeds: GenerationSeeds
  profile(): Promise<OwnProfile>
  route: RotationManager['route']
}): SecureJoin {
  const { vault, mail } = options
  const send = async (to: { did: string }, armored: string, sendOptions: { introduction?: boolean }) => {
    const route = await options.route(to.did)
    const replyToken = replyTokenOf(contactCardForDid((await vault.snapshot()).contactCards, route.toDid))
    const sent = await sendDidCommMessage(route.toDid, '', {
      fromKid: route.fromKid, x25519PrivateKey: route.x25519PrivateKey, subject: SECURE_JOIN_SUBJECT, encrypted: { armored },
      ...(sendOptions.introduction ? { introduction: true } : {}),
      ...(replyToken ? { replyToken } : {}),
    })
    if (!sent.ok) throw new Error(sent.error)
    if (sent.replyTokens) await vault.keepReplyTokens(sent.replyTokens)
  }
  // A key the handshake has vouched for: kept on the contact's card, as verified.
  const learn = async (who: { did: string }, keydata: string, name?: { text: string; source: 'signed' | 'invite' }) => {
    await vault.writeContact(who.did, (cardId, card) => [
      autocryptKeyPatch(cardId, { keydata, seenAt: new Date().toISOString(), preferEncrypt: 'mutual', verified: true }),
      name ? contactNamePatch(cardId, card, name.text, name.source) : undefined,
    ])
  }
  const pending = localPendingJoins(vault.identityId)
  const joinContext = (key: JoinContext['key'], address: string, profile: OwnProfile): JoinContext => ({
    key, address, now: Date.now(), pending, send, learn, profile,
  })

  return {
    async joinInvite(text) {
      const key = await mail?.pgp.current()
      if (!key || !mail) throw new Error('The key is not ready yet')
      const invite = parseInvite(text)
      const did = await resolveMailAddressDid(invite.address, readBisetConfig().mailGateways)
      await beginJoin(invite, { did, address: invite.address }, joinContext(key, mail.address, await options.profile()))
      return { name: invite.name, address: invite.address }
    },
    async answer(message) {
      const armored = pgpArmorOf(message)
      const fromDid = typeof message.from === 'string' ? message.from : undefined
      const fromAddress = fromDid ? mailAddressOfBridgeDid(fromDid) : undefined
      // A step is answered here and never reaches the projector that keeps a mail's reply tokens, and the answer is refused by
      // the bridge without the token of the address it goes to: keep it first.
      const arrived = armored && fromDid ? basicMessageBodyOf(message) : null
      const tokens = arrived && fromDid ? trustedReplyTokens(arrived, fromDid) : {}
      if (Object.keys(tokens).length > 0) await vault.keepReplyTokens(tokens).catch(error => console.warn('[did.md Wallet Secure-Join] reply token not kept:', errorMessage(error)))
      const seed = await options.seeds.current()
      const key = await mail?.pgp.current()
      if (!armored || !fromDid || !fromAddress || !seed || !key || !mail) return false
      const party = { did: fromDid, address: fromAddress }
      try {
        const profile = await options.profile()
        const outcome = await handleSecureJoin(armored, party, {
          seed, key, address: mail.address, now: Date.now(), profile,
          send: (to, answer) => send(to, answer, {}),
          learn,
        }) ?? await handleJoinStep(armored, party, joinContext(key, mail.address, profile))
        if (outcome) console.info(`[did.md Wallet Secure-Join] ${outcome} from ${fromAddress}`)
        return outcome !== undefined
      } catch (error) {
        // Not a valid step (an old invite, a key that does not match): it is not mail either, so it is not shown.
        console.warn('[did.md Wallet Secure-Join] refused:', errorMessage(error))
        return true
      }
    },
  }
}
