// This identity as it presents itself: its own card in the contact list (name, picture, OpenPGP key), the mail address its
// handle gives, and the OpenPGP key derived from its generation seed.
import { autocryptKeydata } from '../../pgp/keyring.ts'
import type { OwnProfile } from '../../pgp/mime.ts'
import { ownPgp, type OwnPgp } from '../../pgp/own.ts'
import { inviteUrl } from '../../pgp/securejoin.ts'
import { contactAvatar, contactCardForDid, contactCryptoKey, contactDisplayName, ownAvatarPatch, ownCryptoKeyPatch, ownNamePatch, type ContactSetPayload, type LocalJmapContactCard } from '../../store/projection/contacts.ts'
import { bytesToBase64url } from '../../../protocol/base64.ts'
import { sha256Bytes } from '../../../protocol/canonical.ts'
import { errorMessage } from '../../../protocol/error-message.ts'
import { randomDisplayName } from '../ui/account/default-name.ts'
import { PGP_KEY_CHANGED, type PgpCardConfig } from '../ui/account/pgp-card.tsx'
import { PROFILE_CHANGED, type ProfileConfig } from '../ui/account/profile.ts'
import type { AccountVault } from './account-vault.ts'

/** The generation seeds: the current one (from the DID document's authority, once it is known) and every one the Vault holds. */
export interface GenerationSeeds {
  current(): Promise<Uint8Array | undefined>
  all(): Promise<Uint8Array[]>
}

/** The identity's mail address and its key: there is one only when the handle names an address (`label.apex`). */
export interface OwnMail {
  address: string
  pgp: OwnPgp
}

export interface OwnIdentity {
  mail: OwnMail | undefined
  profileCard: ProfileConfig
  pgpCard: PgpCardConfig | undefined
  /** What this identity says about itself in what it signs: its name and picture (the base64 of the image), from its card. */
  profile(): Promise<OwnProfile & { avatarHash?: string }>
  /** Whether the picture goes along to `did` (it has not got this one yet); remembers that it went when it does. */
  takePictureFor(did: string, profile: { avatarHash?: string }): boolean
}

/** `label@apex`: the address of an identity at `label.apex` (didmail). */
function mailAddressOfHandle(handle: string): string | undefined {
  const dot = handle.indexOf('.')
  return dot > 0 ? `${handle.slice(0, dot)}@${handle.slice(dot + 1)}` : undefined
}

export function createOwnIdentity(options: {
  vault: AccountVault
  handle: string
  seeds: GenerationSeeds
  /** Opens an invite Delta Chat gave; there is none until the mediator is connected. */
  joinInvite(): ((invite: string) => Promise<{ name: string; address: string }>) | undefined
}): OwnIdentity {
  const { vault, seeds } = options
  const address = mailAddressOfHandle(options.handle)
  const mail: OwnMail | undefined = address ? { address, pgp: ownPgp(address, seeds) } : undefined
  const ownCard = async () => contactCardForDid((await vault.snapshot()).contactCards, vault.identityId)
  const writeOwnCard = async (make: (cardId: string, card: LocalJmapContactCard | undefined) => ContactSetPayload | undefined) => {
    if (await vault.writeContact(vault.identityId, (cardId, card) => [make(cardId, card)])) await vault.refresh()
  }

  const profileCard: ProfileConfig = {
    async current() {
      const card = await ownCard()
      const name = card && contactDisplayName(card), avatar = card && contactAvatar(card)
      return { ...(name ? { name } : {}), ...(avatar ? { avatar } : {}) }
    },
    setName: name => writeOwnCard((cardId, card) => ownNamePatch(cardId, card, name)),
    setAvatar: avatar => writeOwnCard((cardId, card) => ownAvatarPatch(cardId, card, avatar)),
  }
  // A name belongs to an identity from the start: when none is on the own card -- after giving the other devices' Vault a few
  // seconds to bring theirs -- one is made at random and kept there; every device then reads the same one from the Vault.
  setTimeout(() => {
    void ownCard().then(async card => {
      if (card && contactDisplayName(card)) return
      await profileCard.setName(randomDisplayName())
      window.dispatchEvent(new Event(PROFILE_CHANGED))
    }).catch(error => console.warn('[own display name]', errorMessage(error)))
  }, 5000)

  // The picture goes to a contact when it has not got this one: tracked here, per contact, in this browser.
  const sentKey = `biset.profileSent.${vault.identityId}`
  const picturesSent = (): Record<string, string> => { try { return JSON.parse(localStorage.getItem(sentKey) ?? '{}') as Record<string, string> } catch { return {} } }

  return {
    mail,
    profileCard,
    pgpCard: mail && pgpCardOf(mail, seeds, ownCard, writeOwnCard, options.joinInvite),
    async profile() {
      const card = await ownCard()
      const name = card && contactDisplayName(card), avatar = card && contactAvatar(card)
      const base64 = avatar?.slice(avatar.indexOf(',') + 1)
      return { ...(name ? { name } : {}), ...(base64 ? { avatarBase64: base64, avatarHash: bytesToBase64url(sha256Bytes(new TextEncoder().encode(avatar!))).slice(0, 16) } : {}) }
    },
    takePictureFor(did, profile) {
      if (profile.avatarHash === undefined || picturesSent()[did] === profile.avatarHash) return false
      try { localStorage.setItem(sentKey, JSON.stringify({ ...picturesSent(), [did]: profile.avatarHash })) } catch { /* no storage: it is sent again next time */ }
      return true
    },
  }
}

function pgpCardOf(
  mail: OwnMail,
  seeds: GenerationSeeds,
  ownCard: () => Promise<LocalJmapContactCard | undefined>,
  writeOwnCard: (make: (cardId: string, card: LocalJmapContactCard | undefined) => ContactSetPayload | undefined) => Promise<void>,
  joinInvite: () => ((invite: string) => Promise<{ name: string; address: string }>) | undefined,
): PgpCardConfig {
  const { address, pgp } = mail
  // Writes the key the seed gives to this identity's own card, unless the card names it already; says whether it changed anything.
  const rememberOwnKey = async (): Promise<boolean> => {
    const key = await pgp.current()
    if (!key) return false
    const keydata = await autocryptKeydata(key.privateKey, address)
    const before = await ownCard().then(card => card && contactCryptoKey(card)?.fingerprint)
    await writeOwnCard((cardId, card) => ownCryptoKeyPatch(cardId, card, key.fingerprint, keydata))
    return before !== key.fingerprint
  }
  let ownKeyChecked = false
  return {
    address,
    // The key is remembered on this identity's own card (JSContact cryptoKeys): shown from there at once, and checked against
    // the one the seed gives in the background -- the seed comes only after the DID log has been read.
    async current() {
      const remembered = await ownCard().then(card => card && contactCryptoKey(card))
      if (remembered) {
        if (!ownKeyChecked) { ownKeyChecked = true; void rememberOwnKey().then(changed => { if (changed) window.dispatchEvent(new Event(PGP_KEY_CHANGED)) }).catch(() => { ownKeyChecked = false }) }
        return { fingerprint: remembered.fingerprint, userIds: [`<${address}>`] }
      }
      const key = await pgp.current()
      if (key) void rememberOwnKey().catch(() => undefined)
      return key && { fingerprint: key.fingerprint, userIds: key.userIds }
    },
    onCopyPublic: async () => {
      const key = await pgp.current()
      if (!key) throw new Error('There is no PGP key yet')
      return key.publicArmor
    },
    async inviteLink() {
      const [seed, key] = await Promise.all([seeds.current(), pgp.current()])
      if (!seed || !key) throw new Error('The key is not ready yet')
      return inviteUrl({ seed, key, address, now: Date.now() })
    },
    joinInvite: async invite => {
      const join = joinInvite()
      if (!join) throw new Error('Not connected yet')
      return join(invite)
    },
  }
}
