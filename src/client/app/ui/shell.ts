// What the rest of the app calls to drive the mail UI: show it, and refresh what it lists.
import type { LocalJmapEmail, LocalJmapReadModel, LocalJmapSnapshot } from '../../store/projection/gateway.ts'
import { contactAvatar, contactDisplayName, publicDidOf } from '../../store/projection/contacts.ts'
import { setContactAvatars, setContactDids, setContactNames, setVerifiedAddresses } from './did-display.ts'
import { rememberVhLocation } from '../../../protocol/did-resolve.ts'
import { hostOfAddress } from '../../didcomm/address-resolver.ts'
import { identityKey, vhScidOf } from '../../../protocol/vh/identifier.ts'
import type { OpenedMail } from '../../pgp/open.ts'
import { armorOfStoredBody } from '../../pgp/stored.ts'
import { emailToMessageView } from './message/message-view.ts'
import type { ProcessedMessage } from './message/message-view.ts'
import { isNarrow, mail, patchShell } from './stores.ts'

export { showSysMsg } from './sys-msg.tsx'

let shown = false

/** Opens a stored encrypted mail (pgp/open.ts) with this identity's key; set once the key store is up. */
type EncryptedMailOpener = (rawBody: string, email: LocalJmapEmail, snapshot: LocalJmapSnapshot) => Promise<OpenedMail | undefined>
let openEncrypted: EncryptedMailOpener | undefined
export function setEncryptedMailOpener(opener: EncryptedMailOpener | undefined): void { openEncrypted = opener }

/** Told the name a sender signs its mail with (its newest mail's), to keep on its contact card. It is called on every refresh; keeping
 * the same name again changes nothing, so it settles. */
type SignedProfile = { name?: string; avatar?: string | null }
type SignedNameHandler = (did: string, profile: SignedProfile) => void
let onSignedName: SignedNameHandler | undefined
export function setSignedNameHandler(handler: SignedNameHandler | undefined): void { onSignedName = handler }

/** Shows the mail UI (an identity is signed in and its vault is open). The left pane starts open or
 * collapsed as the user left it, on a wide screen. */
export function showApp(): void {
  if (!shown) {
    shown = true
    try { patchShell({ singleCol: !isNarrow() && localStorage.getItem('lp-open') !== '1', paneCompact: localStorage.getItem('lp-compact') === '1' }) } catch { /* private browsing */ }
  }
  patchShell({ appShown: true })
}

// A Wallet session can receive a live DIDComm delivery while its MIMI Vault sync or an outgoing
// message is refreshing the same projection. Letting those reads overlap permits an older snapshot
// to land after a newer one, so they run one after another.
let refreshTail: Promise<void> = Promise.resolve()

/** Replaces the messages shown from a fresh snapshot of the read model. Every locally-committed
 * message is shown regardless of mailbox: there is no folder/trash/spam concept yet, and a sent
 * reply lives in outbox then sent, never inbox, so filtering to inbox would make it vanish. */
export function refreshInbox(readModel: LocalJmapReadModel): Promise<void> {
  const task = refreshTail.then(async () => {
    const snapshot = await readModel.snapshot()
    // The contact list's names, for everything below that names a person.
    const names = new Map<string, string>()
    const dids = new Map<string, string>()
    for (const card of snapshot.contactCards) {
      const did = publicDidOf(card), name = contactDisplayName(card)
      if (did) dids.set(identityKey(did), did)
      if (did && name) { names.set(did, name); names.set(identityKey(did), name) }
    }
    // A did:vh has no host in it: the address on its card (written only once verified, ingress-projector) is what it goes by.
    const addresses = new Map<string, string>()
    for (const card of snapshot.contactCards) {
      const did = publicDidOf(card)
      if (!did || !vhScidOf(did) || typeof card.emails !== 'object' || card.emails === null) continue
      const address = Object.values(card.emails as Record<string, unknown>).map(email => (email as { address?: unknown } | null)?.address).find((value): value is string => typeof value === 'string')
      if (address) { addresses.set(identityKey(did), address); rememberVhLocation(did, hostOfAddress(address)) }
    }
    setVerifiedAddresses(addresses)
    setContactNames(names)
    setContactDids(dids)
    const avatars = new Map<string, string>()
    for (const card of snapshot.contactCards) {
      const did = publicDidOf(card), picture = contactAvatar(card)
      if (did && picture) { avatars.set(did, picture); avatars.set(identityKey(did), picture) }
    }
    setContactAvatars(avatars)
    const views: ProcessedMessage[] = []
    const signedNames = new Map<string, { ts: number; name: string }>()
    const signedAvatars = new Map<string, { ts: number; avatar: string | null }>()
    for (const email of snapshot.emails) {
      if (!email.blobId) continue
      const raw = await readModel.download(email.blobId)
      const body = new TextDecoder().decode(raw)
      const opened = openEncrypted ? await openEncrypted(body, email, snapshot) : undefined
      // An encrypted mail this identity cannot open (a Secure-Join step that came after its join, mail for a key we do not hold) is not
      // shown: its stand-in subject `[...]` and the armor say nothing to read.
      if (openEncrypted && !opened && armorOfStoredBody(body)) { console.warn(`[encrypted mail] not shown, cannot be opened with this identity's keys: ${email.id}`); continue }
      const msg = emailToMessageView(email, opened?.raw ?? raw)
      // A name in the contact list is the one to show (the mail's own From: name is only where there is none).
      const known = names.get(msg.from)
      if (known) msg.from_name = known
      // The outer subject of an encrypted mail is a stand-in; the real one is inside.
      if (opened?.hidden) continue
      if (opened?.fromName && msg.from.startsWith('did:') && msg.ts >= (signedNames.get(msg.from)?.ts ?? 0)) signedNames.set(msg.from, { ts: msg.ts, name: opened.fromName })
      if (opened?.avatar !== undefined && msg.from.startsWith('did:') && msg.ts >= (signedAvatars.get(msg.from)?.ts ?? 0)) signedAvatars.set(msg.from, { ts: msg.ts, avatar: opened.avatar })
      if (opened?.subject) msg.subject = opened.subject
      // ... and so is its time: the outer Date of an encrypted mail is made up.
      if (opened?.sentAt !== undefined) msg.ts = opened.sentAt
      if (opened) msg.encrypted = { signed: opened.signature !== undefined, verified: opened.signature?.verified === true }
      views.push({ msg, bodyText: msg.body })
    }
    mail.set({ messages: views })
    // Only a sender's newest name counts: an older message carries the name it had then.
    if (onSignedName) for (const did of new Set([...signedNames.keys(), ...signedAvatars.keys()])) {
      const name = signedNames.get(did)?.name, avatar = signedAvatars.get(did)
      onSignedName(did, { ...(name ? { name } : {}), ...(avatar ? { avatar: avatar.avatar } : {}) })
    }
  })
  // A rejected refresh stays observable to its caller without poisoning the queue for the next one.
  refreshTail = task.catch(() => {})
  return task
}
