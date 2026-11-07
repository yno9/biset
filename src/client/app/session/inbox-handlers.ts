// What the inbox asks of the session as it shows messages.
import { openStoredMail } from '../../pgp/open.ts'
import { contactAvatarPatch, contactCardForDid, contactNamePatch, currentAutocryptKey } from '../../store/projection/contacts.ts'
import { base64ToBytes } from '../../../protocol/base64.ts'
import { errorMessage } from '../../../protocol/error-message.ts'
import { markSeenDone, setMarkSeenHandler } from '../ui/seen.ts'
import { setEncryptedMailOpener, setSignedNameHandler } from '../ui/shell.ts'
import type { AccountVault } from './account-vault.ts'
import type { OwnMail } from './own-identity.ts'

export function installInboxHandlers(vault: AccountVault, mail: OwnMail | undefined): void {
  // A thread that has been open is read: its messages get the $seen keyword (the store keeps it; other devices see it too).
  setMarkSeenHandler(messages => {
    const ids = messages.map(message => message.jmap_id)
    void (async () => {
      const snapshot = await vault.snapshot()
      const update: Record<string, unknown> = {}
      for (const email of snapshot.emails) if (ids.includes(email.id) && email.keywords['$seen'] !== true) update[email.id] = { keywords: { ...email.keywords, $seen: true } }
      if (Object.keys(update).length === 0) return
      await vault.mutationSink.emailSet({ accountId: vault.accountId, update }, snapshot)
      await vault.refresh()
    })().catch(error => console.warn('[mark read]', errorMessage(error))).finally(() => markSeenDone(ids))
  })
  // Delta Chat shares its profile in what it signs: the name on a message from a key we hold is the sender's own, and follows
  // it when it changes. The newest message's name is kept on the contact card (a card of its own is made if there is none).
  setSignedNameHandler((did, profile) => {
    void vault.writeContact(did, (cardId, card) => [
      profile.name ? contactNamePatch(cardId, card, profile.name, 'signed') : undefined,
      profile.avatar !== undefined ? contactAvatarPatch(cardId, card, profile.avatar) : undefined,
    ]).then(async written => { if (written) await vault.refresh() })
      .catch(error => console.warn('[contact name]', errorMessage(error)))
  })
  // An encrypted mail is opened where it is shown, with this identity's keys and the key held for its sender.
  setEncryptedMailOpener(async (rawBody, email, snapshot) => {
    const card = contactCardForDid(snapshot.contactCards, email.from?.[0]?.email ?? '')
    const held = card && currentAutocryptKey(card)
    return openStoredMail(rawBody, { privateKeys: (await mail?.pgp.all() ?? []).map(key => key.privateKey), senderKeys: held ? [base64ToBytes(held.keydata)] : [] })
  })
}
