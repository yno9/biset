// What the rest of the app calls to drive the mail UI: show it, and refresh what it lists.
import type { LocalJmapEmail, LocalJmapReadModel, LocalJmapSnapshot } from '../../store/projection/gateway.ts'
import type { OpenedMail } from '../../pgp/open.ts'
import { emailToMessageView } from './message/message-view.ts'
import type { ProcessedMessage } from './message/message-view.ts'
import { isNarrow, mail, patchShell } from './stores.ts'

export { showSysMsg } from './sys-msg.tsx'

let shown = false

/** Opens a stored encrypted mail (pgp/open.ts) with this identity's key; set once the key store is up. */
type EncryptedMailOpener = (rawBody: string, email: LocalJmapEmail, snapshot: LocalJmapSnapshot) => Promise<OpenedMail | undefined>
let openEncrypted: EncryptedMailOpener | undefined
export function setEncryptedMailOpener(opener: EncryptedMailOpener | undefined): void { openEncrypted = opener }

/** Shows the mail UI (an identity is signed in and its vault is open). The left pane starts open or
 * collapsed as the user left it, on a wide screen. */
export function showApp(): void {
  if (!shown) {
    shown = true
    try { patchShell({ singleCol: !isNarrow() && localStorage.getItem('lp-open') !== '1' }) } catch { /* private browsing */ }
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
    const views: ProcessedMessage[] = []
    for (const email of snapshot.emails) {
      if (!email.blobId) continue
      const raw = await readModel.download(email.blobId)
      const opened = openEncrypted ? await openEncrypted(new TextDecoder().decode(raw), email, snapshot) : undefined
      const msg = emailToMessageView(email, opened?.raw ?? raw)
      // The outer subject of an encrypted mail is a stand-in; the real one is inside.
      if (opened?.subject) msg.subject = opened.subject
      if (opened) msg.encrypted = { signed: opened.signature !== undefined, verified: opened.signature?.verified === true }
      views.push({ msg, bodyText: msg.body })
    }
    mail.set({ messages: views })
  })
  // A rejected refresh stays observable to its caller without poisoning the queue for the next one.
  refreshTail = task.catch(() => {})
  return task
}
