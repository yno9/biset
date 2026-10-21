// The PGP key row of the identity card: the key this identity decrypts and signs mail with. It is derived from the
// generation seed (pgp/derive.ts), so there is nothing to make, bring or publish here; a new generation (a device was
// removed) is a new key. The row shows its fingerprint; clicking it copies the public half.
import { useCallback, useEffect, useState } from 'react'

export interface PgpCardConfig {
  /** The user's own mail address, whose key this is. */
  address: string
  /** The key in use, or undefined while there is no usable generation seed (yet). */
  current(): Promise<{ fingerprint: string; userIds: string[] } | undefined>
  /** The armored public key, to copy. */
  onCopyPublic(): Promise<string>
  /** The link that makes this identity a contact in Delta Chat when it is opened there (Secure-Join; valid for a month). */
  inviteLink(): Promise<string>
  /** Opens an invite Delta Chat gave (its link, or the text of its QR code): asks that contact for its key. */
  joinInvite(invite: string): Promise<{ name: string; address: string }>
}

type Key = Awaited<ReturnType<PgpCardConfig['current']>>

const errorText = (error: unknown): string => error instanceof Error ? error.message : String(error)

export function PgpKeyRow({ config, showMessage }: { config: PgpCardConfig; showMessage: (text: string) => void }) {
  const [key, setKey] = useState<Key | 'loading'>('loading')

  const refresh = useCallback(async () => { setKey(await config.current().catch(() => undefined)) }, [config])
  useEffect(() => { void refresh() }, [refresh])
  // Right after a sign-in the page is up before the generation seed has been stored: look again until there is a key.
  useEffect(() => {
    if (key !== undefined) return
    let tries = 0
    const timer = setInterval(() => { if (++tries > 60) clearInterval(timer); else void refresh() }, 1500)
    return () => clearInterval(timer)
  }, [key, refresh])

  if (!key || key === 'loading') return null
  return (
    <div id="cmd-acc-pgp-row" title={`PGP key ${key.userIds.join(', ')}: click to copy the public key`}
      onClick={event => { event.stopPropagation(); void config.onCopyPublic().then(text => navigator.clipboard.writeText(text)).then(() => showMessage('Public key copied'), error => showMessage(errorText(error))) }}>
      <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="7.5" cy="15.5" r="4.5" /><path d="m10.7 12.3 9.8-9.8M16 7l3 3M14 9l2 2" /></svg>
      <span id="cmd-acc-pgp-fingerprint">{key.fingerprint.replace(/(.{4})(?=.)/g, '$1 ')}</span>
    </div>
  )
}

/** Copies the Delta Chat invite link (the identity menu's entry). */
export function copyInviteLink(config: PgpCardConfig, showMessage: (text: string) => void): void {
  void config.inviteLink().then(text => navigator.clipboard.writeText(text)).then(() => showMessage('Delta Chat invite link copied: open it in Delta Chat to become contacts'), error => showMessage(errorText(error)))
}

/** Asks for a Delta Chat invite (the identity menu's entry) and starts the Secure-Join with it. */
export function joinDeltaChatInvite(config: PgpCardConfig, showMessage: (text: string) => void): void {
  const invite = window.prompt('Paste the Delta Chat invite link (or the text of its QR code)')?.trim()
  if (!invite) return
  void config.joinInvite(invite).then(({ name, address }) => showMessage(`Asked ${name} <${address}> for their key: the contact is verified when they answer`), error => showMessage(errorText(error)))
}
