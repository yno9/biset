// The PGP key row of the identity card: the key this identity decrypts and signs mail with. It is derived from the
// generation seed (pgp/derive.ts), so there is nothing to make, bring or publish here; a new generation (a device was
// removed) is a new key. The card shows its fingerprint; clicking it turns it over to the public half, and copies that.
import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react'

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

/** Said when the key on show turned out to be another one than the card remembered (a new generation), so the row looks again. */
export const PGP_KEY_CHANGED = 'biset-pgp-key-changed'

const errorText = (error: unknown): string => error instanceof Error ? error.message : String(error)

export function PgpKeyRow({ config }: { config: PgpCardConfig }) {
  const [key, setKey] = useState<Key | 'loading'>('loading')

  const refresh = useCallback(async () => { setKey(await config.current().catch(() => undefined)) }, [config])
  useEffect(() => {
    void refresh()
    const again = () => { void refresh() }
    window.addEventListener(PGP_KEY_CHANGED, again)
    return () => window.removeEventListener(PGP_KEY_CHANGED, again)
  }, [refresh])
  // Right after a sign-in the page is up before the generation seed has been stored: look again until there is a key.
  useEffect(() => {
    if (key !== undefined) return
    let tries = 0
    const timer = setInterval(() => { if (++tries > 60) clearInterval(timer); else void refresh() }, 1500)
    return () => clearInterval(timer)
  }, [key, refresh])

  if (!key || key === 'loading') return null
  return (
    <div id="cmd-acc-pgp-row" className="acc-pgp-row" data-tip={`PGP key ${key.userIds.join(', ')}: click the card to see and copy the public key`}>
      <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="7.5" cy="15.5" r="4.5" /><path d="m10.7 12.3 9.8-9.8M16 7l3 3M14 9l2 2" /></svg>
      <span id="cmd-acc-pgp-fingerprint" className="acc-pgp-fingerprint">{key.fingerprint.replace(/(.{4})(?=.)/g, '$1 ')}</span>
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

/** The PGP Key card: the whole block is the click target. It turns over (a flip) between the fingerprint and the armored public key,
 * its height following the face that is turning up, and turning it to the key copies the key too. */
export function PgpKeyCard({ config, showMessage }: { config: PgpCardConfig | undefined; showMessage: (text: string) => void }) {
  const [flipped, setFlipped] = useState(false)
  const [pub, setPub] = useState<string>()
  // The faces are laid over each other (absolute), so the card's height is not theirs: it is each face's own, measured, and the card
  // takes the height of the face that is up (transitioning, which is what makes it grow and shrink as it turns).
  const front = useRef<HTMLDivElement>(null)
  const back = useRef<HTMLDivElement>(null)
  const [heights, setHeights] = useState<{ front: number; back: number }>()
  useLayoutEffect(() => {
    if (!front.current || !back.current) return
    const measure = () => setHeights({ front: front.current!.offsetHeight, back: back.current!.offsetHeight })
    measure()
    const observer = new ResizeObserver(measure)
    observer.observe(front.current); observer.observe(back.current)
    return () => observer.disconnect()
  }, [config])
  if (!config) return (
    <div className="acc-card-wrap acc-key-card" id="cmd-acc-pgp-key-card">
      <div className="acc-storage-header"><span className="acc-storage-title">PGP Key</span></div>
      <div className="acc-device-empty">No key available</div>
    </div>
  )
  const toggle = () => {
    if (flipped) { setFlipped(false); return }
    setFlipped(true)
    void config.onCopyPublic().then(async text => {
      setPub(text)
      await navigator.clipboard.writeText(text)
      showMessage('Public key copied')
    }).catch(error => showMessage(errorText(error)))
  }
  return (
    <div className="acc-flip-card" id="cmd-acc-pgp-key-card" role="button" tabIndex={0} aria-pressed={flipped}
      onClick={toggle} onKeyDown={event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); toggle() } }}>
      <div className={flipped ? 'acc-flip flipped' : 'acc-flip'} style={heights ? { height: flipped ? heights.back : heights.front } : undefined}>
        <div ref={front} className="acc-flip-face acc-key-card">
          <div className="acc-storage-header"><span className="acc-storage-title">PGP Key</span></div>
          <PgpKeyRow config={config} />
        </div>
        <div ref={back} className="acc-flip-face acc-flip-back acc-key-card" aria-hidden={!flipped}>
          {/* The blank line after the header is left out of what is shown (the copy keeps the key as it is). */}
          <pre className="acc-pgp-armor">{pub ? pub.split('\n').filter(line => line.trim()).join('\n') : '…'}</pre>
        </div>
      </div>
    </div>
  )
}
