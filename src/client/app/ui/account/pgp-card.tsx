// The account page's PGP key card: the key this identity decrypts and signs
// mail with (the secret half stays in the Vault; only the public half is ever
// published, at the mail bridge, where WKD serves it). Everything the card
// does is a callback main.ts supplies.
import { useCallback, useEffect, useRef, useState } from 'react'

export interface PgpCardConfig {
  /** The user's own mail address, whose key this is. */
  address: string
  /** The key in use, or undefined when there is none. */
  current(): Promise<{ fingerprint: string; userIds: string[]; namesAddress: boolean } | undefined>
  onGenerate(): Promise<void>
  /** `key` is the armored (or text-encoded) secret key; throws "protected by a passphrase" when it needs one. */
  onImport(key: string, passphrase?: string): Promise<void>
  onPublish(): Promise<void>
  onWithdraw(): Promise<void>
  /** The armored public key, to copy. */
  onCopyPublic(): Promise<string>
}

type Key = Awaited<ReturnType<PgpCardConfig['current']>>

const errorText = (error: unknown): string => error instanceof Error ? error.message : String(error)

export function PgpCard({ config, showMessage }: { config: PgpCardConfig; showMessage: (text: string) => void }) {
  const [key, setKey] = useState<Key | 'loading'>('loading')
  const [busy, setBusy] = useState(false)
  const file = useRef<HTMLInputElement>(null)

  const refresh = useCallback(async () => { setKey(await config.current().catch(() => undefined)) }, [config])
  useEffect(() => { void refresh() }, [refresh])

  const run = (work: () => Promise<void>) => {
    if (busy) return
    setBusy(true)
    void work().catch(error => showMessage(errorText(error))).finally(() => { setBusy(false); void refresh() })
  }

  const importText = async (text: string): Promise<void> => {
    try {
      await config.onImport(text)
    } catch (error) {
      if (!(error instanceof Error) || !error.message.includes('protected by a passphrase')) throw error
      const passphrase = prompt('Passphrase of this key (it is not kept; the key is stored without it, in your encrypted Vault):')
      if (passphrase === null) return
      await config.onImport(text, passphrase)
    }
    showMessage('PGP key imported')
  }

  const button = (label: string, work: () => Promise<void>, danger = false) => (
    <button type="button" className="acc-pgp-btn" data-danger={danger ? 'true' : undefined} disabled={busy}
      onClick={event => { event.stopPropagation(); run(work) }}>{label}</button>
  )
  const generate = async () => { await config.onGenerate(); showMessage('PGP key generated') }
  const chooseFile = async () => { file.current?.click() }

  return (
    <div className="acc-card-wrap" id="cmd-acc-pgp-card">
      <div className="cmd-page-row" style={{ gap: 12, alignItems: 'center', padding: '10px 12px', flexWrap: 'wrap' }}>
        <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', gap: 4 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
            <span style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.04em', color: 'var(--accent2, #888)', flexShrink: 0 }}>PGP key</span>
            <span style={{ color: 'var(--text-dim)', flexShrink: 0 }}>:</span>
            <span style={{ fontSize: 13, fontWeight: 600, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
              {key === 'loading' ? '…' : key ? key.fingerprint.replace(/(.{4})(?=.)/g, '$1 ') : 'none'}
            </span>
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-dim)', wordBreak: 'break-all' }}>
            {key === 'loading' ? '' : key
              ? (key.namesAddress ? key.userIds.join(', ') : `Its user IDs (${key.userIds.join(', ') || 'none'}) do not name ${config.address}: other people's programs may not use the key published for it.`)
              : `Make a key for ${config.address}, or bring the one you have. Encrypted mail to you is decrypted on this device.`}
          </div>
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
          {key === 'loading' ? null : key ? (
            <>
              {button('Publish', async () => { await config.onPublish(); showMessage(`Public key published for ${config.address}`) })}
              {button('Withdraw', async () => { await config.onWithdraw(); showMessage('Public key withdrawn') })}
              {button('Copy public key', async () => { await navigator.clipboard.writeText(await config.onCopyPublic()); showMessage('Public key copied') })}
              {button('Replace…', chooseFile)}
              {button('New key', async () => {
                if (!confirm('Make a new key? Mail encrypted to the old one can still be read, but people must get the new public key to write to you.')) return
                await generate()
              }, true)}
            </>
          ) : (
            <>
              {button('Generate', generate)}
              {button('Import…', chooseFile)}
            </>
          )}
        </div>
      </div>
      <input ref={file} type="file" accept=".asc,.gpg,.pgp,.key,.txt" style={{ display: 'none' }}
        onChange={event => {
          const chosen = event.target.files?.[0]
          event.target.value = ''
          if (!chosen) return
          run(async () => { await importText(await chosen.text()) })
        }} />
    </div>
  )
}
