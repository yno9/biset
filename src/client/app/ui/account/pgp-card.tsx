// The account page's PGP key card: the key this identity decrypts and signs mail with. It is derived from the
// generation seed (pgp/derive.ts), so there is nothing to make, bring or publish here; a new generation (a device was
// removed) is a new key. The card shows its fingerprint and copies its public half.
import { useCallback, useEffect, useState } from 'react'

export interface PgpCardConfig {
  /** The user's own mail address, whose key this is. */
  address: string
  /** The key in use, or undefined while there is no usable generation seed (yet). */
  current(): Promise<{ fingerprint: string; userIds: string[] } | undefined>
  /** The armored public key, to copy. */
  onCopyPublic(): Promise<string>
}

type Key = Awaited<ReturnType<PgpCardConfig['current']>>

const errorText = (error: unknown): string => error instanceof Error ? error.message : String(error)

export function PgpCard({ config, showMessage }: { config: PgpCardConfig; showMessage: (text: string) => void }) {
  const [key, setKey] = useState<Key | 'loading'>('loading')

  const refresh = useCallback(async () => { setKey(await config.current().catch(() => undefined)) }, [config])
  useEffect(() => { void refresh() }, [refresh])

  return (
    <div className="acc-card-wrap" id="cmd-acc-pgp-card">
      <div className="cmd-page-row" style={{ gap: 12, alignItems: 'center', padding: '10px 12px', flexWrap: 'wrap' }}>
        <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', gap: 4 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
            <span style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.04em', color: 'var(--accent2, #888)', flexShrink: 0 }}>PGP key</span>
            <span style={{ color: 'var(--text-dim)', flexShrink: 0 }}>:</span>
            <span style={{ fontSize: 13, fontWeight: 600, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
              {key === 'loading' ? '…' : key ? key.fingerprint.replace(/(.{4})(?=.)/g, '$1 ') : 'waiting'}
            </span>
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-dim)', wordBreak: 'break-all' }}>
            {key === 'loading' ? '' : key
              ? `${key.userIds.join(', ')}. Derived from this account's generation; a new generation (a device was removed) is a new key.`
              : `The key of ${config.address} follows from the account's generation seed, which this device does not have yet.`}
          </div>
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
          {key && key !== 'loading' ? (
            <button type="button" className="acc-pgp-btn"
              onClick={event => { event.stopPropagation(); void config.onCopyPublic().then(text => navigator.clipboard.writeText(text)).then(() => showMessage('Public key copied'), error => showMessage(errorText(error))) }}>
              Copy public key
            </button>
          ) : null}
        </div>
      </div>
    </div>
  )
}
