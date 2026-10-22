// What sits under the identity card on the account page: the mediator and a notice when the DIDComm key needs
// a Wallet approval (the Services tab), and the keys: this identity's devices, and its PGP key (the Keys tab).
import { useRef, useState } from 'react'
import { useStore } from '../../react/store.ts'
import { openDropdownMenu, type MenuItem } from './menu.tsx'
import { PgpKeyRow } from './pgp-card.tsx'
import { accountConfig, type AccountPageConfig } from './state.ts'

type Wallet = NonNullable<AccountPageConfig['wallet']>
type DidComm = NonNullable<Wallet['didComm']>
type Device = NonNullable<NonNullable<AccountPageConfig['vault']>['devices']>[number]

const errorText = (error: unknown): string => error instanceof Error ? error.message : String(error)

function coordinatorHost(url: string): string {
  try { return new URL(url).host } catch { return url }
}

export function AccountList() {
  const config = useStore(accountConfig)
  const wallet = config?.wallet
  if (!config || !wallet?.didComm) return null
  const showMessage = (text: string) => config.showMessage?.(text)
  return (
    <>
      <MediatorCard config={config} wallet={wallet} didComm={wallet.didComm} showMessage={showMessage} />
      {config.rotationKey ? <DidCommKeyNotice rotationKey={config.rotationKey} showMessage={showMessage} /> : null}
    </>
  )
}

function MediatorCard({ config, wallet, didComm, showMessage }: { config: AccountPageConfig; wallet: Wallet; didComm: DidComm; showMessage: (text: string) => void }) {
  const menuButton = useRef<HTMLButtonElement>(null)
  const loggedOut = didComm.loggedOut === true
  const report = (error: unknown) => showMessage(errorText(error))

  const menuItems = (): MenuItem[] => loggedOut ? [
    { label: 'Log in', onClick: () => { void wallet.onEnableMessaging?.().catch(report) } },
  ] : [
    {
      label: 'Edit server', onClick: () => {
        const url = window.prompt('DIDComm mediator URL', didComm.mediatorUrl)
        // The same URL republishes the endpoint as configured now; no change of URL needed.
        if (!url) return
        void wallet.onEditMediator?.(url).catch(report)
      },
    },
    {
      label: 'Enable Tor', onClick: () => {
        const onionUrl = window.prompt('DIDComm mediator Onion URL', didComm.onionUrl ?? '')?.trim()
        if (!onionUrl) return
        void wallet.onEnableTor?.(onionUrl).catch(report)
      },
    },
    {
      label: 'Log out', danger: true, onClick: () => {
        if (!confirm(`Unregister this browser from ${coordinatorHost(didComm.mediatorUrl)}? DIDComm messages will stop delivering here until you register again.`)) return
        void wallet.onLogOutMediator?.().catch(report)
      },
    },
  ]

  const status = didComm.error ? `Needs attention: ${didComm.error}` : loggedOut ? 'Logged out' : didComm.connecting ? 'Connecting…' : ''
  const dotColor = didComm.error ? '#ff3b30' : loggedOut ? '#8e8e93' : didComm.connecting ? '#ff9f0a' : '#34c759'

  return (
    <div className="acc-card-wrap" id="cmd-acc-mediator-card">
      <div className="cmd-page-row" style={{ gap: 12, alignItems: 'center', padding: '10px 12px' }}>
        <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', gap: 4 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', flexShrink: 0, background: dotColor }} />
            <span style={{ fontSize: 12, fontWeight: 700, letterSpacing: '0.04em', color: 'var(--accent2, #888)', flexShrink: 0 }}>Mediator</span>
            <span style={{ color: 'var(--text-dim)', flexShrink: 0 }}>:</span>
            <span style={{ fontSize: 14.5, fontWeight: 600, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{coordinatorHost(didComm.mediatorUrl)}</span>
            {/* The dot says "registered"; the line only says it when something else is the case. */}
            {status ? <span style={{ fontSize: 12, flexShrink: 1, minWidth: 0, color: didComm.error ? '#ff3b30' : 'var(--text-dim)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{status}</span> : null}
          </div>
        </div>
        {/* Same "⋮" affordance as the identity heading's own menu button. */}
        <button ref={menuButton} type="button" aria-label="Mediator menu"
          style={{ flexShrink: 0, background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-dim)', padding: 4 }}
          onClick={event => { event.stopPropagation(); openDropdownMenu(menuButton.current!, menuItems()) }}>
          <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><circle cx="12" cy="5" r="1.5" /><circle cx="12" cy="12" r="1.5" /><circle cx="12" cy="19" r="1.5" /></svg>
        </button>
      </div>
    </div>
  )
}

/** The Keys tab: the devices that hold this identity's DIDComm key, and its PGP key. */
export function KeysPanel() {
  const config = useStore(accountConfig)
  if (!config) return null
  const showMessage = (text: string) => config.showMessage?.(text)
  return (
    <div id="cmd-acc-keys">
      <DeviceKeyCard config={config} showMessage={showMessage} />
      <div className="acc-card-wrap acc-key-card" id="cmd-acc-pgp-key-card">
        <div className="acc-storage-header"><span className="acc-storage-title">PGP Key</span></div>
        {config.pgp ? <PgpKeyRow config={config.pgp} showMessage={showMessage} /> : <div className="acc-device-empty">No key available</div>}
      </div>
    </div>
  )
}

function DeviceKeyCard({ config, showMessage }: { config: AccountPageConfig; showMessage: (text: string) => void }) {
  const [removing, setRemoving] = useState(false)
  const [previewRemoval, setPreviewRemoval] = useState(false)
  const report = (error: unknown) => showMessage(errorText(error))
  const removeOtherDevices = () => {
    if (removing || !config.onRemoveOtherDevices) return
    if (!confirm('Remove all other devices? They will need to sign in again. Content they already received cannot be revoked.')) return
    setRemoving(true)
    config.onRemoveOtherDevices()
      .then(() => showMessage('Other devices removed'))
      .catch(error => { setRemoving(false); report(error) })
  }

  const roster = [...(config.vault?.devices ?? [])].sort((a, b) => Number(b.current) - Number(a.current))
  return (
    <div className="acc-card-wrap acc-key-card" id="cmd-acc-device-key-card">
      <div className="acc-storage-header"><span className="acc-storage-title">Device Key</span></div>
      <div className={`acc-device-list${previewRemoval ? ' remove-preview' : ''}`} onPointerLeave={() => setPreviewRemoval(false)}
        onPointerOver={event => setPreviewRemoval(event.target instanceof Element && Boolean(event.target.closest('.acc-device-removable')))}>
        {roster.length ? roster.map(device => (
          <DeviceRow key={device.deviceId} device={device} removable={!device.current && Boolean(config.onRemoveOtherDevices)} disabled={removing} onRemove={removeOtherDevices} />
        )) : <div className="acc-device-empty">No devices available</div>}
      </div>
    </div>
  )
}

function DeviceRow({ device, removable, disabled, onRemove }: { device: Device; removable: boolean; disabled: boolean; onRemove: () => void }) {
  const fragment = device.deviceId.includes('#') ? device.deviceId.slice(device.deviceId.indexOf('#')) : device.deviceId
  const content = (
    <>
      <span className="acc-device-label" title={device.deviceId}>{fragment.length > 18 ? `${fragment.slice(0, 10)}…` : fragment}</span>
      {device.lastActivity ? <span className="acc-device-activity">{new Date(device.lastActivity).toLocaleString()}</span> : null}
      {device.current ? <span className="acc-device-current">this device</span> : removable ? (
        <span className="acc-device-trash" aria-hidden="true">
          <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2"><path d="M3 6h18" /><path d="M8 6V4h8v2" /><path d="m19 6-1 14H6L5 6" /><path d="M10 11v5" /><path d="M14 11v5" /></svg>
        </span>
      ) : null}
    </>
  )
  return removable
    ? <button type="button" className="acc-device-row acc-device-removable" disabled={disabled} aria-label={`Remove other devices, including ${device.deviceId}`} onClick={onRemove}>{content}</button>
    : <div className="acc-device-row">{content}</div>
}

/** Why, in the user's words (the states are generation-seed-bootstrap.ts's). */
const DIDCOMM_KEY_REASON = {
  unpublished: 'Your account has no DIDComm key yet. It lets your devices keep a conversation private.',
  lost: 'None of your devices has it any more.',
  stale: 'A device you removed may still have it.',
} as const

/** The system message card for the DIDComm key (generation-seed-bootstrap.ts): "Your DIDComm key
 * needs to be renewed", the link starting the one Wallet approval that publishes a fresh one. It
 * stays until the key is in order. */
function DidCommKeyNotice({ rotationKey, showMessage }: { rotationKey: NonNullable<AccountPageConfig['rotationKey']>; showMessage: (text: string) => void }) {
  const [renewing, setRenewing] = useState(false)
  return (
    <div className="acc-notice" id="cmd-acc-didcomm-key-notice" role="status">
      <span className="acc-notice-dot" />
      <div className="acc-notice-body">
        <div className="acc-notice-title">
          Your DIDComm key needs to be{' '}
          <a className="acc-notice-link" href="#renew-didcomm-key" aria-disabled={renewing ? 'true' : undefined}
            onClick={event => {
              event.preventDefault()
              if (renewing) return
              setRenewing(true)
              rotationKey.onRenew().catch(error => { setRenewing(false); showMessage(errorText(error)) })
            }}>renewed</a>.
        </div>
        <div className="acc-notice-detail">{DIDCOMM_KEY_REASON[rotationKey.state]}</div>
      </div>
    </div>
  )
}
