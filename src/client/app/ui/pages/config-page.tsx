// Biset's own configuration. DID controller key material and pre-rotation belong to the did.md
// Wallet that owns the Master mnemonic, so none of it is represented here.
import { useState } from 'react'
import { usePageChrome } from './page-chrome.ts'

interface MarkdownVault { enabled(): boolean; observerSupported(): boolean; toggle(): Promise<void>; rescan(): Promise<void> }
let markdownVault: MarkdownVault | undefined
export function configureMarkdownVaultToggle(value: MarkdownVault): void { markdownVault = value }

function VaultRow({ vault }: { vault: MarkdownVault | undefined }) {
  const [enabled, setEnabled] = useState(vault?.enabled() ?? false)
  return (
    <div className="cmd-page-row">
      <span>Vault</span>
      <div className={`toggle-switch${enabled ? ' on' : ''}`} id="config-vault-toggle" style={{ cursor: 'pointer' }}
        onClick={() => { if (vault) void vault.toggle().then(() => setEnabled(vault.enabled())) }} />
      {/* Without a file-system observer the vault is rescanned by hand. */}
      {vault && enabled && !vault.observerSupported() ? <button id="config-vault-rescan" className="cmd-page-btn" onClick={() => { void vault.rescan() }}>Rescan Vault</button> : null}
    </div>
  )
}

export function ConfigPage() {
  usePageChrome('config')
  return (
    <div id="active-thread">
      <div className="cmd-thread-card" id="focused-thread-card">
        <div className="cmd-page-content wide-page">
          <div className="cmd-page-section">
            <h3>Notifications</h3>
            <div className="cmd-page-row">
              <span>Push notifications</span>
              <div className="toggle-switch" id="config-notif-toggle" style={{ cursor: 'pointer' }} />
            </div>
          </div>
          {'showDirectoryPicker' in window ? (
            <div className="cmd-page-section">
              <h3>Vault (Markdown)</h3>
              <VaultRow vault={markdownVault} />
            </div>
          ) : null}
          <button id="cmd-acc-fab" type="button"><span className="acc-new-account-plus">+</span>New Relay</button>
          <div id="cmd-acc-panel-backdrop" />
        </div>
      </div>
    </div>
  )
}
