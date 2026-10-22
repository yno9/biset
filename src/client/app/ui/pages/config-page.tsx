// Biset's own configuration. DID controller key material and pre-rotation belong to the did.md
// Wallet that owns the Master mnemonic, so none of it is represented here.
import { useState } from 'react'

interface MarkdownVault { enabled(): boolean; observerSupported(): boolean; toggle(): Promise<void>; rescan(): Promise<void> }
let markdownVault: MarkdownVault | undefined
export function configureMarkdownVaultToggle(value: MarkdownVault): void { markdownVault = value }

function VaultRow({ vault }: { vault: MarkdownVault | undefined }) {
  const [enabled, setEnabled] = useState(vault?.enabled() ?? false)
  return (
    <div className="acc-card-wrap" id="cmd-acc-vault-card">
      <div className="cmd-page-row" style={{ gap: 12, alignItems: 'center', padding: '10px 12px' }}>
        <span className="acc-config-title">Vault (Markdown)</span>
        {/* Without a file-system observer the vault is rescanned by hand. */}
        {vault && enabled && !vault.observerSupported() ? <button id="config-vault-rescan" className="cmd-page-btn" onClick={() => { void vault.rescan() }}>Rescan Vault</button> : null}
        <div className={`toggle-switch${enabled ? ' on' : ''}`} id="config-vault-toggle" style={{ cursor: 'pointer' }}
          onClick={() => { if (vault) void vault.toggle().then(() => setEnabled(vault.enabled())) }} />
      </div>
    </div>
  )
}

/** The Config tab of the account page. */
export function ConfigPanel() {
  return (
    <div id="cmd-acc-config">
      <div className="acc-card-wrap" id="cmd-acc-notifications-card">
        <div className="cmd-page-row" style={{ gap: 12, alignItems: 'center', padding: '10px 12px' }}>
          <span className="acc-config-title">Push notifications</span>
          <div className="toggle-switch" id="config-notif-toggle" style={{ cursor: 'pointer' }} />
        </div>
      </div>
      {'showDirectoryPicker' in window ? <VaultRow vault={markdownVault} /> : null}
    </div>
  )
}
