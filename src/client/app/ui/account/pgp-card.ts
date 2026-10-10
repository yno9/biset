// The account page's PGP key card: the key this identity decrypts and signs
// mail with (the secret half stays in the Vault; only the public half is ever
// published, at the mail bridge, where WKD serves it). Everything the card
// does is a callback main.ts supplies.
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

export function renderPgpCard(config: PgpCardConfig, showMessage: (text: string) => void): HTMLElement {
  const wrap = document.createElement('div')
  wrap.className = 'acc-card-wrap'
  wrap.id = 'cmd-acc-pgp-card'
  const row = document.createElement('div')
  row.className = 'cmd-page-row'
  row.style.cssText = 'gap:12px;align-items:center;padding:10px 12px;flex-wrap:wrap'
  const left = document.createElement('div')
  left.style.cssText = 'flex:1;min-width:0;display:flex;flex-direction:column;gap:4px'
  const head = document.createElement('div')
  head.style.cssText = 'display:flex;align-items:center;gap:8px;min-width:0'
  const title = document.createElement('span')
  title.style.cssText = 'font-size:11px;font-weight:700;letter-spacing:0.04em;color:var(--accent2, #888);flex-shrink:0'
  title.textContent = 'PGP key'
  const sep = document.createElement('span')
  sep.style.cssText = 'color:var(--text-dim);flex-shrink:0'
  sep.textContent = ':'
  const summary = document.createElement('span')
  summary.style.cssText = 'font-size:13px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis'
  head.append(title, sep, summary)
  const detail = document.createElement('div')
  detail.style.cssText = 'font-size:11px;color:var(--text-dim);word-break:break-all'
  left.append(head, detail)
  const actions = document.createElement('div')
  actions.style.cssText = 'display:flex;flex-wrap:wrap;gap:6px'
  row.append(left, actions)
  wrap.appendChild(row)

  const file = document.createElement('input')
  file.type = 'file'
  file.accept = '.asc,.gpg,.pgp,.key,.txt'
  file.style.display = 'none'
  wrap.appendChild(file)

  let busy = false
  const button = (label: string, run: () => Promise<void>, danger = false): HTMLButtonElement => {
    const el = document.createElement('button')
    el.type = 'button'
    el.textContent = label
    el.className = 'acc-pgp-btn'
    if (danger) el.dataset.danger = 'true'
    el.addEventListener('click', event => {
      event.stopPropagation()
      if (busy) return
      busy = true
      actions.querySelectorAll('button').forEach(other => { other.disabled = true })
      void run().catch(error => showMessage(error instanceof Error ? error.message : String(error))).finally(() => { busy = false; void refresh() })
    })
    return el
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
  file.addEventListener('change', () => {
    const chosen = file.files?.[0]
    file.value = ''
    if (!chosen) return
    busy = true
    void chosen.text().then(importText).catch(error => showMessage(error instanceof Error ? error.message : String(error))).finally(() => { busy = false; void refresh() })
  })

  async function refresh(): Promise<void> {
    const key = await config.current().catch(() => undefined)
    actions.replaceChildren()
    if (!key) {
      summary.textContent = 'none'
      detail.textContent = `Make a key for ${config.address}, or bring the one you have. Encrypted mail to you is decrypted on this device.`
      actions.append(
        button('Generate', async () => { await config.onGenerate(); showMessage('PGP key generated') }),
        button('Import…', async () => { file.click() }),
      )
      return
    }
    summary.textContent = key.fingerprint.replace(/(.{4})(?=.)/g, '$1 ')
    detail.textContent = key.namesAddress ? key.userIds.join(', ') : `Its user IDs (${key.userIds.join(', ') || 'none'}) do not name ${config.address}: other people's programs may not use the key published for it.`
    actions.append(
      button('Publish', async () => { await config.onPublish(); showMessage(`Public key published for ${config.address}`) }),
      button('Withdraw', async () => { await config.onWithdraw(); showMessage('Public key withdrawn') }),
      button('Copy public key', async () => { await navigator.clipboard.writeText(await config.onCopyPublic()); showMessage('Public key copied') }),
      button('Replace…', async () => { file.click() }),
      button('New key', async () => {
        if (!confirm('Make a new key? Mail encrypted to the old one can still be read, but people must get the new public key to write to you.')) return
        await config.onGenerate()
        showMessage('PGP key generated')
      }, true),
    )
  }
  summary.textContent = '…'
  void refresh()
  return wrap
}
