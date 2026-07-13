// "Add my own domain" (DID.md Phase 3, biset-verse middle ground): an end
// user brings a domain they own, biset's own mail relay hosts the actual
// mail, but the domain itself — and hence the escape hatch — stays theirs.
// Four DNS records total: ownership-verification TXT, DKIM TXT, MX, and (once
// the account exists) the DID anchor TXT — the last of which the relay's own
// Cloudflare anchor can't write for a domain outside its zone, so it's always
// shown for the user to add themselves.
import { buildEnvelope } from '../cryptenv.ts'

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}

function homeMailUrl(): string {
  const cfg = (window as any).__BISET_CONFIG__
  return (cfg?.mail_url || `https://mail.${cfg?.hostname || ''}`).replace(/\/$/, '')
}

function row(labelText: string, value: string): HTMLElement {
  const wrap = document.createElement('div')
  wrap.style.cssText = 'margin:10px 0;font-size:13px'
  const label = document.createElement('div')
  label.textContent = labelText
  label.style.cssText = 'color:var(--text-dim);margin-bottom:3px'
  const box = document.createElement('div')
  box.style.cssText = 'display:flex;gap:6px;align-items:center'
  const code = document.createElement('code')
  code.textContent = value
  code.style.cssText = 'flex:1;min-width:0;overflow-wrap:break-word;background:var(--input-bg);border:1px solid var(--header-border);border-radius:6px;padding:6px 8px;font-size:12px;user-select:all'
  const copyBtn = document.createElement('button')
  copyBtn.type = 'button'
  copyBtn.textContent = 'Copy'
  copyBtn.style.cssText = 'flex-shrink:0;padding:6px 10px;border-radius:6px;border:none;background:var(--accent);color:#fff;font-size:12px;cursor:pointer'
  copyBtn.addEventListener('click', async () => {
    await navigator.clipboard.writeText(value)
    copyBtn.textContent = 'Copied'
    setTimeout(() => { copyBtn.textContent = 'Copy' }, 1200)
  })
  box.append(code, copyBtn)
  wrap.append(label, box)
  return wrap
}

async function resolveTxt(name: string): Promise<string[]> {
  const providers = [
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=TXT`,
    `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=TXT`,
  ]
  for (const url of providers) {
    try {
      const resp = await fetch(url, { headers: { Accept: 'application/dns-json' } })
      if (!resp.ok) continue
      const body = await resp.json() as { Answer?: Array<{ type: number; data: string }> }
      const txts = (body.Answer ?? []).filter(a => a.type === 16).map(a => a.data.replace(/^"|"$/g, ''))
      if (txts.length) return txts
    } catch { /* try next provider */ }
  }
  return []
}

export function openCustomDomainFlow(): void {
  const overlay = document.createElement('div')
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.4);z-index:10001;display:flex;align-items:center;justify-content:center;padding:16px'
  const box = document.createElement('div')
  box.style.cssText = 'background:var(--bg);color:var(--text);border-radius:12px;padding:20px;max-width:440px;width:100%;box-shadow:0 8px 32px rgba(0,0,0,0.3);max-height:90vh;overflow:auto'
  const header = document.createElement('div')
  header.style.cssText = 'display:flex;justify-content:space-between;align-items:center;margin-bottom:12px'
  const h = document.createElement('h3')
  h.textContent = 'Add my own domain'
  h.style.cssText = 'margin:0;font-size:16px'
  const closeBtn = document.createElement('button')
  closeBtn.textContent = '✕'
  closeBtn.style.cssText = 'background:none;border:none;font-size:16px;cursor:pointer;color:var(--text-dim)'
  closeBtn.addEventListener('click', () => overlay.remove())
  header.append(h, closeBtn)
  const body = document.createElement('div')
  box.append(header, body)
  overlay.append(box)
  document.body.append(overlay)

  const intro = document.createElement('p')
  intro.style.cssText = 'font-size:13px;color:var(--text-dim);margin:0 0 12px'
  intro.textContent = 'Host mail on your own domain — biset runs the server, you keep the domain (and the exit, if you ever need it).'
  const domainInput = document.createElement('input')
  domainInput.id = 'cd-domain'
  domainInput.placeholder = 'yourdomain.com'
  domainInput.style.cssText = 'width:100%;box-sizing:border-box;padding:8px 10px;border-radius:8px;border:1px solid var(--header-border);background:var(--input-bg);color:var(--text);font-size:14px'
  const nextBtn = document.createElement('button')
  nextBtn.type = 'button'
  nextBtn.textContent = 'Get verification record'
  nextBtn.style.cssText = 'margin-top:10px;width:100%;padding:9px;border-radius:8px;border:none;background:var(--accent);color:#fff;font-size:14px;cursor:pointer'
  const errEl = document.createElement('div')
  errEl.style.cssText = 'color:#ff3b30;font-size:12px;margin-top:8px;display:none'
  body.append(intro, domainInput, nextBtn, errEl)

  nextBtn.addEventListener('click', async () => {
    const domain = domainInput.value.trim().toLowerCase()
    if (!domain) return
    nextBtn.disabled = true; nextBtn.textContent = 'Requesting…'; errEl.style.display = 'none'
    try {
      const relay = homeMailUrl()
      const resp = await fetch(`${relay}/domain/verify-token?domain=${encodeURIComponent(domain)}`)
      if (!resp.ok) throw new Error(await resp.text())
      const { txt_name, token } = await resp.json() as { txt_name: string; token: string }
      showVerifyStep(body, () => overlay.remove(), relay, domain, txt_name, token)
    } catch (e) {
      errEl.textContent = e instanceof Error ? e.message : String(e)
      errEl.style.display = 'block'
      nextBtn.disabled = false; nextBtn.textContent = 'Get verification record'
    }
  })
}

function showVerifyStep(body: HTMLElement, close: () => void, relay: string, domain: string, txtName: string, token: string): void {
  body.innerHTML = ''
  const p = document.createElement('p')
  p.style.cssText = 'font-size:13px;color:var(--text-dim);margin:0 0 4px'
  p.textContent = `Add this TXT record at your DNS provider for ${domain}, then verify:`
  const verifyBtn = document.createElement('button')
  verifyBtn.type = 'button'
  verifyBtn.textContent = "I've added it — Verify"
  verifyBtn.style.cssText = 'margin-top:12px;width:100%;padding:9px;border-radius:8px;border:none;background:var(--accent);color:#fff;font-size:14px;cursor:pointer'
  const errEl = document.createElement('div')
  errEl.style.cssText = 'color:#ff3b30;font-size:12px;margin-top:8px;display:none'
  body.append(p, row('TXT record name', txtName), row('TXT record value', token), verifyBtn, errEl)

  verifyBtn.addEventListener('click', async () => {
    verifyBtn.disabled = true; verifyBtn.textContent = 'Verifying…'; errEl.style.display = 'none'
    try {
      const resp = await fetch(`${relay}/domain/add`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ domain }),
      })
      if (!resp.ok) throw new Error(await resp.text())
      const info = await resp.json() as { mx_target: string; dkim_name: string; dkim_value: string }
      showDnsAndCreateStep(body, close, relay, domain, info)
    } catch (e) {
      errEl.textContent = e instanceof Error ? e.message : String(e)
      errEl.style.display = 'block'
      verifyBtn.disabled = false; verifyBtn.textContent = "I've added it — Verify"
    }
  })
}

function showDnsAndCreateStep(body: HTMLElement, close: () => void, relay: string, domain: string, info: { mx_target: string; dkim_name: string; dkim_value: string }): void {
  body.innerHTML = ''
  const p1 = document.createElement('p')
  p1.style.cssText = 'font-size:13px;color:var(--text-dim);margin:0 0 4px'
  p1.textContent = 'Domain verified. Two more records for real mail delivery:'
  body.append(p1)
  body.append(row(`MX record for ${domain}`, `${info.mx_target} (priority 10)`))
  if (info.dkim_value) body.append(row(info.dkim_name, info.dkim_value))

  const p2 = document.createElement('p')
  p2.style.cssText = 'font-size:13px;color:var(--text-dim);margin:16px 0 4px'
  p2.textContent = `Now create your ${domain} account:`
  const usernameInput = document.createElement('input')
  usernameInput.id = 'cd-username'
  usernameInput.placeholder = 'username'
  usernameInput.style.cssText = 'width:100%;box-sizing:border-box;padding:8px 10px;border-radius:8px;border:1px solid var(--header-border);background:var(--input-bg);color:var(--text);font-size:14px;margin-top:6px'
  const pwInput = document.createElement('input')
  pwInput.id = 'cd-password'
  pwInput.type = 'password'
  pwInput.placeholder = 'password'
  pwInput.style.cssText = usernameInput.style.cssText
  const createBtn = document.createElement('button')
  createBtn.type = 'button'
  createBtn.textContent = 'Create account'
  createBtn.style.cssText = 'margin-top:10px;width:100%;padding:9px;border-radius:8px;border:none;background:var(--accent);color:#fff;font-size:14px;cursor:pointer'
  const errEl = document.createElement('div')
  errEl.style.cssText = 'color:#ff3b30;font-size:12px;margin-top:8px;display:none'
  body.append(p2, usernameInput, pwInput, createBtn, errEl)

  createBtn.addEventListener('click', async () => {
    const username = usernameInput.value.trim().toLowerCase()
    const pw = pwInput.value
    if (!username || !pw) return
    createBtn.disabled = true; createBtn.textContent = 'Creating…'; errEl.style.display = 'none'
    try {
      const email = `${username}@${domain}`
      const { envelope, kek, masterSecret } = await buildEnvelope(pw)
      const { initDid } = await import('../did/index.ts')
      const didRecord = await initDid(email, masterSecret)
      const rootPriv = hexToBytes(didRecord!.rootPrivateKey)

      const { provisionAccount } = await import('../did/provision.ts')
      const res = await provisionAccount({ serverUrl: relay, username, domain, did: didRecord!.did, rootPrivateKey: rootPriv, masterSecret, envelope })
      if (!res.ok) throw new Error(res.conflict ? 'Username taken' : `Server error (${res.status})`)

      const stored = { serverUrl: relay, email, password: res.password!, did: didRecord?.did }
      const { initSession } = await import('../jmap/client.ts')
      const session = await initSession(stored)
      if (!session) throw new Error('Provisioned but failed to connect')
      const { loadStoredAccounts, saveStoredAccounts, addSession } = await import('../context.ts')
      const existing = loadStoredAccounts()
      if (!existing.some(a => a.email === stored.email && a.serverUrl === stored.serverUrl)) {
        saveStoredAccounts([...existing, stored])
      }
      const { initPGPForSession } = await import('../app.ts')
      addSession(session)
      initPGPForSession(session, kek)

      import('../did/publish.ts').then(m => m.publishOwnDids()).catch(() => {})

      const { refreshAccountsList, showMenuPage } = await import('./left-pane.ts')
      const { showSysMsg } = await import('./shell.ts')
      refreshAccountsList()
      showMenuPage('/account')
      showSysMsg('Account created')
      const { showMnemonic } = await import('./mnemonic.ts')
      showMnemonic(masterSecret, { firstTime: true })

      showAnchorStep(body, close, email, didRecord!.did)
    } catch (e) {
      errEl.textContent = e instanceof Error ? e.message : String(e)
      errEl.style.display = 'block'
      createBtn.disabled = false; createBtn.textContent = 'Create account'
    }
  })
}

async function showAnchorStep(body: HTMLElement, close: () => void, email: string, did: string): Promise<void> {
  const [localpart, domain] = email.split('@')
  const txtName = `_did.${localpart}.${domain}`
  const expected = `did=${did}`
  const txts = await resolveTxt(txtName)
  const alreadyResolved = txts.includes(expected) // biset's own zone already covers it

  body.innerHTML = ''
  const p = document.createElement('p')
  p.style.cssText = 'font-size:13px;color:var(--text-dim);margin:16px 0 4px'
  const doneBtn = document.createElement('button')
  doneBtn.type = 'button'
  doneBtn.textContent = 'Done'
  doneBtn.style.cssText = 'margin-top:12px;width:100%;padding:9px;border-radius:8px;border:none;background:var(--accent);color:#fff;font-size:14px;cursor:pointer'
  doneBtn.addEventListener('click', close)

  if (alreadyResolved) {
    p.textContent = `Account created — ${email} is ready.`
    body.append(p, doneBtn)
  } else {
    p.textContent = "Last record — this one biset can't add for you (it's outside our DNS zone), so others can find your identity if you ever move relays:"
    body.append(p, row(txtName, expected), doneBtn)
  }
}
