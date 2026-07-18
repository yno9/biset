// "Add a relay or domain" — the single entry point for growing an identity
// past its first account, replacing what used to be three separate UI pieces
// ("Add my own domain", "Add a relay…", and implicitly "create JMAP account
// under the same DID"): they all reduce to the same operation, provision a
// new address for the CURRENT identity, differing only in TARGET.
//
// The Relay URL field (left-pane.ts) is purely "which relay" — it is never
// treated as a domain-ownership claim by its shape (2026-07-14, user-
// reported: typing the bare hostname "mail.biset.md" — no scheme — into that
// field was silently routed into the BYO-domain-ownership flow instead of
// "sign up on this relay", because the old code used "has a scheme?" as an
// implicit domain-vs-relay signal). Which domain the new account ends up
// under is a SEPARATE, explicit choice made after Sign up, once the relay is
// already fixed:
//   - "Use <host>'s own domain" → no ownership to prove, straight to account
//     creation on the relay's own open domain.
//   - "Use my own domain" → DID.md Phase 3, biset-verse middle ground: the
//     typed relay hosts the mail, the domain (and hence the escape hatch)
//     stays yours. Needs an ownership-verification TXT first. Four DNS
//     records total: verification TXT, DKIM TXT, MX, and (once the account
//     exists) the DID anchor TXT — the last of which the relay's own
//     Cloudflare anchor can't write for a domain outside its zone, so it's
//     always shown for the user to add themselves.
import { buildEnvelope } from '../cryptenv.ts'
import { activeSession, isApRelay } from '../context.ts'
import { standaloneDid, clearStandalone } from '../did/create-standalone.ts'

// The add-relay flow only ever reads the identity's record key (account.email —
// which is the DID for a relay-less identity), so it works for a real session or
// a synthetic standalone reference alike.
type IdentityRef = { account: { email: string } }
import { hexToBytes, expandDualRelay } from '../utils.ts'
import * as identityStore from '../store/identities.ts'

// Same self-asserted-name-then-localpart fallback the identity heading uses
// (left-pane.ts's renderAccountsList) — so a password prompt for "your
// existing password" names WHICH identity, not just a bare "account
// password" that reads as if a new one were being set.
function didNameFor(email: string): string {
  return identityStore.all().find(i => i.email === email)?.name || email.split('@')[0]
}

function row(labelText: string, value: string): HTMLElement {
  const wrap = document.createElement('div')
  wrap.style.cssText = 'padding:4px;margin:10px 0;font-size:13px'
  const label = document.createElement('div')
  label.textContent = labelText
  label.style.cssText = 'color:var(--text-dim);margin-bottom:3px;margin-left:4px'
  const box = document.createElement('div')
  box.style.cssText = 'position:relative;cursor:pointer'
  const code = document.createElement('code')
  code.textContent = value
  code.style.cssText = 'display:block;overflow-wrap:break-word;background:var(--input-bg);border:0px solid var(--header-border);border-radius:6px;padding:6px 30px 6px 8px;font-size:12px;font-family:inherit;user-select:all'
  const copyBtn = document.createElement('button')
  copyBtn.type = 'button'
  copyBtn.setAttribute('aria-label', 'Copy')
  copyBtn.title = 'Copy'
  copyBtn.style.cssText = 'position:absolute;right:6px;top:6px;display:flex;align-items:center;padding:2px;border:none;background:none;color:var(--text-dim);cursor:pointer;font-family:inherit'
  const iconSvg = '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>'
  copyBtn.innerHTML = iconSvg
  const doCopy = async () => {
    await navigator.clipboard.writeText(value)
    copyBtn.style.color = 'var(--accent)'
    copyBtn.textContent = 'Copied!'
    copyBtn.style.fontSize = '11px'
    copyBtn.style.fontWeight = '600'
    setTimeout(() => {
      copyBtn.style.color = 'var(--text-dim)'
      copyBtn.innerHTML = iconSvg
    }, 1200)
  }
  // Whole field is the click target, not just the small icon — the icon
  // stays only as the visual "you can copy this" affordance.
  box.addEventListener('click', doCopy)
  copyBtn.addEventListener('click', e => { e.stopPropagation(); doCopy() })
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

// `target` is whatever the user typed into the Relay URL field — already
// known to be non-empty, and purely a "which relay" answer (see file header).
// Normalizes to a full URL, then presents the domain choice.
//
// Renders inline into `body` (the "+ New JMAP account" panel's own signup
// area — left-pane.ts) rather than a separate overlay/modal, so Sign up
// stays on the same screen Log in already uses instead of popping a
// different UI out from under it. `close` resets that panel back to its
// Sign up / Log in choice screen when a step's own "Done"/close action fires.
export function openAddRelayOrDomainFlow(target: string, body: HTMLElement, close: () => void): void {
  body.innerHTML = ''
  const relay = (/^https?:\/\//i.test(target) ? target : 'https://' + target).replace(/\/$/, '')
  let host = relay
  try { host = new URL(relay).hostname } catch { /* keep the raw relay string for display */ }
  // A relay-less identity (DID⊥relay) has no session, but the add-relay flow can
  // still bind a relay to it: its record key is the DID and its envelope is
  // local. Represent it as a synthetic ref keyed by the DID.
  const sDid = standaloneDid()
  const reuseIdentity: IdentityRef | undefined = activeSession() ?? (sDid ? { account: { email: sDid } } : undefined)
  // A bare apex ("biset.md" — no scheme, not already "mail."/"ap.") names a
  // home identity, not one relay: mail and ActivityPub are separate services
  // there (mail.<apex> / ap.<apex>), same pairing #new's onboarding
  // provisions together. "Use default domain" below provisions/connects
  // BOTH when this applies; "Use my own domain" (BYO domain verification —
  // /domain/verify-token — is a mail-relay-only concept) always targets one
  // specific relay regardless, so it uses `relays[0]` — the bare apex itself
  // (`relay`, e.g. https://biset.md) is never a real relay endpoint once
  // `dual` applies, only mail.<apex>/ap.<apex> are.
  const dual = expandDualRelay(target)
  const relays = dual ?? [relay]

  // BYO domain (/domain/verify-token, /domain/add) is a mail-relay-only
  // concept (see file header) — the right test is whether ANY targeted
  // relay is ActivityPub, not whether this is a dual pair (2026-07-14,
  // user-caught: typing "ap.biset.md" alone — one relay, not dual — still
  // showed the now-pointless "Use my own domain" button, since the earlier
  // fix only checked `dual`). Per the 2026-07-14 live test against
  // Mastodon, a cross-domain WebFinger redirect for an AP relay gets
  // resolved but then displayed under the actor's REAL domain anyway, not
  // the vanity one — so BYO buys nothing whenever AP is involved, dual or
  // not. Rather than show a domain-choice screen with only one live option
  // in it, skip straight to provisioning the default domain — there's no
  // real choice left to make.
  if (dual || relays.some(r => isApRelay(r))) {
    if (!reuseIdentity) {
      const p = document.createElement('p')
      p.style.cssText = 'font-size:13px;color:var(--text-dim)'
      p.textContent = 'Log in first — this only adds a relay to an identity that already exists.'
      body.append(p)
      return
    }
    showRelayCreateStep(body, close, relays, reuseIdentity)
    return
  }

  const p = document.createElement('p')
  p.style.cssText = 'font-size:13px;color:var(--text-dim);margin:0 0 12px;background:var(--card);border-radius:8px;padding:10px 12px'
  p.textContent = `Which domain should your new address on ${host} use?`
  body.append(p)

  // Same pill button style as the Sign up/Log in choice above it
  // (.cmd-acc-choice-btn) — this used to be its own plain-text-row-with-
  // hover-arrow style, now unified (2026-07-14, user-reported). Not the
  // #cmd-acc-choice id itself — that belongs to left-pane.ts's own Sign
  // up/Log in row and duplicate ids would break its own getElementById
  // lookups — just the same flex/gap layout inline.
  const choiceRow = document.createElement('div')
  choiceRow.style.cssText = 'display:flex;gap:10px'
  const domainChoiceRow = (label: string): HTMLButtonElement => {
    const btn = document.createElement('button')
    btn.type = 'button'
    btn.className = 'cmd-acc-choice-btn'
    // .cmd-acc-choice-btn is also used by the OUTER Sign up/Log in row
    // (left-pane.ts, not Recursive) — inherit here only, not on the shared
    // class, so this doesn't change that one's font.
    btn.style.fontFamily = 'inherit'
    btn.textContent = label
    return btn
  }
  const hereBtn = domainChoiceRow('Use default domain')
  const ownBtn = domainChoiceRow('Use my own domain')
  choiceRow.append(hereBtn, ownBtn)
  body.append(choiceRow)

  if (!reuseIdentity) {
    // A relay's own default domain is a plain existing-identity operation —
    // adding a relay/address only ever makes sense for an identity that
    // already exists (fresh-identity creation is the separate #new
    // onboarding flow). A BYO domain can still mint a brand new identity
    // (showDnsAndCreateStep handles both), so only this one is gated.
    hereBtn.disabled = true
    hereBtn.style.opacity = '0.4'
    hereBtn.style.cursor = 'not-allowed'
    hereBtn.title = 'Log in first — this only adds a relay to an identity that already exists.'
  }

  hereBtn.addEventListener('click', () => {
    if (!reuseIdentity) return
    showRelayCreateStep(body, close, relays, reuseIdentity)
  })
  ownBtn.addEventListener('click', () => showDomainInputStep(body, close, relays[0]!))
}

function showDomainInputStep(body: HTMLElement, close: () => void, relay: string): void {
  body.innerHTML = ''
  const row = document.createElement('div')
  row.style.cssText = 'display:flex;align-items:center;gap:8px'
  const domainInput = document.createElement('input')
  domainInput.className = 'cmd-input'
  domainInput.placeholder = 'yourdomain.com'
  domainInput.style.cssText = 'font-family:inherit'
  const nextBtn = document.createElement('button')
  nextBtn.type = 'button'
  nextBtn.textContent = 'Get verification record'
  nextBtn.style.cssText = 'flex-shrink:0;padding:9px 14px;border-radius:8px;border:none;background:var(--accent);color:#fff;font-size:14px;cursor:pointer;white-space:nowrap;font-family:inherit'
  row.append(domainInput, nextBtn)
  const p = document.createElement('p')
  p.style.cssText = 'font-size:13px;margin-top:16px;color:var(--text-dim);background:var(--card);border-radius:8px;padding:10px 12px'
  p.textContent = 'Host mail on your own domain — biset runs the server, you keep the domain (and the exit, if you ever need it).'
  const errEl = document.createElement('div')
  errEl.style.cssText = 'color:#ff3b30;font-size:12px;margin-top:8px;display:none'
  body.append(row, p, errEl)
  domainInput.focus()

  nextBtn.addEventListener('click', async () => {
    const domain = domainInput.value.trim().toLowerCase()
    if (!domain) return
    nextBtn.disabled = true; nextBtn.textContent = 'Requesting…'; errEl.style.display = 'none'
    try {
      const resp = await fetch(`${relay}/domain/verify-token?domain=${encodeURIComponent(domain)}`)
      if (!resp.ok) throw new Error(await resp.text())
      const info = await resp.json() as { txt_name: string; token: string; mx_target: string; dkim_name: string; dkim_value: string }
      showVerifyStep(body, close, relay, domain, info)
    } catch (e) {
      errEl.textContent = e instanceof Error ? e.message : String(e)
      errEl.style.display = 'block'
      nextBtn.disabled = false; nextBtn.textContent = 'Get verification record'
    }
  })
}

// The relay-URL branch: no ownership to prove, straight to account creation
// under the current identity (same operation as the domain branch's create
// step below, minus the domain/DNS bookkeeping) — see did/provision.ts's
// unsealCurrentIdentity. Always reuses the active identity; a relay only
// ever makes sense as an addition to one that already exists (fresh-identity
// creation is the separate #new onboarding flow).
// Username/password rows match the #new page's own pill-box style
// (account-create.ts / index.html's #nu-username/#nu-password) — same shape,
// same "@hostname" suffix pattern — rather than a separately-styled pair of
// boxed inputs. Deliberately NOT a full copy of #new's fields though: that
// page's password field is generating a brand-new secret (hence visible
// text + a copy button, so there's something to save), where this one is
// re-entering an identity's EXISTING password to unseal it — masked like any
// other password field, no copy button, and no TOS checkbox (already agreed
// once, when the identity itself was created).
// `relays` is 1 or 2 servers (see expandDualRelay) — the same username +
// unsealed identity provisions each one independently; partial success is
// kept (matches the old best-effort "whichever comes up is kept" login
// behavior) rather than requiring every relay in the set to succeed.
function showRelayCreateStep(body: HTMLElement, close: () => void, relays: string[], reuseIdentity: IdentityRef): void {
  body.innerHTML = ''
  const primary = relays[0]
  // Reuses .cmd-input's own box (border-radius/background/padding) on the
  // ROW instead of the input, with the input itself borderless/transparent
  // inside it — the input's padding still has to match .cmd-input's (8px
  // 10px) exactly, or its text sits at a different left inset than every
  // other field in this panel (2026-07-14, user-reported: this pill's
  // hand-copied 10px/14px padding drifted from .cmd-input's real 8px/10px).
  const usernameRow = document.createElement('div')
  usernameRow.className = 'cmd-input'
  usernameRow.style.cssText = 'display:flex;align-items:center;padding:0;overflow:hidden'
  const usernameInput = document.createElement('input')
  usernameInput.id = 'cd-username'
  usernameInput.type = 'text'
  usernameInput.placeholder = 'username'
  usernameInput.autocomplete = 'username'
  usernameInput.style.cssText = 'flex:1;min-width:0;padding:8px 0 8px 10px;border:none;background:transparent;color:inherit;font-size:inherit;font-family:inherit;outline:none'
  const atSpan = document.createElement('span')
  atSpan.style.cssText = 'padding:8px 10px 8px 2px;color:var(--text-dim);font-size:inherit;white-space:nowrap;user-select:none'
  atSpan.textContent = '@' + new URL(primary).hostname
  usernameRow.append(usernameInput, atSpan)
  // The relay's own hostname is only a fallback guess — the domain a new
  // account actually lands under is server-side config (provisionDomain(),
  // /relay-info's "domain" field) and can genuinely differ (e.g. t.biset.md
  // accounts are provisioned on the mail.biset.md relay). Swap in the real
  // one once it's known; the account itself is always created under
  // whatever the server actually reports back (res.email below), this only
  // fixes the PREVIEW shown before submitting. Both relays of a dual pair
  // land under the same domain (mirrors #new), so the primary's alone is enough.
  ;(async () => {
    const { fetchRelayInfo, relayInfoFor } = await import('../context.ts')
    await fetchRelayInfo(primary)
    const domain = relayInfoFor(primary)?.domain
    if (domain) atSpan.textContent = '@' + domain
  })()

  const pwRow = document.createElement('div')
  pwRow.style.cssText = 'display:flex;align-items:center;gap:8px;margin-top:8px'
  const pwInput = document.createElement('input')
  pwInput.id = 'cd-password'
  pwInput.type = 'password'
  pwInput.placeholder = `your existing password for ${didNameFor(reuseIdentity.account.email)}`
  pwInput.autocomplete = 'current-password'
  pwInput.className = 'cmd-input'
  pwInput.style.cssText = 'font-family:inherit'
  const createBtn = document.createElement('button')
  createBtn.type = 'button'
  createBtn.textContent = 'Create'
  createBtn.className = 'cmd-page-btn primary'
  pwRow.append(pwInput, createBtn)

  const errEl = document.createElement('div')
  errEl.style.cssText = 'color:#ff3b30;font-size:13px;margin-top:8px;display:none;text-align:center'
  body.append(usernameRow, pwRow, errEl)
  usernameInput.focus()

  createBtn.addEventListener('click', async () => {
    const username = usernameInput.value.trim().toLowerCase()
    const pw = pwInput.value
    if (!username || !pw) return
    createBtn.disabled = true; createBtn.textContent = 'Creating…'; errEl.style.display = 'none'
    try {
      const { unsealCurrentIdentity, provisionAccount } = await import('../did/provision.ts')
      const unsealed = await unsealCurrentIdentity(reuseIdentity.account.email, pw)
      if (!unsealed.ok) throw new Error(unsealed.error)
      const { did, rootPrivateKey, masterSecret, kek } = unsealed.identity

      const { initSession } = await import('../jmap/client.ts')
      const { loadStoredAccounts, saveStoredAccounts, addSession, fetchRelayInfo } = await import('../context.ts')
      const { initPGPForSession } = await import('../app.ts')
      const { storeDidRecord, getDidRecord } = await import('../did/store.ts')

      const emails: string[] = []
      let lastError: string | null = null
      for (const relay of relays) {
        const res = await provisionAccount({ serverUrl: relay, username, did, rootPrivateKey, masterSecret })
        if (!res.ok) { lastError = res.conflict ? 'That address is owned by a different key' : `Server error (${res.status})`; continue }
        const email = res.email || `${username}@${new URL(relay).hostname}`
        const session = await initSession({ serverUrl: relay, email, password: res.password!, did }).catch(() => null)
        if (!session) { lastError = 'Provisioned but failed to connect'; continue }
        await fetchRelayInfo(relay)
        const existing = loadStoredAccounts()
        if (!existing.some(a => a.email === email && a.serverUrl === relay)) {
          saveStoredAccounts([...existing, { serverUrl: relay, email, password: res.password!, did }])
        }
        addSession(session)
        initPGPForSession(session, kek)
        // Mirror the DID record under the new address so it stays resolvable
        // if this endpoint later becomes the representative one.
        const rec = await getDidRecord(reuseIdentity.account.email)
        if (rec) await storeDidRecord({ ...rec, email })
        emails.push(email)
      }
      if (!emails.length) throw new Error(lastError ?? 'Failed to create account')

      // This identity now has a relay, so it is no longer relay-less: drop the
      // standalone marker (a no-op for a normal identity) so future boots take
      // the ordinary session path.
      clearStandalone()

      const { refreshAccountsList } = await import('./left-pane.ts')
      const { showSysMsg } = await import('./shell.ts')
      refreshAccountsList()
      showSysMsg(`Added — also reachable at ${emails.join(', ')}. Publishing to the network…`, 30000)
      import('../did/publish.ts').then(m => m.publishOneVisible(reuseIdentity.account.email)).then(ok => {
        showSysMsg(ok ? `Published — ${emails.join(', ')} now discoverable` : 'Added, but no gateway accepted the publish (will retry automatically)')
      }).catch(e => {
        // Only reached when the document itself can't be published, which the
        // automatic republish will hit identically every time — so "will
        // retry automatically" (what this said before) is precisely wrong
        // here. Show the reason instead.
        showSysMsg(`Added, but the DID document could not be published: ${e instanceof Error ? e.message : String(e)}`, 15000)
      })

      // Just the confirmation — no button, no lingering locked relay field
      // above it. The account is already live (refreshAccountsList() above
      // already shows it in the list); there's nothing left to confirm or
      // undo here, so nothing left to click. The panel resets on its own
      // next time the "+ New JMAP account" trigger opens it.
      const p2 = document.createElement('p')
      p2.style.cssText = 'font-size:13px;color:var(--text-dim);margin:16px 0 4px'
      p2.textContent = emails.length < relays.length
        ? `Done — ${emails.join(', ')} ready (${lastError} for the rest).`
        : `Done — ${emails.join(', ')} ready.`
      body.innerHTML = ''
      body.append(p2)
      // Hide, don't remove — this row is static markup outside `body` (part
      // of #cmd-acc-panel itself), reused every time the panel reopens; the
      // trigger card's resetAddAccountPanel() un-hides it again next time.
      const relayRow = document.querySelector<HTMLElement>('.cmd-acc-relay-row')
      if (relayRow) relayRow.style.display = 'none'
    } catch (e) {
      errEl.textContent = e instanceof Error ? e.message : String(e)
      errEl.style.display = 'block'
      createBtn.disabled = false; createBtn.textContent = 'Create'
    }
  })
}

// All the DNS records the owner needs (ownership TXT + MX + DKIM) shown
// together in one screen instead of two sequential ones — the server hands
// out MX/DKIM already at /domain/verify-token time (2026-07-14), since
// neither is privileged (a public key record + this relay's own hostname),
// unlike provision_secret below which stays gated behind actual ownership
// proof. One "I've added them — Verify" click checks the TXT and, on
// success, skips straight to account creation with nothing left to show.
function showVerifyStep(body: HTMLElement, close: () => void, relay: string, domain: string, info: { txt_name: string; token: string; mx_target: string; dkim_name: string; dkim_value: string }): void {
  body.innerHTML = ''
  const p = document.createElement('p')
  p.style.cssText = 'font-size:13px;color:var(--text-dim);padding:5px;margin:0 0 4px;background:var(--card);border-radius:8px;padding:10px 12px'
  p.textContent = `Add these DNS records at your provider for ${domain}, then verify:`
  const verifyBtn = document.createElement('button')
  verifyBtn.type = 'button'
  verifyBtn.textContent = "I've added them — Verify"
  verifyBtn.style.cssText = 'margin-top:12px;width:100%;padding:9px;border-radius:8px;border:none;background:var(--accent);color:#fff;font-size:14px;cursor:pointer;font-family:inherit'
  const errEl = document.createElement('div')
  errEl.style.cssText = 'color:#ff3b30;font-size:12px;margin-top:8px;display:none'
  body.append(p, row('TXT record name', info.txt_name), row('TXT record value', info.token), row(`MX record for ${domain}`, `${info.mx_target} (priority 10)`))
  if (info.dkim_value) body.append(row(info.dkim_name, info.dkim_value))
  body.append(verifyBtn, errEl)

  verifyBtn.addEventListener('click', async () => {
    verifyBtn.disabled = true; verifyBtn.textContent = 'Verifying…'; errEl.style.display = 'none'
    try {
      const resp = await fetch(`${relay}/domain/add`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ domain }),
      })
      if (!resp.ok) throw new Error(await resp.text())
      const { provision_secret } = await resp.json() as { provision_secret: string }
      showCreateAccountStep(body, close, relay, domain, provision_secret)
    } catch (e) {
      errEl.textContent = e instanceof Error ? e.message : String(e)
      errEl.style.display = 'block'
      verifyBtn.disabled = false; verifyBtn.textContent = "I've added them — Verify"
    }
  })
}

function showCreateAccountStep(body: HTMLElement, close: () => void, relay: string, domain: string, provisionSecret: string): void {
  body.innerHTML = ''

  // One client session = one identity (ARC.md, 2026-07-14): if we're already
  // logged in, a new BYO-domain address is a new *relay/address for that same
  // identity* — not a reason to spin up a brand new DID. Reuses the active
  // identity's existing DID/seed (password unseals its EXISTING envelope,
  // exactly like "Move to another relay") instead of buildEnvelope() minting
  // a fresh one. Only with no active session (fresh device, never logged in)
  // does this actually create a new identity.
  const reuseIdentity = activeSession()

  // Same pill-box layout as the default-domain step (showRelayCreateStep) —
  // username row with an "@domain" suffix, password+Create combined in one
  // row below. Here the domain is already known (BYO, just verified) rather
  // than fetched from /relay-info, so the "@" suffix needs no async swap.
  // Reuses .cmd-input's own box (border-radius/background/padding) on the
  // ROW instead of the input, with the input itself borderless/transparent
  // inside it — the input's padding still has to match .cmd-input's (8px
  // 10px) exactly, or its text sits at a different left inset than every
  // other field in this panel (2026-07-14, user-reported: this pill's
  // hand-copied 10px/14px padding drifted from .cmd-input's real 8px/10px).
  const usernameRow = document.createElement('div')
  usernameRow.className = 'cmd-input'
  usernameRow.style.cssText = 'display:flex;align-items:center;padding:0;overflow:hidden'
  const usernameInput = document.createElement('input')
  usernameInput.id = 'cd-username'
  usernameInput.type = 'text'
  usernameInput.placeholder = 'username'
  usernameInput.autocomplete = 'username'
  usernameInput.style.cssText = 'flex:1;min-width:0;padding:8px 0 8px 10px;border:none;background:transparent;color:inherit;font-size:inherit;font-family:inherit;outline:none'
  const atSpan = document.createElement('span')
  atSpan.style.cssText = 'padding:8px 10px 8px 2px;color:var(--text-dim);font-size:inherit;white-space:nowrap;user-select:none'
  atSpan.textContent = '@' + domain
  usernameRow.append(usernameInput, atSpan)

  const pwRow = document.createElement('div')
  pwRow.style.cssText = 'display:flex;align-items:center;gap:8px;margin-top:8px'
  const pwInput = document.createElement('input')
  pwInput.id = 'cd-password'
  pwInput.type = 'password'
  pwInput.placeholder = reuseIdentity ? `your existing password for ${didNameFor(reuseIdentity.account.email)}` : 'password'
  pwInput.autocomplete = 'current-password'
  pwInput.className = 'cmd-input'
  pwInput.style.cssText = 'font-family:inherit'
  const createBtn = document.createElement('button')
  createBtn.type = 'button'
  createBtn.textContent = 'Create'
  createBtn.className = 'cmd-page-btn primary'
  pwRow.append(pwInput, createBtn)

  const errEl = document.createElement('div')
  errEl.style.cssText = 'color:#ff3b30;font-size:13px;margin-top:8px;display:none;text-align:center'
  body.append(usernameRow, pwRow, errEl)
  usernameInput.focus()

  createBtn.addEventListener('click', async () => {
    const username = usernameInput.value.trim().toLowerCase()
    const pw = pwInput.value
    if (!username || !pw) return
    createBtn.disabled = true; createBtn.textContent = 'Creating…'; errEl.style.display = 'none'
    try {
      const email = `${username}@${domain}`
      let envelope: import('../cryptenv.ts').Envelope | undefined
      let kek: Uint8Array, masterSecret: Uint8Array, did: string, rootPriv: Uint8Array

      if (reuseIdentity) {
        const { unsealCurrentIdentity } = await import('../did/provision.ts')
        const result = await unsealCurrentIdentity(reuseIdentity.account.email, pw)
        if (!result.ok) throw new Error(result.error)
        ;({ did, rootPrivateKey: rootPriv, masterSecret, kek, envelope } = result.identity)
      } else {
        const built = await buildEnvelope(pw)
        envelope = built.envelope; kek = built.kek; masterSecret = built.masterSecret
        const { initDid } = await import('../did/index.ts')
        const didRecord = await initDid(email, masterSecret)
        did = didRecord!.did; rootPriv = hexToBytes(didRecord!.rootPrivateKey)
      }

      const { provisionAccount } = await import('../did/provision.ts')
      const res = await provisionAccount({ serverUrl: relay, username, domain, did, rootPrivateKey: rootPriv, masterSecret, envelope, provisionSecret })
      if (!res.ok) throw new Error(res.conflict ? 'Username taken' : `Server error (${res.status})`)

      const stored = { serverUrl: relay, email, password: res.password!, did }
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

      // No showMenuPage('/account') here — this whole flow only ever runs
      // from inside the /account page's own panel already, and re-rendering
      // it (as showMenuPage does, via renderMenuInboxImpl's
      // card.innerHTML = cmd.page()) destroys this very `body` element mid-
      // flow, right before showAnchorStep below appends its DID-record step
      // into it — the step still "ran", just onto an already-detached node,
      // so it silently never appeared (2026-07-14, user-reported: no DID
      // record step showed up after a BYO-domain signup).
      const { refreshAccountsList } = await import('./left-pane.ts')
      const { showSysMsg } = await import('./shell.ts')
      refreshAccountsList()
      showSysMsg('Account created')
      // Recovery phrase is the SAME as the reused identity's — nothing new to
      // show; only a genuinely new identity gets the first-time reveal.
      if (!reuseIdentity) {
        const { showMnemonic } = await import('./mnemonic.ts')
        showMnemonic(masterSecret, { firstTime: true })
      }

      showAnchorStep(body, close, email, did)
    } catch (e) {
      errEl.textContent = e instanceof Error ? e.message : String(e)
      errEl.style.display = 'block'
      createBtn.disabled = false; createBtn.textContent = 'Create'
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
