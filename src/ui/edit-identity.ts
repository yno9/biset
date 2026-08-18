// "Edit identity" — changes a did:webvh identity's location (domain and/or
// username) to anywhere that serves the did:webvh log contract, biset-run or
// not (PLAN.md's did:webvh migration section, 2026-08-16 addendum; the
// abstract migration core is did/webvh/migrate.ts, verified interoperable
// against didwebvh-rs). Domain-only change is a location move; username-only
// change (same domain) is a rename; both together do both at once — one
// operation, not three separate features, since migrateWebvhLocation never
// cared about the distinction.
//
// What the destination does with the identity going forward — relays,
// mediator, anything else — is the destination's concern, not biset's: this
// only ever moves the bare DID document (relays: [], addresses: []).
//
// Mail on THIS instance no longer breaks on a rename (PLANSCID.md,
// 2026-08-18): a SCID-primary account's real JMAP identity never moves, so a
// username/domain change here is just re-pointing that account's alias —
// see the submit handler's own alias-sync step below. Pre-SCID accounts
// (the scheme this replaced) have no alias to update and simply keep
// working under their old address, same as before this existed.
//
// DIDComm reachability is a separate axis from where the document lives
// (DID⊥relay orthogonality) — this re-registers with THIS biset instance's
// own mediator after the move, not a mediator at the new domain, exactly
// the same way any other identity on this instance would.
type OpenModal = (title: string, bodyEl: HTMLElement) => () => void

/** GET https://domain/username/did.jsonl and read what that says about
 * availability. A did:webvh log is public by the spec's own contract (see
 * webvh-server/core.ts's file header), so a 404 vs. 200 is a real answer —
 * anything else (network error, CORS refusal from a host that doesn't open
 * GET the way biset's own server does, timeout) is honestly "unknown", not
 * "available": a false "available" here is what would let a migrate fail
 * loudly at submit time instead of a quiet check beforehand. */
/** `ownScid` lets a 200 response be told apart from a stranger's: a log
 * whose first entry's `parameters.scid` matches this identity's own SCID is
 * a location this SAME identity occupied at some earlier point in its
 * history (webvh-store.ts never deletes on move) — not someone else's name.
 * Cheap: the GET already happened, this only parses the first line already
 * in hand. It does NOT mean the move will succeed — the anchor's own reclaim
 * rule (webvh-server/core.ts) is the actual authority on that, and a
 * non-biset destination may have no reclaim path at all — just that "taken"
 * is the wrong word for it. */
async function checkAvailability(domain: string, username: string, ownScid: string): Promise<'available' | 'taken' | 'own-history' | 'unknown'> {
  if (!domain || !username) return 'unknown'
  try {
    const resp = await fetch(`https://${domain}/${encodeURIComponent(username)}/did.jsonl`, { method: 'GET' })
    if (resp.status === 404) return 'available'
    if (!resp.ok) return 'unknown'
    try {
      const firstLine = (await resp.text()).split('\n').map(l => l.trim()).find(Boolean)
      const scid = firstLine ? (JSON.parse(firstLine) as { parameters?: { scid?: string } }).parameters?.scid : undefined
      return scid === ownScid ? 'own-history' : 'taken'
    } catch {
      return 'taken' // 200 but unparseable — still someone's log, so still not "available"
    }
  } catch {
    return 'unknown'
  }
}

export function openEditIdentityModal(did: string, openModal: OpenModal, onDone: () => void, onDidCommMessage: () => void): void {
  let currentDomain: string, currentUsername: string, currentScid: string

  void (async () => {
    const { parseWebvhDid, bisetWebvhUsername } = await import('../did/webvh/identifier.ts')
    let parsed: ReturnType<typeof parseWebvhDid>
    try {
      parsed = parseWebvhDid(did)
    } catch {
      return
    }
    currentDomain = parsed.domain
    currentScid = parsed.scid
    const username = bisetWebvhUsername(did)
    if (!username) {
      const body = document.createElement('div')
      body.style.cssText = 'font-size:13px;color:var(--text-dim)'
      body.textContent = 'This identity has no single-segment username path to edit.'
      openModal('Edit identity', body)
      return
    }
    currentUsername = username
    renderForm()
  })()

  function renderForm(): void {
    const body = document.createElement('form')
    body.style.cssText = 'display:flex;flex-direction:column;gap:10px'
    body.innerHTML = `
      <div style="font-size:12px;color:var(--text-dim)">
        Change this identity's domain, its username, or both. The identity's
        underlying key stays the same, so a contact who already knows you
        follows the change automatically the next time they resolve you.
      </div>
      <div data-role="domain-warning" style="font-size:12px;color:var(--text-dim);display:none">
        Changing the domain moves this identity to a new destination. What
        that destination does with it from here on is entirely up to that
        destination, not biset — this only edits the bare identity document.
        Your mail address updates to match; existing mail history and your
        PGP key carry over unchanged.
      </div>
      <div style="display:flex;flex-direction:column;gap:3px">
        <label style="font-size:11px;color:var(--text-dim)">Domain</label>
        <input class="cmd-input" type="text" name="domain" required>
      </div>
      <div style="display:flex;flex-direction:column;gap:3px">
        <label style="font-size:11px;color:var(--text-dim)">Username</label>
        <input class="cmd-input" type="text" name="username" required>
      </div>
      <div data-role="availability" style="font-size:12px;color:var(--text-dim);min-height:16px"></div>
      <div data-role="error" style="color:#ff3b30;font-size:12px;display:none"></div>
      <div data-role="ok" style="color:#34c759;font-size:12px;display:none"></div>
      <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:4px">
        <button type="button" data-role="cancel" class="cmd-page-btn" style="width:auto;padding:6px 14px">Cancel</button>
        <button type="submit" data-role="submit" class="cmd-page-btn primary" style="width:auto;padding:6px 14px" disabled>Save</button>
      </div>`
    const dismiss = openModal('Edit identity', body)
    body.querySelector<HTMLButtonElement>('[data-role=cancel]')!.addEventListener('click', dismiss)

    const domainInput = body.elements.namedItem('domain') as HTMLInputElement
    const usernameInput = body.elements.namedItem('username') as HTMLInputElement
    domainInput.value = currentDomain
    usernameInput.value = currentUsername

    const availEl = body.querySelector<HTMLElement>('[data-role=availability]')!
    const domainWarning = body.querySelector<HTMLElement>('[data-role=domain-warning]')!
    const submit = body.querySelector<HTMLButtonElement>('[data-role=submit]')!
    let availToken = 0

    const setSubmitEnabled = (enabled: boolean) => {
      submit.disabled = !enabled
      submit.style.opacity = enabled ? '1' : '0.4'
      submit.style.cursor = enabled ? 'pointer' : 'not-allowed'
    }
    setSubmitEnabled(false)

    const refresh = () => {
      const domain = domainInput.value.trim().toLowerCase()
      const username = usernameInput.value.trim().toLowerCase()
      domainWarning.style.display = domain !== currentDomain ? 'block' : 'none'
      const unchanged = domain === currentDomain && username === currentUsername
      setSubmitEnabled(!unchanged)
      if (unchanged) { availEl.textContent = ''; return }
      if (!domain || !username) { availEl.textContent = ''; return }
      const token = ++availToken
      availEl.textContent = 'Checking availability…'
      checkAvailability(domain, username, currentScid).then(status => {
        if (token !== availToken) return // a newer check superseded this one
        availEl.textContent = status === 'available' ? '✓ Available'
          : status === 'own-history' ? '↺ You used to be here — may or may not accept a move back, depending on the destination'
          : status === 'taken' ? '✗ Already in use at that location'
          : '? Could not check — the destination may not answer GET, or is unreachable'
        availEl.style.color = status === 'available' ? '#34c759' : status === 'own-history' ? '#ff9500' : status === 'taken' ? '#ff3b30' : 'var(--text-dim)'
      })
    }
    domainInput.addEventListener('input', refresh)
    usernameInput.addEventListener('input', refresh)

    body.addEventListener('submit', async (ev) => {
      ev.preventDefault()
      const domain = domainInput.value.trim().toLowerCase()
      const username = usernameInput.value.trim().toLowerCase()
      const errEl = body.querySelector<HTMLElement>('[data-role=error]')!
      const okEl = body.querySelector<HTMLElement>('[data-role=ok]')!
      errEl.style.display = 'none'; okEl.style.display = 'none'
      if (!domain || !username) { errEl.textContent = 'Domain and username required'; errEl.style.display = 'block'; return }

      const label = domain === currentDomain ? 'rename this identity' : username === currentUsername ? 'move this identity' : 'move and rename this identity'
      if (!confirm(`This will ${label} to ${username}@${domain}. It publishes a move entry to your current location and to the new one. It cannot be undone from here.`)) return

      setSubmitEnabled(false); submit.textContent = 'Saving…'
      try {
        const { hasDidCommChannel } = await import('../did/didcomm/channel.ts')
        const hadChannel = await hasDidCommChannel(did)

        // Same wall a rotate hits: while key rotation is active, appending
        // ANY entry — including a move — needs the current Spare Key, not
        // the Root Key (prerotation.ts's own note).
        const { resolveSpareKeyForMove } = await import('./prerotation.ts')
        const spareKey = await resolveSpareKeyForMove(did)
        if (spareKey.active && !spareKey.override) {
          // Cancelled or the phrase didn't match — abort rather than
          // silently falling through to an unauthorized Root Key signature
          // the anchor would reject anyway.
          setSubmitEnabled(true); submit.textContent = 'Save'
          return
        }

        const { moveWebvhIdentity } = await import('../did/webvh/move.ts')
        const newRec = await moveWebvhIdentity({
          oldDid: did, newDomain: domain, newUsername: username, relays: [], addresses: [],
          ...(spareKey.active ? { spareKeyOverride: spareKey.override! } : {}),
        })

        const { sessions, loadStoredAccounts, saveStoredAccounts, isDidCommRelay, isApRelay } = await import('../context.ts')

        // Re-point each mail account's ALIAS to the new username/domain —
        // never a data move, never even a credential change: a SCID-primary
        // account's own login identity (session.account.email) is
        // permanent, so this is the entire cost of a rename on the mail
        // side (PLANSCID.md). Captured against the OLD did, before the
        // bookkeeping loop below reassigns it. Best-effort throughout: the
        // DID move itself already landed by this point, so a relay being
        // unreachable here must not undo it or block the rest of this
        // handler — it just means that one account keeps answering to its
        // old alias too, discoverable again next time this runs.
        const mailSessions = sessions.filter(s => s.account.did === did && !isDidCommRelay(s.account.serverUrl) && !isApRelay(s.account.serverUrl))
        if (mailSessions.length) {
          const { aliasAccountOnRelay } = await import('../cryptenv.ts')
          const newAlias = `${username}@${domain}`
          const oldAlias = `${currentUsername}@${currentDomain}`
          for (const s of mailSessions) {
            const { serverUrl, email: loginEmail, password: credential } = s.account
            const added = await aliasAccountOnRelay(serverUrl, loginEmail, credential, 'add', newAlias).catch(() => false)
            if (!added) {
              console.warn(`[edit-identity] could not register ${newAlias} as an alias on ${serverUrl} — this account will keep answering to ${oldAlias} only`)
              continue
            }
            // Best-effort in the stricter sense: the NEW alias is already
            // live either way, so failing to drop the old one just leaves
            // the account reachable at both, never broken.
            await aliasAccountOnRelay(serverUrl, loginEmail, credential, 'remove', oldAlias).catch(() => false)
            s.account.displayEmail = newAlias
          }
        }

        // moveWebvhIdentity already moved the IndexedDB DidRecord to its new
        // stable key (store.ts) — but every OTHER local pointer to "this
        // identity's DID string" is a snapshot that does not follow along on
        // its own: this device's "which identity is mine" marker, each relay
        // account's did field, and the in-memory sessions this page is
        // currently rendering from. Without repointing them, the identity
        // heading kept showing the OLD DID string even though resolving it
        // correctly followed alsoKnownAs to the new document's content
        // (found live, 2026-08-16 — the move itself worked, only the UI's
        // own bookkeeping didn't follow).
        const { ownDid, setOwnDid } = await import('../did/didcomm-devices.ts')
        if (ownDid() === did) setOwnDid(newRec.did)
        const accounts = loadStoredAccounts()
        let accountsChanged = false
        for (const a of accounts) {
          if (a.did === did) {
            a.did = newRec.did
            const updated = mailSessions.find(s => s.account.serverUrl === a.serverUrl && s.account.email === a.email)
            if (updated?.account.displayEmail) a.displayEmail = updated.account.displayEmail
            accountsChanged = true
          }
        }
        if (accountsChanged) saveStoredAccounts(accounts)
        for (const s of sessions) {
          if (s.account.did === did) s.account.did = newRec.did
        }

        // Device DIDComm registration is scoped to the OLD document's kid/slot
        // and does not carry over (move.ts's own note) — re-register under the
        // new DID with THIS instance's own mediator, same as any other
        // identity here would (mediatorUrl()'s own note: it's a property of
        // the deployment, not something an identity edit changes).
        if (hadChannel) {
          const { registerIdentityChannel } = await import('../did/create.ts')
          await registerIdentityChannel(newRec.did, onDidCommMessage).catch(e =>
            console.error('[edit-identity] mediator re-registration after move failed:', e))
        }

        okEl.textContent = `Saved — now ${newRec.did}`
        okEl.style.display = 'block'
        setTimeout(() => { dismiss(); onDone() }, 1200)
      } catch (e) {
        errEl.textContent = e instanceof Error ? e.message : String(e)
        errEl.style.display = 'block'
      } finally {
        setSubmitEnabled(true); submit.textContent = 'Save'
      }
    })
  }
}
