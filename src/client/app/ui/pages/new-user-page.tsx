// New-user onboarding: since N1 (2026-09-05) one job only, the did.md Wallet login. biset never
// mints, restores, or holds a controller key of its own; did.md is the identity issuer.
//
// Same-site with dito (did.md) the sign-in and creation fields are dito's, in a frame
// (identity/wallet/dito-embed.ts); elsewhere a button opens the wallet.
import { useEffect, useRef, useState } from 'react'
import { readBisetConfig } from '../config.ts'
import {
  beginDidMdWalletLogin,
  completeDidMdWalletCallback,
  prepareDidMdWalletLoginRequest,
  restoreDidMdWalletSession,
  resolveWalletFromSuffix,
  selectWallet,
  currentWallet,
} from '../../../identity/wallet/did-md-oauth.ts'
import { WALLET_DIRECTORY } from '../../../identity/wallet/wallet-directory.ts'
import { ditoEmbedOrigin } from '../../../identity/wallet/dito-embed.ts'
import { walletConnected } from './signup-frame.ts'
import { GitHubIcon } from '../account/github-icon.tsx'
import { useStore } from '../../react/store.ts'
import { randomAlias, heldHost, heldIdentity, checkAlias, createAccountInBackground, passphraseEmbed, passphraseReady, preloadSignup, walletKnown, setPassphraseHandlers, showPassphraseOver } from '../signup-preload.ts'

export { setOnWalletConnected } from './signup-frame.ts'

// A callback is consumed before ordinary session restore (its code is one-use and the URL is
// cleared by the OAuth module after verification). Once per page load, however often this mounts.
let callbackConsumed = false

const errorText = (error: unknown): string => error instanceof Error ? error.message : String(error)

type Result = { message: string; error: boolean } | undefined

function Pigeon({ walking = false }: { walking?: boolean }) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" shapeRendering="crispEdges" className={walking ? 'pigeon-walking' : 'pigeon-done'}>
      <rect x="5" y="2" width="4" height="1" fill="#8b95a5" />
      <rect x="4" y="3" width="5" height="1" fill="#69717d" />
      <rect x="3" y="4" width="2" height="1" fill="#1a1a1a" />
      <rect x="5" y="4" width="1" height="1" fill="#ffffff" />
      <rect x="6" y="4" width="3" height="1" fill="#69717d" />
      <rect x="7" y="3" width="1" height="1" id="pigeon-eye" style={{ fill: 'var(--pigeon-eye-color,#ff4d6d)' }} />
      <rect x="5" y="5" width="4" height="1" fill="#a855a0" />
      <rect x="6" y="6" width="3" height="1" fill="#2a9d8f" />
      <rect x="6" y="7" width="5" height="1" fill="#69717d" />
      <rect x="5" y="8" width="7" height="1" fill="#69717d" />
      <rect x="4" y="9" width="8" height="1" fill="#69717d" />
      <rect x="6" y="9" width="4" height="1" fill="#4a515b" />
      <rect x="3" y="10" width="9" height="1" fill="#69717d" />
      <rect x="5" y="10" width="5" height="1" fill="#4a515b" />
      <rect x="3" y="11" width="8" height="1" fill="#4a515b" />
      <rect x="4" y="12" width="6" height="1" fill="#4a515b" />
      <rect x="11" y="11" width="2" height="1" fill="#1a1a1a" />
      <rect x="10" y="12" width="2" height="1" fill="#1a1a1a" />
      <g className="pigeon-foot pigeon-foot-a">
        <rect x="5" y="13" width="1" height="2" fill="#ff4d6d" />
        <rect className="pigeon-toe-l" x="4" y="14" width="1" height="1" fill="#ff4d6d" />
        <rect className="pigeon-toe-r" x="6" y="14" width="1" height="1" fill="#ff4d6d" />
      </g>
      <g className="pigeon-foot pigeon-foot-b">
        <rect x="8" y="13" width="1" height="2" fill="#ff4d6d" />
        <rect className="pigeon-toe-l" x="7" y="14" width="1" height="1" fill="#ff4d6d" />
        <rect className="pigeon-toe-r" x="9" y="14" width="1" height="1" fill="#ff4d6d" />
      </g>
    </svg>
  )
}

/** `loginAs`: the address of the identity this browser's wallet holds; the page then says it is a log-in as it. */
export function NewUserPage({ loginAs: given }: { loginAs?: string } = {}) {
  // The wallet holding an identity already (it says so once its frame is up): the address is then that one, and the button logs in.
  const held = useStore(heldIdentity)
  const loginAs = given ?? held
  const [result, setResult] = useState<Result>()
  const [connecting, setConnecting] = useState(false)
  const [suffix, setSuffix] = useState('')
  const [walletId, setWalletId] = useState(currentWallet().id)
  const box = useRef<HTMLDivElement>(null)
  const nameField = useRef<HTMLInputElement>(null)
  const logInNow = useRef<() => void>(() => {})
  const host = useStore(heldHost)
  const known = useStore(walletKnown)
  // The wallet's field arrives a moment after the page: a box of its size is drawn meanwhile, and the frame fades in over it.
  const fieldShown = useStore(passphraseReady)
  const ditoOrigin = ditoEmbedOrigin()
  // The wallet callback page finishes a sign-in; it has no create form to show.
  const embedded = Boolean(ditoOrigin) && location.pathname !== '/wallet/callback'
  const report = (error: unknown) => setResult({ message: errorText(error), error: true })
  // Creating is drawn here and done by the wallet out of sight (its `wallet.create`); the wallet's own form is shown only to log in.
  const ownCreate = embedded
  // The name is on the screen at once (made here, as the wallet makes its own), and checked behind it; one that is taken is replaced.
  const [alias, setAlias] = useState(() => randomAlias())
  const auto = useRef(true)
  const attempts = useRef(0)
  const [creating, setCreating] = useState(false)
  // Whether the name in the field is free, as the wallet finds it: undefined while it is being asked, null when it could not say
  // (Create then asks again, and fails with the reason).
  const [free, setFree] = useState<boolean | null | undefined>(undefined)
  const domain = (readBisetConfig().identityDomain || readBisetConfig().mailGateways[0] || '').toLowerCase()
  // The server the alias lives on: the deployment's own until the person edits it. Only the screen takes it so far; Create still makes the account at the
  // deployment's own domain.
  const [server, setServer] = useState(domain)
  const [editingServer, setEditingServer] = useState(false)
  const customServer = server.trim() !== '' && server.trim().toLowerCase() !== domain
  // The host the wallet is asked about: only a server other than the deployment's own; what is being typed in the host field waits until it is settled.
  const askHost = customServer && !editingServer ? server.trim().toLowerCase() : undefined
  const create = () => {
    if (free === undefined || free === false) return
    setCreating(true)
    setResult(undefined)
    const typed = alias.trim().toLowerCase()
    void (async () => {
      try { await createAccountInBackground(typed || undefined, askHost) } catch (error) {
        // A random name that was taken is tried once more with another; a name the person chose is theirs to change.
        if (!typed && /taken/i.test(errorText(error))) await createAccountInBackground(randomAlias(), askHost)
        else throw error
      }
    })().catch(error => { setCreating(false); report(error) })
  }

  useEffect(() => {
    if (callbackConsumed) return
    callbackConsumed = true
    void (async () => {
      try {
        const callback = await completeDidMdWalletCallback()
        const session = callback ?? await restoreDidMdWalletSession()
        if (session) await walletConnected(session)
      } catch (error) { report(error) }
    })()
  }, [])

  useEffect(() => {
    if (ownCreate) {
      preloadSignup()
      if (loginAs) return
      // The wallet offers a random name, already checked; what is typed after is checked as it settles.
      let current = true
      const typed = alias.trim().toLowerCase()
      setFree(undefined)
      // A field the person cleared stays empty (no name is made for it) until something is typed.
      if (!typed && !auto.current) return
      const timer = setTimeout(() => {
        void checkAlias(typed || undefined, askHost).then(found => {
          if (!current) return
          if (!typed) setAlias(found.alias)
          if (!found.available && auto.current && typed && attempts.current < 5) { attempts.current += 1; setAlias(randomAlias()); return }
          setFree(found.available)
        }).catch(() => { if (current) setFree(null) })
      }, typed && !auto.current ? 350 : 0)
      return () => { current = false; clearTimeout(timer) }
    }
  }, [embedded, ownCreate ? alias : '', loginAs, askHost])

  // Logging in: the Passphrase is typed in the wallet's own field (a frame holding that one field); this page asks the wallet to sign the
  // sign-in request with it and takes the response. What is typed never reaches this page.
  useEffect(() => {
    if (!embedded || !loginAs || !box.current) return
    preloadSignup()
    setPassphraseHandlers({ submit: () => logInNow.current(), error: message => setResult({ message, error: true }) })
    const away = showPassphraseOver(box.current)
    return () => { away(); setPassphraseHandlers({}) }
  }, [embedded, Boolean(loginAs)])
  const logIn = () => {
    setCreating(true)
    setResult(undefined)
    void (async () => {
      const embed = await passphraseEmbed()
      if (!embed) throw new Error('The wallet is not available here.')
      if (!host) throw new Error('The wallet has not said whose account this is yet.')
      const config = readBisetConfig()
      const request = await prepareDidMdWalletLoginRequest(config.mediatorUrls, config, host)
      const session = await completeDidMdWalletCallback(await embed.approve(request))
      if (!session) throw new Error('The sign-in was not completed.')
      await walletConnected(session)
    })().catch(error => { setCreating(false); report(error) })
  }
  logInNow.current = logIn

  const connect = () => {
    setConnecting(true)
    const config = readBisetConfig()
    const typed = suffix.trim()
    void (async () => {
      if (typed) {
        setResult({ message: `Resolving ${typed}…`, error: false })
        selectWallet(await resolveWalletFromSuffix(typed))
      }
      setResult({ message: 'Opening did.md Wallet…', error: false })
      await beginDidMdWalletLogin(config.mediatorUrls, config)
    })().catch(error => { setConnecting(false); report(error) })
  }

  const blocked = creating || (!loginAs && (free === false || free === undefined))
  return (
    <div id="new-user-page">
      <div className="nu-column">
        <div id="nu-pigeon">
          <Pigeon walking={creating || (embedded && !loginAs && (!known || free === undefined))} />
          <div id="nu-tagline">Email reimagined for<br />Privacy and Identity</div>
        </div>
        {ownCreate && !known && !loginAs ? <div id="nu-own-wait" /> : null}
        {ownCreate && (known || loginAs) ? (
          <form id="nu-own-create" onSubmit={event => { event.preventDefault(); if (loginAs) logIn(); else create() }}>
            {/* The wallet's own create form, as it looks in its frame: a bold small heading, the field, the full-width button. */}
            <div className="nu-block">
              <label className="nu-label">
                <span className="nu-heading">{loginAs ? 'Your account' : <>Mail alias <small>(can be changed later)</small></>}</span>
                <span className="nu-field">
                  <input id="nu-alias" ref={nameField} type="text" inputMode="email" autoComplete="off" autoCapitalize="off" autoCorrect="off" spellCheck={false} placeholder={customServer ? `alias@${server.trim()}` : 'alias'} value={loginAs ?? alias} readOnly={Boolean(loginAs)} disabled={creating}
                    data-bwignore="true" data-1p-ignore="true" data-lpignore="true" data-form-type="other"
                    onChange={event => { if (!loginAs) { auto.current = false; setAlias(event.target.value) } }}
                    style={{ '--chars': (loginAs ?? alias).length || (loginAs ? 0 : customServer ? `alias@${server.trim()}`.length : 'alias'.length) } as React.CSSProperties} />
                  {loginAs || (customServer && !alias && !editingServer) ? null : editingServer ? (
                    <span className="nu-suffix">@<input id="nu-server" className="nu-server" type="text" inputMode="url" autoComplete="off" autoCapitalize="off" autoCorrect="off" spellCheck={false} placeholder="myserver.com" value={server} autoFocus
                      data-bwignore="true" data-1p-ignore="true" data-lpignore="true" data-form-type="other"
                      onChange={event => setServer(event.target.value.replace(/\s/g, ''))}
                      onKeyDown={event => { if (event.key === 'Enter') { event.preventDefault(); setEditingServer(false); if (!server.trim()) setServer(domain) } }}
                      style={{ '--chars': server.length || 'myserver.com'.length } as React.CSSProperties} /></span>
                  ) : <span className="nu-suffix">@<span className="nu-host">{server.trim() || domain}</span></span>}
                  {loginAs ? null : (
                    <button type="button" className="nu-edit" onClick={event => { event.preventDefault(); if (editingServer && !server.trim()) setServer(domain); setEditingServer(!editingServer) }}>{editingServer ? <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-label="Done"><path d="M5 12.5l4.5 4.5L19 7.5" /></svg> : <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-label="Edit"><path d="M12 20h9" /><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4Z" /></svg>}</button>
                  )}
                </span>
              </label>
              {loginAs ? <div ref={box} className="nu-field nu-passphrase-box">{fieldShown ? null : 'Passphrase'}</div> : null}
              <button id="nu-create-button" className="nu-primary" type="submit" disabled={blocked} data-busy={creating ? '' : undefined}>{creating || (!loginAs && free === undefined) ? <span className="nu-dots" role="status" aria-label={loginAs ? 'Logging in' : creating ? 'Creating' : 'Checking'}><i /><i /><i /></span> : loginAs ? 'Log in' : free === false ? 'ID already taken' : 'Create'}</button>
            </div>
            {loginAs ? null : (
              <a id="nu-terms-line" href={`https://${domain}`} target="_blank" rel="noreferrer">
                By hosting your ID on {domain},<br />you agree to the terms of service.
              </a>
            )}
          </form>
        ) : null}
        <div id="nu-wallet-login-row" hidden={embedded}>
          {/* "connect with [...]": the [...] is WALLET_DIRECTORY, not a hardcoded wallet. With one entry no picker renders. */}
          {WALLET_DIRECTORY.length > 1 ? (
            <select id="nu-wallet-picker" value={walletId}
              onChange={event => {
                setWalletId(event.target.value)
                const entry = WALLET_DIRECTORY.find(candidate => candidate.id === event.target.value)
                if (entry) selectWallet(entry)
              }}>
              {WALLET_DIRECTORY.map(entry => <option key={entry.id} value={entry.id}>{entry.displayName}</option>)}
            </select>
          ) : null}
          {/* Optional: a wallet resolved by the host an identity is published at (alice.did.md) instead of the directory's selection. */}
          <input id="nu-wallet-suffix" type="text" placeholder="your did:web suffix (optional)" autoComplete="off" value={suffix} onChange={event => setSuffix(event.target.value)} />
          <button id="nu-wallet-login" className="nu-primary" type="button" disabled={connecting} onClick={connect}>Connect with your did</button>
        </div>
        <div id="nu-wallet-result" aria-live="polite" hidden={!result} data-error={result?.error ? '' : undefined}>{result?.message}</div>
      </div>
      <a id="nu-github" href="https://github.com/yno9/biset" target="_blank" rel="noreferrer" aria-label="biset on GitHub"><GitHubIcon size={24} /></a>
    </div>
  )
}
