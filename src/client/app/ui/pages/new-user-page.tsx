// New-user onboarding: since N1 (2026-09-05) one job only, the did.md Wallet login. biset never
// mints, restores, or holds a controller key of its own; did.md is the identity issuer.
//
// Same-site with dito (mail.did.md) the sign-in and creation fields are dito's, in a frame
// (identity/wallet/dito-embed.ts); elsewhere a button opens the wallet.
import { useEffect, useRef, useState } from 'react'
import { readBisetConfig } from '../config.ts'
import {
  beginDidMdWalletLogin,
  prepareDidMdWalletLoginRequest,
  completeDidMdWalletCallback,
  restoreDidMdWalletSession,
  resolveWalletFromSuffix,
  selectWallet,
  currentWallet,
  type DidMdActiveSession,
} from '../../../identity/wallet/did-md-oauth.ts'
import { WALLET_DIRECTORY } from '../../../identity/wallet/wallet-directory.ts'
import { ditoEmbedOrigin, mountDito, type DitoEmbed } from '../../../identity/wallet/dito-embed.ts'

// Set once by main.ts (a plain function reference, not an import back to it) so a sign-in can re-run
// the boot routine without importing main.ts, the bundle's entry point: a module reachable both as
// the entry and through another module's import edge made the bundler wrap it in a lazy initializer
// that nothing called, and the app silently never booted (found live, 2026-08-25).
let onWalletConnected: ((session: DidMdActiveSession) => Promise<void>) | undefined
export function setOnWalletConnected(fn: (session: DidMdActiveSession) => Promise<void>): void {
  onWalletConnected = fn
}

// A callback is consumed before ordinary session restore (its code is one-use and the URL is
// cleared by the OAuth module after verification). Once per page load, however often this mounts.
let callbackConsumed = false

const errorText = (error: unknown): string => error instanceof Error ? error.message : String(error)

type Result = { message: string; error: boolean } | undefined

function Pigeon() {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" shapeRendering="crispEdges">
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
      <rect x="5" y="13" width="1" height="2" fill="#ff4d6d" />
      <rect x="4" y="14" width="1" height="1" fill="#ff4d6d" />
      <rect x="8" y="13" width="1" height="2" fill="#ff4d6d" />
      <rect x="7" y="14" width="1" height="1" fill="#ff4d6d" />
    </svg>
  )
}

export function NewUserPage() {
  const [result, setResult] = useState<Result>()
  const [connecting, setConnecting] = useState(false)
  const [suffix, setSuffix] = useState('')
  const [walletId, setWalletId] = useState(currentWallet().id)
  const frame = useRef<HTMLIFrameElement>(null)
  const ditoOrigin = ditoEmbedOrigin()
  // The wallet callback page finishes a sign-in; it has no create form to show.
  const embedded = Boolean(ditoOrigin) && location.pathname !== '/wallet/callback'
  const report = (error: unknown) => setResult({ message: errorText(error), error: true })

  useEffect(() => {
    if (callbackConsumed) return
    callbackConsumed = true
    void (async () => {
      try {
        const callback = await completeDidMdWalletCallback()
        const session = callback ?? await restoreDidMdWalletSession()
        if (session) await onWalletConnected?.(session)
      } catch (error) { report(error) }
    })()
  }, [])

  useEffect(() => {
    if (!embedded || !frame.current || !ditoOrigin) return
    // Nothing on this page may move while the wallet works: the happy path shows no message at all
    // (an "already has" / "created" line pushed the form up and down). Only a failure is reported.
    //
    // Sign-in rides along with the creation, in the background: the signed request is prepared the
    // moment Create is pressed (so nothing waits for it), handed to dito's save page, which approves
    // it while the person saves the Passphrase, and the response lands on /wallet/callback.
    let loginRequest: Promise<string | undefined> | undefined
    let ditoEmbed: DitoEmbed | undefined
    mountDito(frame.current, ditoOrigin, 'create', {
      // An existing identity: dito's frame collects the Passphrase and signs in itself; this page
      // only prepares the signed request and takes the response, so the wallet is never left.
      login: handle => {
        void (async () => {
          const config = readBisetConfig()
          // The frame reports its own failures (wrong Passphrase, ...); only ours are shown here.
          const request = await prepareDidMdWalletLoginRequest(config.mediatorUrls, config, handle)
          const response = await ditoEmbed!.approve(request).catch(() => undefined)
          if (!response) return
          const session = await completeDidMdWalletCallback(response)
          if (!session) return
          await onWalletConnected?.(session)
        })().catch(error => {
          void ditoEmbed?.cancel().catch(() => {})
          report(error)
        })
      },
      creating: handle => {
        const config = readBisetConfig()
        loginRequest = prepareDidMdWalletLoginRequest(config.mediatorUrls, config, handle).catch(error => {
          console.warn('[did.md Wallet login] could not prepare the sign-in request; the identity is still created', errorText(error))
          return undefined
        })
      },
      created: () => {},
      // The same tab goes to dito's top-level save page and comes back: to the wallet callback when
      // the sign-in succeeded, otherwise to this very URL.
      savePage: async () => {
        const login = await loginRequest
        location.assign(`${ditoOrigin}/?embed=save&return=${encodeURIComponent(location.href)}${login ? `&login=${encodeURIComponent(login)}` : ''}`)
      },
      // Nothing to do here: the frame itself opens on the log-in form for the identity this browser holds.
      existing: () => {},
      unloaded: () => {},
      error: message => setResult({ message, error: true }),
    }).then(embed => { ditoEmbed = embed }).catch(report)
  }, [embedded, ditoOrigin])

  const connect = () => {
    setConnecting(true)
    // Safari only permits opening a window in the original click handler -- reserve it now, before
    // the asynchronous suffix resolution below, the same reason redirectToWallet takes an
    // already-opened popup.
    const popup = location.protocol === 'file:' ? window.open('', 'did-md-wallet') ?? undefined : undefined
    const config = readBisetConfig()
    const typed = suffix.trim()
    void (async () => {
      if (typed) {
        setResult({ message: `Resolving ${typed}…`, error: false })
        selectWallet(await resolveWalletFromSuffix(typed))
      }
      setResult({ message: 'Opening did.md Wallet…', error: false })
      await beginDidMdWalletLogin(config.mediatorUrls, popup, config)
    })().catch(error => { setConnecting(false); report(error) })
  }

  return (
    <div id="new-user-page" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: 'calc(100vh - 220px)', padding: '4px 0 20px' }}>
      <div style={{ width: '100%', maxWidth: 440, display: 'flex', flexDirection: 'column', gap: 14 }}>
        <div id="nu-pigeon"><Pigeon /></div>
        <div id="nu-create" style={{ display: embedded ? 'flex' : 'none', flexDirection: 'column', gap: 12 }}>
          <iframe ref={frame} id="nu-dito-frame" title="Create your identity" style={{ width: '100%', height: 230, border: 0, background: 'transparent', colorScheme: 'light dark' }}
            allow="clipboard-write; publickey-credentials-create; publickey-credentials-get" />
        </div>
        <div id="nu-wallet-login-row" style={{ display: embedded ? 'none' : 'flex', alignItems: 'center', justifyContent: 'center', marginTop: 2 }}>
          {/* "connect with [...]": the [...] is WALLET_DIRECTORY, not a hardcoded wallet. With one entry no picker renders. */}
          {WALLET_DIRECTORY.length > 1 ? (
            <select id="nu-wallet-picker" value={walletId} style={{ marginRight: 8, padding: '8px 10px', borderRadius: 8, font: 'inherit', fontSize: 15.5 }}
              onChange={event => {
                setWalletId(event.target.value)
                const entry = WALLET_DIRECTORY.find(candidate => candidate.id === event.target.value)
                if (entry) selectWallet(entry)
              }}>
              {WALLET_DIRECTORY.map(entry => <option key={entry.id} value={entry.id}>{entry.displayName}</option>)}
            </select>
          ) : null}
          {/* Optional: a wallet resolved by did:webvh suffix (alice.did.md) instead of the directory's selection. */}
          <input id="nu-wallet-suffix" type="text" placeholder="your did:web suffix (optional)" autoComplete="off" value={suffix} onChange={event => setSuffix(event.target.value)}
            style={{ marginRight: 8, padding: '8px 10px', borderRadius: 8, font: 'inherit', fontSize: 15.5, width: 200 }} />
          <button id="nu-wallet-login" type="button" disabled={connecting} onClick={connect}
            style={{ padding: '10px 18px', border: 0, borderRadius: 8, background: 'var(--accent)', color: '#fff', font: 'inherit', fontSize: 15.5, fontWeight: 500, cursor: 'pointer', whiteSpace: 'nowrap' }}>Connect with your did</button>
        </div>
        <div id="nu-wallet-result" aria-live="polite"
          style={{ display: result ? 'block' : 'none', minHeight: 18, fontSize: 14.5, textAlign: 'center', overflowWrap: 'anywhere', color: result?.error ? '#ff3b30' : 'var(--text-dim)' }}>{result?.message}</div>
      </div>
    </div>
  )
}
