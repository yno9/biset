// The sign-up as the wallet has it (dito's create form, in a frame): what this page does when the frame reports, shared by the page that
// shows the form (new-user-page.tsx) and by the frame kept ready out of sight (ui/signup-preload.ts), so that the one sign-up is one piece of code.
import { readBisetConfig } from '../config.ts'
import {
  prepareDidMdWalletLoginRequest,
  completeDidMdWalletCallback,
  type DidMdActiveSession,
} from '../../../identity/wallet/did-md-oauth.ts'
import { mountDito, type DitoEmbed } from '../../../identity/wallet/dito-embed.ts'

// Set once by main.ts (a plain function reference, not an import back to it) so a sign-in can re-run
// the boot routine without importing main.ts, the bundle's entry point: a module reachable both as
// the entry and through another module's import edge made the bundler wrap it in a lazy initializer
// that nothing called, and the app silently never booted (found live, 2026-08-25).
let onWalletConnected: ((session: DidMdActiveSession) => Promise<void>) | undefined
export function setOnWalletConnected(fn: (session: DidMdActiveSession) => Promise<void>): void {
  onWalletConnected = fn
}
export async function walletConnected(session: DidMdActiveSession): Promise<void> { await onWalletConnected?.(session) }

const errorText = (error: unknown): string => error instanceof Error ? error.message : String(error)

/** Mounts dito's create form in `frame` and answers what it reports. `report` takes the errors to show; `onError` the frame's own messages;
 * `onExisting` is told the DID of the identity this browser already holds (the form is then a log-in, not a create). */
export function mountSignup(frame: HTMLIFrameElement, ditoOrigin: string, report: (error: unknown) => void, onError: (message: string) => void, onExisting: (did: string) => void = () => {}): Promise<DitoEmbed> {
  // Sign-in rides along with the creation, in the background: the signed request is prepared the
  // moment Create is pressed (so nothing waits for it), handed to dito's save page, which approves
  // it while the person saves the Passphrase, and the response lands on /wallet/callback.
  let loginRequest: Promise<string | undefined> | undefined
  let ditoEmbed: DitoEmbed | undefined
  return mountDito(frame, ditoOrigin, 'create', {
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
        if (!session) { void ditoEmbed?.cancel().catch(() => {}); return }
        await walletConnected(session)
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
      location.assign(login ? `${ditoOrigin}/authorize${login}` : `${ditoOrigin}/?embed=save-done`)
    },
    // The frame itself opens on the log-in form for the identity this browser holds; the page only learns whose it is.
    existing: onExisting,
    unloaded: () => {},
    error: onError,
  }).then(embed => { ditoEmbed = embed; return embed })
}
