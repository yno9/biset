// Embedded dito (PLAN-embedded-wallet.md in ~/did.md): the Alias and
// Passphrase fields on the landing page are rendered by dito itself inside an
// iframe on its own origin, so this page's script can never read them. We only
// lay the frame out and ask dito, over a MessageChannel, to create the
// identity; the one thing that comes back is the new DID.
//
// Same-site only. A cross-site iframe gets a partitioned (empty) IndexedDB, so
// anywhere dito's origin is not the sibling of ours, callers get `undefined`
// and fall back to the popup login.

export function ditoEmbedOrigin(): string | undefined {
  const { protocol, hostname, port } = location
  if (hostname === 'mail.did.md') return 'https://dito.did.md'
  if (hostname === 'mail.did.localhost') return `${protocol}//dito.did.localhost${ditoDevPort(port)}`
  return undefined
}

// Dev only: dito's local server and biset's run on different ports.
function ditoDevPort(own: string): string {
  const configured = new URLSearchParams(location.search).get('dito_port')
  return `:${configured && /^\d{2,5}$/.test(configured) ? configured : own}`
}

export type DitoMode = 'create' | 'approve'

/** What the frame reports; every handler is optional because the approve frame reports only errors. */
export interface DitoEmbedHandlers {
  /** The user pressed Create: `handle` is the host the identity will be published at (`name.did.md`). */
  creating?(handle: string): void
  /** The user created an identity in dito's form (nothing secret is passed). */
  created?(did: string): void
  /** This browser's dito already holds an identity, so no form is shown. */
  existing?(did: string): void
  /**
   * dito asks this page to go to its save page: the password manager only offers to save
   * from a top-level page, never from an iframe. The page, not dito, decides where to
   * navigate (nothing in the message is a URL).
   */
  savePage?(): void
  /** The user removed dito's copy from this browser; the form is back. */
  unloaded?(): void
  /**
   * The user pressed Log in for an identity that already exists: `handle` is its host. The page
   * prepares the signed sign-in request and hands it back with `DitoEmbed.login`.
   */
  login?(handle: string): void
  error?(message: string): void
}

/**
 * Mounts one of dito's embedded screens: the create form, or the approval of a request. The whole
 * screen, its button included, is dito's:
 * password managers only react to a real user gesture inside the frame that
 * holds the form, and a click forwarded from this page would be neither.
 */
const HEIGHT_KEY = 'biset.dito-frame-height'
function rememberHeight(height: number): void {
  try { localStorage.setItem(HEIGHT_KEY, String(Math.round(height))) } catch { /* private mode */ }
}
function recalledHeight(): number | undefined {
  try {
    const value = Number(localStorage.getItem(HEIGHT_KEY))
    return value >= 100 && value <= 800 ? value : undefined
  } catch { return undefined }
}

export interface DitoEmbed {
  /**
   * Has dito approve `request` (the query string of a signed request: a sign-in, a DID document
   * edit). The Passphrase is typed in dito's frame; what comes back is the relying-party response
   * (`vp_token`, `id_token`, `state`, `iss`), the same fields the callback URL would carry.
   */
  approve(request: string): Promise<URLSearchParams>
  /** The page could not prepare the request it announced: the frame's button stops working. */
  cancel(): Promise<void>
}

export function mountDito(frame: HTMLIFrameElement, origin: string, mode: DitoMode, handlers: DitoEmbedHandlers = {}): Promise<DitoEmbed> {
  return new Promise((resolve, reject) => {
    let ready = false
    let port: MessagePort | undefined
    let nextId = 1
    const calls = new Map<number, { resolve(value: unknown): void, reject(error: Error): void }>()
    const call = (method: string, params: unknown) => new Promise<unknown>((done, fail) => {
      if (!port) { fail(new Error('The wallet is not connected.')); return }
      const id = nextId++
      calls.set(id, { resolve: done, reject: fail })
      port.postMessage({ id, method, params })
    })
    const embed: DitoEmbed = {
      async approve(request) {
        const result = await call('wallet.approve', { request }) as { response?: Record<string, unknown> } | null
        const params = new URLSearchParams()
        for (const [name, value] of Object.entries(result?.response ?? {})) if (typeof value === 'string') params.set(name, value)
        return params
      },
      async cancel() { await call('wallet.cancel', {}) },
    }
    const timer = setTimeout(() => {
      removeEventListener('message', onMessage)
      reject(new Error('The wallet did not respond.'))
    }, 20_000)

    // The frame can reload itself (dito's confirm step submits a native form);
    // each time it says ready again we open a fresh channel.
    function onMessage(event: MessageEvent): void {
      if (event.origin !== origin || event.source !== frame.contentWindow) return
      if ((event.data as { type?: unknown } | null)?.type !== 'dito:ready') return
      const channel = new MessageChannel()
      port = channel.port1
      channel.port1.onmessage = message => {
        const data = message.data as { event?: string, did?: unknown, message?: unknown, height?: unknown, handle?: unknown, id?: unknown, result?: unknown, error?: { message?: unknown } }
        if (typeof data.id === 'number') {
          const pending = calls.get(data.id)
          calls.delete(data.id)
          if (data.error) pending?.reject(new Error(typeof data.error.message === 'string' ? data.error.message : 'Wallet error'))
          else pending?.resolve(data.result)
          return
        }
        if (data.event === 'resize' && typeof data.height === 'number') { frame.style.height = `${data.height}px`; if (mode === 'create') rememberHeight(data.height) }
        else if (data.event === 'creating' && typeof data.handle === 'string') handlers.creating?.(data.handle)
        else if (data.event === 'created' && typeof data.did === 'string') handlers.created?.(data.did)
        else if (data.event === 'existing' && typeof data.did === 'string') handlers.existing?.(data.did)
        else if (data.event === 'save-page') handlers.savePage?.()
        else if (data.event === 'unloaded') handlers.unloaded?.()
        else if (data.event === 'login' && typeof data.handle === 'string') handlers.login?.(data.handle)
        else if (data.event === 'error') handlers.error?.(typeof data.message === 'string' ? data.message : 'Wallet error')
      }
      frame.contentWindow!.postMessage({ type: 'dito:hello' }, origin, [channel.port2])
      if (!ready) { ready = true; clearTimeout(timer); resolve(embed) }
    }

    // Start at the height the frame had last time, so the page does not jump when it loads.
    const hint = mode === 'create' ? recalledHeight() : undefined
    if (hint) frame.style.height = `${hint}px`
    addEventListener('message', onMessage)
    frame.src = `${origin}/?embed=${mode}`
  })
}
