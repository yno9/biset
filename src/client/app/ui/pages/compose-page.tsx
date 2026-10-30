// The compose page is a conversation that has not begun: the island at the top (ui/right-col.tsx) takes the recipient and the
// subject where an open conversation shows who it is with and its title, the reply box takes the message, and the page itself is
// the empty conversation. This module holds what the island and the reply box share (the draft), and sends it.
import { useEffect, useLayoutEffect } from 'react'
import { createStore, useStore } from '../../react/store.ts'
import { NewUserPage } from './new-user-page.tsx'
import { accountConfig } from '../account/state.ts'
import { heldIdentity, preloadSignup } from '../signup-preload.ts'
import { setPage } from '../state.ts'
import type { ReplySendInput } from '../reply-box.tsx'

export interface ComposePageConfig {
  selfAddress: string
  /** This identity's own DID -- undefined until enableDidComm has run (main.ts's boot). Needed so
   * "From" has a DID option once "To" resolves to one; with none, DID recipients simply can't be
   * composed to from here. */
  selfDid?: string
  sendMessage(input: ReplySendInput): Promise<void>
  onError?(message: string): void
}

const composeConfig = createStore<ComposePageConfig | undefined>(undefined)
export const configureComposePage = (next: ComposePageConfig): void => composeConfig.set(next)
export const composeConfigured = (): boolean => composeConfig.get() !== undefined

/** The draft's recipient and subject, as typed in the island. `to` can be set before the page opens (a path in the address bar). */
export const composeDraft = createStore<{ to: string; subject: string }>({ to: '', subject: '' })
export const resetComposeDraft = (): void => composeDraft.set({ to: '', subject: '' })

// Someone with no account can still write. Sending then goes through the account's own sign-up (the wallet's create form, as it is),
// and what was written is kept across that trip (the wallet leaves this page and comes back to it).
const PENDING_KEY = 'biset:pending-send'
export function savePendingSend(body: string): void {
  try { sessionStorage.setItem(PENDING_KEY, JSON.stringify({ ...composeDraft.get(), body })) } catch { /* storage blocked: the draft is lost with the page */ }
}
/** Takes back what savePendingSend kept (once): puts the recipients and subject where they were, and returns the message. */
export function takePendingSend(): string | undefined {
  try {
    const raw = sessionStorage.getItem(PENDING_KEY)
    if (!raw) return undefined
    sessionStorage.removeItem(PENDING_KEY)
    const kept = JSON.parse(raw) as { to?: string; subject?: string; body?: string }
    composeDraft.set({ to: kept.to ?? '', subject: kept.subject ?? '' })
    return kept.body
  } catch { return undefined }
}
/** Sending with no account asked for one: the page shows the account's own sign-up (the wallet's create form) in place of the empty conversation. */
export const signingUp = createStore(false)

/** Why the last message of the new message page did not go, said under the island until it is tried again. */
export const sendProblem = createStore<string | undefined>(undefined)

/** Messages can go out: the account is made and its DIDComm is connected (it takes a moment after sign-in). */
export const composeReady = (): boolean => composeConfig.get()?.selfDid !== undefined

/** Sends the draft with `body` as its message, and goes on to the conversation it makes. Throws what the send throws. */
export async function sendComposed(body: string): Promise<void> {
  const config = composeConfig.get()
  if (!config) throw new Error('Not ready to send')
  const { to, subject } = composeDraft.get()
  const toAddrs = to.split(/[,\s]+/).map(address => address.trim()).filter(Boolean)
  if (toAddrs.length === 0) throw new Error('At least one recipient is required')
  if (!body.trim()) throw new Error('Message cannot be empty')
  if (!config.selfDid) throw new Error('DIDComm is not set up on this identity yet')
  await config.sendMessage({ toAddrs, subject: subject.trim(), body: body.trim() })
  resetComposeDraft()
  setPage('thread')
}

/** Sends one message to the given addresses, with no draft in it (what the helper's commands use). Throws what the send throws. */
export async function sendMessageTo(toAddrs: string[], body: string): Promise<void> {
  const config = composeConfig.get()
  if (!config) throw new Error('Not ready to send')
  if (!config.selfDid) throw new Error('DIDComm is not set up on this identity yet')
  await config.sendMessage({ toAddrs, subject: '', body })
}

/** Sends the draft once the account can: it waits for DIDComm to be set up, and tries again while the part that sends is still coming up
 * (it follows the sign-in by seconds, and says "still connecting" until then). Throws what the send throws, or that it never could. */
export async function sendComposedWhenReady(body: string, { timeoutMs = 45_000, pollMs = 500 } = {}): Promise<void> {
  const until = Date.now() + timeoutMs
  const wait = () => new Promise(resolve => setTimeout(resolve, pollMs))
  while (!composeReady() && Date.now() < until) await wait()
  for (;;) {
    try { await sendComposed(body); return }
    catch (error) {
      if (/still connecting/.test(error instanceof Error ? error.message : String(error)) && Date.now() < until) { await wait(); continue }
      throw error
    }
  }
}

/** The page's own part: nothing yet (the conversation is empty). */
export function ComposePage() {
  const asking = useStore(signingUp)
  const held = useStore(heldIdentity)
  // Opened at the top, whatever the page before had scrolled to; and left, the sign-up is closed.
  useLayoutEffect(() => { const outer = document.getElementById('outer'); if (outer) outer.scrollTop = 0; return () => signingUp.set(false) }, [])
  // With no account, the sign-up is loaded out of sight now, so that Send can make the account at once.
  const accountless = useStore(accountConfig)?.did === null
  useEffect(() => { if (accountless) preloadSignup() }, [accountless])
  // The sign-up that is the account page's own, here: what was written waits (savePendingSend) and goes out when the account is made.
  return <div id="active-thread">{asking ? <div className="cmd-thread-card" id="focused-thread-card"><NewUserPage loginAs={held} /></div> : null}</div>
}
