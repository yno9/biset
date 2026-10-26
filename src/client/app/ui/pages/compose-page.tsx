// The compose page is a conversation that has not begun: the island at the top (ui/right-col.tsx) takes the recipient and the
// subject where an open conversation shows who it is with and its title, the reply box takes the message, and the page itself is
// the empty conversation. This module holds what the island and the reply box share (the draft), and sends it.
import { useLayoutEffect } from 'react'
import { createStore } from '../../react/store.ts'
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

/** The page's own part: nothing yet (the conversation is empty). */
export function ComposePage() {
  // Opened at the top, whatever the page before had scrolled to.
  useLayoutEffect(() => { const outer = document.getElementById('outer'); if (outer) outer.scrollTop = 0 }, [])
  return <div id="active-thread" />
}
