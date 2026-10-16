// The compose page (src.bak's #compose, ported): a recipient list, the From the recipients decide,
// a subject and a body. A message goes out over exactly one transport, decided by the first filled
// recipient (DIDComm for a DID, and for a mail address its DID); "From" is never a manual choice.
import { useEffect, useRef, useState } from 'react'
import { createStore, useStore } from '../../react/store.ts'
import { shortWebvhDid, protocolFor, PROTO_COLOR, PROTO_TEXT } from '../did-display.ts'
import type { ReplySendInput } from '../thread.ts'
import type { Proto } from '../did-display.ts'
import { setPage } from '../state.ts'
import { usePageChrome } from './page-chrome.ts'

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

/** One "To" row: what is typed, and the real address when the field shows an elided DID. */
interface Recipient { id: number; text: string; fullDid?: string }

const addressOf = (row: Recipient): string => (row.fullDid || row.text).trim()
const badge = (proto: Proto) => (
  <span style={{ fontSize: 10, fontWeight: 700, color: '#fff', borderRadius: 4, padding: '1px 5px', marginRight: 6, flexShrink: 0, background: PROTO_COLOR[proto] }}>{PROTO_TEXT[proto]}</span>
)

export function ComposePage() {
  const config = useStore(composeConfig)
  usePageChrome('compose')
  const [rows, setRows] = useState<Recipient[]>([{ id: 0, text: '' }])
  const [subject, setSubject] = useState('')
  const [body, setBody] = useState('')
  const [sending, setSending] = useState(false)
  const nextId = useRef(1)
  const lastInput = useRef<HTMLInputElement>(null)
  const focusNewRow = useRef(false)

  useEffect(() => { document.querySelector<HTMLInputElement>('#new-recipients .new-field-input')?.focus() }, [])
  useEffect(() => {
    if (!focusNewRow.current) return
    focusNewRow.current = false
    lastInput.current?.focus()
  }, [rows.length])

  if (!config) return null

  const update = (id: number, change: (row: Recipient) => Recipient) => setRows(current => current.map(row => row.id === id ? change(row) : row))

  // Every send goes from this identity's DID (a mail address is only another name for a recipient's DID).
  const fromAddress = config.selfDid ?? config.selfAddress

  const send = async () => {
    if (sending) return
    const toAddrs = rows.map(addressOf).filter(Boolean)
    const text = body.trim()
    if (toAddrs.length === 0) { config.onError?.('At least one recipient is required'); return }
    if (!text) { config.onError?.('Message cannot be empty'); return }
    if (!config.selfDid) { config.onError?.('DIDComm is not set up on this identity yet'); return }
    setSending(true)
    try {
      await config.sendMessage({ toAddrs, subject: subject.trim(), body: text })
      setPage('thread')
    } catch (error) {
      config.onError?.(error instanceof Error ? error.message : 'Could not send')
      setSending(false)
    }
  }

  return (
    <div id="active-thread">
      <div className="cmd-thread-card" id="focused-thread-card">
        <div className="cmd-page-content compose-page">
          <div className="new-compose-card">
            <div className="new-compose-field">
              <div id="new-recipients" className="new-recipients-list">
                {rows.map((row, index) => {
                  const address = addressOf(row)
                  const proto = address ? protocolFor(address) : undefined
                  return (
                    <div key={row.id} className="new-recipient-row" data-kind={index === 0 ? 'to' : undefined}>
                      <span className="new-field-label">{index === 0 ? 'To' : ''}</span>
                      <span className="new-recip-protos">
                        {proto ? <span style={{ fontSize: 10, fontWeight: 700, color: '#fff', borderRadius: 4, padding: '1px 5px', marginRight: 6, flexShrink: 0, background: PROTO_COLOR[proto] }}
                          title={proto === 'did' ? 'Sends over DIDComm' : 'Sends over DIDComm, to the DID this address names (its own domain or a mail gateway answers)'}>{PROTO_TEXT[proto]}</span> : null}
                      </span>
                      <input ref={index === rows.length - 1 ? lastInput : undefined} className="new-field-input" type="email" placeholder="recipient@example.com" autoComplete="off"
                        value={row.fullDid ? shortWebvhDid(row.fullDid) : row.text}
                        // A manual edit always clears an elided DID's real address.
                        onChange={event => update(row.id, current => ({ id: current.id, text: event.target.value }))}
                        // A typed did:webvh collapses to its elided form once the field is left.
                        onBlur={() => update(row.id, current => {
                          const full = addressOf(current)
                          return full.startsWith('did:webvh:') ? { id: current.id, text: shortWebvhDid(full), fullDid: full } : { id: current.id, text: full ? full : current.text }
                        })} />
                      {index === 0 ? <button id="new-add-btn" className="new-compose-add-btn" tabIndex={-1} style={{ fontSize: 18, padding: '0 4px', lineHeight: 1 }}
                        onClick={() => { focusNewRow.current = true; setRows(current => [...current, { id: nextId.current++, text: '' }]) }}>+</button> : null}
                    </div>
                  )
                })}
              </div>
            </div>
            <div id="new-from-field" className="new-compose-field" style={{ alignItems: 'center' }}>
              <span className="new-field-label">From</span>
              <button type="button" id="new-from" className="new-field-input new-from-btn">
                {badge('did')}
                <span style={{ whiteSpace: 'nowrap', minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis' }} title={fromAddress}>{shortWebvhDid(fromAddress)}</span>
              </button>
            </div>
            <div id="new-title-field" className="new-compose-field">
              <span id="new-title-label" className="new-field-label">Subject</span>
              <input id="new-title" className="new-field-input" placeholder="(no subject)" autoComplete="off" value={subject} onChange={event => setSubject(event.target.value)} />
            </div>
            <div className="new-compose-body-field">
              <span className="new-field-label">Body</span>
              <textarea id="new-body" placeholder="Write a message…" value={body} onChange={event => setBody(event.target.value)} />
            </div>
            <div className="new-compose-actions" style={{ justifyContent: 'flex-end' }}>
              <button id="new-attach-btn" className="reply-attach-btn" type="button" title="Attach file">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48" /></svg>
              </button>
              <button id="new-send-btn" className="t-send-btn always-send" title="Send" disabled={sending} onClick={() => { void send() }}>
                <svg viewBox="0 0 24 24"><path d="M2 12L22 2L12 22L10 14L2 12Z" /></svg>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
