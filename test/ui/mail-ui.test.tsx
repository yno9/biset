// @vitest-environment happy-dom
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import type { ProcessedMessage } from '../../src/client/app/ui/message/message-view.ts'
import { HamburgerMenu } from '../../src/client/app/ui/hamburger-menu.tsx'
import { LeftPane } from '../../src/client/app/ui/left-pane.tsx'
import { accountConfig } from '../../src/client/app/ui/account/state.ts'
import { ReplyBox, composeConfig, type ComposeConfig } from '../../src/client/app/ui/reply-box.tsx'
import { RightCol } from '../../src/client/app/ui/right-col.tsx'
import { refreshInbox, showApp } from '../../src/client/app/ui/shell.ts'
import { setPage, uiPage } from '../../src/client/app/ui/state.ts'
import { mail, shell } from '../../src/client/app/ui/stores.ts'

const ME = 'me@did.md'
const T0 = Date.parse('2026-10-16T12:00:00Z')
let id = 0
const message = (over: Partial<ProcessedMessage['msg']> & { body?: string }): ProcessedMessage => {
  const n = ++id
  const body = over.body ?? `body ${n}`
  return { bodyText: body, msg: { from: 'bob@did.md', from_name: 'Bob', body, subject: '', ts: T0 - (1000 - n) * 60_000, message_id: `m${n}`, jmap_id: `j${n}`, in_reply_to: '', thread_id: `T${n}`, seen: true, ...over } }
}
const setMessages = (messages: ProcessedMessage[]) => act(() => mail.set({ messages }))
const config = (over: Partial<ComposeConfig> = {}): ComposeConfig => ({ selfAddress: ME, sendReply: vi.fn(async () => {}), onError: vi.fn(), ...over })

const store = new Map<string, string>()
beforeEach(() => {
  id = 0
  store.clear()
  vi.stubGlobal('localStorage', { getItem: (k: string) => store.get(k) ?? null, setItem: (k: string, v: string) => { store.set(k, v) }, removeItem: (k: string) => { store.delete(k) } })
  Element.prototype.scrollIntoView = vi.fn()
  window.HTMLElement.prototype.scrollTo = vi.fn() as never
  Object.defineProperty(window, 'innerWidth', { value: 1200, configurable: true, writable: true })
  act(() => {
    mail.set({ messages: [] })
    shell.set({ appShown: true, singleCol: false, showLeft: false, search: '', focusedThreadKey: null, expandedInboxKeys: new Set(), lpFocusedKey: null })
    composeConfig.set(config())
  })
})
afterEach(() => { cleanup(); document.body.innerHTML = ''; vi.unstubAllGlobals(); act(() => { setPage('thread'); composeConfig.set(undefined); accountConfig.set(undefined) }); vi.restoreAllMocks() })

const app = (ui: React.ReactNode) => render(<div id="app">{ui}</div>)

// ── the thread ───────────────────────────────────────────────────────────────

test('the newest thread is open by default, with its subject as the title', () => {
  setMessages([message({ subject: 'Old', thread_id: 'A', ts: T0 - 5 * 3600_000 }), message({ subject: 'Fresh', thread_id: 'B', body: 'newest', ts: T0 })])
  const { container } = app(<RightCol />)
  expect(container.querySelector('#header-thread-title')!.textContent).toBe('Fresh')
  expect(container.querySelector('.t-body')!.textContent).toBe('newest')
})

test('a thread with no subject is "no title", marked untitled; with nothing at all too', () => {
  const { container } = app(<RightCol />)
  expect(container.querySelector('#header-thread-title')!.textContent).toBe('no title')
  expect(container.querySelector('#header-thread-title')!.className).toBe('untitled')
  expect(container.querySelector('#active-thread svg')).not.toBeNull()
  expect(container.querySelector('.reply-box')).toBeNull()
})

test('a message body is text: markup in it is shown, not run, and links are links', () => {
  setMessages([message({ body: '<img src=x onerror=alert(1)> see https://example.com/a & more\n> quoted line' })])
  const { container } = app(<RightCol />)
  const body = container.querySelector('.t-body')!
  expect(body.querySelector('img')).toBeNull()
  expect(body.textContent).toContain('<img src=x onerror=alert(1)>')
  expect(body.querySelector('a')!.getAttribute('href')).toBe('https://example.com/a')
  expect(body.textContent).not.toContain('quoted line')
})

test('a DIDComm sender is shown by its short name; badges mark what is wrong with a mail', () => {
  setMessages([message({ from: 'did:webvh:QmafKp1jjhnP1vjDYZs6rpQ7bk3mQBS2hQvwGbqc2UAEYi:dave.did.md', from_name: 'did:webvh:QmafKp1jjhnP1vjDYZs6rpQ7bk3mQBS2hQvwGbqc2UAEYi:dave.did.md', thread_id: 'D' }),
    message({ auth: { dmarc: 'fail', domain: 'evil.example' } as never, edited: true, undelivered: [{ to: 'bob@did.md', code: 'x', reason: 'mailbox full' }], reactions: [{ from: 'a', emoji: '👍' }], sourceUrl: 'javascript:alert(1)', thread_id: 'E', ts: T0 + 1000 })])
  const { container, rerender } = app(<RightCol />)
  expect(container.querySelector('.t-sender')!.textContent).toBe('Bob')
  expect(container.querySelector('.t-unverified')!.getAttribute('title')).toContain('evil.example')
  expect(container.querySelector('.t-edited')).not.toBeNull()
  expect(container.querySelector('.t-undelivered')!.getAttribute('title')).toContain('mailbox full')
  expect(container.querySelector('.t-reaction-chip')!.textContent).toBe('👍')
  expect(container.querySelector('.t-source-link')).toBeNull()
  act(() => shell.set({ ...shell.get(), focusedThreadKey: 'D' }))
  rerender(<div id="app"><RightCol /></div>)
  expect(container.querySelector('.t-sender')!.textContent).toBe('dave')
})

test('only the latest 100 messages show; "Show older" adds a hundred more', () => {
  setMessages(Array.from({ length: 230 }, (_, i) => message({ thread_id: 'LONG', ts: T0 + i, body: `n${i}` })))
  const { container } = app(<RightCol />)
  expect(container.querySelectorAll('.t-msg')).toHaveLength(100)
  expect(container.querySelector('.t-msg .t-body')!.textContent).toBe('n130')
  fireEvent.click(screen.getByText('Show older (130 more)'))
  expect(container.querySelectorAll('.t-msg')).toHaveLength(200)
  fireEvent.click(screen.getByText('Show older (30 more)'))
  expect(container.querySelectorAll('.t-msg')).toHaveLength(230)
  expect(container.querySelector('.t-load-older')).toBeNull()
})

test('the row\'s other threads are listed above the open one, oldest first; a click opens one', () => {
  setMessages([
    message({ subject: 'First', thread_id: 'A', ts: T0 - 3000 }), message({ subject: 'Second', thread_id: 'B', ts: T0 - 2000 }),
    message({ subject: 'Third', thread_id: 'C', ts: T0 - 1000 }), message({ from: 'carol@did.md', subject: 'Other person', thread_id: 'X', ts: T0 - 4000 }),
  ])
  const { container } = app(<RightCol />)
  expect([...container.querySelectorAll('.past-row-title')].map(e => e.textContent)).toEqual(['First', 'Second'])
  fireEvent.click(container.querySelector('.past-row-header')!)
  expect(container.querySelector('#header-thread-title')!.textContent).toBe('First')
})

test('a thread shows who it is with, over which transport, and its headers on a click', () => {
  setMessages([message({ subject: 'Hi', from: 'bob@did.md' }), message({ from: ME, from_name: 'me', thread_id: 'T1', in_reply_to: '' })])
  const { container } = app(<RightCol />)
  const meta = container.querySelector('#conv-meta')!
  expect(meta.querySelector('#conv-via')!.textContent).toBe('Mail')
  expect(meta.querySelector('#conv-to')!.textContent).toContain('bob@did.md')
  expect(meta.classList.contains('expanded')).toBe(false)
  fireEvent.click(meta.querySelector('#conv-fields')!)
  expect(meta.classList.contains('expanded')).toBe(true)
  expect(meta.querySelector('#conv-meta-expanded')!.textContent).toContain('participants: bob@did.md')
})

test('a group chat is titled by its name and lists its members', async () => {
  const G = 'didcomm-group:g1'
  const did = (n: string) => `did:webvh:QmafKp1jjhnP1vjDYZs6rpQ7bk3mQBS2hQvwGbqc2UAEYi:${n}.did.md`
  act(() => composeConfig.set(config({ selfDid: did('me'), didcommGroup: { groupName: async () => 'Book club', membersOf: async () => [did('me'), did('zed'), did('amy')] } })))
  setMessages([message({ from: did('zed'), from_name: did('zed'), thread_id: G, subject: 'subject' })])
  const { container } = app(<RightCol />)
  await waitFor(() => expect(container.querySelector('#header-thread-title')!.textContent).toBe('Book club'))
  await waitFor(() => expect([...container.querySelectorAll('.conv-member-chip')].map(e => e.textContent)).toEqual(['zed', 'amy']))
})

test('other pages take the title and hide the thread\'s own furniture', () => {
  setMessages([message({ subject: 'Hi' })])
  const { container } = app(<RightCol />)
  act(() => setPage('config'))
  expect(container.querySelector('#header-thread-title')!.textContent).toBe('config')
  expect((container.querySelector('#conv-meta') as HTMLElement).style.display).toBe('none')
  expect(container.querySelector('.reply-box')).toBeNull()
  expect(container.querySelector('#past-threads')!.children).toHaveLength(0)
  expect(uiPage.get()).toBe('config')
})

// ── the reply box ────────────────────────────────────────────────────────────

const thread = () => ({ key: 'T', subject: 'Re', messages: [message({ from: 'bob@did.md', message_id: 'mid1', thread_id: 'T' })] })

test('a reply goes to the other side, in the thread, and the box empties', async () => {
  const cfg = config(); act(() => composeConfig.set(cfg))
  const { container } = render(<ReplyBox group={thread()} />)
  const area = container.querySelector('textarea')!
  fireEvent.change(area, { target: { value: '  thanks  ' } })
  fireEvent.click(container.querySelector('.t-send-btn')!)
  await waitFor(() => expect(cfg.sendReply).toHaveBeenCalledWith(expect.objectContaining({ toAddrs: ['bob@did.md'], subject: 'Re', body: 'thanks', inReplyTo: 'mid1' })))
  await waitFor(() => expect(area.value).toBe(''))
})

test('Ctrl+Enter sends; an empty box does not', async () => {
  const cfg = config(); act(() => composeConfig.set(cfg))
  const { container } = render(<ReplyBox group={thread()} />)
  const area = container.querySelector('textarea')!
  fireEvent.keyDown(area, { key: 'Enter', ctrlKey: true })
  expect(cfg.sendReply).not.toHaveBeenCalled()
  fireEvent.change(area, { target: { value: 'x' } })
  fireEvent.keyDown(area, { key: 'Enter' })
  expect(cfg.sendReply).not.toHaveBeenCalled()
  fireEvent.keyDown(area, { key: 'Enter', ctrlKey: true })
  await waitFor(() => expect(cfg.sendReply).toHaveBeenCalledTimes(1))
})

test('a failed reply puts the text back and says why', async () => {
  const cfg = config({ sendReply: vi.fn(async () => { throw new Error('offline') }) }); act(() => composeConfig.set(cfg))
  const { container } = render(<ReplyBox group={thread()} />)
  const area = container.querySelector('textarea')!
  fireEvent.change(area, { target: { value: 'keep me' } })
  fireEvent.click(container.querySelector('.t-send-btn')!)
  await waitFor(() => expect(cfg.onError).toHaveBeenCalledWith('offline'))
  await waitFor(() => expect(area.value).toBe('keep me'))
  expect(area.disabled).toBe(false)
})

test('what is typed survives a refresh of the messages and a switch of thread', () => {
  setMessages([message({ thread_id: 'A', subject: 'A' }), message({ thread_id: 'B', subject: 'B', from: 'carol@did.md' })])
  const { container } = app(<RightCol />)
  fireEvent.change(container.querySelector('#reply-dock textarea')!, { target: { value: 'draft' } })
  setMessages([...mail.get().messages, message({ thread_id: 'A', from: 'bob@did.md' })])
  act(() => shell.set({ ...shell.get(), focusedThreadKey: 'A' }))
  expect((container.querySelector('#reply-dock textarea') as HTMLTextAreaElement).value).toBe('draft')
})

// ── the left pane ────────────────────────────────────────────────────────────

const people = () => setMessages([
  message({ from: 'bob@did.md', from_name: 'Bob', subject: 'Lunch', thread_id: 'L1', ts: T0 - 3000, seen: false }),
  message({ from: 'bob@did.md', from_name: 'Bob', subject: 'Plans', thread_id: 'L2', ts: T0 - 2000 }),
  message({ from: 'carol@did.md', from_name: 'Carol', subject: 'Hello', thread_id: 'H1', ts: T0 - 1000 }),
])

test('one row per person, newest first, with an unread dot; the open thread\'s row is current', () => {
  people()
  const { container } = app(<LeftPane />)
  const rows = container.querySelectorAll('.lp-item')
  expect(rows).toHaveLength(2)
  expect(rows[0]!.querySelector('.lp-name')!.textContent).toBe('Carol') // who the row is with; the thread's subject is under it
  expect(rows[0]!.classList.contains('current')).toBe(true)
  expect(rows[1]!.querySelector('.unread-dot')).not.toBeNull()
  expect(rows[1]!.querySelector('.lp-name')!.textContent).toBe('Bob')
})

test('the filter hides rows that do not match, and Escape clears it', () => {
  people()
  const { container } = app(<LeftPane />)
  const box = container.querySelector<HTMLInputElement>('#lp-search')!
  fireEvent.change(box, { target: { value: 'plan' } })
  const shown = () => [...container.querySelectorAll<HTMLElement>('.lp-item')].filter(e => e.style.display !== 'none').length
  expect(shown()).toBe(1)
  fireEvent.keyDown(box, { key: 'Escape' })
  expect(box.value).toBe('')
  expect(shown()).toBe(2)
})

test('a click opens a row and its newest thread; the arrow toggles it without navigating', () => {
  people()
  const { container } = app(<LeftPane />)
  const bob = container.querySelectorAll('.lp-item')[1] as HTMLElement
  fireEvent.click(bob)
  expect(shell.get().focusedThreadKey).toBe('L2')
  expect(bob.querySelectorAll('.lp-thread-row')).toHaveLength(2)
  act(() => shell.set({ ...shell.get(), focusedThreadKey: 'H1' }))
  fireEvent.click(bob.querySelector('.lp-thread-toggle')!)
  expect(bob.querySelectorAll('.lp-thread-row')).toHaveLength(0)
  expect(shell.get().focusedThreadKey).toBe('H1')
})

test('a thread row opens that thread', () => {
  people()
  const { container } = app(<LeftPane />)
  fireEvent.click(container.querySelectorAll('.lp-item')[1]!)
  fireEvent.click(container.querySelector('[data-thread-key="L1"]')!)
  expect(shell.get().focusedThreadKey).toBe('L1')
})

test('on a narrow screen a tap opens the newest thread and leaves the pane', () => {
  Object.defineProperty(window, 'innerWidth', { value: 400, configurable: true, writable: true })
  people()
  act(() => shell.set({ ...shell.get(), showLeft: true }))
  const { container } = app(<LeftPane />)
  fireEvent.click(container.querySelectorAll('.lp-item')[1]!)
  expect(shell.get().focusedThreadKey).toBe('L2')
  expect(shell.get().showLeft).toBe(false)
  expect(shell.get().expandedInboxKeys.size).toBe(0)
})

test('opening a thread leaves a menu page', () => {
  people()
  act(() => setPage('account'))
  const { container } = app(<LeftPane />)
  fireEvent.click(container.querySelectorAll('.lp-item')[0]!)
  expect(uiPage.get()).toBe('thread')
})

test('the arrow keys walk the rows and Space opens or closes the open row', () => {
  people()
  const { container } = app(<LeftPane />)
  fireEvent.click(container.querySelectorAll('.lp-item')[0]!)
  expect(shell.get().focusedThreadKey).toBe('H1')
  fireEvent.keyDown(document, { key: 'ArrowDown' })
  expect(shell.get().focusedThreadKey).toBe('L2')
  fireEvent.keyDown(document, { key: 'ArrowUp' })
  expect(shell.get().focusedThreadKey).toBe('H1')
  fireEvent.keyDown(document, { key: ' ' })
  expect(shell.get().expandedInboxKeys.size).toBe(0)
})

test('keys are left alone while typing in a box', () => {
  people()
  const { container } = app(<><LeftPane /><textarea id="ta" /></>)
  fireEvent.click(container.querySelectorAll('.lp-item')[0]!)
  container.querySelector<HTMLTextAreaElement>('#ta')!.focus()
  fireEvent.keyDown(document, { key: 'ArrowDown' })
  expect(shell.get().focusedThreadKey).toBe('H1')
})

test('the pane toggle collapses and reopens it, and remembers on a wide screen', () => {
  const { container } = app(<LeftPane />)
  fireEvent.click(container.querySelector('#main-toggle')!)
  expect(shell.get().singleCol).toBe(true)
  expect(store.get('lp-open')).toBe('0')
  fireEvent.click(container.querySelector('#main-toggle')!)
  expect(shell.get().singleCol).toBe(false)
  expect(store.get('lp-open')).toBe('1')
})

// ── the shell ────────────────────────────────────────────────────────────────

test('the menu opens under its button and goes to the page chosen', () => {
  accountConfig.set({ did: 'did:webvh:QmafKp1jjhnP1vjDYZs6rpQ7bk3mQBS2hQvwGbqc2UAEYi:me.did.md' } as never)
  const { container } = app(<><RightCol /><HamburgerMenu /></>)
  const menu = container.querySelector('#lp-hamburger-menu')!
  expect(menu.classList.contains('open')).toBe(false)
  fireEvent.click(container.querySelector('#lp-hamburger')!)
  expect(menu.classList.contains('open')).toBe(true)
  fireEvent.click(within(menu as HTMLElement).getByText('config'))
  expect(uiPage.get()).toBe('config')
  expect(menu.classList.contains('open')).toBe(false)
})

test('showApp shows the UI once; a refresh replaces the messages, one after another', async () => {
  act(() => shell.set({ ...shell.get(), appShown: false }))
  showApp()
  expect(shell.get().appShown).toBe(true)
  const order: string[] = []
  const model = (name: string, delay: number, subject: string) => ({
    async snapshot() { await new Promise(r => setTimeout(r, delay)); order.push(name); return { emails: [{ id: name, blobId: name, threadId: name, mailboxIds: {}, keywords: {}, receivedAt: '2026-10-16T00:00:00Z', subject }] } as never },
    async download() { return new TextEncoder().encode(`Subject: ${subject}\r\nMessage-ID: <${name}@x>\r\n\r\nhello ${name}\r\n`) },
  })
  const slow = refreshInbox(model('slow', 40, 'S'))
  const fast = refreshInbox(model('fast', 0, 'F'))
  await Promise.all([slow, fast])
  expect(order).toEqual(['slow', 'fast'])
  expect(mail.get().messages.map(p => p.msg.jmap_id)).toEqual(['fast'])
})
