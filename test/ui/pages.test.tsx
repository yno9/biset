// @vitest-environment happy-dom
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'

vi.mock('../../src/client/identity/wallet/did-md-oauth.ts', () => ({
  prepareDidMdWalletLoginRequest: vi.fn(async () => ''), completeDidMdWalletCallback: vi.fn(async () => undefined), restoreDidMdWalletSession: vi.fn(async () => undefined),
  beginDidMdWalletLogin: vi.fn(async () => {}), resolveWalletFromSuffix: vi.fn(), selectWallet: vi.fn(), currentWallet: () => ({ id: 'dito', displayName: 'dito' }),
}))
vi.mock('../../src/protocol/webvh/resolver.ts', () => ({ resolve: vi.fn(async () => ({ name: 'Alice' })) }))

import { accountConfig, type AccountPageConfig } from '../../src/client/app/ui/account/state.ts'
import { AccountPage } from '../../src/client/app/ui/pages/account-page.tsx'
import { ComposePage, configureComposePage } from '../../src/client/app/ui/pages/compose-page.tsx'
import { ConfigPage, configureMarkdownVaultToggle } from '../../src/client/app/ui/pages/config-page.tsx'
import { setPage, uiPage } from '../../src/client/app/ui/state.ts'

const DID = 'did:webvh:QmafKp1jjhnP1vjDYZs6rpQ7bk3mQBS2hQvwGbqc2UAEYi:alice.did.md'
const messages: string[] = []

beforeEach(() => {
  messages.length = 0
  for (const id of ['app', 'past-threads', 'header-thread-title', 'header-group-icon', 'conv-meta', 'reply-dock']) {
    const el = document.createElement('div'); el.id = id; document.body.append(el)
  }
})
afterEach(() => { cleanup(); document.body.innerHTML = ''; vi.restoreAllMocks(); accountConfig.set(undefined); setPage('thread') })

const account = (over: Partial<AccountPageConfig> = {}): AccountPageConfig => ({
  did: DID, wallet: { handle: 'alice.did.md', deviceJkt: 'j', capabilityExpiresAt: '2030-01-01T00:00:00Z', onDisconnect: vi.fn(async () => {}) },
  showMessage: text => { messages.push(text) }, ...over,
})

// ── page chrome ──────────────────────────────────────────────────────────────

test('a page marks the shell while it is on screen, and lets go when it leaves', () => {
  const { unmount } = render(<ConfigPage />)
  expect(document.getElementById('app')!.getAttribute('data-menu-page')).toBe('/config')
  expect(document.getElementById('header-thread-title')!.textContent).toBe('config')
  expect(document.getElementById('conv-meta')!.style.display).toBe('none')
  unmount()
  expect(document.getElementById('app')!.hasAttribute('data-menu-page')).toBe(false)
  expect(document.getElementById('conv-meta')!.style.display).toBe('')
})

// ── compose ──────────────────────────────────────────────────────────────────

const composeConfig = (over = {}) => ({ selfAddress: 'me@did.md', selfDid: 'did:webvh:QmafKp1jjhnP1vjDYZs6rpQ7bk3mQBS2hQvwGbqc2UAEYi:me.did.md', sendMessage: vi.fn(async () => {}), onError: vi.fn(), ...over })

test('compose: From is this identity\'s DID, the To row shows the transport its address uses', () => {
  configureComposePage(composeConfig())
  const { container } = render(<ComposePage />)
  expect(container.querySelector('#new-from')!.textContent).toContain('did:webvh:me.did.md')
  const input = container.querySelector<HTMLInputElement>('#new-recipients .new-field-input')!
  expect(container.querySelector('.new-recip-protos')!.textContent).toBe('')
  fireEvent.change(input, { target: { value: 'bob@did.md' } })
  expect(container.querySelector('.new-recip-protos')!.textContent).toBe('Mail')
  fireEvent.change(input, { target: { value: DID } })
  expect(container.querySelector('.new-recip-protos')!.textContent).toBe('DID')
})

test('compose: a typed did:webvh collapses to its short form on blur and is sent in full', async () => {
  const config = composeConfig()
  configureComposePage(config)
  const { container } = render(<ComposePage />)
  const input = container.querySelector<HTMLInputElement>('#new-recipients .new-field-input')!
  fireEvent.change(input, { target: { value: DID } })
  fireEvent.blur(input)
  expect(input.value).toBe('did:webvh:alice.did.md')
  fireEvent.change(container.querySelector('#new-body')!, { target: { value: ' hello ' } })
  fireEvent.click(container.querySelector('#new-send-btn')!)
  await waitFor(() => expect(config.sendMessage).toHaveBeenCalledWith({ toAddrs: [DID], subject: '', body: 'hello' }))
})

test('compose: rows can be added, and an edit drops an elided DID\'s real address', () => {
  configureComposePage(composeConfig())
  const { container } = render(<ComposePage />)
  fireEvent.click(container.querySelector('#new-add-btn')!)
  const inputs = () => container.querySelectorAll<HTMLInputElement>('#new-recipients .new-field-input')
  expect(inputs()).toHaveLength(2)
  fireEvent.change(inputs()[1]!, { target: { value: DID } })
  fireEvent.blur(inputs()[1]!)
  expect(inputs()[1]!.value).toBe('did:webvh:alice.did.md')
  fireEvent.change(inputs()[1]!, { target: { value: 'did:webvh:alice.did.m' } })
  expect(inputs()[1]!.value).toBe('did:webvh:alice.did.m')
})

test('compose: asks for a recipient, a body, and a DID to send from', async () => {
  const noDid = composeConfig({ selfDid: undefined })
  configureComposePage(noDid)
  const { container } = render(<ComposePage />)
  const send = () => fireEvent.click(container.querySelector('#new-send-btn')!)
  send(); expect(noDid.onError).toHaveBeenLastCalledWith('At least one recipient is required')
  fireEvent.change(container.querySelector('#new-recipients .new-field-input')!, { target: { value: 'bob@did.md' } })
  send(); expect(noDid.onError).toHaveBeenLastCalledWith('Message cannot be empty')
  fireEvent.change(container.querySelector('#new-body')!, { target: { value: 'x' } })
  send(); expect(noDid.onError).toHaveBeenLastCalledWith('DIDComm is not set up on this identity yet')
  expect(noDid.sendMessage).not.toHaveBeenCalled()
})

test('compose: a sent message returns to the thread; a failed one stays and says why', async () => {
  const config = composeConfig()
  configureComposePage(config)
  setPage('compose')
  const { container } = render(<ComposePage />)
  fireEvent.change(container.querySelector('#new-recipients .new-field-input')!, { target: { value: 'bob@did.md' } })
  fireEvent.change(container.querySelector('#new-body')!, { target: { value: 'x' } })
  config.sendMessage.mockRejectedValueOnce(new Error('offline'))
  fireEvent.click(container.querySelector('#new-send-btn')!)
  await waitFor(() => expect(config.onError).toHaveBeenCalledWith('offline'))
  expect(uiPage.get()).toBe('compose')
  await waitFor(() => expect((container.querySelector('#new-send-btn') as HTMLButtonElement).disabled).toBe(false))
  fireEvent.click(container.querySelector('#new-send-btn')!)
  await waitFor(() => expect(uiPage.get()).toBe('thread'))
})

// ── config ───────────────────────────────────────────────────────────────────

test('config: the vault toggle reflects and flips the markdown vault', async () => {
  ;(window as unknown as { showDirectoryPicker: () => void }).showDirectoryPicker = () => {}
  let on = false
  const vault = { enabled: () => on, observerSupported: () => false, toggle: vi.fn(async () => { on = !on }), rescan: vi.fn(async () => {}) }
  configureMarkdownVaultToggle(vault)
  const { container } = render(<ConfigPage />)
  const toggle = container.querySelector('#config-vault-toggle')!
  expect(toggle.classList.contains('on')).toBe(false)
  expect(container.querySelector('#config-vault-rescan')).toBeNull()
  fireEvent.click(toggle)
  await waitFor(() => expect(toggle.classList.contains('on')).toBe(true))
  fireEvent.click(container.querySelector('#config-vault-rescan')!)
  expect(vault.rescan).toHaveBeenCalled()
  delete (window as unknown as { showDirectoryPicker?: unknown }).showDirectoryPicker
})

// ── account ──────────────────────────────────────────────────────────────────

test('account: the identity card shows the domain, then the name the DID document gives', async () => {
  accountConfig.set(account())
  const { container } = render(<AccountPage />)
  expect(container.querySelector('#cmd-acc-identity-did')!.textContent).toBe('did:webvh:alice.did.md')
  expect(container.querySelector('#cmd-acc-identity-avatar')!.textContent).toBe('A')
  await waitFor(() => expect(container.querySelector('#cmd-acc-identity-name')!.textContent).toBe('Alice'))
  expect(container.querySelector('#cmd-acc-capability-expiry')!.textContent).toMatch(/^~ /)
})

test('account: the card opens on click and reads the DID document once', async () => {
  const { resolve } = await import('../../src/protocol/webvh/resolver.ts')
  vi.mocked(resolve).mockResolvedValue({ id: DID, name: 'Alice' } as never)
  accountConfig.set(account())
  const { container } = render(<AccountPage />)
  const section = container.querySelector('#cmd-acc-identity-section')!
  const callsBefore = vi.mocked(resolve).mock.calls.length
  fireEvent.click(container.querySelector('#cmd-acc-identity-fields')!)
  expect(section.classList.contains('expanded')).toBe(true)
  await waitFor(() => expect(container.querySelector('#cmd-acc-identity-doc')!.textContent).toContain('"name": "Alice"'))
  fireEvent.click(container.querySelector('#cmd-acc-identity-fields')!)
  fireEvent.click(container.querySelector('#cmd-acc-identity-fields')!)
  expect(vi.mocked(resolve).mock.calls.length).toBe(callsBefore + 1)
  fireEvent.click(container.querySelector('#cmd-acc-identity-sync-btn')!)
  await waitFor(() => expect(vi.mocked(resolve).mock.calls.length).toBe(callsBefore + 2))
})

test('account: clicking the DID copies it and says so', async () => {
  const writeText = vi.fn(async () => {})
  Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
  accountConfig.set(account())
  const { container } = render(<AccountPage />)
  fireEvent.click(container.querySelector('#cmd-acc-identity-did-row')!)
  expect(writeText).toHaveBeenCalledWith(DID)
  await waitFor(() => expect(messages).toContain('DID copied'))
})

test('account: the identity menu disconnects only after a confirmation', () => {
  const onDisconnect = vi.fn(async () => {})
  accountConfig.set(account({ wallet: { handle: 'alice.did.md', deviceJkt: 'j', capabilityExpiresAt: '2030-01-01T00:00:00Z', onDisconnect } }))
  const { container } = render(<AccountPage />)
  fireEvent.click(container.querySelector('#cmd-acc-identity-menu-btn')!)
  vi.spyOn(window, 'confirm').mockReturnValueOnce(false)
  fireEvent.click(screen.getByText('Disconnect Wallet'))
  expect(onDisconnect).not.toHaveBeenCalled()
  fireEvent.click(container.querySelector('#cmd-acc-identity-menu-btn')!)
  vi.spyOn(window, 'confirm').mockReturnValueOnce(true)
  fireEvent.click(screen.getByText('Disconnect Wallet'))
  expect(onDisconnect).toHaveBeenCalled()
})

test('account: the compose button opens the compose page', () => {
  configureComposePage(composeConfig())
  accountConfig.set(account())
  const { container } = render(<AccountPage />)
  fireEvent.click(container.querySelector('#cmd-acc-compose-fab')!)
  expect(uiPage.get()).toBe('compose')
})

test('account: with no identity the page is the sign-up form', () => {
  accountConfig.set(account({ did: null }))
  const { container } = render(<AccountPage />)
  expect(container.querySelector('#new-user-page')).not.toBeNull()
  expect(container.querySelector('#cmd-acc-identity-section')).toBeNull()
})
