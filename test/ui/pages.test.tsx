// @vitest-environment happy-dom
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'

vi.mock('../../src/client/identity/wallet/did-md-oauth.ts', () => ({
  prepareDidMdWalletLoginRequest: vi.fn(async () => ''), completeDidMdWalletCallback: vi.fn(async () => undefined), restoreDidMdWalletSession: vi.fn(async () => undefined),
  beginDidMdWalletLogin: vi.fn(async () => {}), resolveWalletFromSuffix: vi.fn(), selectWallet: vi.fn(), currentWallet: () => ({ id: 'dito', displayName: 'dito' }),
}))
vi.mock('../../src/client/app/ui/account/profile.ts', async importOriginal => ({ ...await importOriginal<typeof import('../../src/client/app/ui/account/profile.ts')>(), chooseImage: vi.fn(async () => new File(['x'], 'me.png', { type: 'image/png' })) }))
vi.mock('../../src/client/app/ui/account/avatar-crop.tsx', async importOriginal => ({ ...await importOriginal<typeof import('../../src/client/app/ui/account/avatar-crop.tsx')>(), cropAvatar: vi.fn(async () => 'data:image/jpeg;base64,/9j/AAAA') }))
vi.mock('../../src/protocol/webvh/resolver.ts', () => ({ resolve: vi.fn(async () => ({ name: 'Alice' })) }))

import { accountConfig, type AccountPageConfig } from '../../src/client/app/ui/account/state.ts'
import { AccountPage } from '../../src/client/app/ui/pages/account-page.tsx'
import { ComposePage, configureComposePage } from '../../src/client/app/ui/pages/compose-page.tsx'
import { DisplayNameDialog } from '../../src/client/app/ui/account/display-name-dialog.tsx'
import { ConfigPanel, configureMarkdownVaultToggle } from '../../src/client/app/ui/pages/config-page.tsx'
import { setPage, uiPage } from '../../src/client/app/ui/state.ts'

const DID = 'did:webvh:QmafKp1jjhnP1vjDYZs6rpQ7bk3mQBS2hQvwGbqc2UAEYi:alice.did.md'
const messages: string[] = []

beforeEach(() => {
  messages.length = 0
  for (const id of ['app', 'past-threads', 'header-thread-title', 'header-group-icon', 'conv-meta', 'reply-dock']) {
    const el = document.createElement('div'); el.id = id; document.body.append(el)
  }
})
afterEach(() => { fireEvent.keyDown(document, { key: 'Escape' }); cleanup(); document.body.innerHTML = ''; vi.restoreAllMocks(); accountConfig.set(undefined); setPage('thread') })

const account = (over: Partial<AccountPageConfig> = {}): AccountPageConfig => ({
  did: DID, wallet: { handle: 'alice.did.md', deviceJkt: 'j', capabilityExpiresAt: '2030-01-01T00:00:00Z', onDisconnect: vi.fn(async () => {}) },
  showMessage: text => { messages.push(text) }, ...over,
})

// ── compose ──────────────────────────────────────────────────────────────────

const composeConfig = (over = {}) => ({ selfAddress: 'me@did.md', selfDid: 'did:webvh:QmafKp1jjhnP1vjDYZs6rpQ7bk3mQBS2hQvwGbqc2UAEYi:me.did.md', sendMessage: vi.fn(async () => {}), onError: vi.fn(), ...over })

test('compose: From is this identity\'s DID, the To row shows the transport its address uses', () => {
  configureComposePage(composeConfig())
  const { container } = render(<ComposePage />)
  expect(container.querySelector('#new-from')!.textContent).toContain('me@did.md')
  const input = container.querySelector<HTMLInputElement>('#new-recipients .new-field-input')!
  expect(container.querySelector('.new-recip-protos')!.textContent).toBe('')
  fireEvent.change(input, { target: { value: 'bob@did.md' } })
  expect(container.querySelector('.new-recip-protos')!.textContent).toBe('Mail')
  fireEvent.change(input, { target: { value: DID } })
  expect(container.querySelector('.new-recip-protos')!.textContent).toBe('DID')
})

test('compose: a typed did:webvh shows as its address on blur and is sent as the DID', async () => {
  const config = composeConfig()
  configureComposePage(config)
  const { container } = render(<ComposePage />)
  const input = container.querySelector<HTMLInputElement>('#new-recipients .new-field-input')!
  fireEvent.change(input, { target: { value: DID } })
  fireEvent.blur(input)
  expect(input.value).toBe('alice@did.md')
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
  expect(inputs()[1]!.value).toBe('alice@did.md')
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

test('config tab: the vault toggle reflects and flips the markdown vault', async () => {
  ;(window as unknown as { showDirectoryPicker: () => void }).showDirectoryPicker = () => {}
  let on = false
  const vault = { enabled: () => on, observerSupported: () => false, toggle: vi.fn(async () => { on = !on }), rescan: vi.fn(async () => {}) }
  configureMarkdownVaultToggle(vault)
  const { container } = render(<ConfigPanel />)
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

test('account: the identity card shows the DID, then the name the DID document gives', async () => {
  accountConfig.set(account())
  const { container } = render(<AccountPage />)
  expect(container.querySelector('#cmd-acc-identity-did')!.textContent).toBe(DID)
  // no picture: a generated avatar (boringavatars.com) drawn from the name, not an initial
  expect(container.querySelector('#cmd-acc-identity-avatar .avatar-generated svg')).not.toBeNull()
  await waitFor(() => expect(container.querySelector('#cmd-acc-identity-name')!.textContent).toBe('Alice'))
  expect(container.querySelector('#cmd-acc-capability-expiry')).toBeNull() // the identity card shows no expiry date any more
})

test('account: clicking the avatar asks for a picture and sets it, without opening the card; no profile, no click', async () => {
  const profile = { current: vi.fn(async () => ({})), setName: vi.fn(async () => {}), setAvatar: vi.fn(async () => {}) }
  accountConfig.set(account({ profile }))
  const { container } = render(<AccountPage />)
  fireEvent.click(container.querySelector('#cmd-acc-identity-avatar')!)
  await waitFor(() => expect(profile.setAvatar).toHaveBeenCalledWith('data:image/jpeg;base64,/9j/AAAA')) // the picture chosen, then cropped
  expect(container.querySelector('#cmd-acc-identity-section')!.classList.contains('expanded')).toBe(false)
  cleanup()
  accountConfig.set(account())
  const bare = render(<AccountPage />)
  expect(bare.container.querySelector('#cmd-acc-identity-avatar')!.getAttribute('role')).toBeNull()
})

test('account: the identity card has no menu button and no clickable DID panel', () => {
  accountConfig.set(account())
  const { container } = render(<AccountPage />)
  expect(container.querySelector('#cmd-acc-identity-menu-btn')).toBeNull()
  fireEvent.click(container.querySelector('#cmd-acc-identity-fields')!)
  expect(container.querySelector('#cmd-acc-identity-expanded')).toBeNull()
})

test('account: the display name is asked for in a card; Esc or a click outside closes it, Save sets it', async () => {
  const setName = vi.fn(async () => {})
  const profile = { current: async () => ({}), setName, setAvatar: async () => {} }
  accountConfig.set(account({ profile }))
  const { container } = render(<><AccountPage /><DisplayNameDialog /></>)
  const card = () => container.querySelector('dialog#display-name-dialog') as HTMLDialogElement
  const input = () => container.querySelector('#display-name-input') as HTMLInputElement
  fireEvent.click(await screen.findByText('Set display name'))
  await waitFor(() => expect(card().open).toBe(true))
  // Esc (the dialog's own close) answers nothing
  card().close()
  await waitFor(() => expect(card().open).toBe(false))
  expect(setName).not.toHaveBeenCalled()
  // a click on the backdrop (the dialog itself) closes it too
  fireEvent.click(screen.getByText('Set display name'))
  await waitFor(() => expect(card().open).toBe(true))
  fireEvent.click(card())
  await waitFor(() => expect(card().open).toBe(false))
  expect(setName).not.toHaveBeenCalled()
  // the field opens with a new random name, and the button on its right makes another
  fireEvent.click(screen.getByText('Set display name'))
  await waitFor(() => expect(card().open).toBe(true))
  const first = input().value
  expect(first).toMatch(/^[A-Z][a-z]+ [A-Z][a-z]+$/)
  const seen = new Set([first])
  for (let index = 0; index < 20; index += 1) { fireEvent.click(container.querySelector('#display-name-reload')!); expect(input().value).toMatch(/^[A-Z][a-z]+ [A-Z][a-z]+$/); seen.add(input().value) }
  expect(seen.size).toBeGreaterThan(1)
  fireEvent.click(card())
  await waitFor(() => expect(card().open).toBe(false))
  // Save sets the typed name
  fireEvent.click(screen.getByText('Set display name'))
  await waitFor(() => expect(card().open).toBe(true))
  fireEvent.change(input(), { target: { value: 'Alice' } })
  fireEvent.submit(input().closest('form')!)
  await waitFor(() => expect(setName).toHaveBeenCalledWith('Alice'))
  await waitFor(() => expect(card().open).toBe(false))
  // empty makes a random one
  fireEvent.click(screen.getByText('Set display name'))
  await waitFor(() => expect(card().open).toBe(true))
  fireEvent.change(input(), { target: { value: '' } })
  fireEvent.submit(input().closest('form')!)
  await waitFor(() => expect(setName).toHaveBeenLastCalledWith(expect.stringMatching(/^[A-Z][a-z]+ [A-Z][a-z]+$/)))
  cleanup()
  accountConfig.set(account({ profile: { ...profile, current: async () => ({ name: 'Alice' }) } }))
  const named = render(<AccountPage />)
  await waitFor(() => expect(named.container.querySelector('.acc-display-name')!.textContent).toBe('Alice'))
  expect(screen.queryByText('Set display name')).toBeNull()
})

test('account: the Delta Chat row at the foot joins an invite and copies this identity\'s link', async () => {
  const writeText = vi.fn(async () => {})
  Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
  const joinInvite = vi.fn(async () => ({ name: 'Bob', address: 'bob@x.test' }))
  const pgp = { address: 'alice@did.md', current: async () => undefined, onCopyPublic: async () => '', inviteLink: async () => 'https://i.delta.chat/#FP', joinInvite }
  vi.spyOn(window, 'prompt').mockReturnValue('https://i.delta.chat/#ABC')
  accountConfig.set(account({ pgp }))
  render(<AccountPage />)
  fireEvent.click(screen.getByText('Copy URL'))
  await waitFor(() => expect(writeText).toHaveBeenCalledWith('https://i.delta.chat/#FP'))
  fireEvent.click(screen.getByText('Join'))
  await waitFor(() => expect(joinInvite).toHaveBeenCalledWith('https://i.delta.chat/#ABC'))
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

test('account: Disconnect in the Files tab disconnects only after a confirmation', () => {
  const onDisconnect = vi.fn(async () => {})
  accountConfig.set(account({ wallet: { handle: 'alice.did.md', deviceJkt: 'j', capabilityExpiresAt: '2030-01-01T00:00:00Z', onDisconnect } }))
  render(<AccountPage />)
  fireEvent.click(screen.getByRole('tab', { name: 'Files' }))
  vi.spyOn(window, 'confirm').mockReturnValueOnce(false)
  fireEvent.click(screen.getByText('Disconnect'))
  expect(onDisconnect).not.toHaveBeenCalled()
  vi.spyOn(window, 'confirm').mockReturnValueOnce(true)
  fireEvent.click(screen.getByText('Disconnect'))
  expect(onDisconnect).toHaveBeenCalled()
})

test('account: Export is in the Files tab', () => {
  const onExportMessages = vi.fn(async () => {})
  accountConfig.set(account({ wallet: { handle: 'alice.did.md', deviceJkt: 'j', capabilityExpiresAt: '2030-01-01T00:00:00Z', onDisconnect: vi.fn(async () => {}) }, onExportMessages }))
  render(<AccountPage />)
  fireEvent.click(screen.getByRole('tab', { name: 'Files' }))
  fireEvent.click(screen.getByText('Export'))
  expect(onExportMessages).toHaveBeenCalled()
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
