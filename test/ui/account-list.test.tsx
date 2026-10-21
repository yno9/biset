// @vitest-environment happy-dom
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { AccountList } from '../../src/client/app/ui/account/account-list.tsx'
import { DropdownMenu } from '../../src/client/app/ui/account/menu.tsx'
import { accountConfig, type AccountPageConfig } from '../../src/client/app/ui/account/state.ts'

const messages: string[] = []
function config(over: Partial<AccountPageConfig> = {}, didComm: Partial<NonNullable<NonNullable<AccountPageConfig['wallet']>['didComm']>> = {}): AccountPageConfig {
  return {
    did: 'did:webvh:SCID:alice.did.md',
    wallet: {
      handle: 'alice.did.md', deviceJkt: 'jkt', capabilityExpiresAt: '2030-01-01T00:00:00Z',
      didComm: { xKid: 'did:webvh:SCID:alice.did.md#me', mediatorUrl: 'https://mediator.biset.md/', ...didComm },
      onDisconnect: async () => {},
      onEditMediator: vi.fn(async () => {}), onEnableTor: vi.fn(async () => {}), onLogOutMediator: vi.fn(async () => {}), onEnableMessaging: vi.fn(async () => {}),
    },
    vault: { state: 'connected', coordinatorUrl: 'didcomm', devices: [
      { deviceId: 'did:webvh:SCID:alice.did.md#bbbbbbbbbbbbbbbbbbbbbbbb', current: false },
      { deviceId: 'did:webvh:SCID:alice.did.md#me', current: true },
    ] },
    showMessage: text => { messages.push(text) },
    ...over,
  }
}
const set = (next: AccountPageConfig) => act(() => accountConfig.set(next))

beforeEach(() => { messages.length = 0 })
afterEach(() => { fireEvent.keyDown(document, { key: 'Escape' }); cleanup(); vi.restoreAllMocks(); accountConfig.set(undefined) })

test('nothing is drawn before there is a mediator', () => {
  const { container } = render(<AccountList />)
  expect(container.innerHTML).toBe('')
  set(config({ wallet: { handle: 'a', deviceJkt: 'j', capabilityExpiresAt: '2030-01-01T00:00:00Z', onDisconnect: async () => {} } }))
  expect(container.innerHTML).toBe('')
})

test('the card shows the mediator host and its state', () => {
  const { container } = render(<AccountList />)
  set(config())
  expect(container.textContent).toContain('mediator.biset.md')
  expect(container.textContent).toContain('Registered')
  set(config({}, { error: 'unreachable' }))
  expect(container.textContent).toContain('Needs attention: unreachable')
  set(config({}, { loggedOut: true }))
  expect(container.textContent).toContain('Logged out')
})

test('while the mediator is being connected the card says so, and is neither green nor red', () => {
  const { container } = render(<AccountList />)
  set(config({}, { connecting: true }))
  expect(container.textContent).toContain('Connecting…')
  expect(container.textContent).not.toContain('Registered')
  const dot = container.querySelector<HTMLElement>('#cmd-acc-mediator-card .cmd-page-row span')!
  expect(dot.style.background).not.toMatch(/34c759|ff3b30/)
})

test('the card opens and closes on click', () => {
  const { container } = render(<AccountList />)
  set(config())
  const card = container.querySelector('#cmd-acc-mediator-card')!
  expect(card.classList.contains('expanded')).toBe(false)
  fireEvent.click(card.querySelector('.cmd-page-row')!)
  expect(card.classList.contains('expanded')).toBe(true)
  fireEvent.click(card.querySelector('.cmd-page-row')!)
  expect(card.classList.contains('expanded')).toBe(false)
})

test('this device comes first and is tagged; others are removable only when removal is wired', () => {
  const { container } = render(<AccountList />)
  set(config())
  const rows = [...container.querySelectorAll('.acc-device-row')]
  expect(rows[0]!.textContent).toContain('this device')
  expect(rows[1]!.classList.contains('acc-device-removable')).toBe(false)
  set(config({ onRemoveOtherDevices: async () => {} }))
  expect(container.querySelectorAll('.acc-device-removable')).toHaveLength(1)
})

test('removing other devices asks first, then reports', async () => {
  const onRemoveOtherDevices = vi.fn(async () => {})
  const { container } = render(<AccountList />)
  set(config({ onRemoveOtherDevices }))
  vi.spyOn(window, 'confirm').mockReturnValueOnce(false)
  fireEvent.click(container.querySelector('.acc-device-removable')!)
  expect(onRemoveOtherDevices).not.toHaveBeenCalled()
  vi.spyOn(window, 'confirm').mockReturnValueOnce(true)
  fireEvent.click(container.querySelector('.acc-device-removable')!)
  expect(onRemoveOtherDevices).toHaveBeenCalledTimes(1)
  await waitFor(() => expect(messages).toContain('Other devices removed'))
})

test('a failed removal is reported and can be tried again', async () => {
  const onRemoveOtherDevices = vi.fn(async () => { throw new Error('wallet said no') })
  const { container } = render(<AccountList />)
  set(config({ onRemoveOtherDevices }))
  vi.spyOn(window, 'confirm').mockReturnValue(true)
  fireEvent.click(container.querySelector('.acc-device-removable')!)
  await waitFor(() => expect(messages).toContain('wallet said no'))
  await waitFor(() => expect((container.querySelector('.acc-device-removable') as HTMLButtonElement).disabled).toBe(false))
})

test('a new device roster from the vault shows without redrawing the card', () => {
  const { container } = render(<AccountList />)
  set(config())
  fireEvent.click(container.querySelector('#cmd-acc-mediator-card .cmd-page-row')!)
  set({ ...config(), vault: { state: 'connected', coordinatorUrl: 'didcomm', devices: [] } })
  expect(container.textContent).toContain('No devices available')
  expect(container.querySelector('#cmd-acc-mediator-card')!.classList.contains('expanded')).toBe(true)
})

test('the mediator menu edits the server', () => {
  const next = config()
  const { container } = render(<><AccountList /><DropdownMenu /></>)
  set(next)
  vi.spyOn(window, 'prompt').mockReturnValue('https://other.example/')
  fireEvent.click(container.querySelector('[aria-label="Mediator menu"]')!)
  fireEvent.click(screen.getByText('Edit server'))
  expect(next.wallet!.onEditMediator).toHaveBeenCalledWith('https://other.example/')
})

test('logged out, the menu has one item: Log in', () => {
  const next = config({}, { loggedOut: true })
  const { container } = render(<><AccountList /><DropdownMenu /></>)
  set(next)
  fireEvent.click(container.querySelector('[aria-label="Mediator menu"]')!)
  expect(screen.queryByText('Edit server')).toBeNull()
  fireEvent.click(screen.getByText('Log in'))
  expect(next.wallet!.onEnableMessaging).toHaveBeenCalled()
})

test('the DIDComm key notice says why and renews once', async () => {
  const onRenew = vi.fn(() => new Promise<void>(() => {}))
  const { container } = render(<AccountList />)
  set(config({ rotationKey: { state: 'lost', onRenew } }))
  expect(container.querySelector('#cmd-acc-didcomm-key-notice')!.textContent).toContain('None of your devices has it any more.')
  const link = screen.getByText('renewed')
  fireEvent.click(link); fireEvent.click(link)
  expect(onRenew).toHaveBeenCalledTimes(1)
  expect(link.getAttribute('aria-disabled')).toBe('true')
})

test('a failed renewal is reported and the link works again', async () => {
  const { container } = render(<AccountList />)
  set(config({ rotationKey: { state: 'stale', onRenew: async () => { throw new Error('no approval') } } }))
  const link = container.querySelector('.acc-notice-link')!
  fireEvent.click(link)
  await waitFor(() => expect(messages).toContain('no approval'))
  await waitFor(() => expect(link.getAttribute('aria-disabled')).toBeNull())
})

test('the PGP card waits while there is no generation seed, then shows the derived key and copies its public half', async () => {
  let key: { fingerprint: string; userIds: string[] } | undefined
  const writeText = vi.fn(async () => {})
  vi.stubGlobal('navigator', { clipboard: { writeText } })
  const pgp = { address: 'alice@did.md', current: async () => key, onCopyPublic: vi.fn(async () => 'armor'), inviteLink: vi.fn(async () => 'https://i.delta.chat/#FP&v=3') }
  const { container } = render(<AccountList />)
  set(config({ pgp }))
  await waitFor(() => expect(container.querySelector('#cmd-acc-pgp-card')!.textContent).toContain('generation seed'))
  expect(screen.queryByText('Copy public key')).toBeNull()

  key = { fingerprint: 'ABCD1234EF', userIds: ['<alice@did.md>'] }
  set(config({ pgp: { ...pgp } }))
  await waitFor(() => expect(container.querySelector('#cmd-acc-pgp-card')!.textContent).toContain('ABCD 1234 EF'))
  fireEvent.click(screen.getByText('Copy public key'))
  await waitFor(() => expect(writeText).toHaveBeenCalledWith('armor'))
  await waitFor(() => expect(messages).toContain('Public key copied'))
  fireEvent.click(screen.getByText('Copy Delta Chat invite'))
  await waitFor(() => expect(writeText).toHaveBeenCalledWith('https://i.delta.chat/#FP&v=3'))
  await waitFor(() => expect(messages.some(text => text.startsWith('Delta Chat invite link copied'))).toBe(true))
  vi.unstubAllGlobals()
})
