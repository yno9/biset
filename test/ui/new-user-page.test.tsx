// @vitest-environment happy-dom
import { act, cleanup, fireEvent, render, waitFor } from '@testing-library/react'
import { afterEach, expect, test, vi } from 'vitest'

vi.mock('../../src/client/identity/wallet/did-md-oauth.ts', () => ({
  beginDidMdWalletLogin: vi.fn(async () => {}),
  prepareDidMdWalletLoginRequest: vi.fn(async () => ''),
  completeDidMdWalletCallback: vi.fn(async () => undefined),
  restoreDidMdWalletSession: vi.fn(async () => undefined),
  resolveWalletFromSuffix: vi.fn(async (suffix: string) => ({ id: `wallet:${suffix}`, displayName: suffix })),
  selectWallet: vi.fn(),
  currentWallet: () => ({ id: 'dito', displayName: 'dito' }),
}))

import * as oauth from '../../src/client/identity/wallet/did-md-oauth.ts'
import { NewUserPage, setOnWalletConnected } from '../../src/client/app/ui/pages/new-user-page.tsx'

const DID = 'did:vh:QmafKp1jjhnP1vjDYZs6rpQ7bk3mQBS2hQvwGbqc2UAEYi'
afterEach(() => { cleanup(); document.body.innerHTML = '' })

// The sign-up page consumes a wallet callback / restores a stored session once per page load, so
// the test that depends on that runs first, before any other render of the page.
test('a stored session is restored by the sign-up page once per page load', async () => {
  const session = { did: DID, handle: 'alice.did.md' }
  vi.mocked(oauth.restoreDidMdWalletSession).mockResolvedValueOnce(session as never)
  const connected = vi.fn(async () => {})
  setOnWalletConnected(connected)
  const first = render(<NewUserPage />)
  await waitFor(() => expect(connected).toHaveBeenCalledWith(session))
  first.unmount()
  render(<NewUserPage />)
  await act(async () => { await Promise.resolve() })
  expect(connected).toHaveBeenCalledTimes(1)
})

test('sign-up: connect opens the wallet; a failure is shown and the button works again', async () => {
  vi.mocked(oauth.beginDidMdWalletLogin).mockRejectedValueOnce(new Error('popup blocked'))
  const { container } = render(<NewUserPage />)
  const button = container.querySelector<HTMLButtonElement>('#nu-wallet-login')!
  fireEvent.click(button)
  await waitFor(() => expect(container.querySelector('#nu-wallet-result')!.textContent).toBe('popup blocked'))
  expect((container.querySelector('#nu-wallet-result') as HTMLElement).style.color).toMatch(/#ff3b30|rgb\(255, 59, 48\)/)
  await waitFor(() => expect(button.disabled).toBe(false))
  fireEvent.click(button)
  await waitFor(() => expect(oauth.beginDidMdWalletLogin).toHaveBeenCalledTimes(2))
})

test('sign-up: a typed suffix picks the wallet that DID names first', async () => {
  const { container } = render(<NewUserPage />)
  fireEvent.change(container.querySelector('#nu-wallet-suffix')!, { target: { value: ' alice.did.md ' } })
  fireEvent.click(container.querySelector('#nu-wallet-login')!)
  await waitFor(() => expect(oauth.resolveWalletFromSuffix).toHaveBeenCalledWith('alice.did.md'))
  await waitFor(() => expect(oauth.selectWallet).toHaveBeenCalledWith({ id: 'wallet:alice.did.md', displayName: 'alice.did.md' }))
})
