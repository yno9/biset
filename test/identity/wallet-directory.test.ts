import 'fake-indexeddb/auto'
import { afterEach, expect, test, vi } from 'vitest'
import { beginDidMdWalletLogin, currentWallet, selectWallet } from '../../src/client/identity/wallet/did-md-oauth.ts'
import { DEFAULT_WALLET, WALLET_DIRECTORY, type WalletDirectoryEntry } from '../../src/client/identity/wallet/wallet-directory.ts'

// PLAN4 (~/did.md/PLAN4-wallet-connector.md): "connect with [...]" -- these
// tests exercise a SECOND, mocked wallet entry (not added to the real
// WALLET_DIRECTORY, which today lists only dito) to prove the pre-connection
// logic (wallet selection, discovery) is dito-independent. A full OID4VP
// round trip against a second real wallet implementation is out of scope
// (none exists -- see SPEC.md §5.6's documented limit) and not required by
// PLAN4's own verification task.
const mockWallet: WalletDirectoryEntry = { id: 'mock', displayName: 'Mock Wallet', authorizationEndpoint: 'https://app.mock-wallet.example/authorize', handleSuffix: '.mock.example' }
const originalFetch = globalThis.fetch

const originalLocation = globalThis.location
afterEach(() => {
  if (originalLocation === undefined) delete (globalThis as { location?: Location }).location
  else Object.defineProperty(globalThis, 'location', { configurable: true, value: originalLocation })
  globalThis.fetch = originalFetch
  selectWallet(DEFAULT_WALLET)
})

test('WALLET_DIRECTORY lists dito as an ordinary entry, not specially wired', () => {
  expect(WALLET_DIRECTORY.some(entry => entry.id === 'dito' && entry.authorizationEndpoint === 'https://app.did.md/authorize')).toBe(true)
  // The module defaults to it without anyone having to call selectWallet.
  expect(currentWallet()).toEqual(DEFAULT_WALLET)
})

test('selectWallet/currentWallet round-trip to a non-dito entry and back', () => {
  selectWallet(mockWallet)
  expect(currentWallet()).toEqual(mockWallet)
  selectWallet(DEFAULT_WALLET)
  expect(currentWallet()).toEqual(DEFAULT_WALLET)
})

test('the sign-in request goes to the selected wallet\'s authorization endpoint, and asks it nothing beforehand', async () => {
  selectWallet(mockWallet)
  const requested: string[] = []
  globalThis.fetch = (async (input: RequestInfo | URL) => { requested.push(input.toString()); return new Response('not found', { status: 404 }) }) as typeof fetch
  const assigned: string[] = []
  Object.defineProperty(globalThis, 'location', { configurable: true, value: { protocol: 'https:', origin: 'https://biset.example', pathname: '/', assign: (url: string) => { assigned.push(url) } } })
  void beginDidMdWalletLogin().catch(() => {})
  await vi.waitFor(() => expect(assigned).toHaveLength(1))
  const request = new URL(assigned[0]!)
  expect(`${request.origin}${request.pathname}`).toBe(mockWallet.authorizationEndpoint)
  expect(request.searchParams.get('client_id')).toBe('redirect_uri:https://biset.example/wallet/callback')
  expect(request.searchParams.get('response_type')).toBe('vp_token id_token')
  expect(request.searchParams.get('scope')).toBe('openid')
  expect(request.searchParams.get('nonce')).toMatch(/^[A-Za-z0-9_-]{32,}$/)
  for (const forbidden of ['dpop_jkt', 'authorization_details', 'capability_type', 'alias', 'code_challenge']) expect(request.searchParams.has(forbidden)).toBe(false)
  expect(requested).toEqual([])
})
