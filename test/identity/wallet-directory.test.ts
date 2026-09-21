import 'fake-indexeddb/auto'
import { afterEach, expect, test } from 'bun:test'
import { beginDidMdWalletLogin, currentWallet, selectWallet } from '../../src/client/identity/wallet/did-md-oauth.ts'
import { DEFAULT_WALLET, WALLET_DIRECTORY, type WalletDirectoryEntry } from '../../src/client/identity/wallet/wallet-directory.ts'

// PLAN4 (~/did.md/PLAN4-wallet-connector.md): "connect with [...]" -- these
// tests exercise a SECOND, mocked wallet entry (not added to the real
// WALLET_DIRECTORY, which today lists only dito) to prove the pre-connection
// logic (wallet selection, discovery) is dito-independent. A full OID4VP
// round trip against a second real wallet implementation is out of scope
// (none exists -- see SPEC.md §5.6's documented limit) and not required by
// PLAN4's own verification task.
const mockWallet: WalletDirectoryEntry = { id: 'mock', displayName: 'Mock Wallet', issuer: 'https://api.mock-wallet.example', handleSuffix: '.mock.example' }
const originalFetch = globalThis.fetch

afterEach(() => {
  globalThis.fetch = originalFetch
  selectWallet(DEFAULT_WALLET)
})

test('WALLET_DIRECTORY lists dito as an ordinary entry, not specially wired', () => {
  expect(WALLET_DIRECTORY.some(entry => entry.id === 'dito' && entry.issuer === 'https://api.did.md')).toBe(true)
  // The module defaults to it without anyone having to call selectWallet.
  expect(currentWallet()).toEqual(DEFAULT_WALLET)
})

test('selectWallet/currentWallet round-trip to a non-dito entry and back', () => {
  selectWallet(mockWallet)
  expect(currentWallet()).toEqual(mockWallet)
  selectWallet(DEFAULT_WALLET)
  expect(currentWallet()).toEqual(DEFAULT_WALLET)
})

test('discovery follows the selected wallet, not a hardcoded dito issuer', async () => {
  selectWallet(mockWallet)
  const requestedUrls: string[] = []
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    requestedUrls.push(input.toString())
    return new Response('not found', { status: 404 })
  }) as typeof fetch
  // registration() (called first thing by beginDidMdWalletLogin) calls
  // metadata() before anything else -- a 404 here throws before any
  // mediator/popup logic ever runs, which is enough to prove which issuer
  // was actually queried.
  await expect(beginDidMdWalletLogin()).rejects.toThrow(/discovery failed/)
  expect(requestedUrls).toEqual([`${mockWallet.issuer}/.well-known/oauth-authorization-server`])
})

test('discovery reverts to dito once the mock wallet is deselected', async () => {
  selectWallet(mockWallet)
  selectWallet(DEFAULT_WALLET)
  const requestedUrls: string[] = []
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    requestedUrls.push(input.toString())
    return new Response('not found', { status: 404 })
  }) as typeof fetch
  await expect(beginDidMdWalletLogin()).rejects.toThrow(/discovery failed/)
  expect(requestedUrls).toEqual([`${DEFAULT_WALLET.issuer}/.well-known/oauth-authorization-server`])
})
