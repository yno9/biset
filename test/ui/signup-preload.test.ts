// @vitest-environment happy-dom
// The sign-up kept ready out of sight: Send makes the account through the wallet frame's `wallet.create`, with no form shown.
import { beforeEach, expect, test, vi } from 'vitest'

const create = vi.fn(async (_alias?: string) => ({ did: 'did:vh:x' }))
let described: { created: boolean; did?: string } = { created: false }
let handlersSeen: { existing(did: string): void } | undefined
const mountDito = vi.fn(async (_frame: unknown, _origin: unknown, _mode: unknown, handlers?: { existing(did: string): void }) => { handlersSeen = handlers; return { create, approve: vi.fn(), moveAlias: vi.fn(), cancel: vi.fn(), dispose: vi.fn(), describe: async () => described } })
let origin: string | undefined = 'https://wallet.did.md'
vi.mock('../../src/client/identity/wallet/dito-embed.ts', () => ({ ditoEmbedOrigin: () => origin, mountDito: (...args: unknown[]) => (mountDito as (...a: unknown[]) => unknown)(...args) }))

import { randomAlias, canSignUpInBackground, createAccountInBackground, heldIdentity } from '../../src/client/app/ui/signup-preload.ts'

// The accounts live under the deployment's identity domain.
;(window as unknown as { __BISET_CONFIG__?: unknown }).__BISET_CONFIG__ = { identityDomain: '002053.xyz', mailGateways: ['did.md'] }

beforeEach(() => { create.mockClear(); mountDito.mockClear(); document.body.replaceChildren() })

test('the wallet frame is loaded once, out of sight, and the account is made through it', async () => {
  expect(canSignUpInBackground()).toBe(true)
  await createAccountInBackground()
  await createAccountInBackground('quiet-heron-42')
  // The sign-up's frame and the Passphrase field's, both loaded at once, each once.
  expect(mountDito.mock.calls.map(call => call[2]).sort()).toEqual(['create', 'passphrase'])
  const frame = document.querySelector('iframe[title="Account"]')!
  expect(frame.getAttribute('aria-hidden')).toBe('true')
  expect(frame.style.left).toBe('-10000px')
  expect(create.mock.calls).toEqual([[undefined, undefined], ['quiet-heron-42', undefined]])
})

test('a name is six digits', () => {
  expect(randomAlias()).toMatch(/^\d{6}$/)
})

test('without a same-site wallet there is nothing to make it with', () => {
  origin = undefined
  expect(canSignUpInBackground()).toBe(false)
})

test('a wallet that holds an identity says whose: the page logs in as it', async () => {
  origin = 'https://wallet.did.md'
  await createAccountInBackground()
  expect(handlersSeen).toBeDefined()
  handlersSeen!.existing('did:vh:QmZLEhKxDi37FPoTqbiDBHtdUCjKGBckZh33DyXo1mVxGt')
  // The one-time note carries the DID only (the host is not in it): shown cut short until the wallet is asked.
  expect(heldIdentity.get()).toMatch(/^did:vh:QmZLEhKx/)
})

test('the wallet is asked whose identity it holds (the one-time note may have come too early)', async () => {
  described = { created: true, did: 'did:vh:QmZLEhKxDi37FPoTqbiDBHtdUCjKGBckZh33DyXo1mVxGt', host: 'c20d.002053.xyz' }
  heldIdentity.set(undefined)
  document.querySelector('iframe')?.remove()
  // a new page load: the module is fresh
  vi.resetModules()
  const fresh = await import('../../src/client/app/ui/signup-preload.ts')
  fresh.preloadSignup()
  await vi.waitFor(() => expect(fresh.heldIdentity.get()).toBe('c20d@002053.xyz'))
})
