import { ed25519 } from '@noble/curves/ed25519.js'
import { describe, expect, test } from 'bun:test'
import { createMailRecipientResolver, MailRecipientResolutionError } from '../../../src/core/adapters/mail-recipient-resolver.ts'
import { MemoryTrustedDeviceRoster } from '../../../src/core/identity/device-roster.ts'
import { buildGenesisLog, withFetch } from '../../protocol/support/webvh-log-fixture.ts'
import type { LogEntry } from '../../../src/identity/webvh/log.ts'

const rootPrivateKey = ed25519.utils.randomSecretKey()
const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
const { did, log } = buildGenesisLog(rootPrivateKey, rootPublicKey, [])

async function rosterWithDevice(identityId: string): Promise<MemoryTrustedDeviceRoster> {
  const roster = new MemoryTrustedDeviceRoster()
  await roster.installAcceptedProjection({
    version: 1, identityId, selfGroupId: 'self-group-1', epoch: '1', acceptedAt: '2026-08-24T00:00:00.000Z',
    devices: [{ deviceId: 'device-a', deliveryFloor: '1', signingPublicKey: new Uint8Array(32), deviceCredential: new Uint8Array([1]) }],
  })
  return roster
}

describe('createMailRecipientResolver', () => {
  test('resolves a known recipient to its identityId and trusted device ids', async () => {
    const roster = await rosterWithDevice(did)
    const resolver = createMailRecipientResolver({
      apexDomain: 'test.example',
      roster,
      resolveByDomain: async () => (await withFetchDoc(log)),
    })
    const result = await resolver({ address: 'alice@mail.test.example' })
    expect(result).toEqual({ identityId: did, deviceIds: ['device-a'] })
  })

  test('rejects a domain that is not this deployment\'s mail domain, without attempting resolution', async () => {
    let resolveCalls = 0
    const resolver = createMailRecipientResolver({
      apexDomain: 'test.example',
      roster: new MemoryTrustedDeviceRoster(),
      resolveByDomain: async () => { resolveCalls += 1; return null },
    })
    const result = await resolver({ address: 'alice@somewhere-else.example' })
    expect(result).toBeUndefined()
    expect(resolveCalls).toBe(0)
  })

  test('rejects a malformed local-part, without attempting resolution', async () => {
    let resolveCalls = 0
    const resolver = createMailRecipientResolver({
      apexDomain: 'test.example',
      roster: new MemoryTrustedDeviceRoster(),
      resolveByDomain: async () => { resolveCalls += 1; return null },
    })
    const result = await resolver({ address: 'ali ce@mail.test.example' })
    expect(result).toBeUndefined()
    expect(resolveCalls).toBe(0)
  })

  test('resolves to undefined for a domain that matches but has no published identity', async () => {
    const resolver = createMailRecipientResolver({
      apexDomain: 'test.example',
      roster: new MemoryTrustedDeviceRoster(),
      resolveByDomain: async () => null,
    })
    const result = await resolver({ address: 'nobody@mail.test.example' })
    expect(result).toBeUndefined()
  })

  test('resolves to undefined for a published identity with an empty trusted-device roster', async () => {
    const resolver = createMailRecipientResolver({
      apexDomain: 'test.example',
      roster: new MemoryTrustedDeviceRoster(),
      resolveByDomain: async () => (await withFetchDoc(log)),
    })
    const result = await resolver({ address: 'alice@mail.test.example' })
    expect(result).toBeUndefined()
  })

  test('throws MailRecipientResolutionError (not a plain undefined) when resolution itself fails', async () => {
    const roster = await rosterWithDevice(did)
    const resolver = createMailRecipientResolver({
      apexDomain: 'test.example',
      roster,
      resolveByDomain: async () => { throw new Error('network unreachable') },
    })
    await expect(resolver({ address: 'alice@mail.test.example' })).rejects.toBeInstanceOf(MailRecipientResolutionError)
  })

  test('ignores a DID-only reference (mail resolves by address only)', async () => {
    const resolver = createMailRecipientResolver({ apexDomain: 'test.example', roster: new MemoryTrustedDeviceRoster() })
    const result = await resolver({ did })
    expect(result).toBeUndefined()
  })
})

// Small helper: run resolveEntries-backed resolution once under withFetch's
// scoped fetch swap, since resolveByDomain itself calls the real fetch().
async function withFetchDoc(entries: LogEntry[]) {
  const { resolveByDomain } = await import('../../../src/identity/webvh/resolver.ts')
  let doc: Awaited<ReturnType<typeof resolveByDomain>> = null
  await withFetch(entries, async () => { doc = await resolveByDomain('alice.test.example') })
  return doc
}
