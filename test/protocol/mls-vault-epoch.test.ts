import { describe, expect, test } from 'bun:test'
import { bytesToBase64url, equalBytes } from '../../src/shared/protocol/canonical.ts'
import { mlsEpoch, type MlsEpoch } from '../../src/shared/protocol/ids.ts'
import {
  deriveVaultEpochKey,
  MlsVaultEpochKeyResolver,
  VAULT_EPOCH_KEY_LABEL,
  VAULT_EPOCH_KEY_LENGTH,
  vaultEpochKeyContext,
  type MlsEpochExporter,
} from '../../src/mls/vault-epoch.ts'

describe('MLS vault epoch key boundary', () => {
  test('pins label, context, and length while separating group and epoch', async () => {
    const calls: Array<{ label: string; context: Uint8Array; length: number }> = []
    const exporter = (selfGroupId: string, epoch: MlsEpoch): MlsEpochExporter => ({
      selfGroupId,
      epoch,
      async exportSecret(label, context, length) {
        calls.push({ label, context, length })
        return new Uint8Array(await crypto.subtle.digest('SHA-256', arrayBuffer(context)))
      },
    })

    const first = await deriveVaultEpochKey(exporter('self-group-a', '7'))
    const same = await deriveVaultEpochKey(exporter('self-group-a', '7'))
    const nextEpoch = await deriveVaultEpochKey(exporter('self-group-a', '8'))
    const otherGroup = await deriveVaultEpochKey(exporter('self-group-b', '7'))

    expect(calls.every(call => call.label === VAULT_EPOCH_KEY_LABEL && call.length === VAULT_EPOCH_KEY_LENGTH)).toBe(true)
    expect(first).toEqual(same)
    expect(first).not.toEqual(nextEpoch)
    expect(first).not.toEqual(otherGroup)
    expect(bytesToBase64url(vaultEpochKeyContext('self-group-a', '7'))).not.toBe(bytesToBase64url(vaultEpochKeyContext('self-group-a', '8')))
  })

  test('retains the full MLS uint64 epoch value without Number conversion', () => {
    const max = mlsEpoch(18_446_744_073_709_551_615n)
    expect(max).toBe('18446744073709551615')
    expect(equalBytes(vaultEpochKeyContext('self-group-a', max), vaultEpochKeyContext('self-group-a', max))).toBe(true)
  })

  test('rejects a VEK derivation when the self-group epoch changed during the operation', async () => {
    let reads = 0
    const resolver = new MlsVaultEpochKeyResolver({
      async currentSelfGroup() {
        reads += 1
        return {
          selfGroupId: 'self-group-a',
          epoch: reads === 1 ? '7' : '8',
          async exportSecret(_label, context) {
            return new Uint8Array(await crypto.subtle.digest('SHA-256', arrayBuffer(context)))
          },
        }
      },
    })
    const current = await resolver.currentVaultEpoch('did:web:alice.example')
    await expect(resolver.deriveVaultEpochKey('did:web:alice.example', current.selfGroupId, current.epoch)).rejects.toThrow('epoch changed')
  })
})

function arrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.length)
  copy.set(bytes)
  return copy.buffer
}
