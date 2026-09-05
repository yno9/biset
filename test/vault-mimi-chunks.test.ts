import { expect, test } from 'bun:test'
import { decodeMimiVaultChunk, encodeMimiVaultChunk, joinMimiVaultChunks, MIMI_VAULT_CHUNK_BYTES, sendMimiVaultCheckpoint, splitMimiVaultPayload } from '../src/client/store/vault/mimi-vault-chunks.ts'

test('Vault payload chunks are canonical, bounded, and reassemble with a whole-payload hash', () => {
  const payload = new Uint8Array(MIMI_VAULT_CHUNK_BYTES + 23); for (let offset = 0; offset < payload.length; offset += 65_536) crypto.getRandomValues(payload.subarray(offset, Math.min(payload.length, offset + 65_536)))
  const chunks = splitMimiVaultPayload(payload, 'A'.repeat(24)).map(chunk => decodeMimiVaultChunk(encodeMimiVaultChunk(chunk)))
  expect(chunks).toHaveLength(2)
  expect(joinMimiVaultChunks([chunks[1]!, chunks[0]!])).toEqual(payload)
  expect(() => joinMimiVaultChunks([chunks[0]!])).toThrow('incomplete')
})

test('checkpoint sends every encrypted chunk before its manifest', async () => {
  const order: string[] = []
  const manifest = await sendMimiVaultCheckpoint(new Uint8Array(MIMI_VAULT_CHUNK_BYTES + 1).fill(3), 9, { async sendChunk(chunk, id) { order.push(`${id}:${decodeMimiVaultChunk(chunk).ordinal}`) }, async sendManifest(value) { order.push(`manifest:${value.coveredSeq}`) } }, 'B'.repeat(24))
  expect(order).toEqual([`${'B'.repeat(24)}-0:0`, `${'B'.repeat(24)}-1:1`, 'manifest:9'])
  expect(manifest.chunkCount).toBe(2)
})
