import { expect, test } from 'bun:test'
import { decodeMimiVaultChunk, encodeMimiVaultChunk, joinMimiVaultChunks, MIMI_VAULT_CHUNK_BYTES, splitMimiVaultPayload } from '../src/vault/mimi-vault-chunks.ts'

test('Vault payload chunks are canonical, bounded, and reassemble with a whole-payload hash', () => {
  const payload = crypto.getRandomValues(new Uint8Array(MIMI_VAULT_CHUNK_BYTES + 23))
  const chunks = splitMimiVaultPayload(payload, 'A'.repeat(24)).map(chunk => decodeMimiVaultChunk(encodeMimiVaultChunk(chunk)))
  expect(chunks).toHaveLength(2)
  expect(joinMimiVaultChunks([chunks[1]!, chunks[0]!])).toEqual(payload)
  expect(() => joinMimiVaultChunks([chunks[0]!])).toThrow('incomplete')
})
