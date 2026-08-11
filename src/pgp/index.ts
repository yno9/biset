export * from './keys.ts'
export * from './crypto.ts'

import { getKeyRecord, generateAndStoreKeyPair, storeRecoveredKeyPair } from './keys.ts'
import {
  fetchEncryptedPrivKey, decryptPrivKey,
  uploadEncryptedPrivKey, uploadPublicKey, encryptPrivKey,
} from './crypto.ts'
import type { AccountSession } from '../types.ts'

export async function initPGP(session: AccountSession, kek: Uint8Array): Promise<string> {
  const { serverUrl, email, password: authB64 } = session.account

  const existing = await getKeyRecord(email)
  if (existing) {
    const blob = await fetchEncryptedPrivKey(serverUrl, email, authB64)
    if (!blob) {
      const encBlob = await encryptPrivKey(existing.privateKey, kek, email)
      await uploadEncryptedPrivKey(serverUrl, email, authB64, encBlob)
      await uploadPublicKey(serverUrl, email, authB64, existing.publicKey)
    }
    return existing.publicKey
  }

  const blob = await fetchEncryptedPrivKey(serverUrl, email, authB64)
  if (blob) {
    const armoredPrivKey = await decryptPrivKey(blob, kek, email)
    if (armoredPrivKey) {
      return storeRecoveredKeyPair(email, armoredPrivKey)
    }
  }

  const publicKey = await generateAndStoreKeyPair(email, email)
  const record = await getKeyRecord(email)
  if (record) {
    const encBlob = await encryptPrivKey(record.privateKey, kek, email)
    await uploadEncryptedPrivKey(serverUrl, email, authB64, encBlob)
    await uploadPublicKey(serverUrl, email, authB64, publicKey)
  }
  return publicKey
}
