export * from './keys.ts'
export * from './crypto.ts'

import { getKeyRecord, storeKeyPair, generateAndStoreKeyPair, storeRecoveredKeyPair } from './keys.ts'
import {
  fetchEncryptedPrivKey, decryptPrivKey,
  uploadEncryptedPrivKey, uploadPublicKey, encryptPrivKey,
} from './crypto.ts'
import type { AccountSession } from '../types.ts'

/** Re-wraps this device's already-decrypted PGP private key under a NEW kek
 * and overwrites the server-side blob — used when the identity's masterSeed
 * itself changes (ui/prerotation.ts's runRevokeRootKey) so the PGP identity
 * carries forward instead of being silently orphaned.
 *
 * Deliberately does NOT touch the old kek/old server blob at all: the
 * plaintext armored key is read straight out of THIS device's own IndexedDB
 * (getKeyRecord — populated the first time initPGP ran here), which is
 * already the decrypted source of truth regardless of what kek wrapped the
 * server copy. A revoke is, by this codebase's own framing (ARC.md), the
 * legitimate owner exercising the recovery lever from a device they
 * currently control — exactly the device that already holds this plaintext.
 *
 * Without this, the server blob stays wrapped under the OLD kek forever: a
 * device that restores fresh with the NEW Root Key phrase can derive only
 * the new kek, so `initPGP`'s decrypt fails silently and it mints a brand
 * new PGP keypair — orphaning every message ever encrypted to the old one
 * and leaving contacts holding a now-stale public key (found live,
 * 2026-08-17, before this existed).
 *
 * No-op (returns true) when this device has no local key for the email at
 * all — nothing to migrate, same as initPGP's own "not yet initialized"
 * case. Best-effort by design: called for every relay account tied to an
 * identity during revoke, and a failure on one (relay unreachable) must not
 * abort the others or the revoke itself, which has already landed. */
export async function rewrapPgpForNewKek(session: AccountSession, newKek: Uint8Array): Promise<boolean> {
  const { serverUrl, email, password: authB64 } = session.account
  const record = await getKeyRecord(email)
  if (!record) return true
  const encBlob = await encryptPrivKey(record.privateKey, newKek, email)
  return uploadEncryptedPrivKey(serverUrl, email, authB64, encBlob)
}

/** Carries this device's PGP identity across a LOGIN-identity change — the
 * SCID migration (PLANSCID.md), where the kek/masterSeed stays exactly the
 * same but the email this account authenticates as does not. This is the
 * mirror image of `rewrapPgpForNewKek` (kek changes, email doesn't): here
 * the key material itself never changes, only where it's filed — locally
 * (IndexedDB, keyed by email) and the server blob's AAD (`crypto.ts`'s
 * `encryptPrivKey`/`decryptPrivKey`, bound to email as tamper-detection
 * context).
 *
 * Without this, the exact same orphaning `rewrapPgpForNewKek` exists to
 * prevent would happen anyway: `initPGP` looks everything up under
 * `session.account.email` (the new SCID address after migration), finds no
 * local record and a server blob whose AAD no longer matches, and mints a
 * fresh keypair — discarding every message ever encrypted to the old one.
 *
 * No-op (returns true) when this device holds no local key under
 * `oldEmail` — nothing to carry over, same as `rewrapPgpForNewKek`'s own
 * convention. `newSession.account` must already be the POST-migration
 * account (email = the new SCID address) — its own `password` is what
 * authenticates the upload, since the migration already moved the relay
 * account this device is now logged into. */
export async function rekeyPgpForNewLogin(oldEmail: string, newSession: AccountSession, kek: Uint8Array): Promise<boolean> {
  const record = await getKeyRecord(oldEmail)
  if (!record) return true
  const { serverUrl, email: newEmail, password: authB64 } = newSession.account
  await storeKeyPair(newEmail, record.privateKey, record.publicKey)
  const encBlob = await encryptPrivKey(record.privateKey, kek, newEmail)
  const uploaded = await uploadEncryptedPrivKey(serverUrl, newEmail, authB64, encBlob)
  await uploadPublicKey(serverUrl, newEmail, authB64, record.publicKey)
  return uploaded
}

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
    // A blob EXISTS but this kek/email doesn't open it — NOT the same as
    // "nothing here yet". The old code fell through to the mint-and-upload
    // branch below regardless, which OVERWRITES this blob with a brand-new,
    // unrelated key — permanently destroying whatever the undecryptable
    // blob actually held, even if it was perfectly recoverable (the right
    // kek was just a transient mismatch, another device's rewrap hadn't
    // reached this fetch yet, a race with rewrapPgpForNewKek/
    // rekeyPgpForNewLogin still in flight). Found live, 2026-08-18: a
    // revoke had already correctly re-wrapped this exact blob for a SCID
    // migration; the first restore attempt on a fresh device failed to
    // decrypt it (the anchor's own vouch-verification bug, since fixed,
    // meant nothing could even authenticate yet) and this branch destroyed
    // the correctly-rewrapped blob on the spot, before the anchor fix had
    // a chance to let a correct decrypt ever succeed.
    //
    // A LOCAL-only key keeps the account usable (new mail can still be
    // sent/read) without touching the server copy — the one thing that
    // might still make the ORIGINAL history recoverable (another device
    // with the real key, or a corrected kek) is preserved by simply not
    // uploading over it.
    console.warn('[pgp] a server key exists for', email, 'but could not be decrypted with the current kek — using a local-only key instead of overwriting it (recoverable via another device\'s "Repair PGP" or a corrected kek)')
    return generateAndStoreKeyPair(email, email)
  }

  // Genuinely nothing on the server — safe to mint and publish.
  const publicKey = await generateAndStoreKeyPair(email, email)
  const record = await getKeyRecord(email)
  if (record) {
    const encBlob = await encryptPrivKey(record.privateKey, kek, email)
    await uploadEncryptedPrivKey(serverUrl, email, authB64, encBlob)
    await uploadPublicKey(serverUrl, email, authB64, publicKey)
  }
  return publicKey
}
