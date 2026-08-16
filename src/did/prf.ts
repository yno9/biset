// At-rest protection for the two secrets that ARE the identity — the master
// seed and the root private key — using a passkey's WebAuthn PRF extension as
// the key-encryption key.
//
// **Why only these two, and why together.** `rootPrivateKey` signs document
// updates, `bind:` proofs and device vouches: whoever holds it owns the
// identity outright, and unlike a device key there is no revocation for it
// (`rotateUpdateKeys` has no UI, `nextKeyHashes` is empty). The seed is not a
// second secret but the same one in another form — `deriveRootKey` is a
// deterministic SLIP-0010 derivation, so anyone with the seed re-derives the
// root key offline. Protecting one and leaving the other in plaintext beside
// it protects nothing; they go behind the same door or neither does.
//
// Everything else stays plaintext on purpose. Per-device keys
// (`didCommPrivateKey`, `jmapDevicePrivateKey`, the ML-KEM key) are revocable
// by design — `removeDeviceKey` and the removed-key tombstones exist exactly
// so a compromised device can be cut off — and the Service Worker needs them
// without a user gesture to decrypt a push while the app is closed. Gating
// those behind biometrics would break receiving-while-closed, which is the
// feature the mediator exists for.
//
// **What this does and does not buy.** It makes the store useless offline: a
// stolen disk, a synced browser profile, another OS account reading the files
// gets ciphertext. It does not stop an attacker who is *at* the unlocked
// device driving the running app — nothing in a browser app can, since any
// script in the origin acts as the user. The goal is narrower than "safe": to
// stop a copy of the identity from walking off and remaining valid forever.
//
// **Non-extractable CryptoKeys were considered and rejected here.** They would
// stop script from exporting the root key, but every signature in `src/did/`
// goes through @noble (`ed25519.sign`) on raw bytes, so it would mean porting
// all of them to WebCrypto — and it would buy nothing while the seed is
// recoverable, since the root key is re-derivable the moment the seed is
// decrypted. The seam is the seed, not the key object.
//
// **Unsupported browsers fall back to plaintext, deliberately** (decided
// 2026-08-14): PRF is not universally available, and refusing to create an
// identity without it would trade a real, common failure (can't sign up) for
// a rare one. Devices that support it get the protection; the rest are no
// worse off than before this file existed.

/** Stable per-origin handle for the passkey that guards this store. Held in
 * localStorage rather than the DID record: it is not a secret, and it must be
 * readable before anything in the (encrypted) record can be. */
const CRED_ID_KEY = 'biset_prf_cred'
/** The PRF input. Fixed and origin-scoped — the same passkey must derive the
 * same key on every unlock, so this can never include anything per-session. */
const PRF_SALT = new TextEncoder().encode('biset/did-at-rest/v1')

function b64u(b: Uint8Array): string {
  return btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
function b64uDecode(s: string): Uint8Array {
  const pad = s.replace(/-/g, '+').replace(/_/g, '/')
  return Uint8Array.from(atob(pad + '='.repeat((4 - pad.length % 4) % 4)), c => c.charCodeAt(0))
}

/** Whether this browser exposes the pieces at all. Cheap and synchronous —
 * the real answer only comes from actually asking for a credential, so
 * callers treat a `true` here as "worth trying", never as a guarantee. */
export function prfPlausible(): boolean {
  return typeof PublicKeyCredential !== 'undefined' && !!navigator.credentials
}

export function hasPrfCredential(): boolean {
  return !!localStorage.getItem(CRED_ID_KEY)
}

/** Creates the guarding passkey and returns its PRF-derived key, or null when
 * the platform declines (no authenticator, user cancelled, PRF unsupported).
 * Null is an ordinary outcome, not an error: the caller stores plaintext. */
export async function enrollPrfKey(userName: string): Promise<Uint8Array | null> {
  if (!prfPlausible()) return null
  try {
    const cred = await navigator.credentials.create({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rp: { name: 'biset' },
        user: {
          id: crypto.getRandomValues(new Uint8Array(16)),
          name: userName || 'biset',
          displayName: userName || 'biset',
        },
        // Ed25519 first, then ES256/RS256 — the algorithm only signs the
        // WebAuthn ceremony; PRF output is independent of it.
        pubKeyCredParams: [{ type: 'public-key', alg: -8 }, { type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
        // Platform authenticator + resident key: this credential has to be
        // discoverable on this device later without the app remembering a
        // user handle, and must not be a roaming key the user might not have
        // on them when the app needs to sign.
        authenticatorSelection: { authenticatorAttachment: 'platform', residentKey: 'required', userVerification: 'required' },
        extensions: { prf: { eval: { first: PRF_SALT } } } as AuthenticationExtensionsClientInputs,
      },
    }) as PublicKeyCredential | null
    if (!cred) return null
    const ext = cred.getClientExtensionResults() as { prf?: { enabled?: boolean; results?: { first?: ArrayBuffer } } }
    // Some authenticators report `enabled` at creation but only produce
    // output on a later assertion — so if creation gave no bytes, ask once
    // via unlock() rather than concluding PRF is unavailable.
    localStorage.setItem(CRED_ID_KEY, b64u(new Uint8Array(cred.rawId)))
    const first = ext.prf?.results?.first
    if (first) return new Uint8Array(first)
    if (ext.prf?.enabled) return await unlockPrfKey()
    localStorage.removeItem(CRED_ID_KEY)
    return null
  } catch {
    return null
  }
}

/** Asks the existing passkey for the same PRF output — a user-verification
 * gesture (biometric/PIN). Null when there is no enrolled credential, the
 * user cancels, or the platform declines. */
export async function unlockPrfKey(): Promise<Uint8Array | null> {
  const stored = localStorage.getItem(CRED_ID_KEY)
  if (!stored || !prfPlausible()) return null
  try {
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: [{ type: 'public-key', id: b64uDecode(stored) as BufferSource }],
        userVerification: 'required',
        extensions: { prf: { eval: { first: PRF_SALT } } } as AuthenticationExtensionsClientInputs,
      },
    }) as PublicKeyCredential | null
    if (!assertion) return null
    const ext = assertion.getClientExtensionResults() as { prf?: { results?: { first?: ArrayBuffer } } }
    const first = ext.prf?.results?.first
    return first ? new Uint8Array(first) : null
  } catch {
    return null
  }
}

/** Forgets the guarding credential. The passkey itself stays in the
 * authenticator (a web page cannot delete one) — this only drops the handle,
 * which is all that is needed once the secrets it guarded are gone. */
export function forgetPrfCredential(): void {
  localStorage.removeItem(CRED_ID_KEY)
}
