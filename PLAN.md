# did.md Wallet login plan

## 1. Goal

`t.biset.md` will accept a `did:webvh` identity hosted by `did.md` as its
identity.  A person approves a Biset device once in the did.md Wallet.  The
device can subsequently use Biset without reopening the Wallet for ordinary
operations.

The replacement for recovery-phrase login is **not** “copy the Wallet into
Biset.”  Root Key, current Sign Key, future pre-rotation keys, and the Master
mnemonic remain at `did.md`.  Biset receives only a device-specific,
revocable authority and its own device private keys.

The existing Root + Sign phrase login remains available during this work.  It
is removed only after the acceptance criteria in section 12 are satisfied.

## 2. Non-negotiable invariants

- Biset must never receive or persist a did.md Master mnemonic, Root private
  key, current WebVH Sign private key, Spare key, or a key derived for another
  relying party.
- A Biset device has its own P-256 DPoP key and MLS Ed25519 leaf key.  Neither
  key is reused by another origin or another device.
- The Wallet capability is audience-bound to `https://t.biset.md`, bound to the
  device DPoP key thumbprint, scoped, time-bounded, and individually revocable
  at `did.md`.
- The capability, DPoP public key, DID, expiry, and public device credential
  are public metadata.  Access tokens are short lived and are not persisted.
- Private Biset device material is stored only locally.  It is wrapped by a
  non-extractable browser-held key and can additionally be passkey-wrapped.
  Password-based protection is not introduced.
- Key rotation or explicit Wallet revocation immediately prevents capability
  refresh and privileged Biset API operations.  It does not destroy locally
  cached ciphertext or public history.
- No API accepts a capability merely because it has a valid signature.  It
  must validate issuer, exact audience, DPoP proof, requested scope, expiry,
  DID WebVH log, and revocation state.

## 3. Product behaviour

### First use

1. On the zero-account screen the person enters `test1.did.md` (a hostname,
   not `test1@did.md`).
2. Biset resolves and validates the full `did:webvh` log locally, including
   SCID, entry hashes, pre-rotation and proof verification.
3. Biset generates a fresh non-extractable P-256 DPoP key; MLS device
   enrollment is Phase B.  It opens `https://did.md/authorize` in the **same tab**.
4. The Wallet displays `https://t.biset.md`, the DID, the Biset device
   fingerprint, requested scopes, lifetime, and the consequence of approval.
   It unlocks with the configured passkey where possible.
5. A single approval returns a signed public capability and a one-time PKCE
   authorization code.  Biset verifies the capability proof locally, exchanges
   the code with `api.did.md`, and persists its device session.
6. The Wallet is visited only for consent.  After the redirect returns to
   Biset, routine device-scoped actions do not reopen it.  The Biset session
   remains usable until expiry or revocation.

### Later use

- On reload, Biset reads its local device session and silently obtains a new
  short-lived DPoP access token through `/v1/oauth/device-refresh`.  There is no login form,
  popup, mnemonic, or token stored in localStorage.
- An expired, revoked, mismatched, or unusable device session returns the UI
  to the Wallet-login screen.  It never falls back to the bare phrase form
  without an explicit user choice during the migration period.
- Biset shows the DID, device fingerprint, capability expiry, and a
  `Connected · Wallet-managed device` state in the account header.  It also
  provides `Disconnect this device` and lists revocation instructions.

## 4. Authority model

There are three deliberately different credentials.

| Credential | Holder | Purpose | Lifetime / revoke |
| --- | --- | --- | --- |
| Wallet Root / Sign keys | did.md Wallet only | WebVH control and authorizing a Biset device | Wallet key rotation / Wallet logout |
| Biset device capability | Biset browser, DPoP-bound | authenticate the relying-party device and authorize named Biset scopes | bounded; Wallet can revoke by capability id |
| Biset MLS device credential | Biset browser | join and sign as a Biset MLS device | tied to a WebVH generation; removed/revoked as a Biset device |

The capability scopes are fixed, registered strings rather than caller-chosen
permissions:

```text
biset:login       establish / refresh the Biset device session
biset:device      present the Biset device credential to Biset services
biset:routing     update Biset-owned routing metadata
biset:messaging   use Biset mediator and mail-submission APIs
biset:vault       use Biset MIMI Self Vault APIs
```

`biset:routing`, `biset:messaging`, and `biset:vault` are accepted only by
Biset services after DPoP validation.  They do **not** give Biset the WebVH
update key and cannot write `did.jsonl`, rotate keys, move the DID, or create
another relying-party grant.  Those actions remain explicit Wallet actions.

## 5. Protocol — dynamic OAuth clients

did.md will be a general OAuth Authorization Server (AS), and Biset will be
its first Dynamic Client.  It must not have a permanent privileged entry in a
did.md source-code allowlist.  The current `client.did.md` postMessage flow is
only a disposable prototype and is not the production client protocol.

The AS publishes OAuth Authorization Server Metadata at its RFC 8414
well-known location.  That metadata advertises the authorization, token,
revocation, Dynamic Client Registration, and client-management endpoints;
supported PKCE methods; DPoP support; and supported scopes.

### Client registration

An RP registers using RFC 7591 with HTTPS client metadata:

```json
{
  "client_name": "Biset",
  "application_type": "web",
  "redirect_uris": ["https://t.biset.md/wallet/callback"],
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none"
}
```

The AS assigns an opaque `client_id`, stores the validated metadata, and
returns a registration access token plus a client-configuration URI.  The
registration access token permits the client owner to read, replace, or
delete its own registration; it is not a user access token.

Open registration is allowed only with rate limits, size limits, HTTPS
metadata, exact redirect URI validation, and abuse controls.  A later policy
may require a verifiable software statement for high-risk scopes, but it must
not turn ordinary client registration back into a hardcoded RP list.

### Authorization Code flow

```text
Biset browser                   did.md Wallet / AS                 api.did.md
    |  discover AS metadata              |                              |
    |  register or load client_id        |                              |
    |  validate DID + create PKCE/DPoP   |                              |
    |--- /authorize (client_id, exact redirect_uri, state,
    |                 code_challenge, DID hint, requested scopes) -->|
    |                                  Wallet consent                  |
    |<-- 302 https://t.biset.md/wallet/callback?code&state&iss ------|
    |---- /token (code, PKCE verifier, DPoP proof) ------------------>|
    |<--- short-lived DPoP token + nonce -----------------------------|
    |---- /refresh or capability renewal with same DPoP key -------->|
```

This is a normal browser redirect, not a cross-origin `postMessage` return.
Biset stores the `state`, PKCE verifier and DPoP key handle before leaving its
origin, verifies `state` and issuer on the callback, then exchanges the code.
The AS accepts only the exact redirect URI stored for that `client_id`; there
are no wildcards, origin-prefix matching, caller-provided reply targets, or
implicit flow tokens.

During consent, the Wallet resolves the hosted DID log and checks the Root
authentication method.  It produces the internal Root-authentication proof
needed by the non-custodial AS to authorize the one-time code.  The AS records
only client metadata, registration-management state, token hashes, spent-code
hashes, revocation ids, public capability metadata, and DPoP nonces.

### Long-lived, no-repeat-login operation

The long-lived item is the Biset device capability, not an access token and
not a copied Wallet key.  It is refreshed with the same non-extractable DPoP
key.  Its initial maximum validity is 31 days; later work may raise that
bound only after device-revocation UX and replay tests exist.  A person does
not approve per operation or per page load.  They approve again only after
expiry, explicit revoke/disconnect, a browser-device loss, or an identity
change.

Routine Biset services authorize the delegated device capability directly;
they do not open or call a Wallet signing agent.  A WebVH log update, key
rotation, DID move, or new application delegation remains a deliberate
Wallet action outside ordinary Biset usage.  The Wallet never offers a
general-purpose arbitrary-byte signing oracle.

## 6. Biset record and cryptographic migration

The current `IdentityRecord` assumes local copies of `masterSeed`,
`rootPrivateKey`, and `signPrivateKey`.  A Wallet-managed record must be a
separate, explicit variant rather than an object with fake or empty keys.

```text
LocalPhraseIdentity
  existing fields; used only by the temporary bare recovery path

WalletManagedIdentity
  did, rootPublicKey, generation, signPublicKey
  Wallet capability + public proof + capability expiry
  non-extractable DPoP private CryptoKey
  Biset MLS device credential + local MLS leaf private key
  Biset-only vault-storage secret (never a did.md Master seed)
  optional passkey wrapping metadata
```

`WalletManagedIdentity` cannot call code that reads `signPrivateKey` or
derives a Root key from its vault-storage secret.  Such paths must use either
a device-capability-aware Biset service call or an explicit Wallet controller
operation.  Type-level separation and tests are required before the record
can boot the normal application.

The existing vault-storage and recovery checkpoint KDFs currently take the
identity Master seed.  Wallet-managed identities use a domain-separated,
Biset-specific vault secret.  That secret is never a DID controller key and
is not usable at did.md.  Existing phrase identities keep their current KDF
unchanged until an explicit migration is implemented.

## 7. Implementation phases

### Phase A — OAuth Authorization Server and Dynamic Client authentication

- Publish RFC 8414 Authorization Server Metadata from did.md.
- Implement RFC 7591 Dynamic Client Registration and RFC 7592-style client
  management with an opaque client identifier and registration access token.
- Validate HTTPS client metadata, exact redirect URIs, requested scopes and
  registration-management authorization; retain `https://client.did.md` only
  as an isolated legacy prototype.
- Replace Wallet return `postMessage` with Authorization Code redirect to the
  exact registered redirect URI, plus `state`, issuer and PKCE verification.
- Generalize the Wallet consent UI so app name, origin, scopes and redirect
  target come from registered metadata, never untrusted request fields.
- Add a Biset Wallet-login entry to the zero-account page while retaining the
  existing phrase login.
- Add an IndexedDB store for a non-extractable DPoP key, public capability,
  public identity data, and no access token.
- Verify DID logs and Wallet proofs in Biset before token exchange.
- Add visible connected/disconnected state, silent refresh, disconnect, and
  recoverable errors.

**Phase A deliverable:** a real Biset-origin login that survives reload and
can call a protected Biset test resource.  It does not yet claim to open an
existing Biset Vault.

### Phase B — device enrollment

- Biset creates the MLS leaf key locally.
- Wallet approves a narrowly typed Biset device credential bound to the DID,
  WebVH generation, device public key, and DPoP thumbprint.
- Add Biset service verification for that credential plus capability scopes.
- Store an explicit `WalletManagedIdentity`; do not populate phrase fields.
- Create or join the MIMI Self Vault using the enrolled device, with device
  removal/revocation tests.

**Phase B deliverable:** a new did.md identity can open and use a fresh Biset
Vault without importing a mnemonic or private DID-controller key.

### Phase C — normal Biset feature parity

- Convert routing, mediator, mail submission, MIMI, DIDComm, and OpenPGP
  authorization from raw Sign-key assumptions to the defined capability or
  signing-agent boundary.
- Implement the structured Wallet signing-agent channel for the small set of
  WebVH-controller operations that cannot be delegated to a Biset device.
- Ensure no routine action launches an extra window or asks for a second
  approval while the Wallet session is active.
- Add account UI to view and revoke Biset devices from did.md Wallet.

**Phase C deliverable:** a Wallet-managed Biset identity can use every
supported Biset feature under its defined scope.

### Phase D — migrate and retire bare login

- Add an explicit migration flow for an existing phrase identity: first use
  the phrase path once, enroll a Wallet-managed Biset device, rewrap or
  recreate its vault-storage material, and verify a cold-browser restore.
- Keep the old record readable until migration succeeds and has been tested
  after a page reload.  Never silently delete it.
- Hide the bare form only after the gates in section 12.  Delete the bare
  import/restore code only in a later, separately reviewed change.

## 8. Failure and revocation behaviour

- DPoP private key missing, non-extractable key unusable, capability expired,
  audience/scope mismatch, or local record corruption: clear only the Wallet
  device session and ask to connect Wallet again.
- A DPoP nonce challenge must retry exactly once with a new proof.  Replayed
  `jti`, code, token, capability or request id must fail closed.
- Wallet revoke removes active token hashes immediately; capability refresh
  and protected Biset services fail on the next request.
- WebVH Sign rotation changes the generation.  Biset must revalidate its
  enrolled device credential before privileged requests and mark a stale
  device as needing re-enrollment.
- Closing the Wallet tab never leaks a key to Biset.  It only disables the
  signing-agent subset until the user reconnects it.
- Browser logout/disconnect removes the Biset local device material.  It does
  not revoke remotely unless the user selects remote revoke; the UI must make
  that distinction explicit.

## 9. Threat model and explicit non-goals

The design protects against a did.md server compromise (it has no private
keys), an API database leak (only opaque token hashes/public grants), and a
Biset application compromise limited to the enrolled device's scopes.  It
does not make a compromised active Biset origin harmless: that origin can use
the local device until its capability expires or is revoked.  That is why the
key is audience-bound, device-bound, scoped, bounded, and revocable.

Out of scope for this change:

- exporting a Master mnemonic, Root key, Sign key, or Spare key to Biset;
- silently replacing an existing Biset Vault with an empty vault;
- arbitrary `postMessage` signing or cross-origin authorization response;
- a password fallback;
- changing the did:webvh specification or accepting a nonstandard log proof.

## 10. Tests

Automated tests must cover:

1. Dynamic client registration, client-management authorization, metadata
   validation and exact redirect URI matching.
2. Full did:webvh validation: bad SCID, hash, pre-rotation commitment,
   authentication method, proof and hostname are rejected.
3. PKCE mismatch, spent code, wrong DPoP key, bad nonce, replayed `jti`,
   wrong audience, wrong scope, stale timestamp and malformed JWK rejection.
4. Browser reload restores the session through refresh without Wallet keys or
   access token persistence.
5. Capability revoke and WebVH generation change stop refresh and protected
   operations.
6. A Biset device cannot use a `client.did.md` capability, and vice versa.
7. Wallet-managed records cannot enter raw private-key code paths.
8. A fresh Wallet-managed device can create, restart, and use a MIMI Self
   Vault; an existing identity migration restores verified data, not an empty
   substitute.
9. Closing the Wallet signing-agent tab fails only the controller-signing
   path; it neither leaks keys nor corrupts the Biset device session.

Manual acceptance uses `test1.did.md`:

1. Connect Wallet once from `https://t.biset.md`.
2. Reload Biset and confirm it remains connected without a popup.
3. Perform normal device-scoped operations.
4. Revoke from did.md Wallet and confirm Biset loses access.
5. Reconnect and confirm no Root/Sign/Master material appears in Biset
   IndexedDB.

## 11. Deployment sequence

1. Ship did.md discovery, dynamic registration, authorization UI, API
   verification, and tests.
2. Ship Biset Phase A behind a visible experimental Wallet-login control.
3. Run the manual acceptance flow on production origins and inspect server
   logs for rejected origin, scope, nonce and proof failures.
4. Ship Phase B, then Phase C behind the same feature gate.
5. Run migration tests and a cold-browser restore before hiding bare login.
6. Keep a rollback that disables Biset's client registration / UI without
   invalidating existing did.md identities, other client registrations, or
   prototype sessions.

## 12. Bare-login removal gate

The old Root + Sign mnemonic form may be hidden only when all of the following
are demonstrably true:

- a Wallet-managed identity reaches Biset feature parity for supported
  messaging, routing, mail, DIDComm and MIMI workflows;
- reload, browser restart, disconnect, remote revoke, capability expiry,
  WebVH rotation, lost device, and a new device have tested UX and recovery
  paths;
- existing phrase identities have a tested, explicit migration with no
  destructive fallback;
- a security review confirms no Root/Sign/Master material is stored or sent
  by Biset;
- production monitoring covers authentication failures, revocation checks,
  DPoP replay failures, registration failures, and capability renewal
  failures;
- the user explicitly approves removal after observing the production flow.

Until then, phrase login is a migration-only fallback, labeled as such; it is
not removed merely because the Wallet authentication screen succeeds.

## 13. Work checklist

### Protocol and did.md authorization server

- [x] Publish RFC 8414 Authorization Server Metadata and validate its issuer
  in every authorization response.
- [x] Implement RFC 7591 Dynamic Client Registration for public web clients.
- [x] Persist client metadata, opaque `client_id`, registration access-token
  hash and client-configuration endpoint state.
- [x] Validate HTTPS metadata, client name, redirect URI count/size and exact
  redirect URI matching; prohibit wildcards and fragments.
- [x] Implement registration access-token authenticated read/update/delete
  client management.
- [x] Apply registration rate limits, CORS only where a browser endpoint
  requires it, and audit logging without sensitive token values.
- [ ] Define and validate the exact Biset scope set from section 4; consent
  can grant only the intersection of requested, registered and policy-allowed
  scopes.
- [x] Generalize the Wallet consent UI to show registered app name, origin,
  DID, device fingerprint, scopes, expiry and revoke consequence.
- [x] Replace prototype `postMessage` return with exact-URI Authorization Code
  redirect, state validation and issuer parameter.
- [x] Validate Biset capability, Root authentication proof, PKCE, DPoP JWK,
  nonce and replay protection at token exchange.
- [x] Implement capability refresh, token-hash storage, expiry cleanup and
  capability-id revocation for the Biset client.
- [x] Add a Wallet device list and explicit Biset-device remote-revoke action.
- [ ] Test bad client metadata, unauthorized client management, redirect URI
  substitution, state/issuer mismatch, mismatched audience/scope, stale
  proof, malformed JWK, PKCE mismatch, spent code and DPoP replay rejection.

### Biset Phase A — Wallet authentication

- [x] Add a visible `Continue with did.md Wallet` path to the zero-account
  screen without removing the existing phrase form.
- [x] Accept only a `*.did.md` hostname and locally resolve/verify its full
  did:webvh log before opening the Wallet.
- [x] Generate and retain a new non-extractable P-256 DPoP key per Biset
  browser device.
- [x] Discover the did.md AS, dynamically register Biset once, and retain its
  registration-management state without treating it as a user credential.
- [x] Start Authorization Code + PKCE in the same tab and process only the
  registered `/wallet/callback` redirect after state and issuer validation.
- [x] Verify the returned Wallet capability Data Integrity proof locally before
  calling the token endpoint.
- [x] Persist only public capability data, DPoP key handle and public DID
  identity metadata; never persist an access token or Wallet key.
- [x] Restore the device session silently through refresh after reload.
- [x] Add connected state, expiry information and a local
  disconnect control.
- [x] Add a DPoP-protected authorization-server test resource and package the
  Biset UI that calls it for the real `https://t.biset.md` origin.
- [ ] Manually confirm one login, reload without popup, remote revoke, and
  re-connect with `test1.did.md`.

### Biset Phase B — managed device enrollment

- [x] Define the canonical Biset MLS device credential: DID, WebVH
  generation and MLS public key are signed by Root + current Sign; its DPoP
  JKT binding lives in the enclosing Root-authenticated capability.
- [x] Make the Wallet issue only the typed, Root/Sign-authorized device
  credential; do not expose a general signing endpoint.
- [ ] Create an explicit `WalletManagedIdentity` record variant with no
  `masterSeed`, `rootPrivateKey`, or `signPrivateKey` fields.
- [ ] Store Biset MLS private material using browser-held non-extractable
  wrapping and add optional passkey wrapping.
- [ ] Introduce a Biset-specific vault-storage secret with domain-separated
  KDFs; prove it cannot derive a did.md controller key.
- [x] Reserve a public opaque MIMI room URI during Wallet approval, write it
  to Sign-key-authenticated routing metadata, and create/join that exact Self
  Vault with the enrolled device without importing a controller secret.
- [ ] Implement device removal and confirm a removed device cannot refresh,
  join, pull or submit after the relevant epoch transition.
- [ ] Test cold browser restart, local-device loss, and enrollment of a new
  device without an empty-vault substitution.

### Biset Phase C — feature parity

- [ ] Move routing authorization to verified Biset device capability scopes.
- [ ] Move mediator, mail submission, DIDComm and MIMI API authorization to
  verified DPoP-bound Biset device capability scopes.
- [ ] Keep WebVH-controller operations in explicit Wallet UI; routine Biset
  operations must use the delegated device capability and create no popup or
  additional consent step.
- [ ] Verify messaging, routing, mail, DIDComm, OpenPGP and MIMI workflows on
  a Wallet-managed identity.
- [ ] Perform a focused security review of cross-origin messaging, capability
  scope enforcement, key storage and revocation.

### Migration and bare-login retirement

- [ ] Add an explicit phrase-identity-to-Wallet-managed-device migration flow.
- [ ] Preserve the old phrase record until post-migration reload and data
  integrity checks succeed.
- [ ] Test migration for pre-rotation and post-rotation identities.
- [ ] Test browser restart, device loss, remote revoke, key rotation and
  recovery after migration.
- [ ] Label phrase login as migration-only once Wallet feature parity is live.
- [ ] Obtain explicit approval after production acceptance testing.
- [ ] Hide the phrase login UI.
- [ ] In a later reviewed change, remove bare-login code and migration-only
  key storage once no supported records require it.
