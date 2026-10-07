/**
 * Device-local state for a did.md OAuth public client.
 *
 * Access tokens are deliberately excluded.  The DPoP private key is an opaque
 * non-extractable CryptoKey held by the browser; this database never contains
 * a did.md mnemonic, Root key, Sign key, or Spare key.
 */
export type DidMdRegistration = {
  /** Version 2 pins every endpoint returned by current AS discovery. */
  v: 2
  issuer: string
  authorizationEndpoint: string
  tokenEndpoint: string
  refreshEndpoint: string
  registrationEndpoint: string
  clientId: string
  registrationAccessToken: string
  redirectUri: string
}

export type DidMdPendingAuthorization = {
  /** Version 2 uses OAuth authorization_details and a capability audience. */
  v: 2
  issuer: string
  clientId: string
  state: string
  codeVerifier: string
  /** Unknown for the minimal first-shot authorize request, which sends no
   * login_hint and defers all DID resolution to the callback -- filled in
   * from the token response's `sub` once the Wallet identifies the signer. */
  did?: string
  handle?: string
  verificationMethod?: string
  rootPublicKey?: Uint8Array
  deviceJkt: string
  privateKey: CryptoKey
  publicJwk: JsonWebKey
  /** Names this browser as the author of the Vault events it writes
   * (`actorDeviceId`). Random per sign-in; carries no key. */
  vaultDeviceId: string
  /** Omitted for a Wallet request that edits nothing. */
  documentEdit?: DidCoreDocumentEdit
  /** Present only for a Wallet approval that explicitly publishes this
   * browser's Biset DIDComm endpoint. */
  bisetDidCommDevice?: DidMdBisetDidCommDeviceMaterial & {
    mediatorUrl: string
    routingKid: string
    /** The mediator's DID, which a DID document names as its endpoint
     * (unset for a device authorized before that). */
    mediatorDid?: string
    /** This mediator's Tor entrance (PLAN-tor.md D-4), if configured. */
    mediatorOnionUrl?: string
    /** Unset only in the minimal first-shot login request, which prepares
     * this device before the signer's DID is known (see
     * prepareBisetDidCommDevice in did-md-oauth.ts) -- xKid = did +
     * fragment is filled in once the token response reveals the DID, same
     * as did/handle/verificationMethod/rootPublicKey above. */
    xKid?: string
  }
  previousBisetDidCommDevice?: DidMdBisetDidCommDeviceMaterial & {
    mediatorUrl: string
    routingKid: string
    /** The mediator's DID, which a DID document names as its endpoint
     * (unset for a device authorized before that). */
    mediatorDid?: string
    mediatorOnionUrl?: string
    xKid: string
  }
  mediatorPreRegistered?: boolean
  createdAt: string
}

/** `endpointMode: 'merge'` adds the service's endpoints to the ones already published instead of replacing the whole service (did.md Wallet's document-edit contract). */
type DidCoreService = { id: string; type: string; serviceEndpoint: string | Record<string, unknown> | Array<string | Record<string, unknown>>; endpointMode?: 'replace' | 'merge' }
/** Removes, from one service, the endpoints whose properties equal every entry of `match`. */
export type DidCoreEndpointRemoval = { serviceId: string; match: Record<string, unknown> }
type DidCoreVerificationMethod = { id: string; type: string; controller: string; publicKeyMultibase: string }
export type DidCoreDocumentEdit = {
  type: 'urn:did-core:document-edit:v1'
  services: DidCoreService[]
  verificationMethods: DidCoreVerificationMethod[]
  serviceKeyBindings?: { serviceId: string; keyIds: string[] }[]
  remove: string[]
  removeEndpoints?: DidCoreEndpointRemoval[]
}

/** A Biset-owned DIDComm X25519 leaf. It is separate from the MLS signing
 * leaf: the two protocols have distinct key-agreement/signing roles and
 * must not share a private key. */
export type DidMdBisetDidCommDeviceMaterial = {
  v: 2
  x25519PublicKey: Uint8Array
  sealed: { iv: Uint8Array; ciphertext: Uint8Array }
}

export type OpenDidMdBisetDidCommDeviceMaterial = {
  x25519PrivateKey: Uint8Array
  /** Keys this device's mediator inbox labels (protocol/didcomm/
   * mediator-device.ts) -- random per device, never leaves it. */
  mediatorDeviceSecret: Uint8Array
}

export type DidMdDeviceSession = {
  /** Version 2 uses OAuth authorization_details and a capability audience. */
  v: 2
  issuer: string
  clientId: string
  did: string
  handle: string
  verificationMethod: string
  rootPublicKey: Uint8Array
  deviceJkt: string
  privateKey: CryptoKey
  publicJwk: JsonWebKey
  // PLAN3 (~/did.md/PLAN3-oid4vp-transport.md): a VC-DM 2.0 credential with
  // an embedded proof, not a {document, proof} pair. Every consumer
  // re-validates this with asObject/assertMatchesSchema itself (see
  // capabilityFromResponse, pendingFromSession in did-md-oauth.ts), so this
  // stays an opaque record rather than an unenforced shape here.
  capability: Record<string, unknown>
  capabilityExpiresAt: string
  /** This browser's Vault author id (see the pending authorization's). */
  vaultDeviceId?: string
  /** An optional Biset-owned DIDComm leaf, authorized by a Wallet routing
   * approval. It is not a did.md controller key. */
  bisetDidCommDevice?: DidMdBisetDidCommDeviceMaterial & {
    mediatorUrl: string
    routingKid: string
    /** The mediator's DID, which a DID document names as its endpoint
     * (unset for a device authorized before that). */
    mediatorDid?: string
    mediatorOnionUrl?: string
    xKid: string
  }
}

const DB_NAME = 'biset-did-md-wallet'
const DB_VERSION = 2
const REGISTRATION_STORE = 'registration'
const PENDING_STORE = 'pending'
const SESSION_STORE = 'session'
const MATERIAL_KEY_STORE = 'material-keys'
const REGISTRATION_ID = 'current'
const PENDING_ID = 'current'
const SESSION_ID = 'current'
const MATERIAL_KEY_ID = 'biset-device-material-v1'

function database(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION)
    request.onupgradeneeded = () => {
      const db = request.result
      for (const name of [REGISTRATION_STORE, PENDING_STORE, SESSION_STORE, MATERIAL_KEY_STORE]) {
        if (!db.objectStoreNames.contains(name)) db.createObjectStore(name)
      }
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error ?? new Error('Could not open did.md Wallet device storage'))
  })
}

async function materialWrappingKey(): Promise<CryptoKey> {
  // Generate before entering the IndexedDB transaction. WebCrypto promises
  // settle after an IDB request callback returns; generating inside that
  // callback would let the transaction become inactive before `put`.
  const candidate = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']) as CryptoKey
  const db = await database()
  try {
    return await new Promise<CryptoKey>((resolve, reject) => {
      const transaction = db.transaction(MATERIAL_KEY_STORE, 'readwrite')
      const store = transaction.objectStore(MATERIAL_KEY_STORE)
      const request = store.get(MATERIAL_KEY_ID)
      let result: CryptoKey | undefined
      request.onsuccess = () => {
        const existing = request.result
        if (existing instanceof CryptoKey && existing.type === 'secret' && !existing.extractable && existing.algorithm.name === 'AES-GCM') {
          result = existing
          return
        }
        result = candidate
        store.put(candidate, MATERIAL_KEY_ID)
      }
      request.onerror = () => reject(request.error ?? new Error('Could not read Biset device wrapping key'))
      transaction.oncomplete = () => result ? resolve(result) : reject(new Error('Could not create Biset device wrapping key'))
      transaction.onerror = () => reject(transaction.error ?? new Error('Could not save Biset device wrapping key'))
      transaction.onabort = () => reject(transaction.error ?? new Error('Biset device wrapping key transaction aborted'))
    })
  } finally { db.close() }
}

function assertDidCommPrivateMaterial(value: OpenDidMdBisetDidCommDeviceMaterial): void {
  if (!(value.x25519PrivateKey instanceof Uint8Array) || value.x25519PrivateKey.length !== 32 || !(value.mediatorDeviceSecret instanceof Uint8Array) || value.mediatorDeviceSecret.length !== 32) throw new TypeError('Biset DIDComm device private material is invalid')
}

function assertSealedDidCommMaterial(value: DidMdBisetDidCommDeviceMaterial): void {
  if (value.v !== 2 || !(value.x25519PublicKey instanceof Uint8Array) || value.x25519PublicKey.length !== 32
    || !(value.sealed?.iv instanceof Uint8Array) || value.sealed.iv.length !== 12
    || !(value.sealed?.ciphertext instanceof Uint8Array) || value.sealed.ciphertext.length < 17) {
    throw new TypeError('Biset DIDComm device material is invalid')
  }
}

/** Seals a Biset DIDComm X25519 private leaf with a context-bound envelope
 * under this origin's non-extractable browser key. */
export async function sealDidMdBisetDidCommDeviceMaterial(
  x25519PublicKey: Uint8Array,
  privateMaterial: OpenDidMdBisetDidCommDeviceMaterial,
): Promise<DidMdBisetDidCommDeviceMaterial> {
  assertDidCommPrivateMaterial(privateMaterial)
  if (!(x25519PublicKey instanceof Uint8Array) || x25519PublicKey.length !== 32) throw new TypeError('Biset DIDComm device public key is invalid')
  const key = await materialWrappingKey()
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const additionalData = didCommMaterialAad(x25519PublicKey)
  const plaintext = new TextEncoder().encode(JSON.stringify({ v: 2, x25519PrivateKey: [...privateMaterial.x25519PrivateKey], mediatorDeviceSecret: [...privateMaterial.mediatorDeviceSecret] }))
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData }, key, plaintext))
  return { v: 2, x25519PublicKey: x25519PublicKey.slice(), sealed: { iv, ciphertext } }
}

export async function openDidMdBisetDidCommDeviceMaterial(value: DidMdBisetDidCommDeviceMaterial): Promise<OpenDidMdBisetDidCommDeviceMaterial> {
  assertSealedDidCommMaterial(value)
  const key = await materialWrappingKey()
  const additionalData = didCommMaterialAad(value.x25519PublicKey)
  let decoded: unknown
  try {
    const iv = new Uint8Array(value.sealed.iv.length); iv.set(value.sealed.iv)
    const ciphertext = new Uint8Array(value.sealed.ciphertext.length); ciphertext.set(value.sealed.ciphertext)
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData }, key, ciphertext)
    decoded = JSON.parse(new TextDecoder().decode(plaintext))
  } catch { throw new Error('Biset DIDComm device material could not be decrypted on this browser') }
  if (decoded === null || typeof decoded !== 'object' || Array.isArray(decoded)) throw new Error('Biset DIDComm device material is invalid')
  const input = decoded as Record<string, unknown>
  if (input.v !== 2 || !Array.isArray(input.x25519PrivateKey) || !Array.isArray(input.mediatorDeviceSecret)) throw new Error('Biset DIDComm device material is invalid')
  const privateMaterial = { x25519PrivateKey: new Uint8Array(input.x25519PrivateKey), mediatorDeviceSecret: new Uint8Array(input.mediatorDeviceSecret) }
  assertDidCommPrivateMaterial(privateMaterial)
  return privateMaterial
}

function didCommMaterialAad(x25519PublicKey: Uint8Array): ArrayBuffer {
  const bytes = new TextEncoder().encode(JSON.stringify({ label: 'biset/did-md/didcomm-device/v3', x25519PublicKey: [...x25519PublicKey] }))
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer
}

async function transact<T>(storeName: string, mode: IDBTransactionMode, operation: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  const db = await database()
  try {
    return await new Promise<T>((resolve, reject) => {
      const request = operation(db.transaction(storeName, mode).objectStore(storeName))
      request.onsuccess = () => resolve(request.result)
      request.onerror = () => reject(request.error ?? new Error('did.md Wallet device storage failed'))
    })
  } finally {
    db.close()
  }
}

export async function readDidMdRegistration(): Promise<DidMdRegistration | undefined> {
  return transact<DidMdRegistration | undefined>(REGISTRATION_STORE, 'readonly', store => store.get(REGISTRATION_ID))
}

export async function saveDidMdRegistration(value: DidMdRegistration): Promise<void> {
  await transact<IDBValidKey>(REGISTRATION_STORE, 'readwrite', store => store.put(value, REGISTRATION_ID))
}

export async function clearDidMdRegistration(): Promise<void> {
  await transact<undefined>(REGISTRATION_STORE, 'readwrite', store => store.delete(REGISTRATION_ID))
}

export async function readDidMdPendingAuthorization(): Promise<DidMdPendingAuthorization | undefined> {
  return transact<DidMdPendingAuthorization | undefined>(PENDING_STORE, 'readonly', store => store.get(PENDING_ID))
}

export async function saveDidMdPendingAuthorization(value: DidMdPendingAuthorization): Promise<void> {
  await transact<IDBValidKey>(PENDING_STORE, 'readwrite', store => store.put(value, PENDING_ID))
}

export async function clearDidMdPendingAuthorization(): Promise<void> {
  await transact<undefined>(PENDING_STORE, 'readwrite', store => store.delete(PENDING_ID))
}

export async function readDidMdDeviceSession(): Promise<DidMdDeviceSession | undefined> {
  return transact<DidMdDeviceSession | undefined>(SESSION_STORE, 'readonly', store => store.get(SESSION_ID))
}

export async function saveDidMdDeviceSession(value: DidMdDeviceSession): Promise<void> {
  await transact<IDBValidKey>(SESSION_STORE, 'readwrite', store => store.put(value, SESSION_ID))
}

export async function clearDidMdDeviceSession(): Promise<void> {
  await transact<undefined>(SESSION_STORE, 'readwrite', store => store.delete(SESSION_ID))
}
