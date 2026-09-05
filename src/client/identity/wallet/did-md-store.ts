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
  did: string
  handle: string
  verificationMethod: string
  rootPublicKey: Uint8Array
  deviceJkt: string
  privateKey: CryptoKey
  publicJwk: JsonWebKey
  /** Biset-only device material. Its private leaf key and Vault secret are
   * sealed under an opaque, non-extractable browser AES key before this
   * pending authorization is persisted across the Wallet redirect. */
  bisetDevice: DidMdBisetDeviceMaterial
  /** Public, Wallet-authorized pointer to the MIMI Self/Vault room. This is
   * tied to the pending authorization so callback handling can reject a
  * substituted room before any MLS operation. */
  bisetMimiVaultRoom: DidMdBisetMimiVaultRoom
  /** True only when this request reserved a not-yet-existing Vault room. */
  bisetMimiVaultRoomCreated: boolean
  /** Present only for a Wallet approval that explicitly publishes this
   * browser's Biset DIDComm endpoint. */
  bisetDidCommDevice?: DidMdBisetDidCommDeviceMaterial & {
    mediatorUrl: string
    routingKid: string
    xKid: string
  }
  createdAt: string
}

export type DidMdBisetMimiVaultRoom = {
  roomId: string
  providerUrl: string
}

export type DidMdBisetDeviceMaterial = {
  v: 1
  signaturePublicKey: Uint8Array
  sealed: { iv: Uint8Array; ciphertext: Uint8Array }
}

export type OpenDidMdBisetDeviceMaterial = {
  signaturePrivateKey: Uint8Array
  vaultSecret: Uint8Array
}

/** A Biset-owned DIDComm X25519 leaf. It is separate from the MLS signing
 * leaf: the two protocols have distinct key-agreement/signing roles and
 * must not share a private key. */
export type DidMdBisetDidCommDeviceMaterial = {
  v: 1
  x25519PublicKey: Uint8Array
  sealed: { iv: Uint8Array; ciphertext: Uint8Array }
}

export type OpenDidMdBisetDidCommDeviceMaterial = {
  x25519PrivateKey: Uint8Array
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
  capability: { document: unknown; proof: unknown }
  capabilityExpiresAt: string
  /** The typed, public MLS credential the Wallet issued for this exact Biset
   * leaf. Undefined is an older Phase-A session and cannot open a Vault. */
  bisetDevice?: DidMdBisetDeviceMaterial & { credentialWire: string; mimiVaultRoom: DidMdBisetMimiVaultRoom; mimiVaultRoomCreated: boolean }
  /** An optional Biset-owned DIDComm leaf, authorized by a Wallet routing
   * approval. It is not a did.md controller key. */
  bisetDidCommDevice?: DidMdBisetDidCommDeviceMaterial & {
    mediatorUrl: string
    routingKid: string
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

function assertDevicePrivateMaterial(value: OpenDidMdBisetDeviceMaterial): void {
  if (!(value.signaturePrivateKey instanceof Uint8Array) || value.signaturePrivateKey.length !== 32 || !(value.vaultSecret instanceof Uint8Array) || value.vaultSecret.length !== 32) {
    throw new TypeError('Biset device private material is invalid')
  }
}

function assertSealedDeviceMaterial(value: DidMdBisetDeviceMaterial): void {
  if (value.v !== 1 || !(value.signaturePublicKey instanceof Uint8Array) || value.signaturePublicKey.length !== 32
    || !(value.sealed?.iv instanceof Uint8Array) || value.sealed.iv.length !== 12
    || !(value.sealed?.ciphertext instanceof Uint8Array) || value.sealed.ciphertext.length < 17) {
    throw new TypeError('Biset device material is invalid')
  }
}

function assertDidCommPrivateMaterial(value: OpenDidMdBisetDidCommDeviceMaterial): void {
  if (!(value.x25519PrivateKey instanceof Uint8Array) || value.x25519PrivateKey.length !== 32) throw new TypeError('Biset DIDComm device private material is invalid')
}

function assertSealedDidCommMaterial(value: DidMdBisetDidCommDeviceMaterial): void {
  if (value.v !== 1 || !(value.x25519PublicKey instanceof Uint8Array) || value.x25519PublicKey.length !== 32
    || !(value.sealed?.iv instanceof Uint8Array) || value.sealed.iv.length !== 12
    || !(value.sealed?.ciphertext instanceof Uint8Array) || value.sealed.ciphertext.length < 17) {
    throw new TypeError('Biset DIDComm device material is invalid')
  }
}

/** Seals the two Biset-only secrets under an IndexedDB-persisted but
 * non-extractable AES-GCM CryptoKey. The key is unrelated to any did.md
 * controller key and cannot be exported by this origin. */
export async function sealDidMdBisetDeviceMaterial(
  signaturePublicKey: Uint8Array,
  privateMaterial: OpenDidMdBisetDeviceMaterial,
): Promise<DidMdBisetDeviceMaterial> {
  assertDevicePrivateMaterial(privateMaterial)
  if (!(signaturePublicKey instanceof Uint8Array) || signaturePublicKey.length !== 32) throw new TypeError('Biset device public key is invalid')
  const key = await materialWrappingKey()
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const plaintext = new TextEncoder().encode(JSON.stringify({
    v: 1,
    signaturePrivateKey: [...privateMaterial.signaturePrivateKey],
    vaultSecret: [...privateMaterial.vaultSecret],
  }))
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext))
  return { v: 1, signaturePublicKey: signaturePublicKey.slice(), sealed: { iv, ciphertext } }
}

/** Opens device material only into the active Biset tab. Callers must never
 * serialize this return value or use it as a did.md controller secret. */
export async function openDidMdBisetDeviceMaterial(value: DidMdBisetDeviceMaterial): Promise<OpenDidMdBisetDeviceMaterial> {
  assertSealedDeviceMaterial(value)
  const key = await materialWrappingKey()
  let decoded: unknown
  try {
    // Copy values read from IndexedDB into ordinary ArrayBuffer-backed views;
    // WebCrypto's current DOM typings reject a potentially shared buffer.
    const iv = new Uint8Array(value.sealed.iv.length); iv.set(value.sealed.iv)
    const ciphertext = new Uint8Array(value.sealed.ciphertext.length); ciphertext.set(value.sealed.ciphertext)
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext)
    decoded = JSON.parse(new TextDecoder().decode(plaintext))
  } catch { throw new Error('Biset device material could not be decrypted on this browser') }
  if (decoded === null || typeof decoded !== 'object' || Array.isArray(decoded)) throw new Error('Biset device material is invalid')
  const input = decoded as Record<string, unknown>
  if (input.v !== 1 || !Array.isArray(input.signaturePrivateKey) || !Array.isArray(input.vaultSecret)) throw new Error('Biset device material is invalid')
  const privateMaterial = {
    signaturePrivateKey: new Uint8Array(input.signaturePrivateKey),
    vaultSecret: new Uint8Array(input.vaultSecret),
  }
  assertDevicePrivateMaterial(privateMaterial)
  return privateMaterial
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
  const additionalData = new TextEncoder().encode('biset/did-md/didcomm-device/v1')
  const plaintext = new TextEncoder().encode(JSON.stringify({ v: 1, x25519PrivateKey: [...privateMaterial.x25519PrivateKey] }))
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData }, key, plaintext))
  return { v: 1, x25519PublicKey: x25519PublicKey.slice(), sealed: { iv, ciphertext } }
}

export async function openDidMdBisetDidCommDeviceMaterial(value: DidMdBisetDidCommDeviceMaterial): Promise<OpenDidMdBisetDidCommDeviceMaterial> {
  assertSealedDidCommMaterial(value)
  const key = await materialWrappingKey()
  const additionalData = new TextEncoder().encode('biset/did-md/didcomm-device/v1')
  let decoded: unknown
  try {
    const iv = new Uint8Array(value.sealed.iv.length); iv.set(value.sealed.iv)
    const ciphertext = new Uint8Array(value.sealed.ciphertext.length); ciphertext.set(value.sealed.ciphertext)
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData }, key, ciphertext)
    decoded = JSON.parse(new TextDecoder().decode(plaintext))
  } catch { throw new Error('Biset DIDComm device material could not be decrypted on this browser') }
  if (decoded === null || typeof decoded !== 'object' || Array.isArray(decoded)) throw new Error('Biset DIDComm device material is invalid')
  const input = decoded as Record<string, unknown>
  if (input.v !== 1 || !Array.isArray(input.x25519PrivateKey)) throw new Error('Biset DIDComm device material is invalid')
  const privateMaterial = { x25519PrivateKey: new Uint8Array(input.x25519PrivateKey) }
  assertDidCommPrivateMaterial(privateMaterial)
  return privateMaterial
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
