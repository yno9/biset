export interface BisetLoginWalletCredential {
  version: 1
  identityId: string
  issuer: string
  credentialId: string
  credential: string
  holderPrivateKey: Uint8Array
  expiresAt: string
  installedAt: string
}

export interface BisetLoginWalletCredentialStore {
  put(value: BisetLoginWalletCredential): Promise<void>
  current(identityId: string, issuer: string, now?: Date): Promise<BisetLoginWalletCredential | undefined>
  remove(identityId: string, issuer: string, credentialId: string): Promise<void>
  rekeyIdentity(oldIdentityId: string, newIdentityId: string): Promise<void>
  putOidcRefreshSession(value: BisetOidcRefreshSession): Promise<void>
  oidcRefreshSession(identityId: string, issuer: string, clientId: string): Promise<BisetOidcRefreshSession | undefined>
  removeOidcRefreshSession(identityId: string, issuer: string, clientId: string): Promise<void>
}

export interface BisetOidcRefreshSession { version: 1; identityId: string; issuer: string; clientId: string; refreshToken: string; updatedAt: string }

const DATABASE_NAME = 'biset-wallet'
const DATABASE_VERSION = 2
const STORE = 'anchor_login_credentials'
const SESSION_STORE = 'anchor_oidc_refresh_sessions'

/** Device-local login capability, deliberately outside the synchronized Vault. */
export class IndexedDbBisetLoginWalletCredentialStore implements BisetLoginWalletCredentialStore {
  private databasePromise: Promise<IDBDatabase> | null = null
  constructor(private readonly databaseName = DATABASE_NAME) {}

  async put(value: BisetLoginWalletCredential): Promise<void> {
    assertRecord(value)
    const database = await this.database()
    const transaction = database.transaction(STORE, 'readwrite')
    transaction.objectStore(STORE).put(copy(value))
    await done(transaction)
  }

  async current(identityId: string, issuer: string, now = new Date()): Promise<BisetLoginWalletCredential | undefined> {
    const database = await this.database()
    const transaction = database.transaction(STORE, 'readonly')
    const rows = await result<BisetLoginWalletCredential[]>(transaction.objectStore(STORE).index('by_identity_issuer').getAll([identityId, issuer]))
    const current = rows.filter(row => Date.parse(row.expiresAt) > now.getTime()).sort((left, right) => Date.parse(right.installedAt) - Date.parse(left.installedAt))[0]
    return current && copy(current)
  }

  async remove(identityId: string, issuer: string, credentialId: string): Promise<void> {
    const database = await this.database()
    const transaction = database.transaction(STORE, 'readwrite')
    transaction.objectStore(STORE).delete([identityId, issuer, credentialId])
    await done(transaction)
  }

  async rekeyIdentity(oldIdentityId: string, newIdentityId: string): Promise<void> {
    if (oldIdentityId === newIdentityId) return
    const database = await this.database()
    const transaction = database.transaction([STORE, SESSION_STORE], 'readwrite')
    const store = transaction.objectStore(STORE)
    const rows = await result<BisetLoginWalletCredential[]>(store.index('by_identity_issuer').getAll(IDBKeyRange.bound([oldIdentityId, ''], [oldIdentityId, '\uffff'])))
    for (const row of rows) {
      store.delete([row.identityId, row.issuer, row.credentialId])
      store.put({ ...row, identityId: newIdentityId })
    }
    const sessions = await result<BisetOidcRefreshSession[]>(transaction.objectStore(SESSION_STORE).getAll())
    for (const session of sessions.filter(value => value.identityId === oldIdentityId)) {
      transaction.objectStore(SESSION_STORE).delete([session.identityId, session.issuer, session.clientId])
      transaction.objectStore(SESSION_STORE).put({ ...session, identityId: newIdentityId })
    }
    await done(transaction)
  }

  async putOidcRefreshSession(value: BisetOidcRefreshSession): Promise<void> {
    assertSession(value)
    const database = await this.database()
    const transaction = database.transaction(SESSION_STORE, 'readwrite')
    transaction.objectStore(SESSION_STORE).put({ ...value })
    await done(transaction)
  }

  async oidcRefreshSession(identityId: string, issuer: string, clientId: string): Promise<BisetOidcRefreshSession | undefined> {
    const database = await this.database()
    const transaction = database.transaction(SESSION_STORE, 'readonly')
    const value = await result<BisetOidcRefreshSession | undefined>(transaction.objectStore(SESSION_STORE).get([identityId, issuer, clientId]))
    return value && { ...value }
  }

  async removeOidcRefreshSession(identityId: string, issuer: string, clientId: string): Promise<void> {
    const database = await this.database()
    const transaction = database.transaction(SESSION_STORE, 'readwrite')
    transaction.objectStore(SESSION_STORE).delete([identityId, issuer, clientId])
    await done(transaction)
  }

  close(): void { this.databasePromise?.then(database => database.close()).catch(() => {}); this.databasePromise = null }

  private database(): Promise<IDBDatabase> {
    if (!this.databasePromise) this.databasePromise = new Promise<IDBDatabase>((resolve, reject) => {
      const request = indexedDB.open(this.databaseName, DATABASE_VERSION)
      request.onupgradeneeded = () => {
        if (!request.result.objectStoreNames.contains(STORE)) {
          const store = request.result.createObjectStore(STORE, { keyPath: ['identityId', 'issuer', 'credentialId'] })
          store.createIndex('by_identity_issuer', ['identityId', 'issuer'])
        }
        if (!request.result.objectStoreNames.contains(SESSION_STORE)) request.result.createObjectStore(SESSION_STORE, { keyPath: ['identityId', 'issuer', 'clientId'] })
      }
      request.onsuccess = () => resolve(request.result)
      request.onerror = () => reject(request.error ?? new Error('failed to open Biset Wallet database'))
      request.onblocked = () => reject(new Error('Biset Wallet database upgrade is blocked'))
    }).catch(error => { this.databasePromise = null; throw error })
    return this.databasePromise!
  }
}

function assertRecord(value: BisetLoginWalletCredential): void {
  if (value.version !== 1 || !value.identityId || !/^https:\/\//.test(value.issuer) || !value.credentialId || value.credential.split('.').length !== 3 || value.holderPrivateKey.length !== 32 || Number.isNaN(Date.parse(value.expiresAt)) || Number.isNaN(Date.parse(value.installedAt))) throw new TypeError('Biset Wallet login credential is invalid')
}
function assertSession(value: BisetOidcRefreshSession): void { if (value.version !== 1 || !value.identityId || !/^https:\/\//.test(value.issuer) || !value.clientId || !/^[A-Za-z0-9_-]{43}$/.test(value.refreshToken) || Number.isNaN(Date.parse(value.updatedAt))) throw new TypeError('Biset Wallet OIDC refresh session is invalid') }
function copy(value: BisetLoginWalletCredential): BisetLoginWalletCredential { return { ...value, holderPrivateKey: value.holderPrivateKey.slice() } }
function result<T>(request: IDBRequest<T>): Promise<T> { return new Promise((resolve, reject) => { request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error ?? new Error('Biset Wallet request failed')) }) }
function done(transaction: IDBTransaction): Promise<void> { return new Promise((resolve, reject) => { transaction.oncomplete = () => resolve(); transaction.onerror = () => reject(transaction.error ?? new Error('Biset Wallet transaction failed')); transaction.onabort = () => reject(transaction.error ?? new Error('Biset Wallet transaction aborted')) }) }
