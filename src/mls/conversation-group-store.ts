// Where a device's Conversation Group MLS state lives between page loads --
// the group-scoped counterpart of self-group `store.ts`'s
// `IndexedDbMlsSelfGroupStore`. Kept in its OWN IndexedDB database (not
// self-group's, not vault/store.ts's) for the same reason self-group's own
// store is separate from vault/store.ts: this holds key material whose loss
// means losing forward access to a group, and a device may belong to many
// Conversation Groups at once (unlike self-group's one-row-per-identity
// shape), so the schema differs enough to want its own migrations.
//
// **Identity-blind DS revision**: also holds this device's own group-local
// Ed25519 private key for the group (conversation-group.ts's
// `randomGroupLocalKeypair`) and a locally-known `GroupLocalId ↔ mlsKid`
// roster mapping. That mapping is deliberately partial -- this device only
// ever learns the entries it directly witnessed (as inviter, from
// conversation-group-invite.ts's join exchange; as invitee, its own).
// Propagating the full mapping to every member would need a new
// group-control application message, out of scope for now
// (PLAN_biset-mls-ds.md §11).
import { decodeState, encodeState } from './group.ts'
import type { ClientState } from './vendor/index.ts'
import type { GroupLocalId } from '../protocol/conversation-mls-ds.ts'

const DATABASE_NAME = 'biset-mls-conversation-group'
const DATABASE_VERSION = 1
const STORE_NAME = 'conversation-group-state'

export interface ConversationGroupRosterEntry { groupLocalId: GroupLocalId; mlsKid: string }

interface StoredConversationGroup {
  groupId: string
  state: Uint8Array
  /** The highest `ConversationLogEntry.seq` (mls-ds/store.ts) this device
   * has already applied for this group -- the cursor
   * `conversation-group-sync.ts`'s poll-based catch-up
   * (`pullDeliveries(..., afterSeq: lastSeenSeq)`) resumes from. */
  lastSeenSeq: number
  /** This device's own group-local private key for this specific group --
   * never reused across groups (conversation-group.ts's own note on why). */
  ownGroupLocalPrivateKey: Uint8Array
  roster: ConversationGroupRosterEntry[]
  /** This group's Conversation Group DS base URL -- needed to reconstruct a
   * `ConversationMlsDeliveryTransport` after a page reload, when there is no
   * invite message or fresh `resolveMimiProviderUrl` lookup to get it from
   * again. Learned once, at create/join time (main.ts), and never changes
   * for the life of this group locally (a DS migration is out of scope). */
  dsBaseUrl: string
  /** The DID to put in `ConversationGroupInviteBody.ds` (conversation-group-invite.ts)
   * when THIS device invites someone else into this group -- the DID whose
   * document actually publishes `dsBaseUrl` as a `MimiDeliveryService`
   * entry, which an invitee resolves via `resolveMimiProviderUrl`. For the
   * device that created the group, this is its own DID; for a device that
   * was itself invited, it's whatever `ds` arrived in ITS OWN invite,
   * carried forward -- there is no other way to recover it (`dsBaseUrl`
   * alone is just a URL, not proof of which DID vouches for it). */
  dsProviderDid: string
  /** Display-only name from compose's Subject field at group-creation time
   * (conversation-group-invite.ts's `ConversationGroupInviteBody.groupName`)
   * -- the DS has no name concept, and a Conversation Group message's own
   * email carries no `subject` (MimiContent has no such field), so without
   * storing this separately the thread header has nothing to show but "no
   * title" forever. undefined for a group nobody named. */
  groupName?: string
  updatedAt: number
}

export interface LoadedConversationGroup {
  state: ClientState
  lastSeenSeq: number
  ownGroupLocalPrivateKey: Uint8Array
  roster: ConversationGroupRosterEntry[]
  dsBaseUrl: string
  dsProviderDid: string
  groupName?: string
}

export interface MlsConversationGroupStateStore {
  save(groupId: string, state: ClientState, lastSeenSeq: number, ownGroupLocalPrivateKey: Uint8Array, roster: ConversationGroupRosterEntry[], dsBaseUrl: string, dsProviderDid: string, groupName?: string): Promise<void>
  load(groupId: string): Promise<LoadedConversationGroup | undefined>
  /** Every group this device currently holds state for -- the poll-based
   * catch-up loop's own "which groups do I even need to ask about" list,
   * since there is no single-owner identity to look this up from (contrast
   * self-group, where the identity itself names the one group). */
  listGroupIds(): Promise<string[]>
}

export class IndexedDbMlsConversationGroupStore implements MlsConversationGroupStateStore {
  private databasePromise: Promise<IDBDatabase> | null = null

  private database(): Promise<IDBDatabase> {
    // Don't cache a rejection -- see self-group store.ts's own note (a
    // transient open failure would otherwise poison every later call for
    // the life of the page).
    if (!this.databasePromise) this.databasePromise = openDatabase().catch(error => { this.databasePromise = null; throw error })
    return this.databasePromise
  }

  close(): void {
    this.databasePromise?.then(db => db.close()).catch(() => {})
  }

  // `groupName` is merged from whatever's already stored when the caller
  // doesn't pass one -- `put` replaces the whole record, and most callers
  // (every ordinary receive/send re-save) have no opinion on the name at
  // all; without this merge, the first such call after a named group was
  // created would silently erase the name it took a separate round trip to
  // learn in the first place.
  async save(groupId: string, state: ClientState, lastSeenSeq: number, ownGroupLocalPrivateKey: Uint8Array, roster: ConversationGroupRosterEntry[], dsBaseUrl: string, dsProviderDid: string, groupName?: string): Promise<void> {
    const database = await this.database()
    const transaction = database.transaction([STORE_NAME], 'readwrite')
    const store = transaction.objectStore(STORE_NAME)
    const existing = await requestResult<StoredConversationGroup | undefined>(store.get(groupId))
    const resolvedName = groupName ?? existing?.groupName
    const record: StoredConversationGroup = { groupId, state: encodeState(state), lastSeenSeq, ownGroupLocalPrivateKey, roster, dsBaseUrl, dsProviderDid, ...(resolvedName !== undefined ? { groupName: resolvedName } : {}), updatedAt: Date.now() }
    store.put(record)
    await transactionDone(transaction)
  }

  async load(groupId: string): Promise<LoadedConversationGroup | undefined> {
    const database = await this.database()
    const transaction = database.transaction([STORE_NAME], 'readonly')
    const record = await requestResult<StoredConversationGroup | undefined>(transaction.objectStore(STORE_NAME).get(groupId))
    return record === undefined ? undefined : {
      state: decodeState(record.state), lastSeenSeq: record.lastSeenSeq,
      ownGroupLocalPrivateKey: record.ownGroupLocalPrivateKey, roster: record.roster,
      dsBaseUrl: record.dsBaseUrl, dsProviderDid: record.dsProviderDid,
      ...(record.groupName !== undefined ? { groupName: record.groupName } : {}),
    }
  }

  async listGroupIds(): Promise<string[]> {
    const database = await this.database()
    const transaction = database.transaction([STORE_NAME], 'readonly')
    return requestResult<string[]>(transaction.objectStore(STORE_NAME).getAllKeys() as unknown as IDBRequest<string[]>)
  }
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE_NAME, DATABASE_VERSION)
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE_NAME)) request.result.createObjectStore(STORE_NAME, { keyPath: 'groupId' })
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error ?? new Error('failed to open MLS Conversation Group database'))
    request.onblocked = () => reject(new Error('MLS Conversation Group database upgrade is blocked by another client'))
  })
}

function transactionDone(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve()
    transaction.onerror = () => reject(transaction.error ?? new Error('MLS Conversation Group transaction failed'))
    transaction.onabort = () => reject(transaction.error ?? new Error('MLS Conversation Group transaction aborted'))
  })
}

function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error ?? new Error('MLS Conversation Group request failed'))
  })
}
