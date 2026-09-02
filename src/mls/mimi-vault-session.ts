/** Durable MLS/MIMI session used by the Vault data plane.
 *
 * A PrivateMessage is persisted with the post-send MLS state before its HTTP
 * request is attempted.  If the response is lost, the next attempt submits
 * the exact same bytes and delivery ID; it never encrypts the plaintext a
 * second time from a stale ratchet state. */
import { bytesToBase64url, equalBytes, sha256Bytes } from '../protocol/canonical.ts'
import { epochOf, encryptApplication, processIncoming } from './group.ts'
import type { ClientState } from './vendor/index.ts'
import type { MimiClientMode, MimiClientTransport } from './mimi-client-transport.ts'
import type { MimiCredential, MimiDeliveryEntry, VaultCheckpointManifest } from '../mimi/protocol-types.ts'
import { submitMessageSigningBytes, submitVaultCheckpointSigningBytes } from '../mimi/authorizer.ts'
import type { MimiVaultMlsReceiver, MimiVaultMlsSender } from '../vault/mimi-vault-sync.ts'

export interface MimiVaultPendingApplication {
  deliveryId: string
  plaintextHash: Uint8Array
  appMessage: Uint8Array
}
export interface MimiVaultSessionRecord {
  roomId: string
  selfGroupId: string
  state: ClientState
  pending?: MimiVaultPendingApplication
  /** Recent ciphertexts sent by this device. MLS sender chains cannot process
   * their own post-send PrivateMessages (the desired generation is past), so
   * these are recognized and skipped when the room inbox echoes them back. */
  ownApplicationHashes?: string[]
}
export interface MimiVaultSessionStateStore {
  loadMimiVault(identityId: string): Promise<MimiVaultSessionRecord | undefined>
  saveMimiVault(identityId: string, value: MimiVaultSessionRecord): Promise<void>
}
export interface MimiVaultSessionOptions {
  identityId: string
  mode: MimiClientMode
  credential: MimiCredential
  sign(bytes: Uint8Array): Uint8Array | Promise<Uint8Array>
  transport: MimiClientTransport
  stateStore: MimiVaultSessionStateStore
  now?: () => Date
}

export class PersistedMimiVaultSession implements MimiVaultMlsSender, MimiVaultMlsReceiver {
  private readonly now: () => Date
  constructor(private readonly options: MimiVaultSessionOptions) { this.now = options.now ?? (() => new Date()) }

  async sendApplication(plaintext: Uint8Array, deliveryId: string): Promise<void> {
    if (!/^[A-Za-z0-9_-]{16,128}$/.test(deliveryId) || plaintext.length === 0) throw new TypeError('MIMI Vault application delivery is invalid')
    let record = await this.requiredRecord()
    const plaintextHash = sha256Bytes(plaintext)
    if (record.pending) {
      if (record.pending.deliveryId !== deliveryId || !equalBytes(record.pending.plaintextHash, plaintextHash)) throw new Error('MIMI Vault has an earlier pending application delivery')
    } else {
      const encrypted = await encryptApplication(record.state, plaintext)
      record = { ...record, state: encrypted.state, pending: { deliveryId, plaintextHash, appMessage: encrypted.wire } }
      await this.options.stateStore.saveMimiVault(this.options.identityId, record)
    }
    await this.submitApplication(record, record.pending!)
    await this.options.stateStore.saveMimiVault(this.options.identityId, {
      ...record, pending: undefined,
      ownApplicationHashes: rememberOwnApplication(record.ownApplicationHashes, pendingCipherHash(record.pending!)),
    })
  }

  async sendCheckpoint(manifest: VaultCheckpointManifest): Promise<void> {
    const record = await this.requiredRecord()
    if (record.pending) throw new Error('MIMI Vault application delivery must be confirmed before its checkpoint manifest')
    const unsigned = { version: 1 as const, protocol: 'mls10' as const, roomId: record.roomId, sender: this.options.credential, epoch: String(epochOf(record.state)), manifest, submittedAt: this.now().toISOString() }
    const response = await this.options.transport.submitVaultCheckpoint(this.options.mode, { ...unsigned, signature: await this.options.sign(submitVaultCheckpointSigningBytes(unsigned)) })
    if (response.status !== 'accepted') throw new Error(`MIMI Vault checkpoint submission failed: ${response.status}`)
  }

  async receive(entry: MimiDeliveryEntry): Promise<Uint8Array | undefined> {
    const record = await this.requiredRecord()
    if (record.pending) throw new Error('MIMI Vault has a pending local application delivery')
    if (entry.kind === 'vaultCheckpoint') return undefined
    if (entry.kind === 'application' && record.ownApplicationHashes?.includes(pendingCipherHash(entry.payload))) return undefined
    const result = await processIncoming(record.state, entry.payload)
    await this.options.stateStore.saveMimiVault(this.options.identityId, { ...record, state: result.state })
    return result.kind === 'message' ? result.message : undefined
  }

  private async submitApplication(record: MimiVaultSessionRecord, pending: MimiVaultPendingApplication): Promise<void> {
    const unsigned = {
      version: 1 as const, protocol: 'mls10' as const, roomId: record.roomId, sender: this.options.credential, epoch: String(epochOf(record.state)),
      appMessage: pending.appMessage, deliveryId: pending.deliveryId,
      frankAAD: { frankingTag: crypto.getRandomValues(new Uint8Array(32)) }, frankingSignatureCiphersuite: 1, submittedAt: this.now().toISOString(),
    }
    const response = await this.options.transport.submitMessage(this.options.mode, { ...unsigned, signature: await this.options.sign(submitMessageSigningBytes(unsigned)) })
    if (response.status !== 'accepted') throw new Error(`MIMI Vault application submission failed: ${response.status}`)
  }

  private async requiredRecord(): Promise<MimiVaultSessionRecord> {
    const record = await this.options.stateStore.loadMimiVault(this.options.identityId)
    if (!record) throw new Error('MIMI Vault room is not initialized')
    return record
  }
}

function pendingCipherHash(value: Pick<MimiVaultPendingApplication, 'appMessage'> | Uint8Array): string {
  const bytes = value instanceof Uint8Array ? value : value.appMessage
  return bytesToBase64url(sha256Bytes(bytes))
}
function rememberOwnApplication(previous: readonly string[] | undefined, value: string): string[] {
  return [...new Set([...(previous ?? []), value])].slice(-512)
}
