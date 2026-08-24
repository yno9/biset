import { localJmapSnapshotFromProjection, type LocalJmapReadModel, type LocalJmapSnapshot } from './gateway.ts'
import { projectionState } from './reducer.ts'
import type { VaultProjectionReader } from '../vault/store.ts'

/**
 * Reading JMAP state from a vault is independent from decrypting blobs. The
 * projection is already a local, durable derivative; the caller supplies the
 * object/chunk reader that has access to the required SegmentKey.
 */
export interface LocalVaultBlobReader {
  download(identityId: string, blobId: string, range?: { start: number; end?: number }): Promise<Uint8Array>
}

export class IndexedDbLocalJmapReadModel implements LocalJmapReadModel {
  constructor(
    private readonly vault: VaultProjectionReader,
    private readonly identityId: string,
    private readonly blobs: LocalVaultBlobReader,
  ) {
    if (!identityId) throw new TypeError('local JMAP identity is required')
  }

  async snapshot(): Promise<LocalJmapSnapshot> {
    const projection = await this.vault.readProjection(this.identityId)
    // No commit has ever landed for this identity yet -- true for every
    // brand-new account right after signup, not an error. Empty mailboxes/
    // emails, same shape reduceLocalJmapProjection produces from a genuinely
    // empty base.
    if (projection === undefined) return { state: projectionState(this.identityId, [], []), mailboxes: [], emails: [] }
    return localJmapSnapshotFromProjection(projection, this.identityId)
  }

  download(blobId: string, range?: { start: number; end?: number }): Promise<Uint8Array> {
    return this.blobs.download(this.identityId, blobId, range)
  }
}
