import type { LocalVaultBlobReader } from '../local-jmap/indexeddb.ts'
import type { SegmentId, VaultObjectId } from '../protocol/ids.ts'
import { decryptVaultObject } from './objects.ts'
import type { VaultObjectReader } from './store.ts'

/** Resolves an in-memory SegmentKey; the resolver must never persist a VEK. */
export interface SegmentKeyResolver {
  resolveSegmentKey(identityId: string, segmentId: SegmentId): Promise<Uint8Array>
}

/**
 * Local JMAP's encrypted blob reader. The source object is authenticated by
 * `decryptVaultObject` before any byte range is returned to the UI.
 */
export class VaultObjectBlobReader implements LocalVaultBlobReader {
  constructor(
    private readonly objects: VaultObjectReader,
    private readonly segmentKeys: SegmentKeyResolver,
  ) {}

  async download(identityId: string, blobId: string, range?: { start: number; end?: number }): Promise<Uint8Array> {
    const object = await this.objects.readObject(identityId, blobId as VaultObjectId)
    if (!object) throw new Error('local vault blob not found')
    const segmentKey = await this.segmentKeys.resolveSegmentKey(identityId, object.segmentId)
    const plaintext = await decryptVaultObject(segmentKey, object)
    return applyRange(plaintext, range)
  }
}

function applyRange(bytes: Uint8Array, range: { start: number; end?: number } | undefined): Uint8Array {
  if (!range) return bytes
  const end = range.end === undefined ? bytes.length - 1 : range.end
  if (!Number.isSafeInteger(range.start) || !Number.isSafeInteger(end) || range.start < 0 || end < range.start || end >= bytes.length) {
    throw new RangeError('invalid local vault blob range')
  }
  return bytes.slice(range.start, end + 1)
}
