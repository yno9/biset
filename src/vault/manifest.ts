import { canonicalHash } from '../shared/protocol/canonical.ts'
import type { IdentityId, VaultEventId, VaultObjectId } from '../shared/protocol/ids.ts'

export interface VaultManifestV1 {
  version: 1
  identityId: IdentityId
  eventIds: VaultEventId[]
  objectIds: VaultObjectId[]
  root: string
  createdAt: string
}

export interface VaultManifestDiff {
  missingEvents: VaultEventId[]
  missingObjects: VaultObjectId[]
}

export function buildVaultManifest(
  identityId: IdentityId,
  eventIds: Iterable<VaultEventId>,
  objectIds: Iterable<VaultObjectId>,
  createdAt: string,
): VaultManifestV1 {
  if (!identityId || Number.isNaN(Date.parse(createdAt))) throw new TypeError('manifest identityId and createdAt are required')
  const events = sortedUnique(eventIds)
  const objects = sortedUnique(objectIds)
  return {
    version: 1,
    identityId,
    eventIds: events,
    objectIds: objects,
    root: manifestRoot(identityId, events, objects),
    createdAt,
  }
}

export function verifyVaultManifest(manifest: VaultManifestV1): boolean {
  return manifest.version === 1
    && manifest.eventIds.every((value, index, all) => index === 0 || all[index - 1] < value)
    && manifest.objectIds.every((value, index, all) => index === 0 || all[index - 1] < value)
    && manifest.root === manifestRoot(manifest.identityId, manifest.eventIds, manifest.objectIds)
}

/** Objects present in `source` but absent from `target`. */
export function diffVaultManifests(source: VaultManifestV1, target: VaultManifestV1): VaultManifestDiff {
  if (source.identityId !== target.identityId) throw new TypeError('cannot diff manifests from different identities')
  const targetEvents = new Set(target.eventIds)
  const targetObjects = new Set(target.objectIds)
  return {
    missingEvents: source.eventIds.filter((id) => !targetEvents.has(id)),
    missingObjects: source.objectIds.filter((id) => !targetObjects.has(id)),
  }
}

function manifestRoot(identityId: IdentityId, eventIds: VaultEventId[], objectIds: VaultObjectId[]): string {
  return canonicalHash('biset/vault/manifest/v1', { version: 1, identityId, eventIds, objectIds })
}

function sortedUnique(values: Iterable<string>): string[] {
  return [...new Set(values)].sort((left, right) => (left < right ? -1 : left > right ? 1 : 0))
}
