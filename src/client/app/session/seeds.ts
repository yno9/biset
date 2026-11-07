// The generation seed: Vault records, read and written like every other private credential and carried to siblings by Vault
// Sync. Which one is in use is the DID document's say (generation-seed-bootstrap.ts), known once the mediator is connected.
import { createGenerationSeedAuthority, type GenerationSeedAuthority } from '../../didcomm/generation-seed-bootstrap.ts'
import { publishedRotationKey, rotationSigningKey } from '../../didcomm/rotation-key.ts'
import { fetchCurrentLog, freshFetch } from '../../identity/log-io.ts'
import { approvedRotationSeed } from '../../identity/wallet/did-md-oauth.ts'
import { GenerationSeedReader, GenerationSeedSink, generationSeedRecord } from '../../store/vault/generation-seed.ts'
import { equalBytes } from '../../../protocol/canonical.ts'
import { entryVersionNumber } from '../../../protocol/vh/log.ts'
import { errorMessage } from '../../../protocol/error-message.ts'
import type { AccountVault } from './account-vault.ts'
import { timed } from './boot-timing.ts'
import type { GenerationSeeds } from './own-identity.ts'

export interface SessionSeeds extends GenerationSeeds {
  reader: GenerationSeedReader
  /** There is none until the mediator is connected (`connect`). */
  authority: GenerationSeedAuthority | undefined
  /** Starts reading the DID document for the seed in use, and stores one a Wallet approval just published. */
  connect(options: { did: string; ownKid: string }): Promise<GenerationSeedAuthority>
}

export function sessionSeeds(vault: AccountVault): SessionSeeds {
  const reader = new GenerationSeedReader({ identityId: vault.identityId, objects: vault.store, events: vault.store, segmentKeys: vault.boundary.resolver })
  const sink = new GenerationSeedSink({
    identityId: vault.identityId, actorDeviceId: vault.deviceId, ...vault.authoring,
    currentSnapshot: () => vault.snapshot(), committer: vault.store,
    onCommitted: event => vault.pushToSiblings([event]),
  })
  const seeds: SessionSeeds = {
    reader,
    authority: undefined,
    current: async () => seeds.authority?.require().then(value => value.seed, () => undefined),
    all: async () => (await reader.readAll()).map(record => record.seed),
    async connect({ did, ownKid }) {
      const authority = createGenerationSeedAuthority({ ownKid, seeds: reader, readLog: async () => (await fetchCurrentLog(did, freshFetch())).entries })
      seeds.authority = authority
      await timed('storeApprovedRotationSeed', storeApprovedRotationSeed(did, vault.identityId, reader, sink, authority))
        .catch(error => console.warn('[did.md Wallet generation seed]', errorMessage(error)))
      return authority
    },
  }
  return seeds
}

/** Stores the seed a Wallet approval published the rotation key of (the approval's candidate, kept sealed in the session until
 * the Vault is open) -- if the DID document still publishes that key and the Vault lacks it -- and forgets the candidate either way. */
async function storeApprovedRotationSeed(did: string, identityId: string, reader: GenerationSeedReader, sink: GenerationSeedSink, authority: GenerationSeedAuthority): Promise<void> {
  const approved = await approvedRotationSeed()
  if (!approved) return
  try {
    const log = await fetchCurrentLog(did, freshFetch())
    const published = publishedRotationKey(log.last.state as Parameters<typeof publishedRotationKey>[0])
    const stored = (await reader.readAll()).some(value => equalBytes(value.seed, approved.seed))
    if (published === rotationSigningKey(approved.seed).publicKeyMultibase && !stored) {
      await sink.store(generationSeedRecord(identityId, approved.seed, entryVersionNumber(log.last.versionId)))
      authority.refresh()
    }
    await approved.forget()
  } finally { approved.seed.fill(0) }
}
