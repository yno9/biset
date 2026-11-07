// One identity's Vault on this device, as the rest of the session uses it: the store, the read model the UI renders,
// the sink every local change is committed through, and what signs and sequences those changes.
import { buildActorSequencer, buildLocalJmapReadModel, buildWalletVaultCryptoBoundary, type VaultCryptoBoundary } from '../../identity/bootstrap.ts'
import { IndexedDbVaultStore } from '../../store/vault/store.ts'
import { VaultProjector } from '../../store/vault/projector.ts'
import { VaultBackedLocalJmapMutationSink } from '../../store/projection/vault-mutation-sink.ts'
import { contactSetIntent, contactWritesFor, replyTokenWrites, type ContactSetPayload, type LocalJmapContactCard } from '../../store/projection/contacts.ts'
import type { LocalJmapReadModel, LocalJmapSnapshot } from '../../store/projection/gateway.ts'
import type { VaultEventV1 } from '../../../protocol/vault.ts'
import { identityKey } from '../../../protocol/vh/identifier.ts'
import { errorMessage } from '../../../protocol/error-message.ts'
import { refreshInbox } from '../ui/shell.ts'
import { timed } from './boot-timing.ts'

type ActorSequencer = Awaited<ReturnType<typeof buildActorSequencer>>

/** What a new Vault event is written with: passed as it is to everything that authors one. */
interface VaultAuthoring {
  nextActorSeq(): Promise<number>
  initialParents(): ReturnType<ActorSequencer['initialParents']>
  activeSegment: VaultCryptoBoundary['activeSegment']
  signer: VaultCryptoBoundary['author']
}

export interface AccountVault {
  /** What every local store and every address of this identity in stored data is keyed by: stable across an alias change (the
   * DID's host), unlike the DID itself, which is for talking to others. */
  identityId: string
  accountId: string
  deviceId: string
  store: IndexedDbVaultStore
  boundary: VaultCryptoBoundary
  readModel: LocalJmapReadModel
  projector: VaultProjector
  mutationSink: VaultBackedLocalJmapMutationSink
  authoring: VaultAuthoring
  /** Where committed events go besides this device (Vault Sync, once it is connected). */
  setSiblingPush(push: ((events: VaultEventV1[]) => Promise<void>) | undefined): void
  pushToSiblings(events: VaultEventV1[]): Promise<void>
  snapshot(): Promise<LocalJmapSnapshot>
  /** Redraws what the UI shows from the read model. */
  refresh(): Promise<void>
  /** Commits the writes `make` gives for the card of `did` (making the card if there is none); says whether there were any. */
  writeContact(did: string, make: (cardId: string, card: LocalJmapContactCard | undefined) => readonly (ContactSetPayload | undefined)[]): Promise<boolean>
  /** Commits contact writes worked out elsewhere. */
  commitContactWrites(writes: readonly ContactSetPayload[], snapshot?: LocalJmapSnapshot): Promise<void>
  /** Keeps the reply tokens a mail bridge answered with, each on the card of the address it is for. */
  keepReplyTokens(tokens: Record<string, string>): Promise<void>
}

export async function openAccountVault(device: { did: string; deviceId: string }): Promise<AccountVault> {
  const identityId = identityKey(device.did)
  const accountId = `biset:${identityId}`
  const store = await timed('IndexedDbVaultStore.open', IndexedDbVaultStore.open())
  const boundary = buildWalletVaultCryptoBoundary(store, { did: identityId, deviceId: device.deviceId })
  const readModel = buildLocalJmapReadModel(store, identityId)
  const projector = new VaultProjector(store, boundary.resolver)
  const sequencer = await timed('buildActorSequencer', buildActorSequencer(store, identityId, device.deviceId))
  const authoring: VaultAuthoring = {
    nextActorSeq: () => sequencer.nextActorSeq(),
    initialParents: () => sequencer.initialParents(),
    activeSegment: () => boundary.activeSegment(),
    signer: boundary.author,
  }
  let siblingPush: ((events: VaultEventV1[]) => Promise<void>) | undefined
  const pushToSiblings = async (events: VaultEventV1[]): Promise<void> => { if (siblingPush && events.length) await siblingPush(events) }
  const mutationSink = new VaultBackedLocalJmapMutationSink({
    accountId,
    identityId,
    actorDeviceId: device.deviceId,
    ...authoring,
    committer: store,
    onCrdtCommitted: async events => {
      await projector.recomputeEmails(identityId, events.flatMap(event => event.targetIds))
      void pushToSiblings(events).catch(error => console.warn('[did.md Wallet Vault Sync push]', errorMessage(error)))
    },
  })
  const commitContactWrites = async (writes: readonly ContactSetPayload[], snapshot?: LocalJmapSnapshot): Promise<void> => {
    if (writes.length > 0) await mutationSink.commitIntents(writes.map(contactSetIntent), snapshot ?? await readModel.snapshot())
  }
  return {
    identityId, accountId, deviceId: device.deviceId, store, boundary, readModel, projector, mutationSink, authoring,
    setSiblingPush: push => { siblingPush = push },
    pushToSiblings,
    snapshot: () => readModel.snapshot(),
    refresh: () => refreshInbox(readModel),
    async writeContact(did, make) {
      const snapshot = await readModel.snapshot()
      const writes = contactWritesFor(snapshot.contactCards, did, make)
      await commitContactWrites(writes, snapshot)
      return writes.length > 0
    },
    commitContactWrites,
    async keepReplyTokens(tokens) {
      const snapshot = await readModel.snapshot()
      await commitContactWrites(replyTokenWrites(snapshot.contactCards, tokens), snapshot)
    },
  }
}
