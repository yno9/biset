// Minimal identity creation: DID genesis + mediator/DIDComm channel, nothing
// else. Extracted from account-create.ts's submit handler (2026-08-16) so
// left-pane.ts's compose-page "create account" button can create a
// DIDComm-only identity without duplicating the DID⊥relay signup dance —
// mail/AP relay provisioning stays opt-in (claimMailAccount) and is NOT part
// of this path, same as the #new form's own signup since the "claim
// account" redesign.
import { hexToBytes } from '../utils.ts'
import type { DidRecord } from './store.ts'

export interface CreatedIdentity {
  didRecord: DidRecord
  masterSecret: Uint8Array
}

/** DID genesis only — no relay, no mediator. Throws if the identity anchor
 * is unreachable (same fail-fast rule account-create.ts's form uses).
 * Takes masterSecret rather than generating it, so a caller that also needs
 * it for kek derivation / the recovery-phrase display (account-create.ts,
 * left-pane.ts) never ends up showing a different secret than the one the
 * DID was actually derived from. */
export async function createIdentity(masterSecret: Uint8Array, username: string, hostname: string): Promise<CreatedIdentity> {
  const { initDidWebvh } = await import('./index.ts')
  const { storeDidRecord } = await import('./store.ts')
  const { setOwnDid, anchorReachable } = await import('./didcomm-devices.ts')
  const anchorOk = await anchorReachable()
  if (!anchorOk) throw new Error('Identity anchor unreachable — cannot create an account right now.')
  const didRecord = await initDidWebvh(masterSecret, { domain: hostname, username, relays: [], addresses: [] })
  await storeDidRecord(didRecord)
  setOwnDid(didRecord.did)
  return { didRecord, masterSecret }
}

/** Registers with the mediator and brings up the DIDComm channel — awaited
 * (unlike account-create.ts's fire-and-forget copy) because a caller offering
 * this identity as a From option needs the channel actually up first
 * (left-pane.ts's fromOptions only include a DID once hasDidCommChannel is
 * true). onMessage mirrors account-create.ts's own wiring. */
export async function registerIdentityChannel(did: string, onMessage: () => void): Promise<void> {
  const { registerWithMediator, mediatorUrl } = await import('./didcomm-devices.ts')
  const reg = await registerWithMediator(mediatorUrl())
  const { setupDidCommChannel } = await import('./didcomm/channel.ts')
  await setupDidCommChannel(reg.own.did, onMessage)
}

export function rootPrivateKeyBytes(rec: DidRecord): Uint8Array {
  return hexToBytes(rec.rootPrivateKey)
}
