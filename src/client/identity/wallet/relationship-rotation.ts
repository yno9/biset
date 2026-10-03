// Moving relationships to new pairwise did:peers after a device removal.
//
// Removing a device replaces the relationship seed (relationship-seed-
// bootstrap.ts): the removed device still holds every old relationship key,
// so every relationship must move to the did:peer the NEW seed derives -- one
// the removed device cannot compute. The move is an ordinary front-door
// INIT from a device still in the DID document (the one thing the removed
// device cannot send), answered by an ACCEPT over the counterparty's front
// door; the counterparty stops accepting the old did:peer from then on.
//
// It is the same step a send takes on a relationship that has not moved yet
// (WalletRelationshipManager's ensureContact). This only takes it for every
// relationship at once, so counterparties learn of the move without waiting
// for this side's next message. Idempotent: the derived did:peers are the
// same on every run and every device.
import type { ContactKeyV1 } from '../../store/vault/contact-key.ts'

export interface StaleRelationshipMoves { moved: string[]; failed: Array<{ counterpartyDid: string; error: string }> }

export async function moveStaleRelationships(input: {
  reader: { readAll(): Promise<ContactKeyV1[]>; currentFor(counterpartyDid: string): Promise<ContactKeyV1 | null> }
  /** The seed relationships should be derived from now. */
  seedId: string
  ensureContact(counterpartyDid: string): Promise<ContactKeyV1>
}): Promise<StaleRelationshipMoves> {
  const counterparties = [...new Set((await input.reader.readAll()).map(contact => contact.counterpartyDid))]
  const stale: string[] = []
  for (const counterpartyDid of counterparties) {
    const current = await input.reader.currentFor(counterpartyDid).catch(() => null)
    if (current && current.seedId !== input.seedId) stale.push(counterpartyDid)
  }
  const outcomes = await Promise.allSettled(stale.map(counterpartyDid => input.ensureContact(counterpartyDid)))
  const result: StaleRelationshipMoves = { moved: [], failed: [] }
  outcomes.forEach((outcome, index) => {
    const counterpartyDid = stale[index]!
    if (outcome.status === 'fulfilled') result.moved.push(counterpartyDid)
    else result.failed.push({ counterpartyDid, error: outcome.reason instanceof Error ? outcome.reason.message : String(outcome.reason) })
  })
  return result
}
