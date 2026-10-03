// Discover Features 2.0 client: asking a mediator for its
// `max_receive_bytes` constraint (DIDComm v2.1 "Agent Constraint
// Disclosure") -- the largest message it will take for a recipient.
import { sendAndUnpack, type DidCommSender, type MediatorInfo } from './mediator-transport.ts'
import { defaultFetch } from '../net-fetch.ts'
import { DISCOVER_FEATURES_DISCLOSE, DISCOVER_FEATURES_QUERIES, MAX_RECEIVE_BYTES } from './mediator-protocol.ts'

/** The mediator's disclosed `max_receive_bytes`, or undefined when it does
 * not disclose one (an empty disclosure means "not telling", not "none"). */
export async function discoverMaxReceiveBytes(mediator: MediatorInfo, own: DidCommSender, fetchImpl: typeof fetch = defaultFetch()): Promise<number | undefined> {
  const reply = await sendAndUnpack(mediator, own, DISCOVER_FEATURES_QUERIES, { queries: [{ 'feature-type': 'constraint', match: MAX_RECEIVE_BYTES }] }, fetchImpl)
  if (reply.type !== DISCOVER_FEATURES_DISCLOSE) throw new Error(`discoverMaxReceiveBytes: unexpected reply type ${reply.type}`)
  const disclosures = (reply.body as { disclosures?: unknown }).disclosures
  if (!Array.isArray(disclosures)) return undefined
  for (const disclosure of disclosures as Array<Record<string, unknown>>) {
    if (disclosure['feature-type'] !== 'constraint' || disclosure.id !== MAX_RECEIVE_BYTES) continue
    // The spec's own example carries the number as a string.
    const value = Number(disclosure[MAX_RECEIVE_BYTES])
    if (Number.isSafeInteger(value) && value > 0) return value
  }
  return undefined
}
