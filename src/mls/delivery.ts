// Applying what the Delivery Service sends, for ANY group — the self group
// (this identity's own devices) and a conversation with other people alike.
//
// The two differ in who is in them and what a message means, and in nothing
// else that happens here: both advance one stored MLS state strictly in order,
// both keep a cursor of what they have applied, and both have to be able to
// ask the DS for what they never received (mls-ds.ts's everMembers — push is
// advisory, pull is the guarantee). Writing that twice would be writing two
// slightly different answers to "am I missing a delivery", which is exactly
// the class of bug this cursor exists to end.
//
// So the group-specific part is reduced to one thing: what an application
// message's bytes MEAN. That is a JSON object with a `t` tag, and the caller
// dispatches on it.
import { processIncoming, isActiveMember } from './group.ts'
import type { MlsMemberId } from './identity.ts'
import { loadGroup, saveGroup, withGroupLock } from './store.ts'
import type { DidCommSender } from '../did/didcomm/message.ts'
import type { MediatorInfo } from '../did/didcomm/coordinate.ts'
import { fetchDeliveries, type Delivery } from './transport.ts'

/** What applying one delivery produced.
 *
 * `payload` is the decoded application-message object when the delivery was
 * one; every other kind advances state and produces nothing to hand up. */
export interface Applied {
  payload?: Record<string, unknown>
  /** Who sent the application message, as MLS authenticated it — the leaf's
   * credential, not anything the plaintext claims. Absent for everything that
   * is not an application message. */
  sender?: MlsMemberId
  /** A proposal arrived and is sitting in the group's pending set. Somebody
   * has to commit it — in practice a sibling's declared departure. */
  sawProposal?: boolean
  /** Do NOT acknowledge this one: it could not be applied, and MLS advances
   * strictly in order, so acknowledging it (which tells the mediator to forget
   * it) would leave this device permanently a step behind with nothing left to
   * fetch. */
  retry?: boolean
  /** The pull walked past it because this device had already lived through it.
   * Expected, and counted rather than warned about one by one. */
  skipped?: boolean
}

/** Apply one delivery to a group this device already has state for.
 *
 * Never throws for an ordinary "cannot apply this". A poll loop that stops on
 * one bad message stops forever, and the messages most likely to be bad are
 * the ones from before this device joined.
 *
 * `opts.pull` says the delivery was ASKED for, in order, starting from what
 * this device last applied — which inverts what an inapplicable one means. In
 * a push it arrived early and is worth another try; in a pull it is history
 * this device cannot use (an epoch it has passed, or one of its own commits,
 * which the DS's log holds and the fan-out never sends back), and holding the
 * cursor there would stop the catch-up at that entry forever. */
export async function receiveDelivery(id: string, delivery: Delivery, opts: { pull?: boolean } = {}): Promise<Applied> {
  return withGroupLock(id, async () => {
    const stored = await loadGroup(id)
    if (!stored) {
      // Nothing to apply it to, and nothing that will change that by waiting:
      // the ways INTO a group are a Welcome (handled before this) and an
      // external commit, never a replay of deliveries from before membership.
      console.warn(`[mls] delivery ${delivery.seq} for ${id.slice(0, 12)} arrived before this device has group state`)
      return {}
    }
    // The cursor advances only over a CONTIGUOUS delivery. Taking the highest
    // seq applied instead would step over a gap: an application message from
    // an epoch this device is already in applies perfectly well while an
    // earlier one is missing, and the cursor would then never ask for the
    // missing one — a message silently lost, which is the exact failure the
    // pull exists to repair.
    const advance = (): number => delivery.seq === stored.lastSeq + 1 ? delivery.seq : stored.lastSeq
    try {
      const result = await processIncoming(stored.state, delivery.payload)
      await saveGroup({ ...stored, state: result.state, lastSeq: advance() })
      if (delivery.kind === 'proposal') return { sawProposal: true }
      if (result.kind !== 'message') return {}
      const parsed = JSON.parse(new TextDecoder().decode(result.message)) as Record<string, unknown>
      return typeof parsed?.t === 'string' ? { payload: parsed, ...(result.sender ? { sender: result.sender } : {}) } : {}
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e)
      // Permanent means "no later attempt can change this": the group has
      // moved past what this message belongs to. Withholding the ack for one
      // of these would have the mediator redeliver it every poll for as long
      // as it keeps it — the device asking forever for something it can never
      // use. `Desired gen in the past` is the third form of the same thing: a
      // message from a ratchet generation this device has already consumed or
      // skipped, which is what an application message sent BEFORE it joined
      // looks like from inside the group it has now joined.
      const permanent = opts.pull
        || message.includes('epoch too old')
        || message.includes('former epoch')
        || message.includes('Desired gen in the past')
      // A permanently inapplicable delivery still moves the cursor past it, or
      // the pull would fetch that same dead message forever and never reach
      // what follows it.
      if (permanent && advance() !== stored.lastSeq) await saveGroup({ ...stored, lastSeq: advance() })
      // Skipping history is what a pull DOES, not something that went wrong: a
      // device whose cursor starts at zero replays the DS's whole log, and
      // every entry it already lived through fails here. Reported once by the
      // caller as a count.
      if (opts.pull) return { skipped: true }
      console.warn(`[mls] could not apply delivery ${delivery.seq}${permanent ? ' (dropping)' : ' (will retry)'}:`, message)
      return permanent ? {} : { retry: true }
    }
  })
}

/** Fetch and apply everything this device is missing in one group.
 *
 * The **pull** half of delivery, and it has to exist because the push half
 * cannot be verified by anyone. The DS fans out to the roster the last
 * committer declared, and it cannot check that declaration — the commit is a
 * PrivateMessage, and a DS able to read membership changes would be a DS able
 * to read the group. Push is therefore a hint; what a device is owed is
 * defined by the group's own gapless sequence, and asked for here.
 *
 * It repairs the ordinary case by the same mechanism: a fan-out that failed,
 * or a copy lost between mediators, had nothing anywhere that remembered it
 * was owed. Now the DS's log does. */
export async function catchUpGroup(ds: MediatorInfo, own: DidCommSender, id: string): Promise<{ applied: Applied[]; sawProposal: boolean }> {
  const collected: Applied[] = []
  let sawProposal = false
  let skipped = 0
  const done = (): { applied: Applied[]; sawProposal: boolean } => {
    if (skipped) console.info(`[mls] catch-up on ${id.slice(0, 12)} walked past ${skipped} delivery/deliveries this device had already applied`)
    return { applied: collected, sawProposal }
  }
  // Bounded: the DS answers one batch at a time, so a device far behind needs
  // several rounds — but one that makes no progress must stop rather than
  // spin. Progress is the cursor actually moving.
  for (let round = 0; round < 8; round++) {
    const stored = await loadGroup(id)
    if (!stored) return done()
    const from = stored.lastSeq
    const pending = await fetchDeliveries(ds, own, id, from)
    if (pending.length === 0) return done()
    // The DS's log is finite. A first delivery that does not continue from
    // where this device stopped means the missing part has aged out, and no
    // amount of asking brings it back — MLS state cannot be reconstructed from
    // what the DS holds. Said out loud rather than retried silently.
    if (pending[0]!.seq > from + 1) {
      console.warn(`[mls] group ${id.slice(0, 12)} is missing deliveries ${from + 1}..${pending[0]!.seq - 1}, which the delivery service no longer holds; this device has to rejoin`)
      return done()
    }
    for (const delivery of pending) {
      const applied = await receiveDelivery(id, delivery, { pull: true })
      if (applied.retry) break
      if (applied.skipped) skipped++
      if (applied.sawProposal) sawProposal = true
      if (applied.payload) collected.push(applied)
    }
    if ((await loadGroup(id))?.lastSeq === from) return done()
  }
  return done()
}
