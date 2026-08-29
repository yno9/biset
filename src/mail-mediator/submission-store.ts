// Pure state machine for outbound submission idempotency
// (PLAN_biset-mail-mediator.md section 12 -- "idempotency keyごとに一度だけ
// SMTP配送を開始する", section 9's duplicate-submission scenario).
//
// `acquire` is the gate: the caller only actually dials out to SMTP when it
// gets back `{ started: true }`. A retried submit request (client crash
// before it saw the first response, a network retry) gets back the SAME
// record instead of triggering a second delivery attempt -- recipient-unit
// results, not a collapsed boolean (section 12's own requirement).

import type { SubmitResultBody } from './protocol.ts'

export type RecipientResult = NonNullable<SubmitResultBody['results']>[number]

export type SubmissionState = 'in-flight' | 'completed'

export interface SubmissionRecord {
  idempotencyKey: string
  mailFrom: string
  rcptTo: string[]
  rawRfc5322: Uint8Array
  state: SubmissionState
  results?: RecipientResult[]
  createdAt: string
}

/** Bounds memory for completed records the same way spool-store bounds
 * pending mail -- an idempotency key is retained only long enough for a
 * retry to still land on it, not forever. */
const MAX_RECORDS = 100_000

export class SubmissionStoreFullError extends Error {}

export interface MailSubmissionStore {
  acquire(idempotencyKey: string, mailFrom: string, rcptTo: string[], rawRfc5322: Uint8Array, nowIso: string):
    { started: true; record: SubmissionRecord } | { started: false; record: SubmissionRecord }
  complete(idempotencyKey: string, results: RecipientResult[]): SubmissionRecord | undefined
  recordFor(idempotencyKey: string): SubmissionRecord | undefined
}

export class SubmissionStore implements MailSubmissionStore {
  private byKey = new Map<string, SubmissionRecord>()

  /** Returns `started: true` exactly once per idempotency key -- the caller
   * that sees it is the one responsible for actually dialing SMTP and
   * calling `complete` afterwards. Every other caller (a retry that landed
   * concurrently, or after the fact) gets `started: false` with whatever
   * record already exists, in-flight or completed. */
  acquire(
    idempotencyKey: string, mailFrom: string, rcptTo: string[], rawRfc5322: Uint8Array, nowIso: string,
  ): { started: true; record: SubmissionRecord } | { started: false; record: SubmissionRecord } {
    const existing = this.byKey.get(idempotencyKey)
    if (existing) return { started: false, record: existing }
    if (this.byKey.size >= MAX_RECORDS) throw new SubmissionStoreFullError('mail-mediator: too many pending submissions')
    const record: SubmissionRecord = { idempotencyKey, mailFrom, rcptTo, rawRfc5322, state: 'in-flight', createdAt: nowIso }
    this.byKey.set(idempotencyKey, record)
    return { started: true, record }
  }

  /** Idempotent: completing an already-completed record just overwrites its
   * results rather than erroring -- a caller that legitimately retries the
   * whole outbound attempt (not merely the client's submit request) is
   * still allowed to report a fresher outcome. */
  complete(idempotencyKey: string, results: RecipientResult[]): SubmissionRecord | undefined {
    const record = this.byKey.get(idempotencyKey)
    if (!record) return undefined
    record.state = 'completed'
    record.results = results
    return record
  }

  recordFor(idempotencyKey: string): SubmissionRecord | undefined {
    return this.byKey.get(idempotencyKey)
  }
}
