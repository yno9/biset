// Report Problem Protocol 2.0 (problems.md). A problem-report is an ordinary
// DIDComm plaintext message whose `body` names a structured `code` and a
// human `comment`, with the failing thread referenced via the `pthid` header
// and (when a specific message triggered it) `ack`.
//
// biset uses this in two directions:
//   - the mediator emits one, authcrypt'd back to an AUTHENTICATED sender,
//     instead of only an opaque HTTP error (a third-party didcomm agent can
//     then react to the `code` rather than parse an HTTP body it doesn't model);
//   - the client turns a problem-report REPLY into a thrown Error carrying the
//     code and interpolated comment, so requestMediation/updateKeylist/pickup
//     surface "why" instead of "unexpected reply type" (message.ts sendAndUnpack
//     does this centrally for every coordinate/pickup call — one place, per
//     the unify-common-logic rule).
import { buildPlaintext, type DidCommPlaintext, type PlaintextOptions } from './message.ts'

export const PROBLEM_REPORT = 'https://didcomm.org/report-problem/2.0/problem-report'

export interface ProblemBody {
  code: string
  comment?: string
  args?: string[]
  escalate_to?: string
}

export interface BuildProblemOptions {
  /** The `thid` of the thread the problem occurred in — becomes the report's
   * REQUIRED `pthid` (problems.md: the report starts a child thread of the
   * triggering context). */
  pthid: string
  /** Message id(s) this report acknowledges — SHOULD be set when a specific
   * message triggered the problem. */
  ack?: string[]
}

/** Builds a problem-report plaintext. `code` is a dot-delimited problem code
 * (sorter `.` scope `.` descriptors — e.g. `e.p.me.res.storage`); `comment`
 * MUST be statically associated with `code` and may reference `args` as
 * `{1}`, `{2}`, … (problems.md). */
export function buildProblemReport(
  from: string, to: string,
  code: string, comment: string | undefined,
  { pthid, ack }: BuildProblemOptions,
  args?: string[], escalateTo?: string,
): DidCommPlaintext {
  const body: ProblemBody = { code }
  if (comment) body.comment = comment
  if (args && args.length) body.args = args
  if (escalateTo) body.escalate_to = escalateTo
  const opts: PlaintextOptions = { pthid }
  if (ack && ack.length) opts.ack = ack
  return buildPlaintext(PROBLEM_REPORT, body, from, to, opts)
}

export function isProblemReport(msg: { type?: string }): boolean {
  return msg.type === PROBLEM_REPORT
}

/** Interpolates a problem-report's `comment` with its `args`, per problems.md:
 * `{1}`,`{2}`,… are replaced positionally; a missing/null arg becomes `?`;
 * extra args are appended comma-separated. */
export function formatProblem(body: ProblemBody): string {
  const { code, comment, args = [] } = body
  if (!comment) return code
  const used = new Set<number>()
  let text = comment.replace(/\{(\d+)\}/g, (_, n) => {
    const i = Number(n) - 1
    used.add(i)
    const v = args[i]
    return v === undefined || v === null ? '?' : String(v)
  })
  const extra = args.filter((_, i) => !used.has(i))
  if (extra.length) text += ` (${extra.join(', ')})`
  return `${code}: ${text}`
}

/** A problem-report plaintext → an Error whose message is the formatted
 * code+comment, for the client to throw. */
/** A problem-report turned into a throwable, keeping the machine-readable
 * `code` alongside the human text. Callers that must branch on the reason —
 * the MLS client treats an epoch conflict as "apply the winner and retry",
 * not as a failure (mls/transport.ts) — need the code, and parsing it back out
 * of the message string is exactly the kind of thing that breaks silently when
 * the wording changes. */
export class DidCommProblemError extends Error {
  constructor(readonly code: string, message: string, readonly args: string[] = []) {
    super(message)
    this.name = 'DidCommProblemError'
  }
}

export function problemReportError(msg: DidCommPlaintext): DidCommProblemError {
  const body = (msg.body ?? {}) as ProblemBody
  return new DidCommProblemError(body.code ?? '', `DIDComm problem-report ${formatProblem(body)}`, body.args ?? [])
}
