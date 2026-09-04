/** JSON representation of draft §5.5 FanoutMessage objects.  The HTTP
 * boundary is JSON, but every item carries its timestamp, protocol selector,
 * complete MLSMessage, and message-type-specific fields without flattening
 * them into local delivery metadata. */
import { base64urlToBytes, bytesToBase64url, bytesToHex } from '../shared/protocol/canonical.ts'
import { decodeMlsMessage } from '../mls/vendor/index.ts'
import type { Frank, MimiDeliveryEntry, MimiDeliveryKind, MimiEpoch, MimiRoomId } from './protocol-types.ts'
import { decodeFrankWire, encodeFrankWire, MimiWireError } from './wire.ts'
import type { MimiProviderTransport } from './provider-transport.ts'

export interface MimiFanoutMessage {
  timestamp: string // uint64 milliseconds, retained exactly in JSON
  protocol: 'mls10'
  message: Uint8Array
  frank?: Frank
  ratchetTreeOption?: Uint8Array
  moreProposals?: Uint8Array[]
  externalProposals?: Uint8Array[]
}
/** A JSON array represents the draft's concatenated FanoutMessage values. */
export interface MimiFanoutBatch { messages: MimiFanoutMessage[] }
export interface MimiFanoutTarget { providerBaseUrl: string; roomId: MimiRoomId }

export function encodeMimiFanoutBatchWire(batch: MimiFanoutBatch): string {
  if (batch.messages.length === 0) throw new MimiWireError('FanoutMessage batch must be non-empty')
  return JSON.stringify({ messages: batch.messages.map(messageJson) })
}

export function decodeMimiFanoutBatchWire(text: string): MimiFanoutBatch {
  let input: unknown
  try { input = JSON.parse(text) } catch { throw new MimiWireError('FanoutMessage is not JSON') }
  if (input === null || typeof input !== 'object' || Array.isArray(input)) throw new MimiWireError('FanoutMessage batch must be an object')
  const messages = (input as Record<string, unknown>).messages
  if (!Array.isArray(messages) || messages.length === 0) throw new MimiWireError('FanoutMessage batch must have non-empty messages')
  return { messages: messages.map((item, index) => decodeMessage(item, `FanoutMessage[${index}]`)) }
}

/** Verify §5.5's selectors, then assign local queue cursors later in store. */
export function fanoutDeliveries(batch: MimiFanoutBatch, welcomeEpoch: MimiEpoch): MimiDeliveryEntry[] {
  return batch.messages.flatMap(message => deliveries(message, welcomeEpoch))
}

export async function fanoutFingerprint(body: string): Promise<string> {
  return bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body))))
}

export class MimiFanoutDispatcher {
  constructor(private readonly transport: MimiProviderTransport) {}
  async send(target: MimiFanoutTarget, batch: MimiFanoutBatch): Promise<Response> {
    const response = await this.transport.post(target.providerBaseUrl, { path: `/notify/${encodeURIComponent(target.roomId)}`, body: encodeMimiFanoutBatchWire(batch) })
    if (response.status !== 201) throw new Error(`provider fanout was not accepted (${response.status})`)
    return response
  }
}

function messageJson(value: MimiFanoutMessage): Record<string, unknown> {
  validate(value)
  return { timestamp: value.timestamp, protocol: value.protocol, message: bytesToBase64url(value.message),
    ...(value.frank === undefined ? {} : { frank: JSON.parse(encodeFrankWire(value.frank)) }),
    ...(value.ratchetTreeOption === undefined ? {} : { ratchetTreeOption: bytesToBase64url(value.ratchetTreeOption) }),
    ...(value.moreProposals === undefined ? {} : { moreProposals: value.moreProposals.map(bytesToBase64url) }),
    ...(value.externalProposals === undefined ? {} : { externalProposals: value.externalProposals.map(bytesToBase64url) }),
  }
}
function decodeMessage(value: unknown, name: string): MimiFanoutMessage {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new MimiWireError(`${name} must be an object`)
  const input = value as Record<string, unknown>, timestamp = input.timestamp
  if (typeof timestamp !== 'string' || !/^[0-9]+$/.test(timestamp)) throw new MimiWireError(`${name}.timestamp must be an unsigned millisecond value`)
  if (input.protocol !== 'mls10') throw new MimiWireError(`${name}.protocol must be mls10`)
  const result: MimiFanoutMessage = { timestamp, protocol: 'mls10', message: binary(input.message, `${name}.message`),
    ...(input.frank === undefined ? {} : { frank: decodeFrankWire(JSON.stringify(input.frank)) }),
    ...(input.ratchetTreeOption === undefined ? {} : { ratchetTreeOption: binary(input.ratchetTreeOption, `${name}.ratchetTreeOption`) }),
    ...(input.moreProposals === undefined ? {} : { moreProposals: binaries(input.moreProposals, `${name}.moreProposals`) }),
    ...(input.externalProposals === undefined ? {} : { externalProposals: binaries(input.externalProposals, `${name}.externalProposals`) }),
  }
  validate(result); return result
}
function deliveries(value: MimiFanoutMessage, welcomeEpoch: MimiEpoch): MimiDeliveryEntry[] {
  const classified = classify(value.message), acceptedAt = new Date(Number(value.timestamp)).toISOString()
  if (!Number.isFinite(Date.parse(acceptedAt))) throw new MimiWireError('FanoutMessage timestamp is outside the supported date range')
  const make = (kind: MimiDeliveryKind, payload: Uint8Array, frank?: Frank): MimiDeliveryEntry => ({ seq: 0, kind, payload: new Uint8Array(payload), epoch: classified.epoch ?? welcomeEpoch, acceptedAt, ...(frank === undefined ? {} : { frank }) })
  if (classified.kind === 'application') return [make('application', value.message, value.frank)]
  if (classified.kind === 'welcome') return [make('welcome', value.message)]
  if (classified.kind === 'proposal') return [make('proposal', value.message), ...(value.moreProposals ?? []).map(item => make('proposal', item))]
  return [make('commit', value.message), ...(value.externalProposals ?? []).map(item => make('proposal', item))]
}
function validate(value: MimiFanoutMessage): void {
  if (!/^[0-9]+$/.test(value.timestamp)) throw new MimiWireError('FanoutMessage.timestamp must be an unsigned millisecond value')
  const kind = classify(value.message).kind
  if (value.frank !== undefined && kind !== 'application') throw new MimiWireError('FanoutMessage.frank is only valid for an application message')
  if (kind === 'welcome' ? value.ratchetTreeOption === undefined : value.ratchetTreeOption !== undefined) throw new MimiWireError('FanoutMessage ratchetTreeOption must be present only for a Welcome')
  if (value.moreProposals !== undefined && kind !== 'proposal') throw new MimiWireError('FanoutMessage.moreProposals is only valid for a proposal')
  if (value.externalProposals !== undefined && kind !== 'commit') throw new MimiWireError('FanoutMessage.externalProposals is only valid for a commit')
  for (const proposal of [...(value.moreProposals ?? []), ...(value.externalProposals ?? [])]) if (classify(proposal).kind !== 'proposal') throw new MimiWireError('FanoutMessage stapled value must be an MLS proposal')
}
function classify(bytes: Uint8Array): { kind: MimiDeliveryKind; epoch?: MimiEpoch } {
  const decoded = decodeMlsMessage(bytes, 0)
  if (!decoded || decoded[1] !== bytes.length || decoded[0].version !== 'mls10') throw new MimiWireError('FanoutMessage.message must be a complete MLSMessage')
  if (decoded[0].wireformat === 'mls_welcome') return { kind: 'welcome' }
  if (decoded[0].wireformat === 'mls_private_message') return { kind: 'application', epoch: decoded[0].privateMessage.epoch.toString() }
  if (decoded[0].wireformat === 'mls_public_message') {
    const content = decoded[0].publicMessage.content
    if (content.contentType === 'proposal') return { kind: 'proposal', epoch: content.epoch.toString() }
    if (content.contentType === 'commit') return { kind: 'commit', epoch: content.epoch.toString() }
  }
  throw new MimiWireError('FanoutMessage.message has an unsupported MLS wire format')
}
function binary(value: unknown, name: string): Uint8Array { if (typeof value !== 'string') throw new MimiWireError(`${name} must be base64url`); try { return base64urlToBytes(value) } catch { throw new MimiWireError(`${name} must be base64url`) } }
function binaries(value: unknown, name: string): Uint8Array[] { if (!Array.isArray(value)) throw new MimiWireError(`${name} must be an array`); return value.map((item, index) => binary(item, `${name}[${index}]`)) }
