/** Biset JSON representation of draft §5.5 provider fanout batches. */
import { bytesToHex } from '../protocol/canonical.ts'
import type { MimiDeliveryEntry, MimiRoomId } from './protocol-types.ts'
import { decodeDeliveriesWire, encodeDeliveriesWire, MimiWireError } from './wire.ts'
import type { MimiProviderTransport } from './provider-transport.ts'

export interface MimiFanoutBatch { timestamp: string; entries: MimiDeliveryEntry[] }
export interface MimiFanoutTarget { providerBaseUrl: string; roomId: MimiRoomId }

export function encodeMimiFanoutBatchWire(batch: MimiFanoutBatch): string {
  if (!/^[0-9]+$/.test(batch.timestamp)) throw new MimiWireError('FanoutMessage.timestamp must be an unsigned millisecond value')
  const deliveries = JSON.parse(encodeDeliveriesWire(batch.entries)) as { entries: unknown[] }
  return JSON.stringify({ timestamp: batch.timestamp, entries: deliveries.entries })
}

export function decodeMimiFanoutBatchWire(text: string): MimiFanoutBatch {
  let input: unknown
  try { input = JSON.parse(text) } catch { throw new MimiWireError('FanoutMessage is not JSON') }
  if (input === null || typeof input !== 'object' || Array.isArray(input)) throw new MimiWireError('FanoutMessage must be an object')
  const value = input as Record<string, unknown>
  if (typeof value.timestamp !== 'string' || !/^[0-9]+$/.test(value.timestamp)) throw new MimiWireError('FanoutMessage.timestamp must be an unsigned millisecond value')
  if (!Array.isArray(value.entries) || value.entries.length === 0) throw new MimiWireError('FanoutMessage.entries must be a non-empty array')
  return { timestamp: value.timestamp, entries: decodeDeliveriesWire(JSON.stringify({ entries: value.entries })) }
}

export async function fanoutFingerprint(body: string): Promise<string> {
  return bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body))))
}

/** Sends independently retryable fanout batches; callers retain failed work. */
export class MimiFanoutDispatcher {
  constructor(private readonly transport: MimiProviderTransport) {}

  async send(target: MimiFanoutTarget, batch: MimiFanoutBatch): Promise<Response> {
    const body = encodeMimiFanoutBatchWire(batch)
    const response = await this.transport.post(target.providerBaseUrl, { path: `/notify/${encodeURIComponent(target.roomId)}`, body })
    if (response.status !== 201) throw new Error(`provider fanout was not accepted (${response.status})`)
    return response
  }
}
