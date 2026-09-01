/** Short-lived, opaque authorization for one MIMI delivery SSE connection. */
import { bytesToHex } from '../protocol/canonical.ts'
import type { MimiRoomId, MimiUserUri } from './protocol-types.ts'

export interface MimiWatchTokenRecord {
  roomId: MimiRoomId
  requester: MimiUserUri
}

const DEFAULT_TTL_MS = 60 * 60 * 1000

/**
 * Server-held tokens are deliberately used instead of signed bearer tokens:
 * this deployment is single-process and its in-memory map makes immediate
 * revocation possible without a separate signing key or persistent session.
 */
export class MimiWatchTokenIssuer {
  private readonly tokens = new Map<string, MimiWatchTokenRecord & { expiresAt: number }>()

  constructor(private readonly ttlMs: number = DEFAULT_TTL_MS) {}

  issue(roomId: MimiRoomId, requester: MimiUserUri): { token: string; expiresAt: string } {
    const token = bytesToHex(crypto.getRandomValues(new Uint8Array(24)))
    const expiresAt = Date.now() + this.ttlMs
    this.tokens.set(token, { roomId, requester, expiresAt })
    return { token, expiresAt: new Date(expiresAt).toISOString() }
  }

  resolve(token: string): MimiWatchTokenRecord | undefined {
    const record = this.tokens.get(token)
    if (!record) return undefined
    if (record.expiresAt < Date.now()) {
      this.tokens.delete(token)
      return undefined
    }
    return { roomId: record.roomId, requester: record.requester }
  }

  revoke(token: string): void { this.tokens.delete(token) }
}
