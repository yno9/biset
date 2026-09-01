/** Room-scoped pseudonym issuance for Minimal Metadata Rooms (draft §6.1). */
import type { MimiClientUri, MimiRoomId, MimiUserUri } from '../protocol-types.ts'

/**
 * Registry deliberately keys by `(roomId, real user/client)` and never by a
 * global user identifier alone: a re-used pseudonym across rooms would create
 * a hub-visible correlation handle.  Persistence is supplied by the anon-mode
 * store integration in Phase 2.4; this component owns the minting invariant.
 */
export class RoomPseudonymIssuer {
  private readonly users = new Map<string, MimiUserUri>()
  private readonly clients = new Map<string, MimiClientUri>()

  constructor(private readonly providerDomain: string) {
    if (!/^[a-z0-9.-]+$/i.test(providerDomain)) throw new TypeError('provider domain is invalid')
  }

  userPseudonym(roomId: MimiRoomId, user: MimiUserUri): MimiUserUri {
    const key = `${roomId}\u0000${user}`
    return this.users.get(key) ?? this.remember(this.users, key)
  }

  clientPseudonym(roomId: MimiRoomId, client: MimiClientUri): MimiClientUri {
    const key = `${roomId}\u0000${client}`
    return this.clients.get(key) ?? this.remember(this.clients, key)
  }

  private remember<T extends string>(map: Map<string, T>, key: string): T {
    const value = `mimi://${this.providerDomain}/u/${crypto.randomUUID()}` as T
    map.set(key, value)
    return value
  }
}
