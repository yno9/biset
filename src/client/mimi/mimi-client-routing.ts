/**
 * Chooses the local MIMI deployment for a room before its first commit.
 *
 * A room's credential form is part of its durable state.  This module is
 * deliberately creation-only: callers persist the returned route with the
 * room and never call it to migrate an existing room.
 */
import type { MimiClientMode } from './mimi-client-transport.ts'

export type MimiRoomPrivacyPreference = 'normal' | 'prefer-anon' | 'require-anon'

/** Capability data obtained from an authenticated peer discovery document. */
export interface MimiPeerCapability {
  peerId: string
  /** True only after the discovery document's issuer and binding were verified. */
  discoveryVerified: boolean
  supportsNormal: boolean
  /** The anonymous MMR protocol version the peer supports, if any. */
  anonymousMmrVersion?: 1
}

/** Locally configured, separately deployed MIMI provider origins. */
export interface MimiLocalEndpoints {
  normalBaseUrl: string
  anonBaseUrl: string
}

export interface MimiRoomRoute {
  mode: MimiClientMode
  baseUrl: string
}

export class MimiRouteSelectionError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'MimiRouteSelectionError'
  }
}

/**
 * Selects a route for a new room.  A requested anonymous room never silently
 * downgrades; `prefer-anon` may intentionally choose normal only when every
 * participant has verified normal-mode support.
 */
export function selectMimiRoomRoute(
  preference: MimiRoomPrivacyPreference,
  localEndpoints: MimiLocalEndpoints,
  peerCapabilities: readonly MimiPeerCapability[],
): MimiRoomRoute {
  const normalBaseUrl = normalizeProviderUrl(localEndpoints.normalBaseUrl, 'normal')
  const anonBaseUrl = normalizeProviderUrl(localEndpoints.anonBaseUrl, 'anon')
  validatePeerCapabilities(peerCapabilities)

  const allSupportAnon = peerCapabilities.every(peer => peer.anonymousMmrVersion === 1)
  const allSupportNormal = peerCapabilities.every(peer => peer.supportsNormal)

  if (preference === 'require-anon') {
    if (!allSupportAnon) throw new MimiRouteSelectionError('anonymous MMR v1 is unavailable for one or more participants')
    return { mode: 'anon', baseUrl: anonBaseUrl }
  }
  if (preference === 'prefer-anon' && allSupportAnon) return { mode: 'anon', baseUrl: anonBaseUrl }
  if (!allSupportNormal) throw new MimiRouteSelectionError('normal MIMI mode is unavailable for one or more participants')
  return { mode: 'normal', baseUrl: normalBaseUrl }
}

function validatePeerCapabilities(peers: readonly MimiPeerCapability[]): void {
  for (const peer of peers) {
    if (!peer.peerId.trim()) throw new MimiRouteSelectionError('peer capability has no peer ID')
    if (!peer.discoveryVerified) throw new MimiRouteSelectionError(`MIMI capability for ${peer.peerId} is not verified`)
    if (peer.anonymousMmrVersion !== undefined && peer.anonymousMmrVersion !== 1) {
      throw new MimiRouteSelectionError(`MIMI capability for ${peer.peerId} has an unsupported anonymous MMR version`)
    }
  }
}

function normalizeProviderUrl(value: string, mode: MimiClientMode): string {
  let url: URL
  try { url = new URL(value) } catch { throw new MimiRouteSelectionError(`${mode} MIMI provider URL is invalid`) }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.search) {
    throw new MimiRouteSelectionError(`${mode} MIMI provider URL must be a credential-free HTTPS base URL`)
  }
  return url.toString().replace(/\/$/, '')
}
