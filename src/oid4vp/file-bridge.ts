import type { BisetOid4vpWallet } from './wallet.ts'

export interface BisetOid4vpBridgeRequest {
  type: 'biset.oid4vp.request.v1'
  requestUri: string
  bridgeNonce: string
}

/** Handles only messages from the exact Anchor popup opened by this file UI. */
export async function handleBisetOid4vpBridgeMessage(options: {
  event: MessageEvent<unknown>
  popup: Window
  anchorOrigin: string
  wallet: BisetOid4vpWallet
}): Promise<boolean> {
  const anchorOrigin = new URL(options.anchorOrigin).origin
  if (options.event.origin !== anchorOrigin || options.event.source !== options.popup) return false
  const request = bridgeRequest(options.event.data)
  if (!request) return false
  const uri = new URL(request.requestUri)
  if (uri.origin !== anchorOrigin || !uri.pathname.startsWith('/oid4vp/request/') || uri.search || uri.hash) throw new TypeError('OID4VP bridge request URI is not trusted')
  const completionUri = await options.wallet.respond(uri.href)
  options.popup.postMessage({ type: 'biset.oid4vp.complete.v1', bridgeNonce: request.bridgeNonce, completionUri }, anchorOrigin)
  return true
}

function bridgeRequest(value: unknown): BisetOid4vpBridgeRequest | undefined {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return undefined
  const input = value as Record<string, unknown>
  if (input.type !== 'biset.oid4vp.request.v1' || typeof input.requestUri !== 'string' || typeof input.bridgeNonce !== 'string' || !/^[A-Za-z0-9_-]{32}$/.test(input.bridgeNonce)) return undefined
  return { type: input.type, requestUri: input.requestUri, bridgeNonce: input.bridgeNonce }
}
