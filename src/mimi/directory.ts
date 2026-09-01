/** MIMI draft §5.1 provider directory document. */

export const MIMI_PROTOCOL_DIRECTORY_PATH = '/.well-known/mimi-protocol-directory'

export interface MimiProtocolDirectory {
  keyMaterial: string
  update: string
  notify: string
  submitMessage: string
  groupInfo: string
  requestConsent: string
  updateConsent: string
  identifierQuery: string
  reportAbuse: string
  proxyDownload: string
}

/** Builds URI templates without assuming endpoint paths for other providers. */
export function createMimiProtocolDirectory(providerBaseUrl: string | URL): MimiProtocolDirectory {
  const base = new URL(providerBaseUrl)
  if (base.protocol !== 'https:') throw new TypeError('MIMI provider directory requires an HTTPS base URL')
  if (base.username || base.password || base.search || base.hash || base.pathname !== '/') throw new TypeError('MIMI provider base URL must be an HTTPS origin')
  const endpoint = (path: string) => `${base.origin}${path}`
  return {
    keyMaterial: endpoint('/keyMaterial/{targetUser}'),
    update: endpoint('/update/{roomId}'),
    notify: endpoint('/notify/{roomId}'),
    submitMessage: endpoint('/submitMessage/{roomId}'),
    groupInfo: endpoint('/groupInfo/{roomId}'),
    requestConsent: endpoint('/requestConsent/{targetDomain}'),
    updateConsent: endpoint('/updateConsent/{requesterDomain}'),
    identifierQuery: endpoint('/identifierQuery/{domain}'),
    reportAbuse: endpoint('/reportAbuse/{roomId}'),
    proxyDownload: endpoint('/proxyDownload/{downloadUrl}'),
  }
}
