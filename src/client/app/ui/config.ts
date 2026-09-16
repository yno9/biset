// Single source for reading window.__BISET_CONFIG__ -- account-create.ts and
// main.ts each need apexDomain, so this is read in one place
// rather than two copies of the same window-global reach-through drifting
// apart.
declare const __BISET_CONFIG__: {
  apexDomain?: string
  mediatorUrls?: string[]
  mimiSelfBaseUrl?: string
  /** Human-facing application/device label shown by did.md Wallet. */
  walletDeviceName?: string
  /** DID Document service templates proposed during Wallet authorization. */
  didDocumentServices?: DidDocumentServiceTemplate[]
} | undefined

interface DidDocumentServiceTemplate {
  /** Biset-only placeholder binding; never published in the DID Document.
   * MIMI Vault used to have a 'mimi-vault' purpose here too, before its
   * room id became Wallet-derived instead of published (see
   * no longer used for self-Vault synchronization -- there is
   * no longer a DID Document service template for it at all. */
  purpose?: 'didcomm'
  id: string
  type: string
  serviceEndpoint: string | Record<string, unknown>
  /** Earlier IDs this template supersedes during a Wallet document edit. */
  previousIds?: string[]
}

export interface BisetConfig {
  apexDomain: string
  /** Independent, blind DIDComm mediators this deployment registers new
   * identities with (ARC.md's 2026-08-27 redesign, identity/bootstrap.ts's
   * `enableDidComm`) -- empty/unset keeps the legacy direct-delivery model
   * exactly as before (no mediator involved at all). Additive and opt-in on
   * purpose: production currently opts into https://mediator.biset.md. */
  mediatorUrls: string[]
  /** Dedicated normal-mode MIMI endpoint for the owner's Self/Vault room. */
  mimiSelfBaseUrl: string
  walletDeviceName: string
  didDocumentServices: DidDocumentServiceTemplate[]
}

const defaultDidDocumentServices: DidDocumentServiceTemplate[] = [
  { purpose: 'didcomm', id: '#didcomm', type: 'DIDCommMessaging', serviceEndpoint: { uri: '$mediatorUrl', accept: ['didcomm/v2'], routingKeys: ['$routingKid'] }, previousIds: ['#didcomm-biset'] },
  { id: '#biset-vault', type: 'BisetVault', serviceEndpoint: '$vaultGeneration' },
]

export function readBisetConfig(): BisetConfig {
  const cfg = (window as unknown as { __BISET_CONFIG__?: typeof __BISET_CONFIG__ }).__BISET_CONFIG__ ?? {}
  return {
    apexDomain: cfg.apexDomain ?? '',
    mediatorUrls: cfg.mediatorUrls ?? [],
    mimiSelfBaseUrl: cfg.mimiSelfBaseUrl ?? '',
    walletDeviceName: cfg.walletDeviceName ?? 'Biset',
    didDocumentServices: cfg.didDocumentServices ?? defaultDidDocumentServices,
  }
}
