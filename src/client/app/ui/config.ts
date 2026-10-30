// Single source for reading window.__BISET_CONFIG__ -- the new-user page and
// main.ts each need apexDomain, so this is read in one place
// rather than two copies of the same window-global reach-through drifting
// apart.
declare const __BISET_CONFIG__: {
  apexDomain?: string
  mediatorUrls?: string[]
  /** Tor entrance for the mediator at the same index in `mediatorUrls`
   * (PLAN-tor.md D-4), or '' if that mediator has none. Unset/empty keeps
   * clearnet-only behavior exactly as before (I-5). */
  mediatorOnionUrls?: string[]
  /** The address this app itself is served at over Tor (an onion URL), or unset when it is not: the account page offers to copy it. */
  appOnionUrl?: string
  /** The wallet (dito) served as a Tor hidden service, used by the app when it is itself opened at its onion address. */
  ditoOnionUrl?: string
  mimiSelfBaseUrl?: string
  /** Hosts whose WebFinger answers any mail address with a DID (a didmail
   * bridge, didmail PROTOCOL.md §9), asked when the address's own domain
   * has no DID for it. */
  mailGateways?: string[]
  /** The domain whose accounts the address bar names by their name alone (`/alice` is `alice@` and this). Unset: the first of `mailGateways`. */
  identityDomain?: string
  /** The address a line starting with `/` in a reply box is sent to, and where its answer is read (a didmail bridge's own address,
   * PROTOCOL.md §7.5). Unset: `didmail@` and the first of `mailGateways`. */
  helperAddress?: string
  /** Watcher base URLs asked for the log of a did:vh by SCID (`GET /log?scid=`), after the hosts a contact is known by. */
  vhWatchers?: string[]
  /** This deployment's relying-party DID, the client_id of its requests to the Wallet; its document
   * must list the redirect URI. Required over https (a file:// build registers instead). */
  rpDid?: string
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
  serviceEndpoint: string | Record<string, unknown> | Array<string | Record<string, unknown>>
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
  /** Tor entrance for the mediator at the same index in `mediatorUrls`
   * (PLAN-tor.md D-4); '' or a short array means that mediator is
   * clearnet-only. Empty/unset keeps current, clearnet-only behavior (I-5). */
  mediatorOnionUrls: string[]
  /** The onion URL this app is also served at ('' when it is not). */
  appOnionUrl: string
  /** Dedicated normal-mode MIMI endpoint for the owner's Self/Vault room. */
  mimiSelfBaseUrl: string
  /** Mail gateways (WebFinger hosts), in the order they are asked. Empty: a
   * mail address reaches only a domain that publishes its own DIDs. */
  mailGateways: string[]
  /** See the same key above; '' when unset. */
  identityDomain: string
  /** See the same key above; '' when unset. */
  helperAddress: string
  vhWatchers: string[]
  walletDeviceName: string
  didDocumentServices: DidDocumentServiceTemplate[]
}

const defaultDidDocumentServices: DidDocumentServiceTemplate[] = [
  // The endpoint names the mediator by DID (see did-md-oauth.ts's default, which this repeats).
  { purpose: 'didcomm', id: '#didcomm', type: 'DIDCommMessaging', serviceEndpoint: { uri: '$mediatorDid', accept: ['didcomm/v2'] }, previousIds: ['#didcomm-biset'] },
]

export function readBisetConfig(): BisetConfig {
  const cfg = (window as unknown as { __BISET_CONFIG__?: typeof __BISET_CONFIG__ }).__BISET_CONFIG__ ?? {}
  return {
    apexDomain: cfg.apexDomain ?? '',
    mediatorUrls: cfg.mediatorUrls ?? [],
    mediatorOnionUrls: cfg.mediatorOnionUrls ?? [],
    appOnionUrl: cfg.appOnionUrl ?? '',
    mimiSelfBaseUrl: cfg.mimiSelfBaseUrl ?? '',
    mailGateways: cfg.mailGateways ?? [],
    identityDomain: cfg.identityDomain ?? '',
    helperAddress: cfg.helperAddress ?? '',
    vhWatchers: cfg.vhWatchers ?? [],
    walletDeviceName: cfg.walletDeviceName ?? 'Biset',
    didDocumentServices: cfg.didDocumentServices ?? defaultDidDocumentServices,
  }
}
