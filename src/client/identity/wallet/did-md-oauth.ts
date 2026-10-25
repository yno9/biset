/**
 * did.md Wallet sign-in, as SIOPv2 / OpenID4VP (no OAuth: no metadata, registration, tokens, DPoP or refresh).
 *
 * It persists no Wallet controller material. The only Biset-owned secrets
 * it keeps are the DIDComm device's (its X25519 key and mediator inbox-label
 * secret), AES-wrapped under a non-extractable browser key.
 */
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { decodeMultikey } from '../../../protocol/vh/multikey.ts'
import type { DidDocument } from '../../../protocol/vh/document.ts'
import { sameIdentity } from '../../../protocol/vh/identifier.ts'
import { verifyProof, type DataIntegrityProof } from '../../../protocol/vh/proof.ts'
import { freshFetch } from '../log-io.ts'
import { resolveVhByHost } from '../../../protocol/vh/fetch.ts'
import { rememberVhLocation, resolveDidDocument } from '../../../protocol/did-resolve.ts'
import { didWebCandidates } from '../../../protocol/vh/didweb.ts'
import { deviceKid, deviceKidFragment } from '../../../protocol/didcomm/devicekid.ts'
import { decodeX25519Multikey, encodeX25519Multikey } from '../../../protocol/didcomm/multikey.ts'
import { encodePeerDid2 } from '../../../protocol/didcomm/peer.ts'
import { fetchMediatorInfo, updateRecipient } from '../../../protocol/didcomm/mediator-coordinate.ts'
import { mediatorInbox } from '../../../protocol/didcomm/mediator-device.ts'
import { registerWithMediator } from '../../didcomm/mediator-sync.ts'
import { assertMatchesSchema, type JSONSchema } from './json-schema.ts'
import capabilitySchema from './schemas/biset-messenger-capability.schema.json' with { type: 'json' }
import { isOnionUrl } from '../../didcomm/mediator-endpoints.ts'
import { canonical, endpointsAreRemoved, serviceIsPublished } from './did-document-edit-check.ts'
import {
  clearDidMdDeviceSession,
  clearDidMdPendingAuthorization,
  readDidMdDeviceSession,
  readDidMdPendingAuthorization,
  saveDidMdDeviceSession,
  saveDidMdPendingAuthorization,
  sealDidMdBisetDidCommDeviceMaterial,
  openDidMdBisetDidCommDeviceMaterial,
  sealDidMdSecret,
  openDidMdSecret,
  type DidMdBisetDidCommDeviceMaterial,
  type DidMdSealedSecret,
  type DidMdDeviceSession,
  type DidMdPendingAuthorization,
  type DidCoreDocumentEdit,
  type DidCoreEndpointRemoval,
} from './did-md-store.ts'

import { DEFAULT_WALLET, type WalletDirectoryEntry } from './wallet-directory.ts'
import { rotationKeyEditMethod, ROTATION_KEY_FRAGMENT } from '../../didcomm/rotation-key.ts'
// The wallet this module talks to is whichever wallet directory entry is currently selected
// (selectWallet/currentWallet), dito by default. Its authorization screen is `authorizationEndpoint`.
let selectedWallet: WalletDirectoryEntry = DEFAULT_WALLET
export function selectWallet(entry: WalletDirectoryEntry): void { selectedWallet = entry }
export function currentWallet(): WalletDirectoryEntry { return selectedWallet }
const CALLBACK_PATH = '/wallet/callback'
// What the capability is for (the device-capability transaction data's scope); `openid` is the request's own scope.
const REQUESTED_SCOPES = ['biset:login', 'biset:device', 'biset:routing', 'biset:messaging', 'biset:vault']
// Biset's own capability credential type, asked for by the DCQL query.
const CAPABILITY_TYPE = 'biset.md/MessengerCapability'
// This deployment's relying-party DID (`rpDid` in __BISET_CONFIG__): sent as client_metadata.rp_did. The wallet believes it
// only when the DID's own document publishes the redirect URL as a SIOPRedirectTarget; the request itself is not signed.
function rpDid(): string | undefined {
  const configured = (globalThis as { __BISET_CONFIG__?: { rpDid?: unknown } }).__BISET_CONFIG__?.rpDid
  return typeof configured === 'string' ? configured : undefined
}
const DID_DOCUMENT_EDIT_DETAIL = 'urn:did-core:document-edit:v1'
// The did.md-operated SMTP relay is a separate process, but shares did.md's
// authority service.  This detail is Root-signed as part of the ordinary
// Wallet device capability; no controller/update key reaches Biset.
export const DID_MD_JUST_CONNECTED_KEY = 'biset-did-md-just-connected-v1'
const encoder = new TextEncoder()

export type DidMdWalletConfiguration = {
  walletDeviceName?: string
  didDocumentServices?: DidDocumentServiceTemplate[]
}

type WalletConfiguration = Required<DidMdWalletConfiguration>

type DidDocumentServiceTemplate = {
  purpose?: 'didcomm'
  id: string
  type: string
  /** DID Core allows a set of endpoints (a string/map array), not only a
   * single string or map -- PLAN-tor.md D-4 uses this for a mediator's
   * clearnet + Tor entrances, both bound to the same routingKeys. */
  serviceEndpoint: string | Record<string, unknown> | Array<string | Record<string, unknown>>
  previousIds?: string[]
}

// The endpoint names the mediator by its DID (DIDComm Messaging v2.1, "Using a
// DID as an endpoint"): the mediator's keys and URL live in ITS document, so
// they can change without this identity's document being rewritten. (Before
// 2026-10-07 it was `{ uri: '$mediatorUrl', routingKeys: ['$routingKid'] }`.)
// `$mediatorUrl` and `$routingKid` can still be used by a configured template.
const defaultDidDocumentServices: DidDocumentServiceTemplate[] = [
  { purpose: 'didcomm', id: '#didcomm', type: 'DIDCommMessaging', serviceEndpoint: { uri: '$mediatorDid', accept: ['didcomm/v2'] }, previousIds: ['#didcomm-biset'] },
]

function validServiceEndpointEntry(value: unknown): boolean {
  return typeof value === 'string' || (!!value && typeof value === 'object' && !Array.isArray(value))
}

export function walletConfiguration(value: DidMdWalletConfiguration = {}): WalletConfiguration {
  const walletDeviceName = value.walletDeviceName ?? 'Biset'
  const didDocumentServices = value.didDocumentServices ?? defaultDidDocumentServices
  if (!Array.isArray(didDocumentServices) || !didDocumentServices.length || didDocumentServices.length > 64) throw new Error('DID Document services configuration is invalid')
  const ids = new Set<string>()
  for (const service of didDocumentServices) {
    const endpointValid = Array.isArray(service?.serviceEndpoint)
      ? service.serviceEndpoint.length > 0 && service.serviceEndpoint.length <= 8 && service.serviceEndpoint.every(validServiceEndpointEntry)
      : validServiceEndpointEntry(service?.serviceEndpoint)
    if (!service || typeof service !== 'object' || !/^#[^\s#]+$/.test(service.id) || !service.type.trim()
      || !endpointValid || ids.has(service.id)) throw new Error('DID Document service configuration is invalid')
    ids.add(service.id)
    if (service.purpose !== undefined && service.purpose !== 'didcomm') throw new Error('DID Document service purpose is invalid')
    if (service.previousIds?.some(id => !/^#[^\s#]+$/.test(id))) throw new Error('DID Document service previous IDs are invalid')
  }
  const didcomm = didDocumentServices.filter(service => service.purpose === 'didcomm')
  if (didcomm.length !== 1) throw new Error('DID Document services must define one DIDComm template')
  if (!walletDeviceName.trim() || walletDeviceName.length > 160) throw new Error('Wallet device name must be between 1 and 160 characters')
  return { didDocumentServices, walletDeviceName }
}

function configuredService(config: WalletConfiguration, purpose: 'didcomm'): DidDocumentServiceTemplate {
  const service = config.didDocumentServices.find(candidate => candidate.purpose === purpose)
  if (!service) throw new Error(`DID Document services configuration has no ${purpose} template`)
  return service
}

function materializeServiceEndpoint(value: string | Record<string, unknown> | Array<string | Record<string, unknown>>, substitutions: Record<string, string>): string | Record<string, unknown> | Array<string | Record<string, unknown>> {
  if (typeof value === 'string') {
    if (value.startsWith('$') && !(value in substitutions)) throw new Error(`Unknown DID Document service placeholder ${value}`)
    return substitutions[value] ?? value
  }
  if (Array.isArray(value)) return value.map(item => materializeServiceEndpoint(item, substitutions) as string | Record<string, unknown>)
  const result: Record<string, unknown> = {}
  for (const [key, item] of Object.entries(value)) result[key] = typeof item === 'string' || (item && typeof item === 'object')
    ? materializeServiceEndpoint(item as string | Record<string, unknown>, substitutions)
    : item
  return result
}

/** The Tor opt-in (Mediator card's "Enable Tor"): the DID Document then
 * publishes the mediator's clearnet entrance AND its onion entrance as a set
 * for the SAME mediator (PLAN-tor.md D-4). Without an onion URL the endpoint
 * is returned unchanged -- the automatic login/enrollment paths never pass
 * one, so they keep publishing the clearnet-only single map (I-5). */
export function didCommEndpointWithOnion<T extends string | Record<string, unknown> | Array<string | Record<string, unknown>>>(endpoint: T, onionUrl?: string): T | Array<Record<string, unknown>> {
  if (!onionUrl || !endpoint || typeof endpoint !== 'object' || Array.isArray(endpoint)) return endpoint
  // An endpoint that names its mediator by DID has no Tor entrance of its own: the mediator's document lists it.
  if (typeof (endpoint as { uri?: unknown }).uri === 'string' && (endpoint as { uri: string }).uri.startsWith('did:')) return endpoint
  return [endpoint as Record<string, unknown>, { ...endpoint as Record<string, unknown>, uri: onionUrl }]
}

export type DidMdActiveSession = {
  did: string
  handle: string
  clientId: string
  deviceJkt: string
  capabilityExpiresAt: string
  scope: string[]
  deviceKid?: string
  didCommKid?: string
}

/** This browser as an author of the identity's Vault. */
export type DidMdVaultDevice = {
  did: string
  /** The address the identity is published at (`alice.did.md`): the alias, which can change while the DID does not. */
  handle: string
  /** `actorDeviceId` on the Vault events this browser writes. */
  deviceId: string
}

export type DidMdBisetDidCommDevice = {
  did: string
  xKid: string
  x25519PrivateKey: Uint8Array
  mediatorDeviceSecret: Uint8Array
  mediatorUrl: string
  routingKid: string
  /** The mediator's DID (what a DID document's endpoint names), if known. */
  mediatorDid?: string
  /** This mediator's Tor entrance (PLAN-tor.md D-4), if one was published
   * alongside `mediatorUrl` when this device was authorized. */
  mediatorOnionUrl?: string
}

type DidMdBisetMediator = {
  mediatorUrl: string
  routingKid: string
  /** The mediator's DID: its did:web, or its did:peer if that is all it has. */
  mediatorDid: string
  /** This mediator's Tor entrance (PLAN-tor.md D-4), if this deployment's
   * config pairs one with the chosen `mediatorUrl` by array index. Never
   * fetched or otherwise validated over the network -- a non-Tor browser
   * must not even attempt a `.onion` lookup (I-3). */
  mediatorOnionUrl?: string
}

function base64url(bytes: Uint8Array): string {
  let value = ''
  for (const byte of bytes) value += String.fromCharCode(byte)
  return btoa(value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function randomBase64url(length = 32): string {
  return base64url(crypto.getRandomValues(new Uint8Array(length)))
}

async function sha256Base64url(value: string): Promise<string> {
  return base64url(new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(value))))
}

function p256PublicJwk(value: JsonWebKey): JsonWebKey {
  if (value.kty !== 'EC' || value.crv !== 'P-256' || typeof value.x !== 'string' || typeof value.y !== 'string') throw new Error('The browser returned an invalid device public key')
  return { kty: 'EC', crv: 'P-256', x: value.x, y: value.y }
}

async function p256Jkt(value: JsonWebKey): Promise<string> {
  const key = p256PublicJwk(value)
  return sha256Base64url(JSON.stringify({ crv: key.crv, kty: key.kty, x: key.x, y: key.y }))
}

function asObject(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} is invalid`)
  return value as Record<string, unknown>
}


// PLAN4: the hosting-domain suffix a handle must end with is a property of
// the currently selected wallet, not a fixed ".did.md" assumption -- see
// wallet-directory.ts's handleSuffix field. This is a UI input hint only;
// the real trust check is DID resolution, not this pattern.
function didMdHandle(value: string): string {
  const handle = value.trim().toLowerCase()
  const suffix = selectedWallet.handleSuffix
  const escapedSuffix = suffix.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  if (!new RegExp(`^[a-z0-9](?:[a-z0-9-]{0,61})?${escapedSuffix}$`).test(handle)) throw new Error(`Enter a ${suffix.replace(/^\./, '')} hostname, for example test1${suffix}`)
  return handle
}

function sameDocumentEdit(value: unknown, expected: DidCoreDocumentEdit): void {
  if (JSON.stringify(value) !== JSON.stringify(expected)) throw new Error('did.md returned a DID document edit different from the one this browser requested')
}

/** The mediator at `values`' first URL. Over https it is named by its did:web; at an onion address (http) by the did:peer of the
 * same keys whose endpoint is that address -- one entrance, never both (the mediator's own document lists only its clearnet URL, so
 * the onion DID is built here from the keys it lists). Only the document is fetched, from the address given. */
async function bisetMediatorFor(values: readonly string[]): Promise<DidMdBisetMediator | undefined> {
  const index = values.findIndex(value => typeof value === 'string' && value.trim())
  if (index === -1) return undefined
  let url: URL
  try { url = new URL(values[index]!) } catch { throw new Error('Biset DIDComm mediator URL is invalid') }
  const onion = url.protocol === 'http:' && isOnionUrl(url.toString())
  if ((url.protocol !== 'https:' && !onion) || url.username || url.password || url.search || url.hash) throw new Error('Biset DIDComm mediator URL is invalid')
  const mediatorUrl = url.toString()
  const info = await fetchMediatorInfo(mediatorUrl)
  // Named by its did:web, or by its did:peer (a mediator that is not at an https URL): either is a DID a document can name.
  if (!info.xKid || !(info.did.startsWith('did:web:') || info.did.startsWith('did:peer:'))) throw new Error('Biset DIDComm mediator did not provide a valid routing key')
  if (!onion) return { mediatorUrl, routingKid: info.xKid, mediatorDid: info.did }
  if (info.did.startsWith('did:peer:')) return { mediatorUrl, routingKid: info.xKid, mediatorDid: info.did }
  if (!info.edPub) throw new Error('Biset DIDComm mediator lists no authentication key to name it over Tor')
  return { mediatorUrl, routingKid: info.xKid, mediatorDid: encodePeerDid2(info.xPub, info.edPub, { uri: mediatorUrl.replace(/\/$/, '') }) }
}

/** Generates and seals the DIDComm device's own material -- none of it
 * (the X25519 leaf, the mediator inbox-label secret) is bound to
 * this identity's did:vh, so none of it needs the DID known yet. Only
 * `xKid` (did:vh + fragment) does; see withDidCommXKid. */
async function prepareBisetDidCommDevice(mediator: DidMdBisetMediator): Promise<DidMdBisetDidCommDeviceMaterial & { mediatorUrl: string; routingKid: string; mediatorDid?: string; mediatorOnionUrl?: string }> {
  const x25519PrivateKey = x25519.utils.randomSecretKey()
  const x25519PublicKey = x25519.getPublicKey(x25519PrivateKey)
  const mediatorDeviceSecret = crypto.getRandomValues(new Uint8Array(32))
  try {
    const sealed = await sealDidMdBisetDidCommDeviceMaterial(x25519PublicKey, { x25519PrivateKey, mediatorDeviceSecret })
    return { ...sealed, mediatorUrl: mediator.mediatorUrl, routingKid: mediator.routingKid, mediatorDid: mediator.mediatorDid, ...(mediator.mediatorOnionUrl ? { mediatorOnionUrl: mediator.mediatorOnionUrl } : {}) }
  } finally {
    x25519PrivateKey.fill(0)
    mediatorDeviceSecret.fill(0)
  }
}

function withDidCommXKid<T extends { x25519PublicKey: Uint8Array }>(device: T, did: string): T & { xKid: string } {
  return { ...device, xKid: deviceKid(did, device.x25519PublicKey) }
}

/** For the two callers that already know the DID at build time (the
 * mediator-only finalize step, and editing an existing mediator). The
 * minimal first-shot login instead calls prepareBisetDidCommDevice
 * directly and resolves xKid later, once the response reveals the DID. */
async function newBisetDidCommDevice(did: string, mediator: DidMdBisetMediator): Promise<NonNullable<DidMdPendingAuthorization['bisetDidCommDevice']> & DidMdBisetDidCommDeviceMaterial & { xKid: string }> {
  return withDidCommXKid(await prepareBisetDidCommDevice(mediator), did)
}

/** The clearnet endpoints of the OLD form -- the mediator's URL with its routing
 * key -- that a document keeps next to the mediator's DID. Pointing at the
 * mediator by DID replaces them (a document published while the configuration
 * still had the URL form carries one, and senders cannot use its did:web
 * routing key). The onion entrance is left alone: the mediator's own document
 * does not list one, so retiring it would end the user's Tor opt-in. */
function legacyUrlEndpointRemovals(serviceId: string, mediatorUrl: string | undefined): DidCoreEndpointRemoval[] {
  if (!mediatorUrl) return []
  const bare = mediatorUrl.replace(/\/+$/, '')
  return [bare, `${bare}/`].map(uri => ({ serviceId, match: { uri } }))
}

export function buildDocumentEdit(did: string, config: WalletConfiguration, device?: NonNullable<DidMdPendingAuthorization['bisetDidCommDevice']>, remove: string[] = [], removeEndpoints: DidCoreEndpointRemoval[] = [], rotation?: RotationCandidate['method']): DidCoreDocumentEdit {
  const didcomm = configuredService(config, 'didcomm')
  const services = config.didDocumentServices
    .filter(service => service.purpose !== 'didcomm' || device)
    .map(service => ({
      id: service.id,
      type: service.type,
      // The DIDComm service is shared by every device of this identity (and carries the
      // Tor entrance once the user opted in): each device adds ITS endpoints to it and
      // never replaces what another one published.
      ...(service.purpose === 'didcomm' ? { endpointMode: 'merge' as const } : {}),
      serviceEndpoint: ((endpoint) => service.purpose === 'didcomm' ? didCommEndpointWithOnion(endpoint, device?.mediatorOnionUrl) : endpoint)(materializeServiceEndpoint(service.serviceEndpoint, {
        '$mediatorUrl': device?.mediatorUrl ?? '',
        '$routingKid': device?.routingKid ?? '',
        '$mediatorDid': device?.mediatorDid ?? '',
      })),
    }))
  const namesMediatorByDid = services.some(service => service.id === didcomm.id && [service.serviceEndpoint].flat().some(endpoint => typeof endpoint === 'object' && endpoint !== null && typeof (endpoint as { uri?: unknown }).uri === 'string' && (endpoint as { uri: string }).uri.startsWith('did:')))
  const migration = device && namesMediatorByDid ? legacyUrlEndpointRemovals(didcomm.id, device.mediatorUrl) : []
  removeEndpoints = [...removeEndpoints, ...migration.filter(removal => !removeEndpoints.some(existing => canonical(existing) === canonical(removal)))]
  return {
    type: DID_DOCUMENT_EDIT_DETAIL,
    services,
    verificationMethods: [
      ...(device ? [{ id: deviceKidFragment(device.x25519PublicKey), type: 'Multikey', controller: did, publicKeyMultibase: encodeX25519Multikey(device.x25519PublicKey) }] : []),
      ...(rotation ? [{ ...rotation, controller: did }] : []),
    ],
    serviceKeyBindings: device ? [{ serviceId: didcomm.id, keyIds: [deviceKidFragment(device.x25519PublicKey)] }] : [],
    remove,
    ...(removeEndpoints.length ? { removeEndpoints } : {}),
  }
}

/** What the sealed candidate seed is (did-md-store.ts's sealDidMdSecret label). */
export const ROTATION_SEED_CANDIDATE = 'generation-seed-candidate'

interface RotationCandidate { sealed: DidMdSealedSecret; method: ReturnType<typeof rotationKeyEditMethod> }

/** A fresh generation seed, offered to the Wallet by its rotation key
 * (PLAN-refactor.md §7-1): `ifAbsent` when the identity may already have one
 * (sign-in, enabling messaging -- the first device approved wins),
 * `replace` when it is being replaced (removing devices, renewing). The seed
 * itself stays sealed in this browser until the Wallet publishes its key. */
async function rotationCandidate(mode: 'ifAbsent' | 'replace'): Promise<RotationCandidate> {
  const seed = crypto.getRandomValues(new Uint8Array(32))
  try { return { sealed: await sealDidMdSecret(ROTATION_SEED_CANDIDATE, seed), method: rotationKeyEditMethod(seed, mode) } }
  finally { seed.fill(0) }
}

async function setMediatorRegistration(did: string, device: NonNullable<DidMdPendingAuthorization['bisetDidCommDevice']> & { xKid: string }, action: 'add' | 'remove'): Promise<void> {
  const material = await openDidMdBisetDidCommDeviceMaterial(device)
  try {
    const mediator = await fetchMediatorInfo(device.mediatorUrl)
    if (mediator.xKid !== device.routingKid) throw new Error('Mediator routing key changed during DID document edit')
    const inbox = mediatorInbox({ did, xKid: device.xKid, xPriv: material.x25519PrivateKey }, material.mediatorDeviceSecret)
    if (action === 'remove') await updateRecipient(mediator, inbox, 'remove')
    else await registerWithMediator(device.mediatorUrl, inbox)
  } finally { material.x25519PrivateKey.fill(0); material.mediatorDeviceSecret.fill(0) }
}

async function rollbackPendingMediator(pending: DidMdPendingAuthorization): Promise<void> {
  const device = pending.bisetDidCommDevice
  if (!pending.mediatorPreRegistered || !device?.xKid || !pending.did) return
  try { await setMediatorRegistration(pending.did, { ...device, xKid: device.xKid }, 'remove') }
  catch (error) { console.warn('[mediator edit rollback]', error instanceof Error ? error.message : error) }
}

function redirectUri(): string {
  // https, or the Tor hidden service this app is also served at (an onion address carries no TLS).
  if (location.protocol !== 'https:' && !isOnionPage()) throw new Error('Sign-in needs an https page')
  return `${location.origin}${CALLBACK_PATH}`
}

const isOnionPage = (): boolean => location.protocol === 'http:' && location.hostname.endsWith('.onion')

/** Where the selected wallet's authorization screen is reached from this page: over Tor, the default wallet is the
 * one served at its onion address (`ditoOnionUrl` in the config), since a hidden service page cannot count on clearnet. */
function walletEndpoint(): string {
  const onion = (globalThis as { __BISET_CONFIG__?: { ditoOnionUrl?: unknown } }).__BISET_CONFIG__?.ditoOnionUrl
  if (isOnionPage() && selectedWallet === DEFAULT_WALLET && typeof onion === 'string' && onion) return `${onion.replace(/\/$/, '')}/authorize`
  return selectedWallet.authorizationEndpoint
}

function isWalletCallback(): boolean {
  return location.pathname === CALLBACK_PATH
}

/** The Client Identifier of this page as a relying party with no key of its own (OID4VP 1.0 §5.9.3). */
const clientIdFor = (callback: string): string => `redirect_uri:${callback}`

// Wallet discovery from a host the user types (alice.did.md): resolve that identity's own DID document and read its
// "SelfIssuedOPAuthorizationEndpoint" service entry (where its wallet's authorization screen is). Nothing is
// registered or fetched from the wallet; the DID document is the whole directory.
export async function resolveWalletFromSuffix(suffix: string): Promise<WalletDirectoryEntry> {
  const domain = suffix.trim().toLowerCase()
  if (!/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain)) throw new Error('Enter a domain, e.g. alice.did.md.')
  const found = await resolveVhByHost(domain)
  if (!found) throw new Error(`${domain} has no did:vh identity.`)
  const document = found.document
  const service = Array.isArray(document.service) ? document.service : []
  const entry = service.find(candidate => candidate?.type === 'SelfIssuedOPAuthorizationEndpoint' && typeof candidate.serviceEndpoint === 'string')
  if (!entry || typeof entry.serviceEndpoint !== 'string') throw new Error(`${domain} does not publish a wallet.`)
  const endpoint = entry.serviceEndpoint
  let parsed: URL
  try { parsed = new URL(endpoint) } catch { throw new Error(`${domain}'s wallet endpoint is invalid.`) }
  if (parsed.protocol !== 'https:') throw new Error(`${domain}'s wallet endpoint is invalid.`)
  return { id: `suffix:${domain}`, displayName: domain, authorizationEndpoint: endpoint, handleSuffix: `.${domain}` }
}

/** did.md's Root key: the identity's own authentication key, `#pass-1`. */
const ROOT_KEY_FRAGMENT = '#pass-1'

export async function rootAuthority(handle: string, document: DidDocument | null) {
  if (!document) throw new Error(`No DID was found for ${handle}`)
  // The identity is the one published at the handle: its own document names the handle as its place (the host enforced that
  // when it took the log), and only that one.
  if (!document.alsoKnownAs.includes(`did:web:${handle}`)) throw new Error('Resolved DID does not match the requested did.md hostname')
  // The Root key is `#pass-1` by name (did.md's genesis), not whichever
  // authentication entry comes first: the document may list other
  // authentication keys too (PLAN-refactor.md §3-4), in any order.
  const root = `${document.id}${ROOT_KEY_FRAGMENT}`
  const absolute = (id: string) => id.startsWith('#') ? `${document.id}${id}` : id
  const authRef = document.authentication.find(ref => absolute(ref) === root)
  const method = authRef ? document.verificationMethod.find(candidate => absolute(candidate.id) === root) : undefined
  if (!authRef || !method) throw new Error('Resolved DID has no Root authentication key')
  const verificationMethod = method.id.startsWith('#') ? `${document.id}${method.id}` : method.id
  return { did: document.id, verificationMethod, rootPublicKey: decodeMultikey(method.publicKeyMultibase) }
}

function capabilityDetails(value: unknown, pending: ResolvedPendingAuthorization): { didCommDevice?: NonNullable<ResolvedPendingAuthorization['bisetDidCommDevice']> } {
  // Absent when nothing was requested.
  if (value !== undefined && !Array.isArray(value)) throw new Error('did.md returned invalid Biset authorization details')
  const edits = ((value ?? []) as unknown[]).filter(item => { try { return asObject(item, 'authorization detail').type === DID_DOCUMENT_EDIT_DETAIL } catch { return false } })
  if (pending.documentEdit) {
    if (edits.length !== 1) throw new Error('did.md did not return one DID document edit detail')
    sameDocumentEdit(edits[0], pending.documentEdit)
  } else if (edits.length !== 0) throw new Error('did.md returned an unexpected DID document edit detail')
  return { ...(pending.bisetDidCommDevice ? { didCommDevice: pending.bisetDidCommDevice } : {}) }
}

type ResolvedPendingAuthorization = DidMdPendingAuthorization & {
  did: string; handle: string; verificationMethod: string; rootPublicKey: Uint8Array
  // xKid is guaranteed once resolvedPendingAuthorization has run, whether it
  // arrived already-resolved (finalize/documentEdit, did known at build
  // time) or was filled in here (login, prepared before the DID was known).
  bisetDidCommDevice?: NonNullable<DidMdPendingAuthorization['bisetDidCommDevice']> & { xKid: string }
}

/** Resolves the signer's DID/handle/root key from the token response's
 * `sub` when the pending authorization didn't know them up front (the
 * minimal first-shot login request sends no login_hint) -- the exact
 * derivation the now-removed lightweight OIDC step used to do before
 * redirecting a second time, now done once, after the single redirect. */
async function resolvedPendingAuthorization(pending: DidMdPendingAuthorization, did: string): Promise<ResolvedPendingAuthorization> {
  if (pending.did !== undefined) {
    if (pending.did !== did) throw new Error('did.md returned a device capability for an unexpected DID')
    return pending as ResolvedPendingAuthorization
  }
  // A did:vh DID names no host: the handle is the place its own document says the log is published at.
  // The login was started for a handle (`login_hint=alice.did.md`): that is where its log is looked for first.
  if (pending.handle) rememberVhLocation(did, pending.handle)
  const resolved = await resolveDidDocument(did, { fetch: freshFetch() })
  if (!resolved) throw new Error(`No DID was found for ${did}`)
  const place = didWebCandidates(resolved as unknown as Record<string, unknown>)[0]
  if (!place) throw new Error('did.md returned a device capability for an identity that names no place')
  const handle = didMdHandle(place.slice('did:web:'.length))
  const identity = await rootAuthority(handle, resolved)
  if (identity.did !== did) throw new Error('did.md returned a device capability for an unexpected DID')
  // The login request prepared this device before the DID was known (see
  // beginDidMdWalletLogin) -- xKid can only be computed now.
  const bisetDidCommDevice = pending.bisetDidCommDevice ? withDidCommXKid(pending.bisetDidCommDevice, identity.did) : undefined
  const { bisetDidCommDevice: _pendingDevice, ...rest } = pending
  // The login request's documentEdit (if it has a verification method at
  // all) was built with a placeholder controller, since the DID wasn't
  // known yet -- but Wallet always force-overwrites controller to its own
  // loaded DID regardless of what was requested (dispo's client/app.ts,
  // didDocumentEditDetail), so the echoed edit sameDocumentEdit compares
  // against below will carry the REAL DID. Correct this copy the same way
  // before that comparison, or it always mismatches.
  const documentEdit = pending.documentEdit && {
    ...pending.documentEdit,
    verificationMethods: pending.documentEdit.verificationMethods.map(method => ({ ...method, controller: identity.did })),
  }
  return { ...rest, did: identity.did, handle, verificationMethod: identity.verificationMethod, rootPublicKey: identity.rootPublicKey, bisetDidCommDevice, ...(documentEdit ? { documentEdit } : {}) }
}

async function capabilityFromResponse(value: unknown, pending: ResolvedPendingAuthorization) {
  // PLAN3 (~/did.md/PLAN3-oid4vp-transport.md): `value` is now a VC-DM 2.0
  // credential with an embedded `proof`, not a {document, proof} pair.
  // The credential's SHAPE (required fields, formats, patterns, the
  // authorizationDetails item union) is checked against
  // schemas/biset-messenger-capability.schema.json -- see json-schema.ts.
  // That schema is the single source of truth for shape; it is NOT aware
  // of `pending` (the in-flight request this response must match), so
  // everything below that compares against `pending` stays hand-written.
  const vc = asObject(value, 'device capability')
  assertMatchesSchema(capabilitySchema as JSONSchema, vc, 'device capability')
  const subject = asObject(vc.credentialSubject, 'device capability subject')
  if (vc.issuer !== pending.did || subject.audience !== pending.clientId || subject.deviceJkt !== pending.deviceJkt || Date.parse(subject.expiresAt as string) <= Date.now()) throw new Error('did.md returned an invalid device capability')
  const scope = subject.scope as string[]
  if (!scope.includes('biset:device') || !scope.includes('biset:vault')) throw new Error('did.md did not enroll this Biset device')
  const proof = asObject(vc.proof, 'device capability proof') as unknown as DataIntegrityProof
  // Data Integrity Proof convention: verify over the credential WITHOUT its
  // own `proof` property -- the same shape did.md's server checks (see
  // verifiedOauthCapability in server/server.ts).
  const { proof: _vcProof, ...unsignedVc } = vc
  if (proof.proofPurpose !== 'authentication' || proof.verificationMethod !== pending.verificationMethod || !verifyProof(unsignedVc, proof, pending.rootPublicKey)) throw new Error('did.md device capability proof is invalid')
  const detail = capabilityDetails(subject.authorizationDetails, pending)
  return { capability: vc, expiresAt: subject.expiresAt as string, scope: subject.scope as string[], didCommDevice: detail.didCommDevice }
}

// The wallet delivers vp_token/id_token straight to this page (the callback's fragment). `did` is the presentation's holder; the
// session is built only after the presentation and the id_token are checked against this request and the DID document is read.
async function sessionFromVpToken(vpToken: unknown, idToken: string, did: string, pending: DidMdPendingAuthorization): Promise<DidMdActiveSession> {
  // The OID4VP DCQL response envelope -- { "<query_id>": [<presentation>] } -- under the one query id this RP asks with.
  const envelope = asObject(vpToken, 'vp_token')
  const presentations = envelope.capability
  if (!Array.isArray(presentations) || presentations.length !== 1) throw new Error('vp_token must contain exactly one presentation')
  const presentation = asObject(presentations[0], 'presentation')
  const credentials = presentation.verifiableCredential
  if (!Array.isArray(credentials) || credentials.length !== 1) throw new Error('The presentation must hold exactly one capability credential')
  return sessionFromCapabilityValue(credentials[0], did, pending, { presented: { presentation, idToken } })
}

const fromBase64url = (value: string): Uint8Array => {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) throw new Error('Not base64url')
  return Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4)), character => character.charCodeAt(0))
}
const sameBytes = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((byte, index) => byte === b[index])

/** What proves this response is for this request and from this identity: the presentation is signed by the
 * identity's Root key over this request's nonce and Client Identifier (OID4VP §8.6), and the id_token passes
 * SIOPv2 §11.1 (self-issued: iss = sub = the DID, signed by that DID's key, aud = our Client Identifier, our nonce). */
function verifyPresented(presented: { presentation: Record<string, unknown>; idToken: string }, pending: ResolvedPendingAuthorization): void {
  const { presentation, idToken } = presented
  const types = presentation.type
  if (!Array.isArray(types) || !types.includes('VerifiablePresentation') || presentation.holder !== pending.did) throw new Error('did.md returned an invalid presentation')
  const proof = asObject(presentation.proof, 'presentation proof') as unknown as DataIntegrityProof & { challenge?: unknown; domain?: unknown }
  const { proof: _proof, ...unsigned } = presentation
  if (proof.proofPurpose !== 'authentication' || proof.verificationMethod !== pending.verificationMethod || proof.challenge !== pending.nonce || proof.domain !== pending.clientId
    || !verifyProof(unsigned, proof, pending.rootPublicKey)) throw new Error('did.md presentation proof is invalid')
  const parts = idToken.split('.')
  if (parts.length !== 3) throw new Error('did.md id_token is malformed')
  let header: Record<string, unknown>; let claims: Record<string, unknown>; let signature: Uint8Array
  try {
    header = asObject(JSON.parse(new TextDecoder().decode(fromBase64url(parts[0]!))), 'id_token header')
    claims = asObject(JSON.parse(new TextDecoder().decode(fromBase64url(parts[1]!))), 'id_token claims')
    signature = fromBase64url(parts[2]!)
  } catch { throw new Error('did.md id_token is malformed') }
  const now = Math.floor(Date.now() / 1000)
  if (header.alg !== 'EdDSA' || header.kid !== pending.verificationMethod
    || claims.iss !== pending.did || claims.sub !== pending.did || claims.aud !== pending.clientId || claims.nonce !== pending.nonce
    || typeof claims.exp !== 'number' || claims.exp <= now || typeof claims.iat !== 'number' || claims.iat > now + 300) throw new Error('did.md id_token is invalid')
  let valid = false
  try { valid = ed25519.verify(signature, encoder.encode(`${parts[0]}.${parts[1]}`), pending.rootPublicKey) } catch { /* invalid */ }
  if (!valid) throw new Error('did.md id_token signature is invalid')
}

// Shared tail of sessionFromVpToken and restoreDidMdWalletSession: both end up with a single capability VC (`value`) and the DID
// it claims to be issued by, and the same checks (a restore has no presentation to check; the DID document is read afresh).
/** `registerMediator: false` is a restore of a stored session: boot registers this device with the
 * mediator right after, so doing it here too would only repeat the same round trips. */
async function sessionFromCapabilityValue(value: unknown, did: string, pending: DidMdPendingAuthorization, options: { registerMediator?: boolean; presented?: { presentation: Record<string, unknown>; idToken: string } } = {}): Promise<DidMdActiveSession> {
  const resolvedPending = await timedStep('    session: resolvedPendingAuthorization', resolvedPendingAuthorization(pending, did))
  if (options.presented) verifyPresented(options.presented, resolvedPending)
  const capability = await timedStep('    session: capabilityFromResponse', capabilityFromResponse(value, resolvedPending))
  // The identity is published at its handle: that is where its log is looked for (a did:vh names no host).
  rememberVhLocation(resolvedPending.did, resolvedPending.handle)
  const resolved = await timedStep('    session: resolveDidDocument(did)', resolveDidDocument(resolvedPending.did, { fetch: freshFetch() }))
  if (!resolved) throw new Error('Could not resolve the DID document after Wallet approval')
  // The credential stands only while the DID document still names the key that signed it.
  const named = (id: unknown) => typeof id === 'string' && id.startsWith('#') ? `${resolvedPending.did}${id}` : id
  const signer = resolved.verificationMethod?.find(method => named(method.id) === resolvedPending.verificationMethod)
  if (!resolved.authentication?.some(reference => named(reference) === resolvedPending.verificationMethod) || !signer || !sameBytes(decodeMultikey(signer.publicKeyMultibase), resolvedPending.rootPublicKey)) throw new Error('The DID document no longer names the key that signed this capability')
  // A DID URL may be written relative (`#x`) or absolute (`did:...#x`); both name the same.
  const absolute = (id: unknown) => typeof id === 'string' && id.startsWith('#') ? `${resolvedPending.did}${id}` : id
  const serviceOf = (id: string) => resolved.service?.find(value => absolute(value.id) === absolute(id))
  for (const service of resolvedPending.documentEdit?.services ?? []) {
    const published = serviceOf(service.id)
    if (!serviceIsPublished(published && { ...published, id: service.id }, service)) throw new Error(`Wallet did not publish requested service ${service.id}`)
  }
  for (const removal of resolvedPending.documentEdit?.removeEndpoints ?? []) if (!endpointsAreRemoved(serviceOf(removal.serviceId), removal)) throw new Error(`Wallet did not remove the requested endpoints of ${removal.serviceId}`)
  // A method asked for `ifAbsent` may meet another device's already there:
  // then that one stays, and this request's candidate seed is not the
  // identity's (its own seed arrives by Vault Sync). Anything else must be
  // published as asked, referenced from the relationships asked for.
  let rotationSeedPublished = false
  for (const method of resolvedPending.documentEdit?.verificationMethods ?? []) {
    const { relationships, mode, ...wanted } = method
    const published = resolved.verificationMethod?.find(value => absolute(value.id) === absolute(method.id))
    if (!published || canonical({ ...published, id: absolute(published.id) }) !== canonical({ ...wanted, id: absolute(wanted.id) })) {
      if (mode === 'ifAbsent') continue
      throw new Error(`Wallet did not publish requested verification method ${method.id}`)
    }
    const document = resolved as unknown as Record<string, unknown>
    for (const relationship of relationships ?? ['keyAgreement']) {
      const references = Array.isArray(document[relationship]) ? document[relationship] as unknown[] : []
      if (!references.some(reference => absolute(reference) === absolute(method.id))) throw new Error(`Wallet did not reference ${method.id} from ${relationship}`)
    }
    if (method.id === ROTATION_KEY_FRAGMENT) rotationSeedPublished = true
  }
  for (const id of resolvedPending.documentEdit?.remove ?? []) if (resolved.service?.some(value => absolute(value.id) === absolute(id)) || resolved.verificationMethod?.some(value => absolute(value.id) === absolute(id))) throw new Error(`Wallet did not remove ${id}`)
  const previousSession = await readDidMdDeviceSession()
  const session: DidMdDeviceSession = {
    v: 3, wallet: resolvedPending.wallet, clientId: resolvedPending.clientId, did: resolvedPending.did, handle: resolvedPending.handle,
    verificationMethod: resolvedPending.verificationMethod, rootPublicKey: resolvedPending.rootPublicKey, deviceJkt: resolvedPending.deviceJkt,
    privateKey: resolvedPending.privateKey, publicJwk: resolvedPending.publicJwk, capability: capability.capability, capabilityExpiresAt: capability.expiresAt,
    vaultDeviceId: resolvedPending.vaultDeviceId,
    ...(capability.didCommDevice ? { bisetDidCommDevice: capability.didCommDevice } : {}),
    // Kept until this device stores it in its Vault (at boot). An earlier
    // approval's seed not yet stored is kept too, unless this one replaced it.
    ...(rotationSeedPublished && resolvedPending.rotationSeedCandidate ? { rotationSeed: resolvedPending.rotationSeedCandidate }
      : previousSession?.rotationSeed && previousSession.did === resolvedPending.did ? { rotationSeed: previousSession.rotationSeed } : {}),
  }
  await saveDidMdDeviceSession(session)
  // The mediator authenticates this DIDComm sender by resolving xKid from
  // the DID document. Registration before Wallet publication is therefore
  // impossible by construction. Publish + re-resolve above first, persist
  // the recoverable session, then register; boot retries registration if
  // the network fails after the DID commit.
  if (capability.didCommDevice && options.registerMediator !== false) await setMediatorRegistration(resolvedPending.did, capability.didCommDevice, 'add')
  if (resolvedPending.previousBisetDidCommDevice) {
    try { await setMediatorRegistration(resolvedPending.did, resolvedPending.previousBisetDidCommDevice, 'remove') }
    catch (error) { console.warn('[mediator edit cleanup]', error instanceof Error ? error.message : error) }
  }
  return { did: session.did, handle: session.handle, clientId: session.clientId, deviceJkt: session.deviceJkt, capabilityExpiresAt: session.capabilityExpiresAt, scope: capability.scope, deviceKid: resolvedPending.vaultDeviceId, ...(capability.didCommDevice ? { didCommKid: capability.didCommDevice.xKid } : {}) }
}

function pendingFromSession(session: DidMdDeviceSession): ResolvedPendingAuthorization {
  // PLAN3: session.capability is now the whole VC-DM credential (embedded
  // proof) -- the RP-owned content that used to be the flat document is
  // now under credentialSubject.
  const capabilitySubject = (() => { try { return asObject((session.capability as Record<string, unknown>).credentialSubject, 'stored capability subject') } catch { return {} } })()
  const storedEdit = Array.isArray(capabilitySubject.authorizationDetails)
    ? capabilitySubject.authorizationDetails.find(value => { try { return asObject(value, 'stored authorization detail').type === DID_DOCUMENT_EDIT_DETAIL } catch { return false } })
    : undefined
  return {
    v: 3, wallet: session.wallet, clientId: session.clientId, state: '', nonce: '', did: session.did,
    handle: session.handle, verificationMethod: session.verificationMethod, rootPublicKey: session.rootPublicKey,
    deviceJkt: session.deviceJkt, privateKey: session.privateKey, publicJwk: session.publicJwk,
    vaultDeviceId: session.vaultDeviceId ?? (() => { throw new Error('This did.md Wallet session predates this Biset version; connect it again.') })(),
    // None when the capability carries none (a sign-in after a move to another host): the refresh must not expect one.
    ...(storedEdit ? { documentEdit: storedEdit as DidCoreDocumentEdit } : {}),
    ...(session.bisetDidCommDevice ? { bisetDidCommDevice: session.bisetDidCommDevice } : {}),
    createdAt: '',
  }
}

/** What the wallet needs to know about this page as a relying party, and where its authorization screen is. */
type WalletClient = { authorizationEndpoint: string; clientId: string; redirectUri: string }
function walletClient(): WalletClient {
  const callback = redirectUri()
  return { authorizationEndpoint: walletEndpoint(), clientId: clientIdFor(callback), redirectUri: callback }
}

const base64urlJson = (value: unknown): string => base64url(encoder.encode(JSON.stringify(value)))

/** Saves the pending authorization and builds the Wallet's authorization request URL (SIOPv2 / OpenID4VP,
 * `client_id=redirect_uri:<callback>`, the request not signed): the credential asked for is named by `dcql_query`, what the
 * person approves rides in `transaction_data`, and the response (vp_token + id_token) comes back in the callback's fragment.
 * It does not navigate. */
async function walletRequestUrl(client: WalletClient, pending: DidMdPendingAuthorization): Promise<string> {
  await saveDidMdPendingAuthorization(pending)
  const request = new URL(client.authorizationEndpoint)
  const transactionData = [
    base64urlJson({ type: 'device_capability', credential_ids: ['capability'], device_jkt: pending.deviceJkt, scope: REQUESTED_SCOPES }),
    // Optional: a plain sign-in changes nothing in the DID document.
    ...(pending.documentEdit ? [base64urlJson({ type: 'did_document_edit', credential_ids: ['capability'], detail: pending.documentEdit })] : []),
  ]
  const configured = rpDid()
  const params = new URLSearchParams({
    client_id: pending.clientId, redirect_uri: client.redirectUri, response_type: 'vp_token id_token', response_mode: 'fragment',
    scope: 'openid', nonce: pending.nonce, state: pending.state,
    ...(pending.handle !== undefined ? { login_hint: pending.handle } : {}),
    dcql_query: JSON.stringify({ credentials: [{ id: 'capability', format: 'ldp_vc', meta: { type_values: [['VerifiableCredential', CAPABILITY_TYPE]] } }] }),
    transaction_data: JSON.stringify(transactionData),
    client_metadata: JSON.stringify({ client_name: 'Biset', ...(configured ? { rp_did: configured } : {}) }),
  })
  request.search = params.toString()
  return request.toString()
}

async function redirectToWallet(client: WalletClient, pending: DidMdPendingAuthorization): Promise<never> {
  const request = new URL(await walletRequestUrl(client, pending))
  location.assign(request.toString())
  // Navigation is asynchronous: the page keeps running until it unloads, so
  // throwing here at once showed a "did not navigate" error right before the
  // wallet opened. Wait for the unload; only a navigation that never
  // happens (blocked, say) is an error.
  return await new Promise<never>((_resolve, reject) => {
    window.setTimeout(() => reject(new Error('The browser did not navigate to did.md Wallet')), 10_000)
  })
}

async function otherDeviceMethodIds(did: string, ownKid: string): Promise<string[]> {
  // Read past the host's CDN (`freshFetch`): a stale copy would leave a recently added device out of the removal.
  const resolved = await resolveDidDocument(did, { fetch: freshFetch() })
  if (!resolved || resolved.id !== did) throw new Error('Could not resolve the current DID document before removing other devices')
  return (resolved.verificationMethod ?? []).flatMap(method => {
    try {
      const key = decodeX25519Multikey(method.publicKeyMultibase)
      const fragment = method.id.startsWith('#') ? method.id : method.id.slice(did.length)
      const kid = `${did}${fragment}`
      if (fragment !== deviceKidFragment(key) || kid === ownKid) return []
      return [method.id]
    } catch { return [] }
  })
}

/** The only round trip needed to sign in: no DID is resolved and no
 * document edit is requested up front, so this never needs to know which
 * did.md handle the user has open in Wallet beforehand (no login_hint). The
 * signer's DID and DIDComm mediator enrollment are both
 * resolved/deferred to after Wallet approves -- see `tokenFrom` for DID
 * derivation. */
/** The only round trip needed to sign in and, when a mediator is configured
 * and reachable, publish a DIDComm device. No DID is resolved up front
 * (no login_hint). The DIDComm device's own
 * material -- the X25519 leaf, its mediator inbox-label secret, even
 * the document edit's verification method (a fragment-only id; its
 * `controller` is ignored and overwritten by Wallet regardless) -- turns
 * out not to need the DID either, only `xKid` (did:vh + fragment) does.
 * prepareBisetDidCommDevice builds everything else now; withDidCommXKid
 * fills in `xKid` once the token response reveals the DID, the same
 * resolve-after-response pattern resolvedPendingAuthorization already uses
 * for did/handle/verificationMethod/rootPublicKey.
 *
 * Best-effort: a mediator that's unconfigured or unreachable right now
 * just means no DIDComm device this round -- it must never block sign-in
 * itself; beginDidMdDocumentEdit publishes the device afterwards. */
async function newLoginPending(mediatorUrls: readonly string[], config: WalletConfiguration, handle?: string): Promise<{ client: WalletClient, pending: DidMdPendingAuthorization }> {
  const client = walletClient()
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']) as CryptoKeyPair
  const publicJwk = p256PublicJwk(await crypto.subtle.exportKey('jwk', pair.publicKey))
  let bisetDidCommDevice: NonNullable<DidMdPendingAuthorization['bisetDidCommDevice']> | undefined
  try {
    const mediator = await bisetMediatorFor(mediatorUrls)
    if (mediator) bisetDidCommDevice = await prepareBisetDidCommDevice(mediator)
  } catch (error) {
    console.warn('[did.md Wallet login] DIDComm mediator unavailable, signing in without it', error instanceof Error ? error.message : error)
  }
  const rotation = bisetDidCommDevice ? await rotationCandidate('ifAbsent') : undefined
  const pending: DidMdPendingAuthorization = {
    v: 3, wallet: client.authorizationEndpoint, clientId: client.clientId, state: randomBase64url(32), nonce: randomBase64url(32),
    ...(handle !== undefined ? { handle } : {}),
    deviceJkt: await p256Jkt(publicJwk), privateKey: pair.privateKey, publicJwk, vaultDeviceId: `urn:uuid:${crypto.randomUUID()}`,
    documentEdit: buildDocumentEdit('', config, bisetDidCommDevice, [], [], rotation?.method),
    ...(bisetDidCommDevice ? { bisetDidCommDevice } : {}),
    ...(rotation ? { rotationSeedCandidate: rotation.sealed } : {}),
    createdAt: new Date().toISOString(),
  }
  return { client, pending }
}

export async function beginDidMdWalletLogin(mediatorUrls: readonly string[] = [], configured: DidMdWalletConfiguration = {}): Promise<never> {
  const { client, pending } = await newLoginPending(mediatorUrls, walletConfiguration(configured))
  return redirectToWallet(client, pending)
}

/**
 * The same login, prepared but not started: the pending authorization is saved and the signed
 * request is built, and its query string is returned for the wallet to open itself (the embedded
 * create hands it to dito's save page, which signs in as the person finishes saving the Passphrase;
 * the response comes back to the wallet callback as usual). `handle` pins the login to the
 * identity being created (`name.did.md`).
 */
export async function prepareDidMdWalletLoginRequest(mediatorUrls: readonly string[] = [], configured: DidMdWalletConfiguration = {}, handle?: string): Promise<string> {
  const { client, pending } = await newLoginPending(mediatorUrls, walletConfiguration(configured), handle)
  return new URL(await walletRequestUrl(client, pending)).search
}

/** The endpoints a DID document stops listing when its DIDComm device moves to `next`.
 * Pointing at a DIFFERENT mediator retires every endpoint of the old one; the same
 * mediator keeps what is published. An endpoint naming its mediator by URL carries
 * the mediator's routing key (its clearnet and its onion alike); one naming it by DID
 * is the DID itself. A move from the URL form to the DID form retires the former, so
 * a document does not keep both. */
export function retiredMediatorEndpoints(
  old: { routingKid: string; mediatorDid?: string } | undefined,
  next: { routingKid: string; mediatorDid?: string },
  serviceId: string,
): DidCoreEndpointRemoval[] {
  return [
    ...(old?.routingKid && old.routingKid !== next.routingKid ? [{ serviceId, match: { routingKeys: [old.routingKid] } }] : []),
    ...(old?.mediatorDid && old.mediatorDid !== next.mediatorDid ? [{ serviceId, match: { uri: old.mediatorDid } }] : []),
  ]
}

/**
 * Approves a signed request without leaving the page (dito's embedded frame): resolves with the
 * response the relying party would otherwise get in the callback URL. Without one, an approval is a
 * full-page round trip through the Wallet (`redirectToWallet`).
 */
export type DidMdWalletApprover = (request: Promise<string>) => Promise<URLSearchParams>
let walletApprover: DidMdWalletApprover | undefined
export function useDidMdWalletApprover(approver: DidMdWalletApprover | undefined): void { walletApprover = approver }

/** Sends the pending authorization to the Wallet: in place when there is an approver (resolving
 * with the new session), otherwise by navigating away (never resolving). */
async function submitToWallet(client: WalletClient, pending: DidMdPendingAuthorization): Promise<DidMdActiveSession> {
  if (!walletApprover) return redirectToWallet(client, pending)
  // The approver gets the request still being prepared (the RP signer is a network round trip), so
  // its dialog can open and the Wallet frame can wake while that runs.
  const request = walletRequestUrl(client, pending).then(url => new URL(url).search)
  let response: URLSearchParams
  try { response = await walletApprover(request) }
  catch (error) {
    await rollbackPendingMediator(pending)
    await clearDidMdPendingAuthorization()
    throw error
  }
  const session = await completeDidMdWalletCallback(response)
  if (!session) throw new Error('did.md Wallet did not return a session')
  return session
}

/**
 * What one Wallet approval changes in the identity's DID document. Every edit is the same round
 * trip (the session's pending authorization plus a document edit the Wallet shows and signs);
 * only the edit differs:
 *  - `mediator`: publish this device's DIDComm key for the mediator (first connect, a new server,
 *    Tor), replacing the previous one.
 *  - `leaveMediator`: take this device's DIDComm key and the DIDComm service out.
 *  - `rotation`: replace the rotation key (a fresh generation seed's) -- for an identity that has
 *    none yet, one whose seed no device has any more, or one whose seed a device removed from the
 *    Wallet still holds (generation-seed-bootstrap.ts's "unpublished", "lost", "stale"). With
 *    `removeOtherDevices` the same edit drops every other device's keyAgreement key, which is the
 *    one place the rest of the system learns who the devices are (a mediator revokes their inboxes
 *    on the next log it is handed; senders stop encrypting to them, Vault Sync stops reaching them).
 */
export type DidMdDocumentChange =
  | { kind: 'mediator'; mediatorUrls: readonly string[] }
  | { kind: 'leaveMediator' }
  | { kind: 'rotation'; removeOtherDevices?: boolean }

export async function beginDidMdDocumentEdit(change: DidMdDocumentChange, configured: DidMdWalletConfiguration = {}): Promise<DidMdActiveSession> {
  const config = walletConfiguration(configured)
  const session = await readDidMdDeviceSession()
  if (!session?.vaultDeviceId || session.v !== 3 || Date.parse(session.capabilityExpiresAt) <= Date.now()) throw new Error('Reconnect did.md Wallet before editing the DID document')
  const client = walletClient()
  const pending = pendingFromSession(session)
  pending.state = randomBase64url(32); pending.nonce = randomBase64url(32); pending.createdAt = new Date().toISOString()
  const previousDevice = session.bisetDidCommDevice
  if (change.kind === 'leaveMediator') {
    if (previousDevice) pending.previousBisetDidCommDevice = previousDevice
    const didcomm = configuredService(config, 'didcomm')
    pending.documentEdit = buildDocumentEdit(session.did, config, undefined, [didcomm.id, ...(didcomm.previousIds ?? []), ...(previousDevice ? [previousDevice.xKid] : [])])
    delete pending.bisetDidCommDevice
  } else if (change.kind === 'mediator') {
    const mediator = await bisetMediatorFor(change.mediatorUrls)
    if (!mediator) throw new Error('Biset DIDComm mediator is not configured')
    if (previousDevice) pending.previousBisetDidCommDevice = previousDevice
    pending.bisetDidCommDevice = await newBisetDidCommDevice(session.did, mediator)
    const retired = retiredMediatorEndpoints(previousDevice, mediator, configuredService(config, 'didcomm').id)
    // Replacing this device's DIDComm key drops the previous one from the document, which reads as a
    // device removed after the rotation key was published ("stale"): the same edit renews that key
    // (a device removed in the entry that publishes a key was removed with its renewal).
    const rotation = await rotationCandidate(previousDevice ? 'replace' : 'ifAbsent')
    pending.rotationSeedCandidate = rotation.sealed
    pending.documentEdit = buildDocumentEdit(session.did, config, pending.bisetDidCommDevice, previousDevice ? [previousDevice.xKid] : [], retired, rotation.method)
  } else {
    if (!previousDevice) throw new Error('Connect the mediator before changing the keys')
    const remove = change.removeOtherDevices ? await otherDeviceMethodIds(session.did, previousDevice.xKid) : []
    if (change.removeOtherDevices && remove.length === 0) throw new Error('There are no other devices to remove')
    const rotation = await rotationCandidate('replace')
    pending.rotationSeedCandidate = rotation.sealed
    pending.documentEdit = buildDocumentEdit(session.did, config, previousDevice, remove, [], rotation.method)
  }
  return submitToWallet(client, pending)
}

/** The sign-in for the same device after the Wallet moved this identity to another host (its DID is the same). */
async function movedDidLoginPending(did: string, host: string, config: WalletConfiguration): Promise<{ client: WalletClient, pending: DidMdPendingAuthorization }> {
  const session = await readDidMdDeviceSession()
  if (!session?.vaultDeviceId || session.v !== 3) throw new Error('Reconnect did.md Wallet before changing the address')
  if (!sameIdentity(session.did, did)) throw new Error('The moved DID is not this account')
  const client = walletClient()
  const { did: _old, ...rest } = pendingFromSession(session)
  const pending: DidMdPendingAuthorization = {
    ...rest, state: randomBase64url(32), nonce: randomBase64url(32), createdAt: new Date().toISOString(),
    handle: didMdHandle(host),
  }
  delete pending.documentEdit
  return { client, pending }
}

/**
 * The Wallet moved this identity to another address (the host its log is published at): the sign-in request for the
 * same device at the new address, prepared and saved but not started -- its query string goes to the Wallet's save page
 * (the person's password manager updates the saved account there), whose last page signs in with the Passphrase it was
 * given and returns to the wallet callback. The DID, the device keys and the DIDComm key ids are the same; the handle is
 * the new address, and the capability is a fresh one for it.
 */
export async function prepareDidMdMovedDidLoginRequest(did: string, host: string, configured: DidMdWalletConfiguration = {}): Promise<string> {
  const { client, pending } = await movedDidLoginPending(did, host, walletConfiguration(configured))
  return new URL(await walletRequestUrl(client, pending)).search
}

/** The generation seed whose rotation key a Wallet approval published for
 * this session, until this device has stored it in its Vault. `forget()`
 * once it is stored (or found to be no longer the identity's). */
export async function approvedRotationSeed(): Promise<{ seed: Uint8Array; forget(): Promise<void> } | undefined> {
  const session = await readDidMdDeviceSession()
  if (!session?.rotationSeed) return undefined
  const sealed = session.rotationSeed
  return {
    seed: await openDidMdSecret(sealed, ROTATION_SEED_CANDIDATE),
    async forget() {
      const latest = await readDidMdDeviceSession()
      // A later approval may have put another seed here meanwhile: keep that one.
      const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((byte, index) => byte === b[index])
      if (!latest?.rotationSeed || !same(latest.rotationSeed.sealed.iv, sealed.sealed.iv)) return
      const { rotationSeed: _done, ...rest } = latest
      await saveDidMdDeviceSession(rest)
    },
  }
}

/** `delivered` is a response the embedded Wallet frame handed over its port, in place of the callback URL. */
export async function completeDidMdWalletCallback(delivered?: URLSearchParams): Promise<DidMdActiveSession | undefined> {
  if (!delivered && !isWalletCallback()) return undefined
  const callback = new URL(location.href)
  // A response is used once, whatever comes of it: leaving it in the address bar would make a reload (or a failed attempt's retry)
  // process the same fragment again and fail the same way.
  const clearFragment = () => { if (!delivered) try { history.replaceState(null, '', '/') } catch { /* no history to clean */ } }
  const pending = await readDidMdPendingAuthorization()
  if (!pending || pending.v !== 3 || pending.wallet !== walletEndpoint()) { clearFragment(); throw new Error('No matching did.md Wallet authorization is pending') }
  // The response comes in the URL fragment (never sent to any server, unlike a query string).
  const params = delivered ?? new URLSearchParams(callback.hash.slice(1))
  clearFragment()
  const abandon = async (message: string): Promise<never> => { await rollbackPendingMediator(pending); await clearDidMdPendingAuthorization(); throw new Error(message) }
  if (params.get('state') !== pending.state) return abandon('did.md Wallet callback state did not match')
  const error = params.get('error')
  if (error) return abandon(params.get('error_description') ?? `did.md Wallet authorization failed: ${error}`)
  const vpToken = params.get('vp_token')
  const idToken = params.get('id_token')
  if (!vpToken || !idToken) return abandon('did.md Wallet callback has no vp_token or id_token')
  if (pending.clientId !== clientIdFor(redirectUri())) { await clearDidMdPendingAuthorization(); throw new Error('This page is not the one that asked for the sign-in') }
  try {
    let parsedVpToken: unknown
    try { parsedVpToken = JSON.parse(vpToken) } catch { throw new Error('did.md Wallet callback vp_token is invalid') }
    const presentations = asObject(parsedVpToken, 'vp_token').capability
    const holder = Array.isArray(presentations) && presentations.length === 1 ? asObject(presentations[0], 'presentation').holder : undefined
    if (typeof holder !== 'string') throw new Error('did.md Wallet callback vp_token is invalid')
    return await sessionFromVpToken(parsedVpToken, idToken, holder, pending)
  } catch (error) {
    await rollbackPendingMediator(pending)
    throw error
  } finally { await clearDidMdPendingAuthorization() }
}

// Temporary boot timing (console.info "[boot] ...").
async function timedStep<T>(label: string, work: Promise<T>): Promise<T> {
  const startedAt = performance.now()
  try { return await work } finally { console.info(`[boot] ${label} +${Math.round(performance.now() - startedAt)}ms`) }
}

/** The stored session as the active one, without asking the Wallet anything: what is on screen
 * before the refresh below has been answered. Absent when there is none, it is for another Wallet,
 * or its capability has run out. */
export async function peekDidMdWalletSession(): Promise<DidMdActiveSession | undefined> {
  const session = await readDidMdDeviceSession()
  if (!session || session.v !== 3 || session.wallet !== walletEndpoint() || Date.parse(session.capabilityExpiresAt) <= Date.now()) return undefined
  const subject = (() => { try { return asObject((session.capability as Record<string, unknown>).credentialSubject, 'stored capability subject') } catch { return {} } })()
  return {
    did: session.did, handle: session.handle, clientId: session.clientId, deviceJkt: session.deviceJkt, capabilityExpiresAt: session.capabilityExpiresAt,
    scope: Array.isArray(subject.scope) ? subject.scope.filter((value): value is string => typeof value === 'string') : [],
    ...(session.vaultDeviceId ? { deviceKid: session.vaultDeviceId } : {}),
    ...(session.bisetDidCommDevice?.xKid ? { didCommKid: session.bisetDidCommDevice.xKid } : {}),
  }
}

/** A stored session is believed again only after the identity's DID document has been read afresh and still names the
 * key that signed its capability (sessionFromCapabilityValue); the wallet is not asked anything. */
export async function restoreDidMdWalletSession(): Promise<DidMdActiveSession | undefined> {
  const session = await readDidMdDeviceSession()
  if (!session || session.v !== 3 || session.wallet !== walletEndpoint() || Date.parse(session.capabilityExpiresAt) <= Date.now()) return undefined
  if ((location.protocol !== 'https:' && !isOnionPage()) || session.clientId !== clientIdFor(redirectUri())) return undefined
  try {
    return await timedStep('  restore: sessionFromCapabilityValue', sessionFromCapabilityValue(session.capability, session.did, pendingFromSession(session), { registerMediator: false }))
  } catch (error) {
    // Being offline says nothing about the session: it stays, to be checked another time.
    if (error instanceof TypeError) throw error
    // A stored session that no longer validates would otherwise fail this exact way on every load. Drop it so the
    // account page comes up clean and the person is asked to reconnect.
    await clearDidMdDeviceSession()
    throw error
  }
}

export async function didMdWalletReconnectState(): Promise<{ did: string; handle: string; capabilityExpiresAt: string; expired: boolean } | undefined> {
  const session = await readDidMdDeviceSession()
  if (!session || session.v !== 3 || session.wallet !== walletEndpoint()) return undefined
  return { did: session.did, handle: session.handle, capabilityExpiresAt: session.capabilityExpiresAt, expired: Date.parse(session.capabilityExpiresAt) <= Date.now() }
}

export async function disconnectDidMdWallet(): Promise<void> {
  await Promise.all([clearDidMdPendingAuthorization(), clearDidMdDeviceSession()])
}

/** This browser's identity as a Vault author. */
export async function openDidMdWalletVaultDevice(): Promise<DidMdVaultDevice> {
  const session = await readDidMdDeviceSession()
  if (!session?.vaultDeviceId || session.v !== 3) throw new Error('Connect did.md Wallet again to use this Biset device')
  rememberVhLocation(session.did, session.handle)
  return { did: session.did, handle: session.handle, deviceId: session.vaultDeviceId }
}

/** Opens the optional Biset-owned DIDComm leaf. The corresponding public
 * key and mediator route were included in the Root-authenticated Wallet
 * capability and published by Wallet before this session was stored. */
export async function openDidMdWalletBisetDidCommDevice(): Promise<DidMdBisetDidCommDevice | undefined> {
  const session = await readDidMdDeviceSession()
  const stored = session?.bisetDidCommDevice
  if (!session || session.v !== 3 || !stored) return undefined
  const privateMaterial = await openDidMdBisetDidCommDeviceMaterial(stored)
  const derivedPublic = x25519.getPublicKey(privateMaterial.x25519PrivateKey)
  if (!derivedPublic.every((byte, index) => byte === stored.x25519PublicKey[index])) throw new Error('Biset DIDComm private key does not match its Wallet-authorized public key')
  if (stored.xKid !== deviceKid(session.did, derivedPublic)) throw new Error('Biset DIDComm device key identifier is invalid')
  return { did: session.did, xKid: stored.xKid, x25519PrivateKey: privateMaterial.x25519PrivateKey, mediatorDeviceSecret: privateMaterial.mediatorDeviceSecret, mediatorUrl: stored.mediatorUrl, routingKid: stored.routingKid, ...(stored.mediatorOnionUrl ? { mediatorOnionUrl: stored.mediatorOnionUrl } : {}) }
}

