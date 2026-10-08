/**
 * did.md OAuth public-client integration.
 *
 * It persists no Wallet controller material. The only Biset-owned secrets
 * it keeps are the DIDComm device's (its X25519 key and mediator inbox-label
 * secret), AES-wrapped under a non-extractable browser key.
 */
import { x25519 } from '@noble/curves/ed25519.js'
import { decodeMultikey } from '../../../protocol/webvh/multikey.ts'
import { parseWebvhDid } from '../../../protocol/webvh/identifier.ts'
import { verifyProof, type DataIntegrityProof } from '../../../protocol/webvh/proof.ts'
import { freshFetch } from '../webvh/log-io.ts'
import { resolveByDomain } from '../../../protocol/webvh/resolver.ts'
import { deviceKid, deviceKidFragment } from '../../../protocol/didcomm/devicekid.ts'
import { decodeX25519Multikey, encodeX25519Multikey } from '../../../protocol/didcomm/multikey.ts'
import { fetchMediatorInfo, updateRecipient } from '../../../protocol/didcomm/mediator-coordinate.ts'
import { mediatorInbox } from '../../../protocol/didcomm/mediator-device.ts'
import { registerWithMediator } from '../../didcomm/mediator-sync.ts'
import { assertMatchesSchema, type JSONSchema } from './json-schema.ts'
import capabilitySchema from './schemas/biset-messenger-capability.schema.json' with { type: 'json' }
import { isOnionUrl } from '../../didcomm/mediator-endpoints.ts'
import { canonical, endpointsAreRemoved, serviceIsPublished } from './did-document-edit-check.ts'
import {
  clearDidMdRegistration,
  clearDidMdDeviceSession,
  clearDidMdPendingAuthorization,
  readDidMdDeviceSession,
  readDidMdPendingAuthorization,
  readDidMdRegistration,
  saveDidMdDeviceSession,
  saveDidMdPendingAuthorization,
  saveDidMdRegistration,
  sealDidMdBisetDidCommDeviceMaterial,
  openDidMdBisetDidCommDeviceMaterial,
  sealDidMdSecret,
  openDidMdSecret,
  type DidMdBisetDidCommDeviceMaterial,
  type DidMdSealedSecret,
  type DidMdDeviceSession,
  type DidMdPendingAuthorization,
  type DidMdRegistration,
  type DidCoreDocumentEdit,
  type DidCoreEndpointRemoval,
} from './did-md-store.ts'

import { DEFAULT_WALLET, type WalletDirectoryEntry } from './wallet-directory.ts'
import { rotationKeyEditMethod, ROTATION_KEY_FRAGMENT } from '../../didcomm/rotation-key.ts'
// PLAN4 (~/did.md/PLAN4-wallet-connector.md): the OAuth/OID4VP issuer this
// module talks to is no longer a fixed constant -- it is whichever wallet
// directory entry is currently selected (selectWallet/currentWallet
// below), defaulting to dito so existing single-wallet UX is unchanged.
// WALLET_ORIGIN was removed entirely: the popup-message origin check
// (see the window "message" listener below) now derives the expected
// origin from the active popup's own discovered authorization_endpoint,
// rather than assuming app.did.md.
let selectedWallet: WalletDirectoryEntry = DEFAULT_WALLET
export function selectWallet(entry: WalletDirectoryEntry): void { selectedWallet = entry }
export function currentWallet(): WalletDirectoryEntry { return selectedWallet }
const CALLBACK_PATH = '/wallet/callback'
const REQUESTED_SCOPES = ['openid', 'profile', 'biset:login', 'biset:device', 'biset:routing', 'biset:messaging', 'biset:vault']
// Biset's own capability document type (see did.md's
// PLAN2-capability-ownership.md): did.md no longer names this for us. The
// legacy 'did.md/DeviceCapability' name is still accepted ON RECEIPT --
// see the "type" property's enum in schemas/biset-messenger-capability.
// schema.json, which is the single source of truth for what's accepted --
// for a did.md Wallet that predates the capability_type request parameter
// and so falls back to its own old default. This constant is only ever
// what Biset itself REQUESTS.
const CAPABILITY_TYPE = 'biset.md/MessengerCapability'
// PLAN6 (~/did.md/PLAN6-rp-did-authentication.md): when biset runs at its
// normal https://t.biset.md origin, it authenticates its Authorization
// Requests to did.md with this DID (JAR/RFC 9101, client_id_scheme=did)
// instead of a DCR client_id/secret -- see registration() and
// redirectToWallet() below. Published at
// https://t.biset.md/.well-known/did.jsonl (created once via
// ~/did.md/scripts/create-rp-did.ts; the corresponding private key lives
// only in biset-rp-signer's own secret storage, never in this bundle).
// A file:// build has no fixed origin to bind a DID to (§0.1bis) and stays
// on the DCR path unconditionally, forever.
const RP_DID = 'did:webvh:QmaQdf3VFoXtk7WjfP2rhmKAvMNinLh4qU1bjZ4mPDzVr6:t.biset.md'
const RP_SIGNER_URL = 'https://t.biset.md/api/rp-signer/sign'
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

type FileWalletPopup = {
  popup: Window
  timer: number
  reject: (reason?: unknown) => void
  client: DidMdRegistration
  pending: DidMdPendingAuthorization
  polling: boolean
}

let fileWalletPopup: FileWalletPopup | undefined

function finishFileWalletPopup(active: FileWalletPopup, value: Record<string, unknown>) {
  if (value.state !== active.pending.state || value.iss !== active.client.issuer) return
  window.clearInterval(active.timer)
  if (fileWalletPopup === active) fileWalletPopup = undefined
  active.popup.close()
  const callback = new URL(redirectUri())
  // PLAN7: vp_token/id_token replace code -- did.md posts these straight to
  // window.opener (this popup's whole point: Safari severs window.opener
  // for a file:// popup in some cases, so did.md's message here is the only
  // channel; see pollFileWalletCallback's relay for when even that fails).
  // Carried via this document's own query string (never any server, so the
  // fragment-vs-query distinction that matters for the https path doesn't
  // apply here).
  for (const name of ['vp_token', 'id_token', 'state', 'iss', 'error', 'error_description']) {
    if (typeof value[name] === 'string') callback.searchParams.set(name, value[name] as string)
  }
  // The local document, rather than an HTTPS page, performs this file://
  // navigation. Chromium therefore does not reject an HTTPS-to-file hop.
  location.assign(callback.toString())
}

async function pollFileWalletCallback(active: FileWalletPopup) {
  if (active.polling || fileWalletPopup !== active) return
  active.polling = true
  try {
    const endpoint = new URL('/v1/oauth/file-callback', active.client.issuer)
    endpoint.searchParams.set('client_id', active.pending.clientId)
    endpoint.searchParams.set('state', active.pending.state)
    const response = await fetch(endpoint, { cache: 'no-store' })
    if (response.status === 204) return
    if (!response.ok) throw new Error(`did.md file callback relay failed (${response.status})`)
    const value = asObject(await response.json(), 'did.md file callback relay')
    finishFileWalletPopup(active, value)
  } catch (error) {
    // The relay is a Safari fallback; transient network errors must not turn
    // an already-open Wallet approval into a failed authorization.
    console.warn('did.md Wallet file callback relay polling failed', error)
  } finally {
    active.polling = false
  }
}

if (typeof window !== 'undefined') {
  window.addEventListener('message', event => {
    const active = fileWalletPopup
    const value = event.data as Record<string, unknown> | undefined
    // The expected popup origin is derived from THIS popup's own
    // discovered authorization_endpoint (see registration()/metadata()),
    // not a fixed dito origin -- any wallet directory entry's popup is
    // validated against its own endpoint, never another wallet's.
    const expectedOrigin = new URL(active?.client.authorizationEndpoint ?? 'about:blank').origin
    if (!active || event.origin !== expectedOrigin || event.source !== active.popup
      || value?.type !== 'did.md/oauth-file-callback' || value.protocol !== 1
      || typeof value.state !== 'string' || typeof value.iss !== 'string') return
    finishFileWalletPopup(active, value)
  })
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

type Metadata = {
  issuer: string
  authorization_endpoint: string
  token_endpoint: string
  registration_endpoint: string
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
  if (value.kty !== 'EC' || value.crv !== 'P-256' || typeof value.x !== 'string' || typeof value.y !== 'string') throw new Error('The browser returned an invalid DPoP public key')
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

/** Validates an onion counterpart URL (PLAN-tor.md D-4). Syntactic only --
 * unlike `mediatorUrl`, never fetched, so a browser with no Tor path never
 * issues a `.onion` lookup just to configure a DID Document (I-3). */
function validatedMediatorOnionUrl(value: string): string {
  let url: URL
  try { url = new URL(value) } catch { throw new Error('Biset DIDComm mediator Tor URL is invalid') }
  if ((url.protocol !== 'https:' && url.protocol !== 'http:') || url.username || url.password || url.search || url.hash || !isOnionUrl(url.toString())) {
    throw new Error('Biset DIDComm mediator Tor URL is invalid')
  }
  return url.toString()
}

async function bisetMediatorFor(values: readonly string[], onionValues: readonly string[] = []): Promise<DidMdBisetMediator | undefined> {
  const index = values.findIndex(value => typeof value === 'string' && value.trim())
  if (index === -1) return undefined
  let url: URL
  try { url = new URL(values[index]!) } catch { throw new Error('Biset DIDComm mediator URL is invalid') }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) throw new Error('Biset DIDComm mediator URL is invalid')
  const mediatorUrl = url.toString()
  const info = await fetchMediatorInfo(mediatorUrl)
  // Named by its did:web, or by its did:peer (a mediator that is not at an https URL): either is a DID a document can name.
  if (!info.xKid || !(info.did.startsWith('did:web:') || info.did.startsWith('did:peer:'))) throw new Error('Biset DIDComm mediator did not provide a valid routing key')
  const onionCandidate = onionValues[index]
  const mediatorOnionUrl = onionCandidate && onionCandidate.trim() ? validatedMediatorOnionUrl(onionCandidate) : undefined
  return { mediatorUrl, routingKid: info.xKid, mediatorDid: info.did, ...(mediatorOnionUrl ? { mediatorOnionUrl } : {}) }
}

/** Generates and seals the DIDComm device's own material -- none of it
 * (the X25519 leaf, the mediator inbox-label secret) is bound to
 * this identity's did:webvh, so none of it needs the DID known yet. Only
 * `xKid` (did:webvh + fragment) does; see withDidCommXKid. */
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
export const ROTATION_SEED_CANDIDATE = 'relationship-seed-candidate'

interface RotationCandidate { sealed: DidMdSealedSecret; method: ReturnType<typeof rotationKeyEditMethod> }

/** A fresh relationship seed, offered to the Wallet by its rotation key
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
  if (location.protocol === 'file:') {
    const callback = new URL(location.href)
    callback.search = ''
    callback.hash = ''
    return callback.toString()
  }
  return `${location.origin}${CALLBACK_PATH}`
}

function isWalletCallback(): boolean {
  if (location.pathname === CALLBACK_PATH) return true
  // A packaged file:// build cannot navigate to an origin-root callback
  // route. Wallet therefore returns to the same local HTML file with the
  // OAuth parameters appended.
  return location.protocol === 'file:' && new URL(location.href).searchParams.has('state')
}

async function metadataFor(issuer: string): Promise<Metadata> {
  const response = await fetch(`${issuer}/.well-known/oauth-authorization-server`, { cache: 'no-store' })
  if (!response.ok) throw new Error(`did.md authorization-server discovery failed (${response.status})`)
  const value = asObject(await response.json(), 'authorization-server metadata')
  if (value.issuer !== issuer || typeof value.authorization_endpoint !== 'string' || typeof value.token_endpoint !== 'string' || typeof value.registration_endpoint !== 'string') throw new Error('did.md authorization-server metadata is invalid')
  for (const endpoint of [value.authorization_endpoint, value.token_endpoint, value.registration_endpoint]) {
    const parsed = new URL(endpoint)
    if (parsed.protocol !== 'https:') throw new Error('did.md authorization-server metadata contains a non-HTTPS endpoint')
  }
  return value as Metadata
}
async function metadata(): Promise<Metadata> {
  return metadataFor(selectedWallet.issuer)
}

// Wallet discovery from a did:webvh suffix the user types (rather than
// picking from WALLET_DIRECTORY): resolve that identity's own DID document,
// read its "UDIWalletIssuer" service entry (published by
// ~/did.md/client/did-webvh.ts's buildGenesis, the same pattern atproto uses
// for #atproto_pds/AtprotoPersonalDataServer PDS discovery), then run the
// ordinary OAuth-authorization-server discovery against that issuer. No new
// registry or protocol -- just the did:webvh resolution biset already does,
// applied to wallet discovery instead of identity/data hosting.
export async function resolveWalletFromSuffix(suffix: string): Promise<WalletDirectoryEntry> {
  const domain = suffix.trim().toLowerCase()
  if (!/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain)) throw new Error('Enter a domain, e.g. alice.did.md.')
  const document = await resolveByDomain(domain)
  if (!document) throw new Error(`${domain} has no did:webvh identity.`)
  const service = Array.isArray(document.service) ? document.service : []
  const entry = service.find(candidate => candidate?.type === 'UDIWalletIssuer' && typeof candidate.serviceEndpoint === 'string')
  if (!entry || typeof entry.serviceEndpoint !== 'string') throw new Error(`${domain} does not publish a wallet.`)
  const issuer = entry.serviceEndpoint
  if (new URL(issuer).protocol !== 'https:') throw new Error(`${domain}'s wallet issuer is invalid.`)
  await metadataFor(issuer) // fails loudly if this issuer cannot actually be discovered
  return { id: `suffix:${domain}`, displayName: domain, issuer, handleSuffix: `.${domain}` }
}

function registrationIsUsable(value: DidMdRegistration | undefined, discovered: Metadata): value is DidMdRegistration {
  return !!value && value.v === 2 && value.issuer === selectedWallet.issuer
    && value.authorizationEndpoint === discovered.authorization_endpoint
    && value.tokenEndpoint === discovered.token_endpoint
    && value.registrationEndpoint === discovered.registration_endpoint
    && /^client_[A-Za-z0-9_-]{32,128}$/.test(value.clientId)
    && typeof value.registrationAccessToken === 'string' && value.registrationAccessToken.length >= 32
    && value.redirectUri === redirectUri()
}

async function registration(walletDeviceName = 'Biset'): Promise<DidMdRegistration> {
  const discovered = await metadata()
  // PLAN6 §0.1bis: JAR mode needs no DCR round trip at all -- RP_DID is a
  // fixed constant, so there is nothing to register or cache. Only applies
  // when biset itself runs at a fixed https origin (see RP_DID's comment).
  if (location.protocol !== 'file:') {
    return {
      v: 2, issuer: discovered.issuer, authorizationEndpoint: discovered.authorization_endpoint,
      tokenEndpoint: discovered.token_endpoint, refreshEndpoint: `${selectedWallet.issuer}/v1/oauth/device-refresh`,
      registrationEndpoint: discovered.registration_endpoint, clientId: RP_DID,
      registrationAccessToken: '', redirectUri: redirectUri(),
    }
  }
  const existing = await readDidMdRegistration()
  if (registrationIsUsable(existing, discovered)) {
    const response = await fetch(`${selectedWallet.issuer}/v1/oauth/register/${encodeURIComponent(existing.clientId)}`, {
      headers: { authorization: `Bearer ${existing.registrationAccessToken}` }, cache: 'no-store',
    })
    if (response.ok) {
      const value = asObject(await response.json(), 'client registration configuration')
      if (value.client_id === existing.clientId
        && Array.isArray(value.redirect_uris) && value.redirect_uris.length === 1 && value.redirect_uris[0] === existing.redirectUri
        && value.scope === REQUESTED_SCOPES.join(' ')
        && value.token_endpoint_auth_method === 'none') return existing
    }
    // A lost/replaced AS database, a manually deleted registration, or a
    // changed local origin is recoverable.  The old capability remains
    // harmless because the AS no longer accepts its client_id.
    await clearDidMdRegistration()
  }
  const response = await fetch(discovered.registration_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      client_name: walletDeviceName, application_type: 'web', redirect_uris: [redirectUri()],
      grant_types: ['authorization_code'], response_types: ['code'], token_endpoint_auth_method: 'none',
      scope: REQUESTED_SCOPES.join(' '),
    }),
  })
  if (!response.ok) throw new Error(await response.text())
  const value = asObject(await response.json(), 'client registration response')
  if (!/^client_[A-Za-z0-9_-]{32,128}$/.test(String(value.client_id ?? '')) || typeof value.registration_access_token !== 'string' || value.registration_access_token.length < 32 || value.registration_client_uri !== `${selectedWallet.issuer}/v1/oauth/register/${encodeURIComponent(String(value.client_id))}`) throw new Error('did.md client registration response is invalid')
  const result: DidMdRegistration = {
    v: 2, issuer: discovered.issuer, authorizationEndpoint: discovered.authorization_endpoint,
    tokenEndpoint: discovered.token_endpoint, refreshEndpoint: `${selectedWallet.issuer}/v1/oauth/device-refresh`,
    registrationEndpoint: discovered.registration_endpoint, clientId: String(value.client_id),
    registrationAccessToken: value.registration_access_token, redirectUri: redirectUri(),
  }
  await saveDidMdRegistration(result)
  return result
}

async function createDpop(privateKey: CryptoKey, publicJwk: JsonWebKey, method: string, url: string, nonce?: string): Promise<string> {
  const header = { typ: 'dpop+jwt', alg: 'ES256', jwk: p256PublicJwk(publicJwk) }
  const payload = { jti: randomBase64url(24), htm: method, htu: url, iat: Math.floor(Date.now() / 1000), ...(nonce ? { nonce } : {}) }
  const input = `${base64url(encoder.encode(JSON.stringify(header)))}.${base64url(encoder.encode(JSON.stringify(payload)))}`
  const signature = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, encoder.encode(input)))
  return `${input}.${base64url(signature)}`
}

/** did.md's Root key: the identity's own authentication key, `#pass-1`. */
const ROOT_KEY_FRAGMENT = '#pass-1'

export async function rootAuthority(handle: string, document: Awaited<ReturnType<typeof resolveByDomain>>) {
  if (!document) throw new Error(`No DID was found for ${handle}`)
  const parts = parseWebvhDid(document.id)
  if (parts.domain !== handle || parts.pathSegments.length || parts.port !== undefined) throw new Error('Resolved DID does not match the requested did.md hostname')
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
  const parts = parseWebvhDid(did)
  const handle = didMdHandle(parts.domain)
  const resolved = await resolveByDomain(handle, undefined, { cache: 'no-store' })
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

// PLAN7 (~/did.md/PLAN7-pure-siopv2-direct-delivery.md): did.md delivers
// vp_token/id_token straight to this RP -- fragment (https) or postMessage
// (file://), see completeDidMdWalletCallback -- with no api.did.md call in
// between. `did` comes from the capability VC's own `issuer` (there is no
// token-endpoint `sub` claim anymore); everything from here on is exactly
// the independent verification this module always did (resolvedPending
// resolves the DID itself, capabilityFromResponse verifies the Data
// Integrity Proof against that resolved key) -- unrelated to, and
// unweakened by, removing the code+token round trip.
async function sessionFromVpToken(vpToken: unknown, did: string, pending: DidMdPendingAuthorization): Promise<DidMdActiveSession> {
  // The OID4VP DCQL response envelope -- { "<query_id>": [<credential>] } --
  // same fixed query id did.md's server has always used (CAPABILITY_DCQL_QUERY_ID
  // in server/oauth-server.ts); this RP requests exactly one capability
  // credential, so unwrapping it here is the RP-side mirror of that
  // server-side convention.
  const envelope = asObject(vpToken, 'vp_token')
  const credentials = envelope.capability
  if (!Array.isArray(credentials) || credentials.length !== 1) throw new Error('vp_token must contain exactly one capability credential')
  return sessionFromCapabilityValue(credentials[0], did, pending)
}

// Shared tail of sessionFromVpToken and restoreDidMdWalletSession: both end
// up with a single bare capability VC (`value`) and the DID it claims to be
// issued by, just packaged differently -- the direct-delivery vp_token
// wraps it in a DCQL envelope (PLAN7), while device-refresh's response body
// (unchanged by PLAN7, see restoreDidMdWalletSession) carries it flat as
// `vp_token`. This is where they reconverge.
async function sessionFromCapabilityValue(value: unknown, did: string, pending: DidMdPendingAuthorization): Promise<DidMdActiveSession> {
  const resolvedPending = await resolvedPendingAuthorization(pending, did)
  const capability = await capabilityFromResponse(value, resolvedPending)
  const resolved = await resolveByDomain(parseWebvhDid(resolvedPending.did).domain, undefined, undefined, freshFetch())
  if (!resolved) throw new Error('Could not resolve the DID document after Wallet approval')
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
    v: 2, issuer: resolvedPending.issuer, clientId: resolvedPending.clientId, did: resolvedPending.did, handle: resolvedPending.handle,
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
  if (capability.didCommDevice) await setMediatorRegistration(resolvedPending.did, capability.didCommDevice, 'add')
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
    v: 2, issuer: session.issuer, clientId: session.clientId, state: '', codeVerifier: '', did: session.did,
    handle: session.handle, verificationMethod: session.verificationMethod, rootPublicKey: session.rootPublicKey,
    deviceJkt: session.deviceJkt, privateKey: session.privateKey, publicJwk: session.publicJwk,
    vaultDeviceId: session.vaultDeviceId ?? (() => { throw new Error('This did.md Wallet session predates this Biset version; connect it again.') })(),
    documentEdit: storedEdit as DidCoreDocumentEdit ?? { type: DID_DOCUMENT_EDIT_DETAIL, services: [], verificationMethods: [], remove: [] },
    ...(session.bisetDidCommDevice ? { bisetDidCommDevice: session.bisetDidCommDevice } : {}),
    createdAt: '',
  }
}

async function redirectToWallet(client: DidMdRegistration, pending: DidMdPendingAuthorization, openedPopup?: Window): Promise<never> {
  await saveDidMdPendingAuthorization(pending)
  const request = new URL(client.authorizationEndpoint)
  // RFC 9396 details are optional: a plain sign-in asks for none, and the
  // parameter is left out rather than sent empty.
  const authorizationDetails = pending.documentEdit ? JSON.stringify([pending.documentEdit]) : undefined
  if (client.clientId === RP_DID) {
    // PLAN6: a JAR (RFC 9101) Authorization Request signed by biset's own
    // RP DID key, obtained from biset-rp-signer (which holds that key;
    // this bundle never does). redirect_uri/client_id/response_type are
    // fixed server-side by the signer itself and not sent here (§0.1bis).
    // No "capability_type"/"alias" fields: the JAR path expresses the
    // requested capability *document* entirely through dcql_query (§0.4).
    // scope is independent of that -- it is what the resulting id_token/
    // access token are good for (e.g. "openid" gates id_token issuance),
    // so it is still sent explicitly, same as the flat-query flow. The
    // one-shot Alias-toggle UI hint has no JAR equivalent yet (a known,
    // accepted gap for this first rollout -- see PLAN6's phase 2 notes).
    const signed = await fetch(RP_SIGNER_URL, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        state: pending.state,
        ...(pending.handle !== undefined ? { login_hint: pending.handle } : {}),
        ...(pending.deviceJkt !== undefined ? { dpop_jkt: pending.deviceJkt } : {}),
        scope: REQUESTED_SCOPES.join(' '),
        ...(authorizationDetails ? { authorization_details: authorizationDetails } : {}),
        dcql_query: { credentials: [{ id: 'capability', format: 'vc+di', meta: { type_values: [['VerifiableCredential', CAPABILITY_TYPE]] } }] },
      }),
    })
    if (!signed.ok) throw new Error(`biset-rp-signer request failed: ${signed.status} ${await signed.text()}`)
    const { jwt } = asObject(await signed.json(), 'biset-rp-signer response') as { jwt: unknown }
    if (typeof jwt !== 'string') throw new Error('biset-rp-signer response is invalid')
    request.search = new URLSearchParams({ client_id: RP_DID, response_type: 'vp_token id_token', request: jwt }).toString()
  } else {
    // PLAN7 (~/did.md/PLAN7-pure-siopv2-direct-delivery.md): no `code`, no
    // PKCE (nothing to protect from interception once the response is
    // delivered directly -- see completeDidMdWalletCallback). did.md
    // delivers the signed capability/id_token straight to redirectUri, by
    // URL fragment (https) or postMessage (file://); no api.did.md call
    // happens in between.
    const params = new URLSearchParams({
      client_id: pending.clientId, redirect_uri: client.redirectUri, response_type: 'vp_token id_token', state: pending.state,
      ...(pending.handle !== undefined ? { login_hint: pending.handle } : {}),
      dpop_jkt: pending.deviceJkt, scope: REQUESTED_SCOPES.join(' '),
      // Biset owns this capability type's shape (see did.md's
      // PLAN2-capability-ownership.md) -- the Wallet no longer decides it.
      // A did.md Wallet that predates this parameter falls back to its own
      // "did.md/DeviceCapability" default, which is why the check below still
      // accepts that legacy value too during the transition.
      capability_type: CAPABILITY_TYPE,
      // A one-shot UI hint only (dispo ignores it once an identity already
      // exists in that tab, e.g. every finalize/edit round after login): asks
      // the did.md Wallet creation screen to start with its Alias toggle on,
      // since a biset user is expected to want a memorable did.md hostname
      // rather than the default SCID-derived one. Presence-only -- the value
      // is never read.
      alias: '',
      ...(authorizationDetails ? { authorization_details: authorizationDetails } : {}),
    })
    request.search = params.toString()
  }
  if (location.protocol === 'file:') {
    // Safari only permits opening a window in the original click handler.
    // account-create reserves it before the asynchronous DID verification;
    // navigate that same harmless about:blank window once the URL is ready.
    const popup = openedPopup ?? window.open('', 'did-md-wallet')
    if (!popup) throw new Error('Allow popups to continue with did.md Wallet from a packaged Biset file')
    popup.location.replace(request.toString())
    return await new Promise<never>((_resolve, reject) => {
      const timer = window.setInterval(() => {
        const active = fileWalletPopup
        if (active?.popup === popup) void pollFileWalletCallback(active)
        if (!popup.closed) return
        window.clearInterval(timer)
        if (fileWalletPopup?.popup === popup) fileWalletPopup = undefined
        void rollbackPendingMediator(pending).finally(() => reject(new Error('did.md Wallet popup was closed before authorization completed')))
      }, 500)
      const active: FileWalletPopup = { popup, timer, reject, client, pending, polling: false }
      fileWalletPopup = active
      void pollFileWalletCallback(active)
    })
  }
  location.assign(request.toString())
  // Navigation is asynchronous: the page keeps running until it unloads, so
  // throwing here at once showed a "did not navigate" error right before the
  // wallet opened. Wait for the unload; only a navigation that never
  // happens (blocked, say) is an error.
  return await new Promise<never>((_resolve, reject) => {
    window.setTimeout(() => reject(new Error('The browser did not navigate to did.md Wallet')), 10_000)
  })
}

/**
 * Removes every other device of this identity in one Wallet approval: the
 * DID document edit drops their keyAgreement keys, which is the one place
 * the rest of the system learns who this identity's devices are (a mediator
 * revokes their inboxes on the next log it is handed; a sender stops
 * encrypting to them, and Vault Sync stops reaching them). Every message
 * goes to the keys the DID document lists, so nothing else needs to move.
 */
export async function beginDidMdRemoveOtherDevices(configured: DidMdWalletConfiguration = {}): Promise<never> {
  const config = walletConfiguration(configured)
  const session = await readDidMdDeviceSession()
  if (!session?.vaultDeviceId || !session.bisetDidCommDevice || session.v !== 2 || Date.parse(session.capabilityExpiresAt) <= Date.now()) {
    throw new Error('Reconnect did.md Wallet before removing other devices')
  }
  // Read past the host's CDN (`freshFetch`): a stale copy would leave a recently added device out of the removal.
  const resolved = await resolveByDomain(parseWebvhDid(session.did).domain, undefined, undefined, freshFetch())
  if (!resolved || resolved.id !== session.did) throw new Error('Could not resolve the current DID document before removing other devices')
  const ownKid = session.bisetDidCommDevice.xKid
  const remove = (resolved.verificationMethod ?? []).flatMap(method => {
    try {
      const key = decodeX25519Multikey(method.publicKeyMultibase)
      const fragment = method.id.startsWith('#') ? method.id : method.id.slice(session.did.length)
      const kid = `${session.did}${fragment}`
      if (fragment !== deviceKidFragment(key) || kid === ownKid) return []
      return [method.id]
    } catch { return [] }
  })
  if (remove.length === 0) throw new Error('There are no other devices to remove')
  const client = await registration(config.walletDeviceName)
  const pending = pendingFromSession(session)
  pending.state = randomBase64url(32); pending.codeVerifier = randomBase64url(48); pending.createdAt = new Date().toISOString()
  // The removed devices hold the current seed: the same edit publishes a new
  // one's rotation key in its place (PLAN-refactor.md §4.5).
  const rotation = await rotationCandidate('replace')
  pending.rotationSeedCandidate = rotation.sealed
  pending.documentEdit = buildDocumentEdit(session.did, config, session.bisetDidCommDevice, remove, [], rotation.method)
  return redirectToWallet(client, pending)
}

/**
 * Publishes a fresh relationship seed's rotation key in place of the current
 * one, in one Wallet approval: for an identity that has none yet, one whose
 * seed no device has any more, or one whose seed a device removed from the
 * Wallet itself still holds (relationship-seed-bootstrap.ts's "unpublished",
 * "lost" and "stale").
 */
export async function beginDidMdRotationKeyRenewal(configured: DidMdWalletConfiguration = {}): Promise<never> {
  const config = walletConfiguration(configured)
  const session = await readDidMdDeviceSession()
  if (!session?.vaultDeviceId || !session.bisetDidCommDevice || session.v !== 2 || Date.parse(session.capabilityExpiresAt) <= Date.now()) {
    throw new Error('Reconnect did.md Wallet before renewing the key')
  }
  const client = await registration(config.walletDeviceName)
  const pending = pendingFromSession(session)
  pending.state = randomBase64url(32); pending.codeVerifier = randomBase64url(48); pending.createdAt = new Date().toISOString()
  const rotation = await rotationCandidate('replace')
  pending.rotationSeedCandidate = rotation.sealed
  // Only the rotation key: no service or device key changes.
  pending.documentEdit = { type: DID_DOCUMENT_EDIT_DETAIL, services: [], verificationMethods: [{ ...rotation.method, controller: session.did }], remove: [] }
  return redirectToWallet(client, pending)
}

/** The only round trip needed to sign in: no DID is resolved and no
 * document edit is requested up front, so this never needs to know which
 * did.md handle the user has open in Wallet beforehand (no login_hint). The
 * signer's DID and DIDComm mediator enrollment are both
 * resolved/deferred to after Wallet approves -- see `tokenFrom` for DID
 * derivation and `beginDidMdWalletFinalizeEnrollment` for the follow-up
 * step the user triggers explicitly from Biset's own UI. */
/** The only round trip needed to sign in and, when a mediator is configured
 * and reachable, publish a DIDComm device. No DID is resolved up front
 * (no login_hint). The DIDComm device's own
 * material -- the X25519 leaf, its mediator inbox-label secret, even
 * the document edit's verification method (a fragment-only id; its
 * `controller` is ignored and overwritten by Wallet regardless) -- turns
 * out not to need the DID either, only `xKid` (did:webvh + fragment) does.
 * prepareBisetDidCommDevice builds everything else now; withDidCommXKid
 * fills in `xKid` once the token response reveals the DID, the same
 * resolve-after-response pattern resolvedPendingAuthorization already uses
 * for did/handle/verificationMethod/rootPublicKey.
 *
 * Best-effort: a mediator that's unconfigured or unreachable right now
 * just means no DIDComm device this round -- it must never block sign-in
 * itself. beginDidMdWalletFinalizeEnrollment remains for that case, and for
 * enabling messaging after the fact. */
export async function beginDidMdWalletLogin(mediatorUrls: readonly string[] = [], openedPopup?: Window, configured: DidMdWalletConfiguration = {}): Promise<never> {
  const config = walletConfiguration(configured)
  const client = await registration(config.walletDeviceName)
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
    v: 2, issuer: client.issuer, clientId: client.clientId, state: randomBase64url(32), codeVerifier: randomBase64url(48),
    deviceJkt: await p256Jkt(publicJwk), privateKey: pair.privateKey, publicJwk, vaultDeviceId: `urn:uuid:${crypto.randomUUID()}`,
    documentEdit: buildDocumentEdit('', config, bisetDidCommDevice, [], [], rotation?.method),
    ...(bisetDidCommDevice ? { bisetDidCommDevice } : {}),
    ...(rotation ? { rotationSeedCandidate: rotation.sealed } : {}),
    createdAt: new Date().toISOString(),
  }
  return redirectToWallet(client, pending, openedPopup)
}

/** The explicit, user-triggered follow-up ("Connect to MIMI/mediator" in
 * Biset's UI) that publishes the DIDComm mediator device for an already
 * signed-in session, via a second Wallet approval -- for a session that
 * signed in before a mediator was configured, or whose mediator wasn't
 * reachable during beginDidMdWalletLogin above. */
export async function beginDidMdWalletFinalizeEnrollment(mediatorUrls: readonly string[] = [], configured: DidMdWalletConfiguration = {}): Promise<never> {
  const config = walletConfiguration(configured)
  const session = await readDidMdDeviceSession()
  if (!session?.vaultDeviceId || session.v !== 2 || session.issuer !== selectedWallet.issuer || Date.parse(session.capabilityExpiresAt) <= Date.now()) {
    throw new Error('Connect did.md Wallet again before finishing setup on this browser')
  }
  const client = await registration()
  if (client.clientId !== session.clientId || client.redirectUri !== redirectUri()) throw new Error('The did.md Wallet client registration changed; reconnect this browser')
  const mediator = await bisetMediatorFor(mediatorUrls)
  if (!mediator) throw new Error('Biset DIDComm mediator is not configured')
  const bisetDidCommDevice = await newBisetDidCommDevice(session.did, mediator)
  // A retry of this same follow-up (the user hitting "Enable messaging"
  // again, or a stale reachability check re-triggering it) must not leave
  // the previous round's device published alongside the new one -- an
  // orphaned #didcomm verification method a sibling still tries to send to,
  // which the mediator then refuses with e.m.req.not-enrolled since nothing
  // ever registered it (found live, 2026-09-15).
  const previous = session.bisetDidCommDevice?.xKid
  const pending: DidMdPendingAuthorization = {
    ...pendingFromSession(session),
    state: randomBase64url(32),
    codeVerifier: randomBase64url(48),
    createdAt: new Date().toISOString(),
    bisetDidCommDevice,
    ...(session.bisetDidCommDevice ? { previousBisetDidCommDevice: session.bisetDidCommDevice } : {}),
  }
  const rotation = await rotationCandidate('ifAbsent')
  pending.rotationSeedCandidate = rotation.sealed
  pending.documentEdit = buildDocumentEdit(session.did, config, bisetDidCommDevice, previous ? [previous] : [], [], rotation.method)
  return redirectToWallet(client, pending)
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

export async function beginDidMdWalletDocumentEdit(options: { mediatorUrls?: readonly string[]; mediatorOnionUrls?: readonly string[]; removeMediator?: boolean; configuration?: DidMdWalletConfiguration }): Promise<never> {
  const config = walletConfiguration(options.configuration)
  const session = await readDidMdDeviceSession()
  if (!session?.vaultDeviceId || session.v !== 2 || Date.parse(session.capabilityExpiresAt) <= Date.now()) throw new Error('Reconnect did.md Wallet before editing the DID document')
  const client = await registration()
  const pending = pendingFromSession(session)
  pending.state = randomBase64url(32); pending.codeVerifier = randomBase64url(48); pending.createdAt = new Date().toISOString()
  if (options.removeMediator) {
    if (session.bisetDidCommDevice) pending.previousBisetDidCommDevice = session.bisetDidCommDevice
    const didcomm = configuredService(config, 'didcomm')
    pending.documentEdit = buildDocumentEdit(session.did, config, undefined, [didcomm.id, ...(didcomm.previousIds ?? []), ...(session.bisetDidCommDevice ? [session.bisetDidCommDevice.xKid] : [])])
    delete pending.bisetDidCommDevice
  } else {
    const mediator = await bisetMediatorFor(options.mediatorUrls ?? [], options.mediatorOnionUrls ?? [])
    if (!mediator) throw new Error('Biset DIDComm mediator is not configured')
    const previous = session.bisetDidCommDevice?.xKid
    if (session.bisetDidCommDevice) pending.previousBisetDidCommDevice = session.bisetDidCommDevice
    pending.bisetDidCommDevice = await newBisetDidCommDevice(session.did, mediator)
    const retired = retiredMediatorEndpoints(session.bisetDidCommDevice, mediator, configuredService(config, 'didcomm').id)
    const rotation = await rotationCandidate('ifAbsent')
    pending.rotationSeedCandidate = rotation.sealed
    pending.documentEdit = buildDocumentEdit(session.did, config, pending.bisetDidCommDevice, previous ? [previous] : [], retired, rotation.method)
  }
  return redirectToWallet(client, pending)
}

/** The relationship seed whose rotation key a Wallet approval published for
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

export async function completeDidMdWalletCallback(): Promise<DidMdActiveSession | undefined> {
  if (!isWalletCallback()) return undefined
  const callback = new URL(location.href)
  const pending = await readDidMdPendingAuthorization()
  if (!pending || pending.v !== 2 || pending.issuer !== selectedWallet.issuer) throw new Error('No matching did.md Wallet authorization is pending')
  // PLAN7: did.md delivers vp_token/id_token directly -- by URL fragment on
  // the https path (never sent to any server, unlike a query string), or
  // via the query string of this same local document on the file:// path
  // (finishFileWalletPopup's own re-navigation; there is no server on that
  // path either way, see its own comment). Try the fragment first since a
  // fragment and a query string can coexist on the same URL.
  const params = callback.hash ? new URLSearchParams(callback.hash.slice(1)) : callback.searchParams
  const state = params.get('state')
  const issuer = params.get('iss')
  const vpToken = params.get('vp_token')
  const error = params.get('error')
  if (state !== pending.state || issuer !== pending.issuer) { await rollbackPendingMediator(pending); await clearDidMdPendingAuthorization(); throw new Error('did.md Wallet callback state or issuer did not match') }
  if (error) { await rollbackPendingMediator(pending); await clearDidMdPendingAuthorization(); throw new Error(params.get('error_description') ?? `did.md Wallet authorization failed: ${error}`) }
  if (!vpToken) { await rollbackPendingMediator(pending); await clearDidMdPendingAuthorization(); throw new Error('did.md Wallet callback has no vp_token') }
  const client = await registration()
  if (client.clientId !== pending.clientId || client.redirectUri !== redirectUri()) { await clearDidMdPendingAuthorization(); throw new Error('did.md Wallet client registration changed during authorization') }
  try {
    // id_token is intentionally not read from params: this module has
    // never derived anything from it (did/handle come from the capability
    // VC's own issuer, verified independently below) -- see
    // sessionFromVpToken's own comment.
    let parsedVpToken: unknown
    try { parsedVpToken = JSON.parse(vpToken) } catch { throw new Error('did.md Wallet callback vp_token is invalid') }
    const credentials = asObject(parsedVpToken, 'vp_token').capability
    const issuerDid = Array.isArray(credentials) && credentials.length === 1 ? asObject(credentials[0], 'capability credential').issuer : undefined
    if (typeof issuerDid !== 'string') throw new Error('did.md Wallet callback vp_token is invalid')
    const active = await sessionFromVpToken(parsedVpToken, issuerDid, pending)
    // Chromium assigns each file: URL a unique opaque origin and rejects
    // history.replaceState even when only the query string changes. A
    // top-level replacement is allowed and also prevents replay on reload.
    if (location.protocol === 'file:') {
      if (typeof sessionStorage !== 'undefined') sessionStorage.setItem(DID_MD_JUST_CONNECTED_KEY, '1')
      location.replace(redirectUri())
    }
    else history.replaceState(null, '', '/')
    return active
  } catch (error) {
    await rollbackPendingMediator(pending)
    throw error
  } finally { await clearDidMdPendingAuthorization() }
}

export async function restoreDidMdWalletSession(): Promise<DidMdActiveSession | undefined> {
  const session = await readDidMdDeviceSession()
  if (!session || session.v !== 2 || session.issuer !== selectedWallet.issuer || Date.parse(session.capabilityExpiresAt) <= Date.now()) return undefined
  const client = await registration()
  if (client.clientId !== session.clientId) return undefined
  const pending = pendingFromSession(session)
  const response = await fetch(client.refreshEndpoint, {
    method: 'POST', headers: { 'content-type': 'application/json', dpop: await createDpop(session.privateKey, session.publicJwk, 'POST', client.refreshEndpoint) },
    body: JSON.stringify({ client_id: client.clientId, vp_token: { capability: [session.capability] } }),
  })
  try {
    // device-refresh (server/oauth-server.ts's oauthRefresh/oauthIssueToken)
    // is untouched by PLAN7 -- it still returns the pre-PLAN7 token-response
    // shape (bare vp_token, not the direct-delivery DCQL envelope), so this
    // reads that shape directly instead of going through sessionFromVpToken.
    if (!response.ok) throw new Error('did.md rejected the device refresh request')
    const value = asObject(await response.json(), 'device refresh response')
    if (typeof value.access_token !== 'string' || value.token_type !== 'DPoP' || typeof value.sub !== 'string') throw new Error('did.md returned an invalid device refresh response')
    return await sessionFromCapabilityValue(value.vp_token, value.sub, pending)
  } catch (error) {
    // A stored session that no longer validates (e.g. did.md issued a
    // capability against a stale DID generation) would otherwise fail this
    // exact way on every future load. Drop it so the account page comes up
    // clean and the user is prompted to reconnect, instead of re-raising the
    // same fatal error forever.
    await clearDidMdDeviceSession()
    throw error
  }
}

export async function didMdWalletReconnectState(): Promise<{ did: string; handle: string; capabilityExpiresAt: string; expired: boolean } | undefined> {
  const session = await readDidMdDeviceSession()
  if (!session || session.v !== 2 || session.issuer !== selectedWallet.issuer) return undefined
  return { did: session.did, handle: session.handle, capabilityExpiresAt: session.capabilityExpiresAt, expired: Date.parse(session.capabilityExpiresAt) <= Date.now() }
}

export async function disconnectDidMdWallet(): Promise<void> {
  await Promise.all([clearDidMdPendingAuthorization(), clearDidMdDeviceSession()])
}

/** This browser's identity as a Vault author. */
export async function openDidMdWalletVaultDevice(): Promise<DidMdVaultDevice> {
  const session = await readDidMdDeviceSession()
  if (!session?.vaultDeviceId || session.v !== 2) throw new Error('Connect did.md Wallet again to use this Biset device')
  return { did: session.did, deviceId: session.vaultDeviceId }
}

/** Opens the optional Biset-owned DIDComm leaf. The corresponding public
 * key and mediator route were included in the Root-authenticated Wallet
 * capability and published by Wallet before this session was stored. */
export async function openDidMdWalletBisetDidCommDevice(): Promise<DidMdBisetDidCommDevice | undefined> {
  const session = await readDidMdDeviceSession()
  const stored = session?.bisetDidCommDevice
  if (!session || session.v !== 2 || !stored) return undefined
  const privateMaterial = await openDidMdBisetDidCommDeviceMaterial(stored)
  const derivedPublic = x25519.getPublicKey(privateMaterial.x25519PrivateKey)
  if (!derivedPublic.every((byte, index) => byte === stored.x25519PublicKey[index])) throw new Error('Biset DIDComm private key does not match its Wallet-authorized public key')
  if (stored.xKid !== deviceKid(session.did, derivedPublic)) throw new Error('Biset DIDComm device key identifier is invalid')
  return { did: session.did, xKid: stored.xKid, x25519PrivateKey: privateMaterial.x25519PrivateKey, mediatorDeviceSecret: privateMaterial.mediatorDeviceSecret, mediatorUrl: stored.mediatorUrl, routingKid: stored.routingKid, ...(stored.mediatorOnionUrl ? { mediatorOnionUrl: stored.mediatorOnionUrl } : {}) }
}

