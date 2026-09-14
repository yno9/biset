/**
 * did.md OAuth public-client integration.
 *
 * It persists no Wallet controller material.  During Phase B the Wallet
 * additionally certifies a Biset-generated MLS leaf key; that Biset-only
 * private leaf key and Vault secret remain locally AES-wrapped here.
 */
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { decodeMultikey, encodeMultikey } from '../../../protocol/webvh/multikey.ts'
import { parseWebvhDid } from '../../../protocol/webvh/identifier.ts'
import { verifyProof, type DataIntegrityProof } from '../../../protocol/webvh/proof.ts'
import { fetchCurrentLog } from '../webvh/log-io.ts'
import { resolveByDomain, resolveEntries } from '../../../protocol/webvh/resolver.ts'
import { decodeMlsDeviceCredential, mlsCredentialFromKeyAuthorization, verifyMlsDeviceCredential, verifyMlsDeviceCredentialRoot, type MlsDeviceCredentialV2 } from '../../mls/device-credential.ts'
import { base64urlToBytes } from '../../../protocol/canonical.ts'
import { deviceKid, deviceKidFragment } from '../../../protocol/didcomm/devicekid.ts'
import { encodeX25519Multikey } from '../../../protocol/didcomm/multikey.ts'
import { fetchMediatorInfo, requestMediation, updateKeylist } from '../../../protocol/didcomm/mediator-coordinate.ts'
import { generatePeerIdentity } from '../../../protocol/didcomm/peer.ts'
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
  sealDidMdBisetDeviceMaterial,
  openDidMdBisetDidCommDeviceMaterial,
  openDidMdBisetDeviceMaterial,
  type DidMdBisetDidCommDeviceMaterial,
  type DidMdBisetMimiVaultRoom,
  type DidMdDeviceSession,
  type DidMdPendingAuthorization,
  type DidMdRegistration,
  type DidCoreDocumentEdit,
} from './did-md-store.ts'

const ISSUER = 'https://api.did.md'
const WALLET_ORIGIN = 'https://app.did.md'
const CALLBACK_PATH = '/wallet/callback'
const REQUESTED_SCOPES = ['openid', 'profile', 'biset:login', 'biset:device', 'biset:routing', 'biset:messaging', 'biset:vault']
const DID_DOCUMENT_EDIT_DETAIL = 'urn:did-core:document-edit:v1'
const KEY_AUTHORIZATION_DETAIL = 'urn:did.md:key-authorization:v1'
const DERIVED_SECRET_DETAIL = 'urn:did.md:derived-secret:v1'
// The Wallet-derived (never DID-document-published) MIMI Vault room
// locator: HKDF(Root private key, this purpose + the provider URL as
// context). See client/did-webvh.ts's deriveWalletSecret in the did.md
// repo -- only the Wallet holds the Root key, so only devices signed in
// through the same Wallet mnemonic can ever reproduce this value; an
// outside observer who only knows the (public) DID cannot.
const MIMI_VAULT_ROOM_DERIVED_SECRET_PURPOSE = 'biset:mimi-vault-room:v1'
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
  serviceEndpoint: string | Record<string, unknown>
  previousIds?: string[]
}

// MIMI Vault used to have a template here too, published as a DID Document
// service so a device could discover an existing room before joining. It no
// longer needs to be discoverable at all: every device derives the exact
// same room id from the identity's own Root key (see
// MIMI_VAULT_ROOM_DERIVED_SECRET_PURPOSE above), so there is nothing left to
// publish or resolve.
const defaultDidDocumentServices: DidDocumentServiceTemplate[] = [
  { purpose: 'didcomm', id: '#didcomm', type: 'DIDCommMessaging', serviceEndpoint: { uri: '$mediatorUrl', accept: ['didcomm/v2'], routingKeys: ['$routingKid'] }, previousIds: ['#didcomm-biset'] },
]

function walletConfiguration(value: DidMdWalletConfiguration = {}): WalletConfiguration {
  const walletDeviceName = value.walletDeviceName ?? 'Biset'
  const didDocumentServices = value.didDocumentServices ?? defaultDidDocumentServices
  if (!Array.isArray(didDocumentServices) || !didDocumentServices.length || didDocumentServices.length > 64) throw new Error('DID Document services configuration is invalid')
  const ids = new Set<string>()
  for (const service of didDocumentServices) {
    if (!service || typeof service !== 'object' || !/^#[^\s#]+$/.test(service.id) || !service.type.trim()
      || (typeof service.serviceEndpoint !== 'string' && (!service.serviceEndpoint || typeof service.serviceEndpoint !== 'object' || Array.isArray(service.serviceEndpoint)))
      || ids.has(service.id)) throw new Error('DID Document service configuration is invalid')
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

function materializeServiceEndpoint(value: string | Record<string, unknown>, substitutions: Record<string, string>): string | Record<string, unknown> {
  if (typeof value === 'string') {
    if (value.startsWith('$') && !(value in substitutions)) throw new Error(`Unknown DID Document service placeholder ${value}`)
    return substitutions[value] ?? value
  }
  if (Array.isArray(value)) return value.map(item => materializeServiceEndpoint(item as string | Record<string, unknown>, substitutions)) as unknown as Record<string, unknown>
  const result: Record<string, unknown> = {}
  for (const [key, item] of Object.entries(value)) result[key] = typeof item === 'string' || (item && typeof item === 'object')
    ? materializeServiceEndpoint(item as string | Record<string, unknown>, substitutions)
    : item
  return result
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
  for (const name of ['code', 'state', 'iss', 'error', 'error_description']) {
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
    if (!active || event.origin !== WALLET_ORIGIN || event.source !== active.popup
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
  accessToken: string
  nonce: string
  scope: string[]
  deviceKid?: string
  mimiVaultRoom?: DidMdBisetMimiVaultRoom
  didCommKid?: string
}

export type DidMdBisetDevice = {
  did: string
  /** Public only.  This is required to verify locally persisted Biset
   * capability records; it is never a did.md controller secret. */
  rootPublicKey: Uint8Array
  credential: MlsDeviceCredentialV2
  signaturePrivateKey: Uint8Array
  vaultSecret: Uint8Array
  mimiVaultRoom: DidMdBisetMimiVaultRoom
  mimiVaultRoomCreated: boolean
}

export type DidMdBisetDidCommDevice = {
  did: string
  xKid: string
  x25519PrivateKey: Uint8Array
  mediatorControlDid: string
  mediatorControlKid: string
  mediatorControlPrivateKey: Uint8Array
  mediatorUrl: string
  routingKid: string
}

type DidMdBisetMediator = {
  mediatorUrl: string
  routingKid: string
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

function exactKeys(value: Record<string, unknown>, keys: string[], label: string): void {
  if (Object.keys(value).sort().join(',') !== [...keys].sort().join(',')) throw new Error(`${label} has unexpected fields`)
}

function didMdHandle(value: string): string {
  const handle = value.trim().toLowerCase()
  if (!/^[a-z0-9](?:[a-z0-9-]{0,61})?\.did\.md$/.test(handle)) throw new Error('Enter a did.md hostname, for example test1.did.md')
  return handle
}

/** Validates and canonicalizes the configured MIMI Self/Vault provider URL --
 * used both to build the derived-secret request's `context` (so the room id
 * is bound to a specific provider) and to compute the resulting room URI. */
function normalizedMimiProviderUrl(providerValue: string): URL {
  let provider: URL
  try { provider = new URL(providerValue) } catch { throw new Error('Biset MIMI Self/Vault is not configured') }
  if (provider.protocol !== 'https:' || provider.username || provider.password || provider.search || provider.hash) throw new Error('Biset MIMI Self/Vault URL is invalid')
  return provider
}

/** The room id itself is never published or resolved -- see
 * MIMI_VAULT_ROOM_DERIVED_SECRET_PURPOSE. `value` is the base64url HKDF
 * output Wallet returned for that request (32 bytes, so a 43-character
 * base64url string -- the exact shape `ensureWalletMimiVaultRoom` in
 * biset's bootstrap.ts already expects). */
function mimiVaultRoomFromDerivedSecret(provider: URL, value: string): DidMdBisetMimiVaultRoom {
  if (!/^[A-Za-z0-9_-]{43}$/.test(value)) throw new Error('did.md returned an invalid MIMI Vault room secret')
  return { providerUrl: provider.toString(), roomId: `mimi://${provider.hostname}/r/vault-${value}` }
}

function sameDocumentEdit(value: unknown, expected: DidCoreDocumentEdit): void {
  if (JSON.stringify(value) !== JSON.stringify(expected)) throw new Error('did.md returned a DID document edit different from the one this browser requested')
}

async function bisetMediatorFor(values: readonly string[]): Promise<DidMdBisetMediator | undefined> {
  const configured = values.find(value => typeof value === 'string' && value.trim())
  if (!configured) return undefined
  let url: URL
  try { url = new URL(configured) } catch { throw new Error('Biset DIDComm mediator URL is invalid') }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) throw new Error('Biset DIDComm mediator URL is invalid')
  const mediatorUrl = url.toString()
  const info = await fetchMediatorInfo(mediatorUrl)
  if (!info.xKid || !info.xKid.startsWith('did:peer:')) throw new Error('Biset DIDComm mediator did not provide a valid routing key')
  return { mediatorUrl, routingKid: info.xKid }
}

/** Generates and seals the DIDComm device's own material -- none of it
 * (the X25519 leaf, the did:peer mediator-control identity) is bound to
 * this identity's did:webvh, so none of it needs the DID known yet. Only
 * `xKid` (did:webvh + fragment) does; see withDidCommXKid. */
async function prepareBisetDidCommDevice(mediator: DidMdBisetMediator): Promise<DidMdBisetDidCommDeviceMaterial & { mediatorUrl: string; routingKid: string }> {
  const x25519PrivateKey = x25519.utils.randomSecretKey()
  const x25519PublicKey = x25519.getPublicKey(x25519PrivateKey)
  const control = generatePeerIdentity()
  try {
    const sealed = await sealDidMdBisetDidCommDeviceMaterial(
      x25519PublicKey,
      { did: control.did, kid: control.xKid, publicKey: control.xPub },
      { x25519PrivateKey, mediatorControlPrivateKey: control.xPriv },
    )
    return { ...sealed, mediatorUrl: mediator.mediatorUrl, routingKid: mediator.routingKid }
  } finally {
    x25519PrivateKey.fill(0)
    control.xPriv.fill(0); control.edPriv.fill(0)
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

function buildDocumentEdit(did: string, config: WalletConfiguration, device?: NonNullable<DidMdPendingAuthorization['bisetDidCommDevice']>, remove: string[] = []): DidCoreDocumentEdit {
  const didcomm = configuredService(config, 'didcomm')
  const services = config.didDocumentServices
    .filter(service => service.purpose !== 'didcomm' || device)
    .map(service => ({
      id: service.id,
      type: service.type,
      serviceEndpoint: materializeServiceEndpoint(service.serviceEndpoint, {
        '$mediatorUrl': device?.mediatorUrl ?? '',
        '$routingKid': device?.routingKid ?? '',
      }),
    }))
  return {
    type: DID_DOCUMENT_EDIT_DETAIL,
    services,
    verificationMethods: device ? [{ id: deviceKidFragment(device.x25519PublicKey), type: 'Multikey', controller: did, publicKeyMultibase: encodeX25519Multikey(device.x25519PublicKey) }] : [],
    serviceKeyBindings: device ? [{ serviceId: didcomm.id, keyIds: [deviceKidFragment(device.x25519PublicKey)] }] : [],
    remove,
  }
}

async function setMediatorRegistration(_did: string, device: NonNullable<DidMdPendingAuthorization['bisetDidCommDevice']> & { xKid: string }, action: 'add' | 'remove'): Promise<void> {
  const material = await openDidMdBisetDidCommDeviceMaterial(device)
  try {
    const mediator = await fetchMediatorInfo(device.mediatorUrl)
    if (mediator.xKid !== device.routingKid) throw new Error('Mediator routing key changed during DID document edit')
    const own = { did: device.mediatorControlDid, xKid: device.mediatorControlKid, xPriv: material.mediatorControlPrivateKey }
    if (action === 'add') await requestMediation(mediator, own)
    await updateKeylist(mediator, own, device.xKid, action)
  } finally { material.x25519PrivateKey.fill(0); material.mediatorControlPrivateKey.fill(0) }
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

export function isWalletCallback(): boolean {
  if (location.pathname === CALLBACK_PATH) return true
  // A packaged file:// build cannot navigate to an origin-root callback
  // route. Wallet therefore returns to the same local HTML file with the
  // OAuth parameters appended.
  return location.protocol === 'file:' && new URL(location.href).searchParams.has('state')
}

async function metadata(): Promise<Metadata> {
  const response = await fetch(`${ISSUER}/.well-known/oauth-authorization-server`, { cache: 'no-store' })
  if (!response.ok) throw new Error(`did.md authorization-server discovery failed (${response.status})`)
  const value = asObject(await response.json(), 'authorization-server metadata')
  if (value.issuer !== ISSUER || typeof value.authorization_endpoint !== 'string' || typeof value.token_endpoint !== 'string' || typeof value.registration_endpoint !== 'string') throw new Error('did.md authorization-server metadata is invalid')
  for (const endpoint of [value.authorization_endpoint, value.token_endpoint, value.registration_endpoint]) {
    const parsed = new URL(endpoint)
    if (parsed.protocol !== 'https:') throw new Error('did.md authorization-server metadata contains a non-HTTPS endpoint')
  }
  return value as Metadata
}

function registrationIsUsable(value: DidMdRegistration | undefined, discovered: Metadata): value is DidMdRegistration {
  return !!value && value.v === 2 && value.issuer === ISSUER
    && value.authorizationEndpoint === discovered.authorization_endpoint
    && value.tokenEndpoint === discovered.token_endpoint
    && value.registrationEndpoint === discovered.registration_endpoint
    && /^client_[A-Za-z0-9_-]{32,128}$/.test(value.clientId)
    && typeof value.registrationAccessToken === 'string' && value.registrationAccessToken.length >= 32
    && value.redirectUri === redirectUri()
}

async function registration(walletDeviceName = 'Biset'): Promise<DidMdRegistration> {
  const discovered = await metadata()
  const existing = await readDidMdRegistration()
  if (registrationIsUsable(existing, discovered)) {
    const response = await fetch(`${ISSUER}/v1/oauth/register/${encodeURIComponent(existing.clientId)}`, {
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
  if (!/^client_[A-Za-z0-9_-]{32,128}$/.test(String(value.client_id ?? '')) || typeof value.registration_access_token !== 'string' || value.registration_access_token.length < 32 || value.registration_client_uri !== `${ISSUER}/v1/oauth/register/${encodeURIComponent(String(value.client_id))}`) throw new Error('did.md client registration response is invalid')
  const result: DidMdRegistration = {
    v: 2, issuer: discovered.issuer, authorizationEndpoint: discovered.authorization_endpoint,
    tokenEndpoint: discovered.token_endpoint, refreshEndpoint: `${ISSUER}/v1/oauth/device-refresh`,
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

async function rootAuthority(handle: string, document: Awaited<ReturnType<typeof resolveByDomain>>) {
  if (!document) throw new Error(`No DID was found for ${handle}`)
  const parts = parseWebvhDid(document.id)
  if (parts.domain !== handle || parts.pathSegments.length || parts.port !== undefined) throw new Error('Resolved DID does not match the requested did.md hostname')
  const authRef = document.authentication[0]
  const method = authRef ? document.verificationMethod.find(candidate => candidate.id === authRef || `${document.id}${candidate.id}` === authRef || candidate.id === `${document.id}${authRef}`) : undefined
  if (!authRef || !method) throw new Error('Resolved DID has no Root authentication key')
  const verificationMethod = method.id.startsWith('#') ? `${document.id}${method.id}` : method.id
  return { did: document.id, verificationMethod, rootPublicKey: decodeMultikey(method.publicKeyMultibase) }
}

async function validateBisetMlsCredential(wire: string, pending: ResolvedPendingAuthorization): Promise<MlsDeviceCredentialV2> {
  let credential: MlsDeviceCredentialV2
  try {
    const input = asObject(JSON.parse(new TextDecoder().decode(base64urlToBytes(wire))), 'key authorization credential')
    exactKeys(input, ['type', 'version', 'issuer', 'audience', 'subject', 'generation', 'publicKey', 'purposes', 'issuedAt', 'expiresAt', 'rootSignature', 'signSignature'], 'key authorization credential')
    const key = asObject(input.publicKey, 'authorized public key'); exactKeys(key, ['type', 'publicKeyMultibase'], 'authorized public key')
    if (input.type !== 'did.md/KeyAuthorizationCredential' || input.version !== 1 || input.issuer !== pending.did || input.audience !== pending.clientId
      || input.subject !== pending.keyAuthorizationSubject || key.type !== 'Multikey' || typeof key.publicKeyMultibase !== 'string'
      || !Array.isArray(input.purposes) || input.purposes.length !== 1 || input.purposes[0] !== 'signing'
      || typeof input.generation !== 'string' || typeof input.issuedAt !== 'string' || typeof input.expiresAt !== 'string'
      || typeof input.rootSignature !== 'string' || typeof input.signSignature !== 'string') throw new Error()
    credential = mlsCredentialFromKeyAuthorization({ issuer: input.issuer, audience: input.audience, subject: input.subject,
      generation: input.generation, signaturePublicKey: decodeMultikey(key.publicKeyMultibase), issuedAt: input.issuedAt,
      expiresAt: input.expiresAt, rootSignature: base64urlToBytes(input.rootSignature), signSignature: base64urlToBytes(input.signSignature) })
  } catch { throw new Error('did.md returned an invalid key authorization credential') }
  if (credential.identityId !== pending.did || !credential.signaturePublicKey.every((byte, index) => byte === pending.bisetDevice.signaturePublicKey[index])) {
    throw new Error('did.md returned a Biset MLS credential for another device')
  }
  const current = await fetchCurrentLog(pending.did)
  if (!resolveEntries(pending.did, current.entries)) throw new Error('The published did:webvh log is no longer valid')
  const currentSign = current.last.parameters.updateKeys
  if (!currentSign || currentSign.length !== 1 || credential.generation !== current.last.versionId || !verifyMlsDeviceCredential(credential, decodeMultikey(currentSign[0]!)) || !verifyMlsDeviceCredentialRoot(credential, pending.rootPublicKey)) {
    throw new Error('did.md returned an MLS credential not authorized by the current DID generation — reconnect did.md Wallet')
  }
  return credential
}

function capabilityDetails(value: unknown, pending: ResolvedPendingAuthorization): { credentialWire: string; didCommDevice?: NonNullable<ResolvedPendingAuthorization['bisetDidCommDevice']>; mimiVaultRoom?: DidMdBisetMimiVaultRoom } {
  if (!Array.isArray(value)) throw new Error('did.md did not return Biset authorization details')
  const matches = value.filter(detail => {
    try { return asObject(detail, 'authorization detail').type === KEY_AUTHORIZATION_DETAIL } catch { return false }
  })
  if (matches.length !== 1) throw new Error('did.md did not return one key authorization detail')
  const detail = asObject(matches[0], 'key authorization detail')
  exactKeys(detail, ['type', 'credential'], 'key authorization detail')
  if (typeof detail.credential !== 'string') throw new Error('did.md returned an invalid key authorization detail')
  const edits = (value as unknown[]).filter(item => { try { return asObject(item, 'authorization detail').type === DID_DOCUMENT_EDIT_DETAIL } catch { return false } })
  if (edits.length !== 1) throw new Error('did.md did not return one DID document edit detail')
  sameDocumentEdit(edits[0], pending.documentEdit)
  let mimiVaultRoom: DidMdBisetMimiVaultRoom | undefined
  if (pending.mimiVaultRoomDerivation) {
    const derivedMatches = (value as unknown[]).filter(item => { try { return asObject(item, 'authorization detail').type === DERIVED_SECRET_DETAIL } catch { return false } })
    if (derivedMatches.length !== 1) throw new Error('did.md did not return the requested MIMI Vault room secret')
    const derived = asObject(derivedMatches[0], 'derived secret detail')
    exactKeys(derived, ['type', 'purpose', 'context', 'value'], 'derived secret detail')
    if (derived.purpose !== pending.mimiVaultRoomDerivation.purpose || derived.context !== pending.mimiVaultRoomDerivation.context || typeof derived.value !== 'string') throw new Error('did.md returned an invalid MIMI Vault room secret')
    mimiVaultRoom = mimiVaultRoomFromDerivedSecret(new URL(pending.mimiVaultRoomDerivation.context), derived.value)
  }
  return { credentialWire: detail.credential, ...(pending.bisetDidCommDevice ? { didCommDevice: pending.bisetDidCommDevice } : {}), ...(mimiVaultRoom ? { mimiVaultRoom } : {}) }
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
  const documentEdit: DidCoreDocumentEdit = {
    ...pending.documentEdit,
    verificationMethods: pending.documentEdit.verificationMethods.map(method => ({ ...method, controller: identity.did })),
  }
  return { ...rest, did: identity.did, handle, verificationMethod: identity.verificationMethod, rootPublicKey: identity.rootPublicKey, bisetDidCommDevice, documentEdit }
}

async function capabilityFromResponse(value: unknown, pending: ResolvedPendingAuthorization) {
  const signed = asObject(value, 'device capability')
  exactKeys(signed, ['document', 'proof'], 'device capability')
  const document = asObject(signed.document, 'device capability document')
  exactKeys(document, [
    'audience', 'authorizationDetails', 'deviceJkt', 'expiresAt', 'id', 'issuedAt', 'issuer', 'scope', 'type', 'version',
  ], 'device capability document')
  if (document.type !== 'did.md/DeviceCapability' || document.version !== 1 || document.issuer !== pending.did || document.audience !== pending.clientId || document.deviceJkt !== pending.deviceJkt || !Array.isArray(document.scope) || document.scope.some(scope => typeof scope !== 'string') || typeof document.expiresAt !== 'string' || Date.parse(document.expiresAt) <= Date.now()) throw new Error('did.md returned an invalid device capability')
  if (!document.scope.includes('biset:device') || !document.scope.includes('biset:vault')) throw new Error('did.md did not enroll this Biset device')
  const proof = asObject(signed.proof, 'device capability proof') as unknown as DataIntegrityProof
  if (proof.proofPurpose !== 'authentication' || proof.verificationMethod !== pending.verificationMethod || !verifyProof(document, proof, pending.rootPublicKey)) throw new Error('did.md device capability proof is invalid')
  const detail = capabilityDetails(document.authorizationDetails, pending)
  const credentialWire = detail.credentialWire
  const credential = await validateBisetMlsCredential(credentialWire, pending)
  return { capability: { document, proof }, expiresAt: document.expiresAt, scope: document.scope as string[], credential, credentialWire, didCommDevice: detail.didCommDevice, mimiVaultRoom: detail.mimiVaultRoom }
}

async function tokenFrom(response: Response, pending: DidMdPendingAuthorization): Promise<DidMdActiveSession> {
  if (!response.ok) throw new Error(await response.text())
  const value = asObject(await response.json(), 'token response')
  const nonce = response.headers.get('dpop-nonce')
  if (typeof value.access_token !== 'string' || value.token_type !== 'DPoP' || typeof value.sub !== 'string' || typeof value.expires_in !== 'number' || !nonce) throw new Error('did.md returned an invalid token response')
  const resolvedPending = await resolvedPendingAuthorization(pending, value.sub)
  const capability = await capabilityFromResponse(value.device_capability, resolvedPending)
  const resolved = await resolveByDomain(parseWebvhDid(resolvedPending.did).domain, undefined, { cache: 'no-store' })
  if (!resolved) throw new Error('Could not resolve the DID document after Wallet approval')
  for (const service of resolvedPending.documentEdit.services) if (JSON.stringify(resolved.service?.find(value => value.id === service.id)) !== JSON.stringify(service)) throw new Error(`Wallet did not publish requested service ${service.id}`)
  for (const method of resolvedPending.documentEdit.verificationMethods) if (JSON.stringify(resolved.verificationMethod?.find(value => value.id === method.id)) !== JSON.stringify(method)) throw new Error(`Wallet did not publish requested verification method ${method.id}`)
  for (const id of resolvedPending.documentEdit.remove) if (resolved.service?.some(value => value.id === id) || resolved.verificationMethod?.some(value => value.id === id)) throw new Error(`Wallet did not remove ${id}`)
  // The MIMI Vault room is never republished (see MIMI_VAULT_ROOM_DERIVED_
  // SECRET_PURPOSE), so a round that doesn't ask Wallet to derive it again
  // (session restore, or the mediator-only finalize step) would otherwise
  // lose it here -- carry the previous session's value forward whenever
  // this round's response didn't include a fresh one.
  const previousSession = await readDidMdDeviceSession()
  const mimiVaultRoom = capability.mimiVaultRoom ?? previousSession?.mimiVaultRoom
  const session: DidMdDeviceSession = {
    v: 2, issuer: resolvedPending.issuer, clientId: resolvedPending.clientId, did: resolvedPending.did, handle: resolvedPending.handle,
    verificationMethod: resolvedPending.verificationMethod, rootPublicKey: resolvedPending.rootPublicKey, deviceJkt: resolvedPending.deviceJkt,
    privateKey: resolvedPending.privateKey, publicJwk: resolvedPending.publicJwk, capability: capability.capability, capabilityExpiresAt: capability.expiresAt,
    bisetDevice: { ...resolvedPending.bisetDevice, credentialWire: capability.credentialWire, keyAuthorizationSubject: resolvedPending.keyAuthorizationSubject, mimiVaultRoomCreated: resolvedPending.bisetMimiVaultRoomCreated },
    ...(mimiVaultRoom ? { mimiVaultRoom } : {}),
    ...(capability.didCommDevice ? { bisetDidCommDevice: capability.didCommDevice } : {}),
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
  return { did: session.did, handle: session.handle, clientId: session.clientId, deviceJkt: session.deviceJkt, capabilityExpiresAt: session.capabilityExpiresAt, accessToken: value.access_token, nonce, scope: capability.scope, deviceKid: capability.credential.deviceKid, ...(mimiVaultRoom ? { mimiVaultRoom } : {}), ...(capability.didCommDevice ? { didCommKid: capability.didCommDevice.xKid } : {}) }
}

function pendingFromSession(session: DidMdDeviceSession): ResolvedPendingAuthorization {
  const capabilityDocument = (() => { try { return asObject(session.capability.document, 'stored capability document') } catch { return {} } })()
  const storedEdit = Array.isArray(capabilityDocument.authorizationDetails)
    ? capabilityDocument.authorizationDetails.find(value => { try { return asObject(value, 'stored authorization detail').type === DID_DOCUMENT_EDIT_DETAIL } catch { return false } })
    : undefined
  return {
    v: 2, issuer: session.issuer, clientId: session.clientId, state: '', codeVerifier: '', did: session.did,
    handle: session.handle, verificationMethod: session.verificationMethod, rootPublicKey: session.rootPublicKey,
    deviceJkt: session.deviceJkt, privateKey: session.privateKey, publicJwk: session.publicJwk,
    bisetDevice: session.bisetDevice ?? (() => { throw new Error('This did.md Wallet session predates Biset device enrollment; connect it again.') })(),
    bisetMimiVaultRoomCreated: session.bisetDevice?.mimiVaultRoomCreated ?? false,
    documentEdit: storedEdit as DidCoreDocumentEdit ?? { type: DID_DOCUMENT_EDIT_DETAIL, services: [], verificationMethods: [], remove: [] },
    requestMlsCredential: true,
    keyAuthorizationSubject: session.bisetDevice?.keyAuthorizationSubject ?? `urn:uuid:${crypto.randomUUID()}`,
    ...(session.bisetDidCommDevice ? { bisetDidCommDevice: session.bisetDidCommDevice } : {}),
    createdAt: '',
  }
}

async function redirectToWallet(client: DidMdRegistration, pending: DidMdPendingAuthorization, openedPopup?: Window): Promise<never> {
  await saveDidMdPendingAuthorization(pending)
  const request = new URL(client.authorizationEndpoint)
  const params = new URLSearchParams({
    client_id: pending.clientId, redirect_uri: client.redirectUri, response_type: 'code', state: pending.state,
    code_challenge: await sha256Base64url(pending.codeVerifier), code_challenge_method: 'S256',
    ...(pending.handle !== undefined ? { login_hint: pending.handle } : {}),
    dpop_jkt: pending.deviceJkt, scope: REQUESTED_SCOPES.join(' '),
    // A one-shot UI hint only (dispo ignores it once an identity already
    // exists in that tab, e.g. every finalize/edit round after login): asks
    // the did.md Wallet creation screen to start with its Alias toggle on,
    // since a biset user is expected to want a memorable did.md hostname
    // rather than the default SCID-derived one. Presence-only -- the value
    // is never read.
    alias: '',
    authorization_details: JSON.stringify([
      pending.documentEdit,
      { type: KEY_AUTHORIZATION_DETAIL, subject: pending.keyAuthorizationSubject,
        publicKey: { type: 'Multikey', publicKeyMultibase: encodeMultikey(pending.bisetDevice.signaturePublicKey) }, purposes: ['signing'] },
      ...(pending.mimiVaultRoomDerivation ? [{ type: DERIVED_SECRET_DETAIL, purpose: pending.mimiVaultRoomDerivation.purpose, context: pending.mimiVaultRoomDerivation.context }] : []),
    ]),
  })
  request.search = params.toString()
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
  throw new Error('The browser did not navigate to did.md Wallet')
}

/** The only round trip needed to sign in: no DID is resolved and no
 * document edit is requested up front, so this never needs to know which
 * did.md handle the user has open in Wallet beforehand (no login_hint). The
 * signer's DID, MIMI Vault room, and DIDComm mediator enrollment are all
 * resolved/deferred to after Wallet approves -- see `tokenFrom` for DID
 * derivation and `beginDidMdWalletFinalizeEnrollment` for the follow-up
 * step the user triggers explicitly from Biset's own UI. */
/** The only round trip needed to sign in, provision a MIMI Vault room, AND
 * (when a mediator is configured and reachable) publish a DIDComm device:
 * no DID is resolved up front (no login_hint). The MIMI Vault room id is
 * Wallet-derived rather than published (see
 * MIMI_VAULT_ROOM_DERIVED_SECRET_PURPOSE), and the DIDComm device's own
 * material -- the X25519 leaf, its did:peer mediator-control identity, even
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
export async function beginDidMdWalletLogin(mimiSelfBaseUrl: string, mediatorUrls: readonly string[] = [], openedPopup?: Window, configured: DidMdWalletConfiguration = {}): Promise<never> {
  const config = walletConfiguration(configured)
  const provider = normalizedMimiProviderUrl(mimiSelfBaseUrl)
  const client = await registration(config.walletDeviceName)
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']) as CryptoKeyPair
  const publicJwk = p256PublicJwk(await crypto.subtle.exportKey('jwk', pair.publicKey))
  const signaturePrivateKey = ed25519.utils.randomSecretKey()
  const signaturePublicKey = ed25519.getPublicKey(signaturePrivateKey)
  const bisetDevice = await sealDidMdBisetDeviceMaterial(signaturePublicKey, {
    signaturePrivateKey,
    vaultSecret: crypto.getRandomValues(new Uint8Array(32)),
  })
  signaturePrivateKey.fill(0)
  let bisetDidCommDevice: NonNullable<DidMdPendingAuthorization['bisetDidCommDevice']> | undefined
  try {
    const mediator = await bisetMediatorFor(mediatorUrls)
    if (mediator) bisetDidCommDevice = await prepareBisetDidCommDevice(mediator)
  } catch (error) {
    console.warn('[did.md Wallet login] DIDComm mediator unavailable, signing in without it', error instanceof Error ? error.message : error)
  }
  const pending: DidMdPendingAuthorization = {
    v: 2, issuer: client.issuer, clientId: client.clientId, state: randomBase64url(32), codeVerifier: randomBase64url(48),
    deviceJkt: await p256Jkt(publicJwk), privateKey: pair.privateKey, publicJwk, bisetDevice, bisetMimiVaultRoomCreated: false,
    documentEdit: buildDocumentEdit('', config, bisetDidCommDevice), requestMlsCredential: true,
    keyAuthorizationSubject: `urn:uuid:${crypto.randomUUID()}`,
    mimiVaultRoomDerivation: { purpose: MIMI_VAULT_ROOM_DERIVED_SECRET_PURPOSE, context: provider.toString() },
    ...(bisetDidCommDevice ? { bisetDidCommDevice } : {}),
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
  if (!session?.bisetDevice || session.v !== 2 || session.issuer !== ISSUER || Date.parse(session.capabilityExpiresAt) <= Date.now()) {
    throw new Error('Connect did.md Wallet again before finishing setup on this browser')
  }
  const client = await registration()
  if (client.clientId !== session.clientId || client.redirectUri !== redirectUri()) throw new Error('The did.md Wallet client registration changed; reconnect this browser')
  const mediator = await bisetMediatorFor(mediatorUrls)
  if (!mediator) throw new Error('Biset DIDComm mediator is not configured')
  const bisetDidCommDevice = await newBisetDidCommDevice(session.did, mediator)
  const pending: DidMdPendingAuthorization = {
    ...pendingFromSession(session),
    state: randomBase64url(32),
    codeVerifier: randomBase64url(48),
    createdAt: new Date().toISOString(),
    bisetDidCommDevice,
  }
  pending.documentEdit = buildDocumentEdit(session.did, config, bisetDidCommDevice)
  return redirectToWallet(client, pending)
}

export async function beginDidMdWalletDocumentEdit(options: { mediatorUrls?: readonly string[]; removeMediator?: boolean; configuration?: DidMdWalletConfiguration }): Promise<never> {
  const config = walletConfiguration(options.configuration)
  const session = await readDidMdDeviceSession()
  if (!session?.bisetDevice || session.v !== 2 || Date.parse(session.capabilityExpiresAt) <= Date.now()) throw new Error('Reconnect did.md Wallet before editing the DID document')
  const client = await registration()
  const pending = pendingFromSession(session)
  pending.state = randomBase64url(32); pending.codeVerifier = randomBase64url(48); pending.createdAt = new Date().toISOString()
  if (options.removeMediator) {
    if (session.bisetDidCommDevice) pending.previousBisetDidCommDevice = session.bisetDidCommDevice
    const didcomm = configuredService(config, 'didcomm')
    pending.documentEdit = buildDocumentEdit(session.did, config, undefined, [didcomm.id, ...(didcomm.previousIds ?? []), ...(session.bisetDidCommDevice ? [session.bisetDidCommDevice.xKid] : [])])
    delete pending.bisetDidCommDevice
  } else {
    const mediator = await bisetMediatorFor(options.mediatorUrls ?? [])
    if (!mediator) throw new Error('Biset DIDComm mediator is not configured')
    const previous = session.bisetDidCommDevice?.xKid
    if (session.bisetDidCommDevice) pending.previousBisetDidCommDevice = session.bisetDidCommDevice
    pending.bisetDidCommDevice = await newBisetDidCommDevice(session.did, mediator)
    pending.documentEdit = buildDocumentEdit(session.did, config, pending.bisetDidCommDevice, previous ? [previous] : [])
  }
  return redirectToWallet(client, pending)
}

export async function completeDidMdWalletCallback(): Promise<DidMdActiveSession | undefined> {
  if (!isWalletCallback()) return undefined
  const callback = new URL(location.href)
  const pending = await readDidMdPendingAuthorization()
  if (!pending || pending.v !== 2 || pending.issuer !== ISSUER) throw new Error('No matching did.md Wallet authorization is pending')
  const state = callback.searchParams.get('state')
  const issuer = callback.searchParams.get('iss')
  const code = callback.searchParams.get('code')
  const error = callback.searchParams.get('error')
  if (state !== pending.state || issuer !== pending.issuer) { await rollbackPendingMediator(pending); await clearDidMdPendingAuthorization(); throw new Error('did.md Wallet callback state or issuer did not match') }
  if (error) { await rollbackPendingMediator(pending); await clearDidMdPendingAuthorization(); throw new Error(callback.searchParams.get('error_description') ?? `did.md Wallet authorization failed: ${error}`) }
  if (!code || !/^code_[A-Za-z0-9_-]{32,128}$/.test(code)) { await rollbackPendingMediator(pending); await clearDidMdPendingAuthorization(); throw new Error('did.md Wallet callback has no valid authorization code') }
  const client = await registration()
  if (client.clientId !== pending.clientId || client.redirectUri !== redirectUri()) { await clearDidMdPendingAuthorization(); throw new Error('did.md Wallet client registration changed during authorization') }
  const response = await fetch(client.tokenEndpoint, {
    method: 'POST', headers: { 'content-type': 'application/json', dpop: await createDpop(pending.privateKey, pending.publicJwk, 'POST', client.tokenEndpoint) },
    body: JSON.stringify({ grant_type: 'authorization_code', client_id: client.clientId, code, code_verifier: pending.codeVerifier, redirect_uri: client.redirectUri }),
  })
  try {
    const active = await tokenFrom(response, pending)
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
  if (!session || session.v !== 2 || session.issuer !== ISSUER || Date.parse(session.capabilityExpiresAt) <= Date.now()) return undefined
  const client = await registration()
  if (client.clientId !== session.clientId) return undefined
  const pending = pendingFromSession(session)
  const response = await fetch(client.refreshEndpoint, {
    method: 'POST', headers: { 'content-type': 'application/json', dpop: await createDpop(session.privateKey, session.publicJwk, 'POST', client.refreshEndpoint) },
    body: JSON.stringify({ client_id: client.clientId, capability: session.capability }),
  })
  try {
    return await tokenFrom(response, pending)
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
  if (!session || session.v !== 2 || session.issuer !== ISSUER) return undefined
  return { did: session.did, handle: session.handle, capabilityExpiresAt: session.capabilityExpiresAt, expired: Date.parse(session.capabilityExpiresAt) <= Date.now() }
}

export async function disconnectDidMdWallet(): Promise<void> {
  await Promise.all([clearDidMdPendingAuthorization(), clearDidMdDeviceSession()])
}

/** Opens only this browser's Biset leaf material.  The Wallet's controller
 * keys never occur in this database or return value. The MIMI Vault room is
 * read straight from the stored session -- it was Wallet-derived at sign-in
 * (or a later finalize round), never published, so there is nothing to
 * resolve here. */
export async function openDidMdWalletBisetDevice(providerUrl: string): Promise<DidMdBisetDevice> {
  const session = await readDidMdDeviceSession()
  if (!session?.bisetDevice || session.v !== 2) throw new Error('Connect did.md Wallet again to enroll this Biset device')
  const credential = await validateBisetMlsCredential(session.bisetDevice.credentialWire, pendingFromSession(session))
  const privateMaterial = await openDidMdBisetDeviceMaterial(session.bisetDevice)
  const derivedPublic = ed25519.getPublicKey(privateMaterial.signaturePrivateKey)
  if (!derivedPublic.every((byte, index) => byte === credential.signaturePublicKey[index])) throw new Error('Biset device private key does not match its Wallet credential')
  if (!session.mimiVaultRoom) throw new Error('Connect did.md Wallet again to provision a MIMI Vault room for this device')
  const provider = normalizedMimiProviderUrl(providerUrl)
  if (session.mimiVaultRoom.providerUrl !== provider.toString()) throw new Error('Wallet MIMI Vault pointer does not match this Biset provider')
  return {
    did: session.did,
    rootPublicKey: session.rootPublicKey.slice(),
    credential,
    ...privateMaterial,
    mimiVaultRoom: session.mimiVaultRoom,
    mimiVaultRoomCreated: false,
  }
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
  const derivedControlPublic = x25519.getPublicKey(privateMaterial.mediatorControlPrivateKey)
  if (!derivedPublic.every((byte, index) => byte === stored.x25519PublicKey[index])) throw new Error('Biset DIDComm private key does not match its Wallet-authorized public key')
  if (!derivedControlPublic.every((byte, index) => byte === stored.mediatorControlPublicKey[index])) throw new Error('Biset mediator control key does not match its did:peer identity')
  if (stored.xKid !== deviceKid(session.did, derivedPublic)) throw new Error('Biset DIDComm device key identifier is invalid')
  return { did: session.did, xKid: stored.xKid, x25519PrivateKey: privateMaterial.x25519PrivateKey, mediatorControlDid: stored.mediatorControlDid, mediatorControlKid: stored.mediatorControlKid, mediatorControlPrivateKey: privateMaterial.mediatorControlPrivateKey, mediatorUrl: stored.mediatorUrl, routingKid: stored.routingKid }
}

export async function callDidMdWalletTestResource(active: DidMdActiveSession): Promise<string> {
  const endpoint = `${ISSUER}/v1/oauth/resource`
  const session = await readDidMdDeviceSession()
  if (!session || session.did !== active.did) throw new Error('The did.md Wallet device session is unavailable')
  const response = await fetch(endpoint, {
    headers: { authorization: `DPoP ${active.accessToken}`, dpop: await createDpop(session.privateKey, session.publicJwk, 'GET', endpoint, active.nonce) },
  })
  if (!response.ok) throw new Error(await response.text())
  const value = asObject(await response.json(), 'protected resource response')
  if (value.ok !== true || value.sub !== active.did) throw new Error('The protected resource response is invalid')
  return typeof value.message === 'string' ? value.message : 'DPoP-bound device session accepted'
}
