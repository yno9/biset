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
import { mimiVaultRoomFromRouting } from '../../../protocol/didcomm/webvh-routing.ts'
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
const REQUESTED_SCOPES = ['biset:login', 'biset:device', 'biset:routing', 'biset:messaging', 'biset:vault']
const DID_DOCUMENT_EDIT_DETAIL = 'urn:did-core:document-edit:v1'
const KEY_AUTHORIZATION_DETAIL = 'urn:did.md:key-authorization:v1'
const MIMI_VAULT_SERVICE_TYPE = 'BisetMimiVaultRoom'
export const DID_MD_JUST_CONNECTED_KEY = 'biset-did-md-just-connected-v1'
const encoder = new TextEncoder()

export type DidMdWalletConfiguration = {
  walletDeviceName?: string
  didDocumentServices?: DidDocumentServiceTemplate[]
}

type WalletConfiguration = Required<DidMdWalletConfiguration>

type DidDocumentServiceTemplate = {
  purpose?: 'mimi-vault' | 'didcomm'
  id: string
  type: string
  serviceEndpoint: string | Record<string, unknown>
  previousIds?: string[]
}

const defaultDidDocumentServices: DidDocumentServiceTemplate[] = [
  { purpose: 'mimi-vault', id: '#mimi', type: MIMI_VAULT_SERVICE_TYPE, serviceEndpoint: '$mimiVaultRoom', previousIds: ['#biset-mimi-vault'] },
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
    if (service.purpose !== undefined && service.purpose !== 'mimi-vault' && service.purpose !== 'didcomm') throw new Error('DID Document service purpose is invalid')
    if (service.previousIds?.some(id => !/^#[^\s#]+$/.test(id))) throw new Error('DID Document service previous IDs are invalid')
  }
  const mimi = didDocumentServices.filter(service => service.purpose === 'mimi-vault')
  const didcomm = didDocumentServices.filter(service => service.purpose === 'didcomm')
  if (mimi.length !== 1 || didcomm.length !== 1) throw new Error('DID Document services must define one MIMI Vault and one DIDComm template')
  if (!walletDeviceName.trim() || walletDeviceName.length > 160) throw new Error('Wallet device name must be between 1 and 160 characters')
  return { didDocumentServices, walletDeviceName }
}

function configuredService(config: WalletConfiguration, purpose: 'mimi-vault' | 'didcomm'): DidDocumentServiceTemplate {
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

/** DID Core permits fragment-only service IDs. Accept legacy absolute IDs
 * while reading, but always ask Wallet to publish the compact form. */
function isServiceId(did: string, value: string | undefined, fragment: string): boolean {
  return value === fragment || value === `${did}${fragment}`
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

/** The public, opaque room URI is made by this browser, published by Wallet,
 * then compared exactly at callback time. It contains neither Vault content
 * nor a Vault key. */
async function bisetMimiVaultRoomFor(did: string, providerValue: string, mimiService: DidDocumentServiceTemplate): Promise<{ room: DidMdBisetMimiVaultRoom; created: boolean }> {
  let provider: URL
  try { provider = new URL(providerValue) } catch { throw new Error('Biset MIMI Self/Vault is not configured') }
  if (provider.protocol !== 'https:' || provider.username || provider.password || provider.search || provider.hash) throw new Error('Biset MIMI Self/Vault URL is invalid')
  const providerUrl = provider.toString()
  const resolved = await resolveByDomain(parseWebvhDid(did).domain, undefined, { cache: 'no-store' })
  const service = resolved?.service?.find(candidate => (isServiceId(did, candidate.id, mimiService.id) || mimiService.previousIds?.some(id => isServiceId(did, candidate.id, id))) && candidate.type === mimiService.type)
  const roomId = typeof service?.serviceEndpoint === 'string'
    ? mimiVaultRoomFromRouting({ service: [], mimiVaultRoom: { roomId: service.serviceEndpoint, providerUrl } }, providerUrl)
    : undefined
  return { room: { providerUrl, roomId: roomId ?? `mimi://${provider.hostname}/r/vault-${randomBase64url(32)}` }, created: !roomId }
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

async function newBisetDidCommDevice(did: string, mediator: DidMdBisetMediator): Promise<NonNullable<DidMdPendingAuthorization['bisetDidCommDevice']> & DidMdBisetDidCommDeviceMaterial> {
  const x25519PrivateKey = x25519.utils.randomSecretKey()
  const x25519PublicKey = x25519.getPublicKey(x25519PrivateKey)
  const control = generatePeerIdentity()
  const xKid = deviceKid(did, x25519PublicKey)
  try {
    const sealed = await sealDidMdBisetDidCommDeviceMaterial(
      x25519PublicKey,
      { did: control.did, kid: control.xKid, publicKey: control.xPub },
      { x25519PrivateKey, mediatorControlPrivateKey: control.xPriv },
    )
    return { ...sealed, mediatorUrl: mediator.mediatorUrl, routingKid: mediator.routingKid, xKid }
  } finally {
    x25519PrivateKey.fill(0)
    control.xPriv.fill(0); control.edPriv.fill(0)
  }
}

function buildDocumentEdit(did: string, config: WalletConfiguration, room?: DidMdBisetMimiVaultRoom, device?: NonNullable<DidMdPendingAuthorization['bisetDidCommDevice']>, remove: string[] = []): DidCoreDocumentEdit {
  const mimi = configuredService(config, 'mimi-vault')
  const didcomm = configuredService(config, 'didcomm')
  const services = config.didDocumentServices
    .filter(service => (service.purpose !== 'mimi-vault' || room) && (service.purpose !== 'didcomm' || device))
    .map(service => ({
      id: service.id,
      type: service.type,
      serviceEndpoint: materializeServiceEndpoint(service.serviceEndpoint, {
        '$mimiVaultRoom': room?.roomId ?? '',
        '$mediatorUrl': device?.mediatorUrl ?? '',
        '$routingKid': device?.routingKid ?? '',
      }),
    }))
  return {
    type: DID_DOCUMENT_EDIT_DETAIL,
    services,
    verificationMethods: device ? [{ id: deviceKidFragment(device.x25519PublicKey), type: 'Multikey', controller: did, publicKeyMultibase: encodeX25519Multikey(device.x25519PublicKey) }] : [],
    serviceKeyBindings: [
      ...(room ? [{ serviceId: mimi.id, keyIds: [] }] : []),
      ...(device ? [{ serviceId: didcomm.id, keyIds: [deviceKidFragment(device.x25519PublicKey)] }] : []),
    ],
    remove,
  }
}

async function setMediatorRegistration(_did: string, device: NonNullable<DidMdPendingAuthorization['bisetDidCommDevice']>, action: 'add' | 'remove'): Promise<void> {
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
  if (!pending.mediatorPreRegistered || !pending.bisetDidCommDevice) return
  try { await setMediatorRegistration(pending.did, pending.bisetDidCommDevice, 'remove') }
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

async function validateBisetMlsCredential(wire: string, pending: DidMdPendingAuthorization): Promise<MlsDeviceCredentialV2> {
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

function capabilityDetails(value: unknown, pending: DidMdPendingAuthorization): { credentialWire: string; didCommDevice?: NonNullable<DidMdPendingAuthorization['bisetDidCommDevice']> } {
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
  return { credentialWire: detail.credential, ...(pending.bisetDidCommDevice ? { didCommDevice: pending.bisetDidCommDevice } : {}) }
}

async function capabilityFromResponse(value: unknown, pending: DidMdPendingAuthorization) {
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
  return { capability: { document, proof }, expiresAt: document.expiresAt, scope: document.scope as string[], credential, credentialWire, didCommDevice: detail.didCommDevice }
}

async function tokenFrom(response: Response, pending: DidMdPendingAuthorization): Promise<DidMdActiveSession> {
  if (!response.ok) throw new Error(await response.text())
  const value = asObject(await response.json(), 'token response')
  const nonce = response.headers.get('dpop-nonce')
  if (typeof value.access_token !== 'string' || value.token_type !== 'DPoP' || value.sub !== pending.did || typeof value.expires_in !== 'number' || !nonce) throw new Error('did.md returned an invalid token response')
  const capability = await capabilityFromResponse(value.device_capability, pending)
  const resolved = await resolveByDomain(parseWebvhDid(pending.did).domain, undefined, { cache: 'no-store' })
  if (!resolved) throw new Error('Could not resolve the DID document after Wallet approval')
  for (const service of pending.documentEdit.services) if (JSON.stringify(resolved.service?.find(value => value.id === service.id)) !== JSON.stringify(service)) throw new Error(`Wallet did not publish requested service ${service.id}`)
  for (const method of pending.documentEdit.verificationMethods) if (JSON.stringify(resolved.verificationMethod?.find(value => value.id === method.id)) !== JSON.stringify(method)) throw new Error(`Wallet did not publish requested verification method ${method.id}`)
  for (const id of pending.documentEdit.remove) if (resolved.service?.some(value => value.id === id) || resolved.verificationMethod?.some(value => value.id === id)) throw new Error(`Wallet did not remove ${id}`)
  const session: DidMdDeviceSession = {
    v: 2, issuer: pending.issuer, clientId: pending.clientId, did: pending.did, handle: pending.handle,
    verificationMethod: pending.verificationMethod, rootPublicKey: pending.rootPublicKey, deviceJkt: pending.deviceJkt,
    privateKey: pending.privateKey, publicJwk: pending.publicJwk, capability: capability.capability, capabilityExpiresAt: capability.expiresAt,
    bisetDevice: { ...pending.bisetDevice, credentialWire: capability.credentialWire, keyAuthorizationSubject: pending.keyAuthorizationSubject, mimiVaultRoomCreated: pending.bisetMimiVaultRoomCreated },
    ...(capability.didCommDevice ? { bisetDidCommDevice: capability.didCommDevice } : {}),
  }
  await saveDidMdDeviceSession(session)
  // The mediator authenticates this DIDComm sender by resolving xKid from
  // the DID document. Registration before Wallet publication is therefore
  // impossible by construction. Publish + re-resolve above first, persist
  // the recoverable session, then register; boot retries registration if
  // the network fails after the DID commit.
  if (capability.didCommDevice) await setMediatorRegistration(pending.did, capability.didCommDevice, 'add')
  if (pending.previousBisetDidCommDevice) {
    try { await setMediatorRegistration(pending.did, pending.previousBisetDidCommDevice, 'remove') }
    catch (error) { console.warn('[mediator edit cleanup]', error instanceof Error ? error.message : error) }
  }
  return { did: session.did, handle: session.handle, clientId: session.clientId, deviceJkt: session.deviceJkt, capabilityExpiresAt: session.capabilityExpiresAt, accessToken: value.access_token, nonce, scope: capability.scope, deviceKid: capability.credential.deviceKid, ...(capability.didCommDevice ? { didCommKid: capability.didCommDevice.xKid } : {}) }
}

function pendingFromSession(session: DidMdDeviceSession): DidMdPendingAuthorization {
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
    login_hint: pending.handle, dpop_jkt: pending.deviceJkt, scope: REQUESTED_SCOPES.join(' '),
    authorization_details: JSON.stringify([
      pending.documentEdit,
      { type: KEY_AUTHORIZATION_DETAIL, subject: pending.keyAuthorizationSubject,
        publicKey: { type: 'Multikey', publicKeyMultibase: encodeMultikey(pending.bisetDevice.signaturePublicKey) }, purposes: ['signing'] },
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

export async function beginDidMdWalletLogin(rawHandle: string, mimiSelfBaseUrl: string, mediatorUrls: readonly string[] = [], openedPopup?: Window, configured: DidMdWalletConfiguration = {}): Promise<never> {
  const config = walletConfiguration(configured)
  const handle = didMdHandle(rawHandle)
  const document = await resolveByDomain(handle, undefined, { cache: 'no-store' })
  const identity = await rootAuthority(handle, document)
  const client = await registration(config.walletDeviceName)
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']) as CryptoKeyPair
  const publicJwk = p256PublicJwk(await crypto.subtle.exportKey('jwk', pair.publicKey))
  const signaturePrivateKey = ed25519.utils.randomSecretKey()
  const signaturePublicKey = ed25519.getPublicKey(signaturePrivateKey)
  const requestedVault = await bisetMimiVaultRoomFor(identity.did, mimiSelfBaseUrl, configuredService(config, 'mimi-vault'))
  const bisetMimiVaultRoom = requestedVault.room
  const bisetDevice = await sealDidMdBisetDeviceMaterial(signaturePublicKey, {
    signaturePrivateKey,
    vaultSecret: crypto.getRandomValues(new Uint8Array(32)),
  })
  signaturePrivateKey.fill(0)
  const mediator = await bisetMediatorFor(mediatorUrls)
  const bisetDidCommDevice = mediator ? await newBisetDidCommDevice(identity.did, mediator) : undefined
  const pending: DidMdPendingAuthorization = {
    v: 2, issuer: client.issuer, clientId: client.clientId, state: randomBase64url(32), codeVerifier: randomBase64url(48),
    did: identity.did, handle, verificationMethod: identity.verificationMethod, rootPublicKey: identity.rootPublicKey,
    deviceJkt: await p256Jkt(publicJwk), privateKey: pair.privateKey, publicJwk, bisetDevice, bisetMimiVaultRoomCreated: requestedVault.created,
    documentEdit: buildDocumentEdit(identity.did, config, bisetMimiVaultRoom, bisetDidCommDevice), requestMlsCredential: true,
    keyAuthorizationSubject: `urn:uuid:${crypto.randomUUID()}`,
    ...(bisetDidCommDevice ? { bisetDidCommDevice } : {}),
    createdAt: new Date().toISOString(),
  }
  return redirectToWallet(client, pending, openedPopup)
}

/** A current Wallet session can add a DIDComm device without replacing its
 * Biset MLS leaf or allocating a second Vault member. The new capability
 * carries the exact X25519 public key and mediator route that the Wallet
 * publishes under its current Sign key. */
export async function beginDidMdWalletMessagingEnrollment(mediatorUrls: readonly string[], configured: DidMdWalletConfiguration = {}): Promise<never> {
  const config = walletConfiguration(configured)
  const session = await readDidMdDeviceSession()
  if (!session?.bisetDevice || session.v !== 2 || session.issuer !== ISSUER || Date.parse(session.capabilityExpiresAt) <= Date.now()) {
    throw new Error('Connect did.md Wallet again before enabling messaging on this browser')
  }
  const client = await registration()
  if (client.clientId !== session.clientId || client.redirectUri !== redirectUri()) throw new Error('The did.md Wallet client registration changed; reconnect this browser')
  const mediator = await bisetMediatorFor(mediatorUrls)
  if (!mediator) throw new Error('Biset DIDComm mediator is not configured')
  const pending: DidMdPendingAuthorization = {
    ...pendingFromSession(session),
    state: randomBase64url(32),
    codeVerifier: randomBase64url(48),
    bisetDidCommDevice: await newBisetDidCommDevice(session.did, mediator),
    createdAt: new Date().toISOString(),
  }
  pending.documentEdit = buildDocumentEdit(session.did, config, undefined, pending.bisetDidCommDevice)
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
    pending.documentEdit = buildDocumentEdit(session.did, config, undefined, undefined, [didcomm.id, ...(didcomm.previousIds ?? []), ...(session.bisetDidCommDevice ? [session.bisetDidCommDevice.xKid] : [])])
    delete pending.bisetDidCommDevice
  } else {
    const mediator = await bisetMediatorFor(options.mediatorUrls ?? [])
    if (!mediator) throw new Error('Biset DIDComm mediator is not configured')
    const previous = session.bisetDidCommDevice?.xKid
    if (session.bisetDidCommDevice) pending.previousBisetDidCommDevice = session.bisetDidCommDevice
    pending.bisetDidCommDevice = await newBisetDidCommDevice(session.did, mediator)
    pending.documentEdit = buildDocumentEdit(session.did, config, undefined, pending.bisetDidCommDevice, previous ? [previous] : [])
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
 * keys never occur in this database or return value. */
export async function openDidMdWalletBisetDevice(providerUrl: string, configured: DidMdWalletConfiguration = {}): Promise<DidMdBisetDevice> {
  const config = walletConfiguration(configured)
  const session = await readDidMdDeviceSession()
  if (!session?.bisetDevice || session.v !== 2) throw new Error('Connect did.md Wallet again to enroll this Biset device')
  const credential = await validateBisetMlsCredential(session.bisetDevice.credentialWire, pendingFromSession(session))
  const privateMaterial = await openDidMdBisetDeviceMaterial(session.bisetDevice)
  const derivedPublic = ed25519.getPublicKey(privateMaterial.signaturePrivateKey)
  if (!derivedPublic.every((byte, index) => byte === credential.signaturePublicKey[index])) throw new Error('Biset device private key does not match its Wallet credential')
  const document = await resolveByDomain(parseWebvhDid(session.did).domain, undefined, { cache: 'no-store' })
  let normalizedProviderUrl: string
  try {
    const provider = new URL(providerUrl)
    if (provider.protocol !== 'https:' || provider.username || provider.password || provider.search || provider.hash) throw new Error()
    normalizedProviderUrl = provider.toString()
  } catch { throw new Error('Biset MIMI Self/Vault URL is invalid') }
  const mimi = configuredService(config, 'mimi-vault')
  const service = document?.service?.find(candidate => (isServiceId(session.did, candidate.id, mimi.id) || mimi.previousIds?.some(id => isServiceId(session.did, candidate.id, id))) && candidate.type === mimi.type)
  let roomId: string | undefined
  if (typeof service?.serviceEndpoint === 'string') {
    try {
      roomId = mimiVaultRoomFromRouting({ service: [], mimiVaultRoom: { roomId: service.serviceEndpoint, providerUrl: normalizedProviderUrl } }, normalizedProviderUrl)
    } catch { /* handled below */ }
  }
  if (!roomId) throw new Error('The resolved DID document has no valid Biset MIMI Vault room service')
  return {
    did: session.did,
    rootPublicKey: session.rootPublicKey.slice(),
    credential,
    ...privateMaterial,
    mimiVaultRoom: { roomId, providerUrl: normalizedProviderUrl },
    mimiVaultRoomCreated: session.bisetDevice.mimiVaultRoomCreated,
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
