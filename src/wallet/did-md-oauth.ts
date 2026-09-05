/**
 * did.md OAuth public-client integration.
 *
 * It persists no Wallet controller material.  During Phase B the Wallet
 * additionally certifies a Biset-generated MLS leaf key; that Biset-only
 * private leaf key and Vault secret remain locally AES-wrapped here.
 */
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { decodeMultikey } from '../identity/webvh/multikey.ts'
import { parseWebvhDid } from '../identity/webvh/identifier.ts'
import { verifyProof, type DataIntegrityProof } from '../identity/webvh/proof.ts'
import { fetchCurrentLog } from '../identity/webvh/log-io.ts'
import { resolveByDomain, resolveEntries } from '../identity/webvh/resolver.ts'
import { decodeMlsDeviceCredential, verifyMlsDeviceCredential, verifyMlsDeviceCredentialRoot, type MlsDeviceCredentialV2 } from '../mls/device-credential.ts'
import { base64urlToBytes } from '../shared/protocol/canonical.ts'
import { fetchRouting, mimiVaultRoomFromRouting } from '../didcomm/webvh-routing.ts'
import { deviceKid } from '../didcomm/devicekid.ts'
import { fetchMediatorInfo } from '../didcomm/mediator-coordinate.ts'
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
} from './did-md-store.ts'

const ISSUER = 'https://api.did.md'
const WALLET_ORIGIN = 'https://app.did.md'
const CALLBACK_PATH = '/wallet/callback'
const REQUESTED_SCOPES = ['biset:login', 'biset:device', 'biset:routing', 'biset:messaging', 'biset:vault']
const BISET_DEVICE_AUTHORIZATION_DETAIL = 'urn:biset:device-enrollment:v1'
const encoder = new TextEncoder()

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
async function bisetMimiVaultRoomFor(did: string, providerValue: string): Promise<{ room: DidMdBisetMimiVaultRoom; created: boolean }> {
  let provider: URL
  try { provider = new URL(providerValue) } catch { throw new Error('Biset MIMI Self/Vault is not configured') }
  if (provider.protocol !== 'https:' || provider.username || provider.password || provider.search || provider.hash) throw new Error('Biset MIMI Self/Vault URL is invalid')
  const providerUrl = provider.toString()
  const existing = await fetchRouting(did, fetch, { cache: 'no-store' })
  const roomId = mimiVaultRoomFromRouting(existing, providerUrl)
  return { room: { providerUrl, roomId: roomId ?? `mimi://${provider.hostname}/r/vault-${randomBase64url(32)}` }, created: !roomId }
}

function sameBisetMimiVaultRoom(value: unknown, expected: DidMdBisetMimiVaultRoom): DidMdBisetMimiVaultRoom {
  const room = asObject(value, 'did.md Biset MIMI Vault room')
  exactKeys(room, ['providerUrl', 'roomId'], 'did.md Biset MIMI Vault room')
  if (room.providerUrl !== expected.providerUrl || room.roomId !== expected.roomId) throw new Error('did.md returned a Biset MIMI Vault room different from the one this browser requested')
  return expected
}

function didCommCapabilityFor(value: unknown, expected: NonNullable<DidMdPendingAuthorization['bisetDidCommDevice']>) {
  const device = asObject(value, 'did.md Biset DIDComm device')
  exactKeys(device, ['mediatorUrl', 'routingKid', 'x25519PublicKey', 'xKid'], 'did.md Biset DIDComm device')
  if (device.mediatorUrl !== expected.mediatorUrl || device.routingKid !== expected.routingKid || device.xKid !== expected.xKid
    || device.x25519PublicKey !== base64url(expected.x25519PublicKey)) {
    throw new Error('did.md returned a Biset DIDComm device different from the one this browser requested')
  }
  return expected
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
  const xKid = deviceKid(did, x25519PublicKey)
  try {
    const sealed = await sealDidMdBisetDidCommDeviceMaterial(x25519PublicKey, { x25519PrivateKey })
    return { ...sealed, mediatorUrl: mediator.mediatorUrl, routingKid: mediator.routingKid, xKid }
  } finally {
    x25519PrivateKey.fill(0)
  }
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

async function registration(): Promise<DidMdRegistration> {
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
      client_name: 'Biset', application_type: 'web', redirect_uris: [redirectUri()],
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
  const verificationMethod = `${document.id}#key-1`
  const method = document.verificationMethod.find(candidate => candidate.id === verificationMethod)
  if (!method || !document.authentication.includes(verificationMethod)) throw new Error('Resolved DID has no Root authentication key')
  return { did: document.id, verificationMethod, rootPublicKey: decodeMultikey(method.publicKeyMultibase) }
}

async function validateBisetMlsCredential(wire: string, pending: DidMdPendingAuthorization): Promise<MlsDeviceCredentialV2> {
  let credential: MlsDeviceCredentialV2
  try { credential = decodeMlsDeviceCredential(base64urlToBytes(wire)) } catch { throw new Error('did.md returned an invalid Biset MLS device credential') }
  if (credential.identityId !== pending.did || !credential.signaturePublicKey.every((byte, index) => byte === pending.bisetDevice.signaturePublicKey[index])) {
    throw new Error('did.md returned a Biset MLS credential for another device')
  }
  const current = await fetchCurrentLog(pending.did)
  if (!resolveEntries(pending.did, current.entries)) throw new Error('The published did:webvh log is no longer valid')
  const currentSign = current.last.parameters.updateKeys
  if (!currentSign || currentSign.length !== 1 || credential.generation !== current.last.versionId || !verifyMlsDeviceCredential(credential, decodeMultikey(currentSign[0]!)) || !verifyMlsDeviceCredentialRoot(credential, pending.rootPublicKey)) {
    throw new Error('did.md returned an MLS credential not authorized by the current DID generation')
  }
  return credential
}

function bisetCapabilityDetail(value: unknown, pending: DidMdPendingAuthorization): { credentialWire: string; mimiVaultRoom: DidMdBisetMimiVaultRoom; didCommDevice?: NonNullable<DidMdPendingAuthorization['bisetDidCommDevice']> } {
  if (!Array.isArray(value)) throw new Error('did.md did not return Biset authorization details')
  const matches = value.filter(detail => {
    try { return asObject(detail, 'authorization detail').type === BISET_DEVICE_AUTHORIZATION_DETAIL } catch { return false }
  })
  if (matches.length !== 1) throw new Error('did.md did not return one Biset device authorization detail')
  const detail = asObject(matches[0], 'Biset device authorization detail')
  exactKeys(detail, ['type', 'mlsCredential', 'mimiVaultRoom', ...(pending.bisetDidCommDevice ? ['didCommDevice'] : [])], 'Biset device authorization detail')
  if (detail.type !== BISET_DEVICE_AUTHORIZATION_DETAIL || typeof detail.mlsCredential !== 'string') throw new Error('did.md returned an invalid Biset device authorization detail')
  const mimiVaultRoom = sameBisetMimiVaultRoom(detail.mimiVaultRoom, pending.bisetMimiVaultRoom)
  const didCommDevice = pending.bisetDidCommDevice ? didCommCapabilityFor(detail.didCommDevice, pending.bisetDidCommDevice) : undefined
  return { credentialWire: detail.mlsCredential, mimiVaultRoom, didCommDevice }
}

async function capabilityFromResponse(value: unknown, pending: DidMdPendingAuthorization): Promise<{ capability: { document: unknown; proof: unknown }; expiresAt: string; scope: string[]; credential: MlsDeviceCredentialV2; credentialWire: string; mimiVaultRoom: DidMdBisetMimiVaultRoom; didCommDevice?: NonNullable<DidMdPendingAuthorization['bisetDidCommDevice']> }> {
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
  const detail = bisetCapabilityDetail(document.authorizationDetails, pending)
  const credentialWire = detail.credentialWire
  const credential = await validateBisetMlsCredential(credentialWire, pending)
  return { capability: { document, proof }, expiresAt: document.expiresAt, scope: document.scope as string[], credential, credentialWire, mimiVaultRoom: detail.mimiVaultRoom, didCommDevice: detail.didCommDevice }
}

async function tokenFrom(response: Response, pending: DidMdPendingAuthorization): Promise<DidMdActiveSession> {
  if (!response.ok) throw new Error(await response.text())
  const value = asObject(await response.json(), 'token response')
  const nonce = response.headers.get('dpop-nonce')
  if (typeof value.access_token !== 'string' || value.token_type !== 'DPoP' || value.sub !== pending.did || typeof value.expires_in !== 'number' || !nonce) throw new Error('did.md returned an invalid token response')
  const capability = await capabilityFromResponse(value.device_capability, pending)
  const session: DidMdDeviceSession = {
    v: 2, issuer: pending.issuer, clientId: pending.clientId, did: pending.did, handle: pending.handle,
    verificationMethod: pending.verificationMethod, rootPublicKey: pending.rootPublicKey, deviceJkt: pending.deviceJkt,
    privateKey: pending.privateKey, publicJwk: pending.publicJwk, capability: capability.capability, capabilityExpiresAt: capability.expiresAt,
    bisetDevice: { ...pending.bisetDevice, credentialWire: capability.credentialWire, mimiVaultRoom: capability.mimiVaultRoom, mimiVaultRoomCreated: pending.bisetMimiVaultRoomCreated },
    ...(capability.didCommDevice ? { bisetDidCommDevice: capability.didCommDevice } : {}),
  }
  await saveDidMdDeviceSession(session)
  return { did: session.did, handle: session.handle, clientId: session.clientId, deviceJkt: session.deviceJkt, capabilityExpiresAt: session.capabilityExpiresAt, accessToken: value.access_token, nonce, scope: capability.scope, deviceKid: capability.credential.deviceKid, mimiVaultRoom: capability.mimiVaultRoom, ...(capability.didCommDevice ? { didCommKid: capability.didCommDevice.xKid } : {}) }
}

function pendingFromSession(session: DidMdDeviceSession): DidMdPendingAuthorization {
  return {
    v: 2, issuer: session.issuer, clientId: session.clientId, state: '', codeVerifier: '', did: session.did,
    handle: session.handle, verificationMethod: session.verificationMethod, rootPublicKey: session.rootPublicKey,
    deviceJkt: session.deviceJkt, privateKey: session.privateKey, publicJwk: session.publicJwk,
    bisetDevice: session.bisetDevice ?? (() => { throw new Error('This did.md Wallet session predates Biset device enrollment; connect it again.') })(),
    bisetMimiVaultRoom: session.bisetDevice?.mimiVaultRoom ?? (() => { throw new Error('This did.md Wallet session predates Biset Vault enrollment; connect it again.') })(),
    bisetMimiVaultRoomCreated: session.bisetDevice?.mimiVaultRoomCreated ?? false,
    ...(session.bisetDidCommDevice ? { bisetDidCommDevice: session.bisetDidCommDevice } : {}),
    createdAt: '',
  }
}

async function redirectToWallet(client: DidMdRegistration, pending: DidMdPendingAuthorization): Promise<never> {
  await saveDidMdPendingAuthorization(pending)
  const request = new URL(client.authorizationEndpoint)
  const params = new URLSearchParams({
    client_id: pending.clientId, redirect_uri: client.redirectUri, response_type: 'code', state: pending.state,
    code_challenge: await sha256Base64url(pending.codeVerifier), code_challenge_method: 'S256',
    login_hint: pending.handle, dpop_jkt: pending.deviceJkt, scope: REQUESTED_SCOPES.join(' '),
    authorization_details: JSON.stringify([{
      type: BISET_DEVICE_AUTHORIZATION_DETAIL,
      mlsPublicKey: base64url(pending.bisetDevice.signaturePublicKey),
      mimiVaultRoom: pending.bisetMimiVaultRoom,
      ...(pending.bisetDidCommDevice ? {
        didCommDevice: {
          publicKey: base64url(pending.bisetDidCommDevice.x25519PublicKey),
          mediatorUrl: pending.bisetDidCommDevice.mediatorUrl,
          routingKid: pending.bisetDidCommDevice.routingKid,
        },
      } : {}),
    }]),
  })
  request.search = params.toString()
  if (location.protocol === 'file:') {
    const popup = window.open(request.toString(), 'did-md-wallet')
    if (!popup) throw new Error('Allow popups to continue with did.md Wallet from a packaged Biset file')
    return await new Promise<never>((_resolve, reject) => {
      const timer = window.setInterval(() => {
        const active = fileWalletPopup
        if (active?.popup === popup) void pollFileWalletCallback(active)
        if (!popup.closed) return
        window.clearInterval(timer)
        if (fileWalletPopup?.popup === popup) fileWalletPopup = undefined
        reject(new Error('did.md Wallet popup was closed before authorization completed'))
      }, 500)
      const active: FileWalletPopup = { popup, timer, reject, client, pending, polling: false }
      fileWalletPopup = active
      void pollFileWalletCallback(active)
    })
  }
  location.assign(request.toString())
  throw new Error('The browser did not navigate to did.md Wallet')
}

export async function beginDidMdWalletLogin(rawHandle: string, mimiSelfBaseUrl: string, mediatorUrls: readonly string[] = []): Promise<never> {
  const handle = didMdHandle(rawHandle)
  const document = await resolveByDomain(handle, undefined, { cache: 'no-store' })
  const identity = await rootAuthority(handle, document)
  const client = await registration()
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']) as CryptoKeyPair
  const publicJwk = p256PublicJwk(await crypto.subtle.exportKey('jwk', pair.publicKey))
  const signaturePrivateKey = ed25519.utils.randomSecretKey()
  const signaturePublicKey = ed25519.getPublicKey(signaturePrivateKey)
  const requestedVault = await bisetMimiVaultRoomFor(identity.did, mimiSelfBaseUrl)
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
    deviceJkt: await p256Jkt(publicJwk), privateKey: pair.privateKey, publicJwk, bisetDevice, bisetMimiVaultRoom, bisetMimiVaultRoomCreated: requestedVault.created,
    ...(bisetDidCommDevice ? { bisetDidCommDevice } : {}),
    createdAt: new Date().toISOString(),
  }
  return redirectToWallet(client, pending)
}

/** A current Wallet session can add a DIDComm device without replacing its
 * Biset MLS leaf or allocating a second Vault member. The new capability
 * carries the exact X25519 public key and mediator route that the Wallet
 * publishes under its current Sign key. */
export async function beginDidMdWalletMessagingEnrollment(mediatorUrls: readonly string[]): Promise<never> {
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
  if (state !== pending.state || issuer !== pending.issuer) { await clearDidMdPendingAuthorization(); throw new Error('did.md Wallet callback state or issuer did not match') }
  if (error) { await clearDidMdPendingAuthorization(); throw new Error(callback.searchParams.get('error_description') ?? `did.md Wallet authorization failed: ${error}`) }
  if (!code || !/^code_[A-Za-z0-9_-]{32,128}$/.test(code)) { await clearDidMdPendingAuthorization(); throw new Error('did.md Wallet callback has no valid authorization code') }
  const client = await registration()
  if (client.clientId !== pending.clientId || client.redirectUri !== redirectUri()) { await clearDidMdPendingAuthorization(); throw new Error('did.md Wallet client registration changed during authorization') }
  const response = await fetch(client.tokenEndpoint, {
    method: 'POST', headers: { 'content-type': 'application/json', dpop: await createDpop(pending.privateKey, pending.publicJwk, 'POST', client.tokenEndpoint) },
    body: JSON.stringify({ grant_type: 'authorization_code', client_id: client.clientId, code, code_verifier: pending.codeVerifier, redirect_uri: client.redirectUri }),
  })
  try {
    const active = await tokenFrom(response, pending)
    history.replaceState(null, '', location.protocol === 'file:' ? redirectUri() : '/')
    return active
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
  return tokenFrom(response, pending)
}

export async function disconnectDidMdWallet(): Promise<void> {
  await Promise.all([clearDidMdPendingAuthorization(), clearDidMdDeviceSession()])
}

/** Opens only this browser's Biset leaf material.  The Wallet's controller
 * keys never occur in this database or return value. */
export async function openDidMdWalletBisetDevice(): Promise<DidMdBisetDevice> {
  const session = await readDidMdDeviceSession()
  if (!session?.bisetDevice || session.v !== 2) throw new Error('Connect did.md Wallet again to enroll this Biset device')
  const credential = await validateBisetMlsCredential(session.bisetDevice.credentialWire, pendingFromSession(session))
  const privateMaterial = await openDidMdBisetDeviceMaterial(session.bisetDevice)
  const derivedPublic = ed25519.getPublicKey(privateMaterial.signaturePrivateKey)
  if (!derivedPublic.every((byte, index) => byte === credential.signaturePublicKey[index])) throw new Error('Biset device private key does not match its Wallet credential')
  return {
    did: session.did,
    rootPublicKey: session.rootPublicKey.slice(),
    credential,
    ...privateMaterial,
    mimiVaultRoom: session.bisetDevice.mimiVaultRoom,
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
  if (!derivedPublic.every((byte, index) => byte === stored.x25519PublicKey[index])) throw new Error('Biset DIDComm private key does not match its Wallet-authorized public key')
  if (stored.xKid !== deviceKid(session.did, derivedPublic)) throw new Error('Biset DIDComm device key identifier is invalid')
  return { did: session.did, xKid: stored.xKid, x25519PrivateKey: privateMaterial.x25519PrivateKey, mediatorUrl: stored.mediatorUrl, routingKid: stored.routingKid }
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
