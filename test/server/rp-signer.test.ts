import { afterAll, expect, test } from 'bun:test'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { ed25519 } from '@noble/curves/ed25519.js'

// biset-rp-signer (PLAN6, ~/did.md/PLAN6-rp-did-authentication.md §0.1bis):
// a stateless service that holds biset's own did:webvh RP signing key and
// signs JAR (RFC 9101) Authorization Request objects on demand, so that
// https://t.biset.md can authenticate itself to did.md by DID instead of a
// DCR client_id/secret embedded in the public browser bundle. These tests
// spawn the real service as a subprocess (same pattern did.md's own
// tests/oauth-loopback.test.ts uses) rather than importing src/server/
// rp-signer/index.ts directly, since that module's top-level Bun.serve()
// call is itself the thing under test.

const dataDir = mkdtempSync(join(tmpdir(), 'biset-rp-signer-'))
const keyFile = join(dataDir, 'rp-did-key.json')
const did = 'did:webvh:z6MkfakeRpScidForTestingOnlyXXXXXXXXXXXX:t.biset.md'
const privateKey = ed25519.utils.randomSecretKey()
writeFileSync(keyFile, JSON.stringify({
  did,
  verificationMethod: `${did}#pass-1`,
  privateKey: Buffer.from(privateKey).toString('base64url'),
}))

const port = 18_700 + Math.floor(Math.random() * 1000)
const base = `http://127.0.0.1:${port}`
const redirectUri = 'https://t.biset.md/wallet/callback'
const allowedOrigin = 'https://t.biset.md'
const server = Bun.spawn({
  cmd: [process.execPath, 'run', 'src/server/rp-signer/index.ts'],
  cwd: new URL('../..', import.meta.url).pathname,
  env: { ...process.env, PORT: String(port), RP_DID_KEY_FILE: keyFile, RP_REDIRECT_URI: redirectUri, RP_SIGNER_ALLOWED_ORIGIN: allowedOrigin },
  stdout: 'ignore',
  stderr: 'ignore',
})

async function ready(): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      if ((await fetch(`${base}/healthz`)).ok) return
    } catch { /* still starting */ }
    await Bun.sleep(20)
  }
  throw new Error('biset-rp-signer did not start')
}

afterAll(async () => {
  server.kill()
  await server.exited
  rmSync(dataDir, { recursive: true, force: true })
})

function base64urlDecode(value: string): Uint8Array {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4)
  return Uint8Array.from(atob(padded), character => character.charCodeAt(0))
}

test('GET /healthz reports the configured RP DID', async () => {
  await ready()
  const response = await fetch(`${base}/healthz`)
  expect(response.status).toBe(200)
  expect(await response.json()).toEqual({ ok: true, did })
})

test('POST /sign returns a JAR whose signature verifies against the RP DID key, with iss/client_id/redirect_uri fixed server-side', async () => {
  await ready()
  const response = await fetch(`${base}/sign`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: allowedOrigin },
    body: JSON.stringify({ state: 'abcdefghijklmnopqrstuvwxyz1234', code_challenge: 'A'.repeat(43), code_challenge_method: 'S256', nonce: 'n-1' }),
  })
  expect(response.status).toBe(200)
  expect(response.headers.get('access-control-allow-origin')).toBe(allowedOrigin)
  const { jwt } = await response.json() as { jwt: string }
  const [headerPart, payloadPart, signaturePart] = jwt.split('.')

  const header = JSON.parse(new TextDecoder().decode(base64urlDecode(headerPart)))
  expect(header).toEqual({ alg: 'EdDSA', typ: 'JWT', kid: `${did}#pass-1` })

  const payload = JSON.parse(new TextDecoder().decode(base64urlDecode(payloadPart)))
  expect(payload).toMatchObject({
    iss: did, client_id: did, client_id_scheme: 'did', response_type: 'code',
    redirect_uri: redirectUri, state: 'abcdefghijklmnopqrstuvwxyz1234',
    code_challenge: 'A'.repeat(43), code_challenge_method: 'S256', nonce: 'n-1',
  })

  const publicKey = ed25519.getPublicKey(privateKey)
  const valid = ed25519.verify(base64urlDecode(signaturePart), new TextEncoder().encode(`${headerPart}.${payloadPart}`), publicKey)
  expect(valid).toBe(true)
})

// A caller must never be able to redirect the resulting JAR anywhere but
// biset's own fixed callback -- the whole reason this endpoint can safely
// skip caller authentication (see the service's own module comment) is that
// redirect_uri is never accepted from the request body.
test('POST /sign ignores a caller-supplied redirect_uri and keeps the fixed one', async () => {
  await ready()
  const response = await fetch(`${base}/sign`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ state: 'abcdefghijklmnopqrstuvwxyz1234', code_challenge: 'A'.repeat(43), code_challenge_method: 'S256', redirect_uri: 'https://evil.example/steal' }),
  })
  expect(response.status).toBe(400)
  expect(await response.text()).toContain('unexpected field: redirect_uri')
})

test('POST /sign rejects an unknown claim rather than silently dropping it', async () => {
  await ready()
  const response = await fetch(`${base}/sign`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ state: 'abcdefghijklmnopqrstuvwxyz1234', code_challenge: 'A'.repeat(43), code_challenge_method: 'S256', scope: 'openid' }),
  })
  expect(response.status).toBe(400)
  expect(await response.text()).toContain('unexpected field: scope')
})

test('OPTIONS preflight and 404 responses both still carry CORS headers', async () => {
  await ready()
  const preflight = await fetch(`${base}/sign`, { method: 'OPTIONS', headers: { origin: allowedOrigin } })
  expect(preflight.status).toBe(204)
  expect(preflight.headers.get('access-control-allow-origin')).toBe(allowedOrigin)

  const notFound = await fetch(`${base}/nope`)
  expect(notFound.status).toBe(404)
  expect(notFound.headers.get('access-control-allow-origin')).toBe(allowedOrigin)
})
