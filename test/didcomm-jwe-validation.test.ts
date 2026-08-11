// A body that is not a DIDComm message must be refused, not decoded.
//
// Reported from the running mediator: POSTing `{}` to the endpoint the DID
// document advertises came back as
//
//   {"error":"TypeError: undefined is not an object (evaluating 's.length')"}
//
// `unpack` did `JSON.parse(raw) as DidCommJWE` — an assertion, not a check —
// and the first field touched (`jwe.protected`, undefined) reached
// `b64urlToBytes`, whose `s.length` threw. The handler then returned
// `String(e)`, naming the runtime and the failing expression to whoever asked.
//
// Two halves are tested: the parser refuses everything that is not a JWE, and
// the mediator answers the reported request with a deliberate refusal.
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { parseJwe, protectedHeaderOf, type DidCommJWE } from '../src/did/didcomm/crypto.ts'
import { createMediator } from '../src/anchor/mediator/server.ts'
import { loadMediatorIdentity } from '../src/anchor/mediator/identity.ts'

let fails = 0
const ok = (name: string, cond: boolean, detail = '') => {
  console.log(`  ${cond ? 'ok  ' : 'FAIL'}  ${name}${cond || !detail ? '' : '\n          → ' + detail}`)
  if (!cond) fails++
}

const b64u = (s: string) => Buffer.from(s, 'utf8').toString('base64url')

/** Runs a predicate that is allowed to throw. A mutation that makes `parseJwe`
 * throw instead of returning `null` should read as a failed expectation here,
 * not as the whole run disappearing at assertion 17. */
const okFn = (name: string, f: () => boolean) => {
  try {
    ok(name, f())
  } catch (e) {
    ok(name, false, `threw instead of answering: ${e}`)
  }
}

/** A structurally valid JWE. Nothing here decrypts — that is not what
 * `parseJwe` decides. */
const wellFormed = (): DidCommJWE => ({
  protected: b64u(JSON.stringify({ alg: 'ECDH-1PU+A256KW', enc: 'A256CBC-HS512' })),
  recipients: [{ header: { kid: 'did:example:a#k1' }, encrypted_key: 'AAAA' }],
  iv: 'AAAA',
  ciphertext: 'AAAA',
  tag: 'AAAA',
})

console.log('=== parseJwe は JWE でないものを通さない ===')
{
  const drop = <T>(o: Record<string, unknown>, k: string) => {
    const c = { ...o }
    delete c[k]
    return c as T
  }
  okFn('the reported body: {}', () => parseJwe({}) === null)
  okFn('null', () => parseJwe(null) === null)
  okFn('an array', () => parseJwe([]) === null)
  okFn('a string', () => parseJwe('not a jwe') === null)
  okFn('a number', () => parseJwe(7) === null)
  for (const field of ['protected', 'iv', 'ciphertext', 'tag', 'recipients']) {
    okFn(`${field} missing`, () => parseJwe(drop(wellFormed() as unknown as Record<string, unknown>, field)) === null)
    okFn(`${field} empty`, () => parseJwe({ ...wellFormed(), [field]: '' }) === null)
    okFn(`${field} wrong type`, () => parseJwe({ ...wellFormed(), [field]: 42 }) === null)
  }
  okFn('recipients empty', () => parseJwe({ ...wellFormed(), recipients: [] }) === null)
  okFn('a recipient with no kid', () => parseJwe({ ...wellFormed(), recipients: [{ header: {}, encrypted_key: 'AAAA' }] }) === null)
  okFn('a recipient with no header', () => parseJwe({ ...wellFormed(), recipients: [{ encrypted_key: 'AAAA' }] }) === null)
  okFn('a recipient with no key', () => parseJwe({ ...wellFormed(), recipients: [{ header: { kid: 'a' } }] }) === null)
  okFn('a recipient that is null', () => parseJwe({ ...wellFormed(), recipients: [null] }) === null)
}

console.log('\n=== …and lets a well-formed one through ===')
{
  const jwe = parseJwe(wellFormed())
  ok('accepted', jwe !== null)
  ok('returned as given', jwe !== null && jwe.ciphertext === 'AAAA')
  // Extra members are the sender's business, not a reason to refuse.
  ok('unknown members do not matter', parseJwe({ ...wellFormed(), aad: 'x' }) !== null)
}

console.log('\n=== protectedHeaderOf — the second thing that used to throw ===')
{
  ok('reads a header', protectedHeaderOf(wellFormed())?.alg === 'ECDH-1PU+A256KW')
  ok('not base64url', protectedHeaderOf({ ...wellFormed(), protected: '!!!!' }) === null)
  ok('not JSON', protectedHeaderOf({ ...wellFormed(), protected: b64u('nope') }) === null)
  ok('JSON, but not an object', protectedHeaderOf({ ...wellFormed(), protected: b64u('[1,2]') }) === null)
}

console.log('\n=== the mediator answers the reported request deliberately ===')
{
  const dir = mkdtempSync(join(tmpdir(), 'jwetest-'))
  const PORT = 8917
  const URL_ = `http://127.0.0.1:${PORT}`
  const mediator = createMediator({
    mediator: loadMediatorIdentity(join(dir, 'identity.json'), URL_),
  })
  const server = Bun.serve({
    port: PORT,
    async fetch(req) {
      return (await mediator.handle(req, new URL(req.url))) ?? new Response('not found', { status: 404 })
    },
  })

  const post = async (body: string) => {
    const r = await fetch(URL_, {
      method: 'POST',
      headers: { 'content-type': 'application/didcomm-encrypted+json' },
      body,
    })
    return { status: r.status, text: await r.text() }
  }

  for (const [name, body] of [
    ['the reported one: {}', '{}'],
    ['not JSON at all', 'hello'],
    ['JSON, not a JWE', '{"hello":"world"}'],
    ['a JWE with an unreadable header', JSON.stringify({ ...wellFormed(), protected: '!!!!' })],
    // Structurally a JWE and readable as far as the header — so it passes
    // every check above and fails *inside* decryption. That is the path where
    // an unexpected throw is still possible, and where returning `String(e)`
    // would hand back the internals. Without this case the "don't echo
    // internals" half of the fix is never exercised.
    ['a well-formed JWE that cannot be decrypted', JSON.stringify(wellFormed())],
  ] as const) {
    const { status, text } = await post(body)
    ok(`${name}: 400`, status === 400, `got ${status} ${text}`)
    ok(`${name}: no runtime detail leaked`, !/TypeError|undefined is not|\.length|at Object|SyntaxError/.test(text), text)
  }

  server.stop(true)
  rmSync(dir, { recursive: true, force: true })
}

console.log(fails === 0 ? '\n  全て通過' : `\n  ${fails} 件失敗`)
if (fails > 0) process.exit(1)
