// DIDComm Messaging v2.1 requirements beyond X25519 authcrypt/anoncrypt (ARC.md
// §9.9): HTTP 2xx, A256GCM, the P-256/P-384 key-agreement curves, and signed
// messages (JWS) with EdDSA, ES256 and ES256K.
import { describe, expect, test } from 'bun:test'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { p256, p384 } from '@noble/curves/nist.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { gcm, aeskw } from '@noble/ciphers/aes.js'
import { base58 } from '@scure/base'
import {
  __internal, b64url, didCommAccepted, packAnoncrypt, packAuthcrypt, recipientsForSender, sameCurveRecipients, unpackAnoncrypt, unpackAuthcrypt, type DidCommJWE,
} from '../../src/protocol/didcomm/crypto.ts'
import { decodeKeyAgreementMultikey, encodeKeyAgreementMultikey, keyAgreementKeyFromJwk, jwkOfKeyAgreementKey } from '../../src/protocol/didcomm/key-agreement.ts'
import { keyAgreementRecipients } from '../../src/protocol/didcomm/webvh-route.ts'
import { decodePeerDid2, generatePeerIdentity, peerKeyAgreementRecipients } from '../../src/protocol/didcomm/peer.ts'
import { wrapForwardHops } from '../../src/protocol/didcomm/forward-wrap.ts'
import { authenticationSigningKey, parseDidCommJws, signDidCommMessage, SignatureError, verifyDidCommJws, verifyJwsSignature, type SigningKey } from '../../src/protocol/didcomm/jws.ts'
import { openDidCommPayload } from '../../src/protocol/didcomm/open.ts'
import { buildPlaintext, DidCommSenderMismatchError } from '../../src/protocol/didcomm/message.ts'
import { unpackQueuedMessage } from '../../src/protocol/didcomm/mediator-pickup.ts'
import { verifyFromPrior } from '../../src/protocol/didcomm/from-prior.ts'
import { bytesToBase64url } from '../../src/protocol/canonical.ts'

const utf8 = (s: string) => new TextEncoder().encode(s)
const text = (bytes: Uint8Array) => new TextDecoder().decode(bytes)

function nistKey(curve: typeof p256 | typeof p384) {
  const privateKey = curve.utils.randomSecretKey()
  return { privateKey, publicKey: curve.getPublicKey(privateKey, false) }
}

describe('HTTP transport', () => {
  test('any 2xx is acceptance (202 is only recommended)', () => {
    for (const status of [200, 202, 204]) expect(didCommAccepted(status)).toBe(true)
    for (const status of [301, 400, 413, 500]) expect(didCommAccepted(status)).toBe(false)
  })
})

describe('A256GCM (anoncrypt)', () => {
  test('a third-party anoncrypt envelope with enc A256GCM opens', async () => {
    const recipientPriv = x25519.utils.randomSecretKey()
    const kid = 'did:peer:2.x#key-1'
    const ephemPriv = x25519.utils.randomSecretKey()
    const apv = new Uint8Array(await crypto.subtle.digest('SHA-256', utf8(kid)))
    const header = { typ: 'application/didcomm-encrypted+json', alg: 'ECDH-ES+A256KW', enc: 'A256GCM', apv: b64url(apv), epk: { kty: 'OKP', crv: 'X25519', x: b64url(x25519.getPublicKey(ephemPriv)) } }
    const protectedB64 = b64url(utf8(JSON.stringify(header)))
    const cek = crypto.getRandomValues(new Uint8Array(32))
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const sealed = gcm(cek, iv, utf8(protectedB64)).encrypt(utf8('{"hello":"gcm"}'))
    const kek = __internal.deriveEcdhEs(__internal.ecdh('X25519', ephemPriv, x25519.getPublicKey(recipientPriv)), 'ECDH-ES+A256KW', new Uint8Array(0), apv, 256)
    const jwe: DidCommJWE = {
      protected: protectedB64, recipients: [{ header: { kid }, encrypted_key: b64url(aeskw(kek).encrypt(cek)) }],
      iv: b64url(iv), ciphertext: b64url(sealed.slice(0, -16)), tag: b64url(sealed.slice(-16)),
    }
    expect(text(await unpackAnoncrypt(jwe, { kid, privateKey: recipientPriv }))).toBe('{"hello":"gcm"}')
  })
})

describe('P-256 and P-384 key agreement', () => {
  for (const [name, curve] of [['P-256', p256], ['P-384', p384]] as const) {
    test(`${name}: anoncrypt and authcrypt round trips, every recipient opening its own copy`, async () => {
      const a = nistKey(curve), b = nistKey(curve), sender = nistKey(curve)
      const recipients = [{ kid: 'did:example:r#a', publicKey: a.publicKey, curve: name }, { kid: 'did:example:r#b', publicKey: b.publicKey, curve: name }]
      const anon = packAnoncrypt(utf8('anon'), recipients)
      expect(JSON.parse(text(Uint8Array.from(atob(anon.protected.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)))).epk).toMatchObject({ kty: 'EC', crv: name })
      expect(text(await unpackAnoncrypt(anon, { kid: 'did:example:r#b', privateKey: b.privateKey, curve: name }))).toBe('anon')
      const auth = packAuthcrypt(utf8('auth'), { kid: 'did:example:s#k', privateKey: sender.privateKey, curve: name }, recipients)
      const opened = await unpackAuthcrypt(auth, { kid: 'did:example:r#a', privateKey: a.privateKey, curve: name }, async () => sender.publicKey)
      expect(text(opened.plaintext)).toBe('auth')
      expect(opened.senderKid).toBe('did:example:s#k')
    })
  }

  test('one JWE is one curve: mixed recipients, a sender on another curve, or an epk on another curve are refused', async () => {
    const nist = nistKey(p384)
    const x = x25519.utils.randomSecretKey()
    const mixed = [{ kid: 'a#1', publicKey: x25519.getPublicKey(x) }, { kid: 'a#2', publicKey: nist.publicKey, curve: 'P-384' as const }]
    expect(() => packAnoncrypt(utf8('m'), mixed)).toThrow('different curves')
    expect(() => packAuthcrypt(utf8('m'), { kid: 's#1', privateKey: x }, [mixed[1]!])).toThrow('ECDH-1PU needs one curve')
    const jwe = packAnoncrypt(utf8('m'), [mixed[1]!])
    await expect(unpackAnoncrypt(jwe, { kid: 'a#2', privateKey: x })).rejects.toThrow('the epk is P-384')
  })

  test('a NIST public key not on the curve is refused', () => {
    const bad = new Uint8Array(65); bad[0] = 0x04; bad[1] = 1
    expect(() => keyAgreementKeyFromJwk({ kty: 'EC', crv: 'P-256', x: b64url(bad.slice(1, 33)), y: b64url(bad.slice(33)) })).toThrow()
  })

  test('the recipients an authcrypt can reach, and the one curve a Forward is wrapped on', () => {
    const recipients = [{ kid: 'a#1', publicKey: new Uint8Array(32) }, { kid: 'a#2', publicKey: nistKey(p256).publicKey, curve: 'P-256' as const }]
    expect(recipientsForSender(recipients, { kid: 's', privateKey: new Uint8Array(32) }).map(r => r.kid)).toEqual(['a#1'])
    expect(() => recipientsForSender([recipients[1]!], { kid: 's', privateKey: new Uint8Array(32) })).toThrow('no key-agreement key on this sender')
    expect(sameCurveRecipients(recipients).map(r => r.kid)).toEqual(['a#1'])
    expect(sameCurveRecipients([recipients[1]!]).map(r => r.kid)).toEqual(['a#2'])
  })

  test('keys are read from a DID document as Multikey or JWK, and from a did:peer:2', () => {
    const p256Key = nistKey(p256), p384Key = nistKey(p384)
    const p384Multikey = encodeKeyAgreementMultikey({ curve: 'P-384', publicKey: p384Key.publicKey })
    expect(decodeKeyAgreementMultikey(p384Multikey).curve).toBe('P-384')
    const doc = {
      id: 'did:web:agent.example', keyAgreement: ['#k1', '#k2'],
      verificationMethod: [
        { id: '#k1', publicKeyMultibase: p384Multikey },
        { id: '#k2', publicKeyJwk: jwkOfKeyAgreementKey({ curve: 'P-256', publicKey: p256Key.publicKey }) },
      ],
    }
    expect(keyAgreementRecipients(doc).map(r => [r.kid, r.curve])).toEqual([['did:web:agent.example#k1', 'P-384'], ['did:web:agent.example#k2', 'P-256']])

    const ed = ed25519.getPublicKey(ed25519.utils.randomSecretKey())
    const peer = `did:peer:2.E${encodeKeyAgreementMultikey({ curve: 'P-256', publicKey: p256Key.publicKey })}.Vz${base58.encode(new Uint8Array([0xed, 0x01, ...ed]))}`
    const decoded = decodePeerDid2(peer)
    expect(peerKeyAgreementRecipients(decoded).map(r => r.curve)).toEqual(['P-256'])
    expect(decoded.authentication).toHaveLength(1)
  })

  test('a Forward to a mediator whose key is P-384 is wrapped on that curve and opens', async () => {
    const mediator = nistKey(p384)
    const inner = packAnoncrypt(utf8('inner'), [{ kid: 'did:example:bob#x', publicKey: x25519.getPublicKey(x25519.utils.randomSecretKey()) }])
    const outer = wrapForwardHops(inner, 'did:example:bob', [{ kid: 'did:web:m.example#key-1', recipients: [{ kid: 'did:web:m.example#key-1', publicKey: mediator.publicKey, curve: 'P-384' }] }])
    const forward = JSON.parse(text(await unpackAnoncrypt(outer, { kid: 'did:web:m.example#key-1', privateKey: mediator.privateKey, curve: 'P-384' })))
    expect(forward.body.next).toBe('did:example:bob')
  })
})

describe('signed messages (JWS)', () => {
  const signer = generatePeerIdentity()
  const resolvePeer = async (kid: string) => authenticationSigningKey(decodePeerDid2(kid.split('#')[0]!) as never, kid)

  test('EdDSA, General and Flattened alike: the signer key must be one its DID\'s authentication references', async () => {
    const message = buildPlaintext('https://didcomm.org/basicmessage/2.0/message', { content: 'signed' }, signer.did)
    const general = signDidCommMessage(message, signer.edKid, signer.edPriv)
    const { payload, signerKid } = await verifyDidCommJws(parseDidCommJws(general)!, resolvePeer)
    expect(JSON.parse(text(payload)).body.content).toBe('signed')
    expect(signerKid).toBe(signer.edKid)
    const flattened = { payload: general.payload, protected: general.signatures[0]!.protected, signature: general.signatures[0]!.signature }
    expect((await verifyDidCommJws(parseDidCommJws(flattened)!, resolvePeer)).signerKid).toBe(signer.edKid)
    // The X25519 key is not an authentication key.
    await expect(verifyDidCommJws(parseDidCommJws(signDidCommMessage(message, signer.xKid, signer.edPriv))!, resolvePeer)).rejects.toBeInstanceOf(SignatureError)
    // A changed payload does not verify.
    await expect(verifyDidCommJws({ ...general, payload: bytesToBase64url(utf8('{"forged":true}')) }, resolvePeer)).rejects.toThrow('does not verify')
  })

  test('ES256 and ES256K verify (EdDSA too); an algorithm that is not the key\'s does not', () => {
    const input = utf8('header.payload')
    const pPriv = p256.utils.randomSecretKey()
    const kPriv = secp256k1.utils.randomSecretKey()
    const eddsa = ed25519.utils.randomSecretKey()
    const keys: Array<[string, SigningKey, Uint8Array]> = [
      ['ES256', { type: 'P-256', publicKey: p256.getPublicKey(pPriv) }, p256.sign(input, pPriv)],
      ['ES256K', { type: 'secp256k1', publicKey: secp256k1.getPublicKey(kPriv) }, secp256k1.sign(input, kPriv)],
      ['EdDSA', { type: 'Ed25519', publicKey: ed25519.getPublicKey(eddsa) }, ed25519.sign(input, eddsa)],
    ]
    for (const [alg, key, signature] of keys) {
      expect(verifyJwsSignature(alg, key, input, signature)).toBe(true)
      expect(verifyJwsSignature(alg === 'EdDSA' ? 'ES256' : 'EdDSA', key, input, signature)).toBe(false)
    }
  })

  test('a signing key from a DID document (Multikey for P-256 and secp256k1, JWK for Ed25519)', () => {
    const pPub = p256.getPublicKey(p256.utils.randomSecretKey())
    const kPub = secp256k1.getPublicKey(secp256k1.utils.randomSecretKey())
    const doc = {
      id: 'did:web:s.example', authentication: ['#p', '#k', '#e'],
      verificationMethod: [
        { id: '#p', publicKeyMultibase: 'z' + base58.encode(new Uint8Array([0x80, 0x24, ...pPub])) },
        { id: '#k', publicKeyMultibase: 'z' + base58.encode(new Uint8Array([0xe7, 0x01, ...kPub])) },
        { id: '#e', publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: b64url(new Uint8Array(32)) } },
        { id: '#not-referenced', publicKeyMultibase: 'z' + base58.encode(new Uint8Array([0x80, 0x24, ...pPub])) },
      ],
    }
    expect(authenticationSigningKey(doc, 'did:web:s.example#p').type).toBe('P-256')
    expect(authenticationSigningKey(doc, 'did:web:s.example#k').type).toBe('secp256k1')
    expect(authenticationSigningKey(doc, 'did:web:s.example#e').type).toBe('Ed25519')
    expect(() => authenticationSigningKey(doc, 'did:web:s.example#not-referenced')).toThrow('is not an authentication key')
  })

  test('opening a payload: authcrypt and signed by the same DID, anoncrypt and signed, and the mismatches that are errors', async () => {
    const message = buildPlaintext('https://didcomm.org/trust-ping/2.0/ping', {}, signer.did)
    const signed = utf8(JSON.stringify(signDidCommMessage(message, signer.edKid, signer.edPriv)))
    expect((await openDidCommPayload(signed, signer.xKid, resolvePeer)).senderKid).toBe(signer.xKid)
    expect((await openDidCommPayload(signed, undefined, resolvePeer))).toMatchObject({ senderKid: signer.edKid, signerKid: signer.edKid })
    await expect(openDidCommPayload(signed, generatePeerIdentity().xKid, resolvePeer)).rejects.toThrow('is not the authcrypt sender')
    const lying = utf8(JSON.stringify(signDidCommMessage({ ...message, from: generatePeerIdentity().did }, signer.edKid, signer.edPriv)))
    await expect(openDidCommPayload(lying, undefined, resolvePeer)).rejects.toBeInstanceOf(DidCommSenderMismatchError)
  })

  test('a queued anoncrypt(sign(message)) is authenticated by its signer; a signed message that was never encrypted too', async () => {
    const own = generatePeerIdentity()
    const message = buildPlaintext('https://didcomm.org/basicmessage/2.0/message', { content: 'x' }, signer.did, own.did)
    const signed = signDidCommMessage(message, signer.edKid, signer.edPriv)
    const queued = packAnoncrypt(utf8(JSON.stringify(signed)), [{ kid: own.xKid, publicKey: own.xPub }])
    const self = { did: own.did, xKid: own.xKid, xPriv: own.xPriv }
    const delivered = await unpackQueuedMessage(queued, 'q1', self, async () => { throw new Error('no authcrypt here') }, resolvePeer)
    expect(delivered?.senderKid).toBe(signer.edKid)
    const bare = await unpackQueuedMessage(signed, 'q2', self, async () => { throw new Error('no authcrypt here') }, resolvePeer)
    expect((bare?.plaintext as { body: { content: string } }).body.content).toBe('x')
  })

  test('from_prior signed with ES256 verifies against the prior DID\'s P-256 authentication key', async () => {
    const priv = p256.utils.randomSecretKey()
    const key: SigningKey = { type: 'P-256', publicKey: p256.getPublicKey(priv) }
    const sub = generatePeerIdentity().did
    const header = bytesToBase64url(utf8(JSON.stringify({ typ: 'JWT', alg: 'ES256', kid: 'did:web:prior.example#p' })))
    const payload = bytesToBase64url(utf8(JSON.stringify({ iss: 'did:web:prior.example', sub, iat: 1 })))
    const jwt = `${header}.${payload}.${bytesToBase64url(p256.sign(utf8(`${header}.${payload}`), priv))}`
    expect((await verifyFromPrior(jwt, sub, async () => key)).prior).toBe('did:web:prior.example')
  })
})
