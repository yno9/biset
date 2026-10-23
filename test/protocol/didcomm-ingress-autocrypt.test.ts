import { describe, expect, test } from 'vitest'
import { x25519 } from '@noble/curves/ed25519.js'
import { equalBytes, sha256Bytes } from '../../src/protocol/canonical.ts'
import type { IngressEnvelopeV1 } from '../../src/protocol/ingress.ts'
import { packAuthcrypt } from '../../src/protocol/didcomm/crypto.ts'
import { buildPlaintext } from '../../src/protocol/didcomm/message.ts'
import { BASIC_MESSAGE } from '../../src/client/didcomm/basicmessage.ts'
import { DidCommIngressProjector } from '../../src/client/didcomm/ingress-projector.ts'
import { createSegmentKey } from '../../src/client/store/vault/objects.ts'
import type { VaultEventAuthor } from '../../src/client/store/vault/events.ts'
import { decryptVaultObject } from '../../src/client/store/vault/objects.ts'
import { armorOfStoredBody } from '../../src/client/pgp/stored.ts'
import { AUTOCRYPT_CONTACT_PROPERTY, autocryptKeyId, contactDisplayName, currentAutocryptKey } from '../../src/client/store/projection/contacts.ts'

const identityId = 'did:webvh:abc123:alice.test.example'
const recipientKid = `${identityId}#k_devicehash`
// What a mail bridge's sender looks like: the DID of the address n@4r.ma.
const bridgeDid = 'did:web:did.md:4r.ma:n'
const senderKid = `${bridgeDid}#key-1`
const KEYDATA = 'xjMEZ5QkSRYJKwYBBAHaRw8BAQdAsKuiml2Fq41/hfeRhnz/7phL7Imk63rySFbLt6NK3/'

const signer: VaultEventAuthor = {
  deviceId: recipientKid,
  async sign(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)) },
  async verify(deviceId, bytes, signature) { return deviceId === recipientKid && equalBytes(signature, await this.sign(bytes)) },
}
const senderX = x25519.utils.randomSecretKey()
const recipientX = x25519.utils.randomSecretKey()
const segmentKey = createSegmentKey()

function projector() {
  const seen = new Set<string>()
  let seq = 0 // events are folded by (time, device, sequence): the sequence must grow, as it does on a device
  return new DidCommIngressProjector({
    identityId, actorDeviceId: recipientKid,
    resolveOwnKey: kid => kid === recipientKid ? { kid: recipientKid, x25519PrivateKey: recipientX } : null,
    async resolveSenderKey() { return x25519.getPublicKey(senderX) },
    async alreadyProcessed(id) { if (seen.has(id)) return true; seen.add(id); return false },
    async nextActorSeq() { return ++seq },
    async initialParents() { return [] },
    async activeSegment() { return { segmentId: 'segment-1', segmentKey } },
    async currentSnapshot() { return { state: 'state-0', mailboxes: [], emails: [], contactCards: [] } },
    signer, now: () => new Date('2026-10-20T00:01:00.000Z'),
  })
}

function envelope(body: Record<string, unknown>, attachments?: Array<{ id: string; data: { base64: string } }>) {
  const plaintext = buildPlaintext(BASIC_MESSAGE, body, bridgeDid, identityId, attachments ? { attachments } : {})
  const payload = new TextEncoder().encode(JSON.stringify(packAuthcrypt(new TextEncoder().encode(JSON.stringify(plaintext)), { kid: senderKid, privateKey: senderX }, [{ kid: recipientKid, publicKey: x25519.getPublicKey(recipientX) }])))
  return {
    version: 1, ingressId: crypto.randomUUID(), protocol: 'didcomm', recipientIdentityId: identityId, recipientDeviceSnapshot: [recipientKid],
    createdAt: '2026-10-20T00:00:00.000Z', expiresAt: '2026-10-21T00:00:00.000Z', transportMetadata: {}, sourceEvidence: new Uint8Array([1]),
    protectedPayload: payload, protectedPayloadHash: sha256Bytes(payload),
  } satisfies IngressEnvelopeV1
}

const autocrypt = { addr: 'n@4r.ma', keydata: KEYDATA, preferEncrypt: 'mutual' }
const dmarc = { dmarc: 'pass', domain: '4r.ma' }

describe('a bridged mail with an Autocrypt key', () => {
  test('its key is written to the sender\'s card, dated by the mail', async () => {
    const result = await projector().verifyAndProject(envelope({ content: 'hi', sentAt: '2026-10-20T00:00:30.000Z', auth: dmarc, autocrypt }))
    const [card] = result.projection.contactCards
    expect(card![AUTOCRYPT_CONTACT_PROPERTY]).toEqual({ keys: { [autocryptKeyId(KEYDATA)]: { keydata: KEYDATA, seenAt: '2026-10-20T00:00:30.000Z', preferEncrypt: 'mutual' } } })
    expect(currentAutocryptKey(card!)).toMatchObject({ keydata: KEYDATA, preferEncrypt: 'mutual' })
  })

  test('not without a DMARC pass, and not for another address than the DID stands for', async () => {
    for (const body of [
      { content: 'hi', autocrypt },
      { content: 'hi', auth: { dmarc: 'fail' }, autocrypt },
      { content: 'hi', auth: dmarc, autocrypt: { ...autocrypt, addr: 'someone@else.example' } },
    ]) {
      const [card] = (await projector().verifyAndProject(envelope(body))).projection.contactCards
      expect(card).toBeDefined()
      expect(card![AUTOCRYPT_CONTACT_PROPERTY]).toBeUndefined()
    }
  })

  test('a message whose sentAt is not a date still lands, dated by its own created_time', async () => {
    const result = await projector().verifyAndProject(envelope({ content: 'hi', sentAt: 'tomorrow-ish', auth: dmarc, autocrypt }))
    const sentAt = result.projection.emails[0]!.sentAt!
    expect(Number.isNaN(Date.parse(sentAt))).toBe(false)
    expect(currentAutocryptKey(result.projection.contactCards[0]!)!.seenAt).toBe(sentAt)
  })

  test('an encrypted mail keeps its armored message in the record, so it can be opened where it is shown', async () => {
    const armor = '-----BEGIN PGP MESSAGE-----\n\nwcBMA0\n=abcd\n-----END PGP MESSAGE-----\n'
    const data = btoa(armor).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
    const result = await projector().verifyAndProject(envelope({ content: 'This message is encrypted with OpenPGP.', encryption: 'openpgp' }, [{ id: 'pgp', data: { base64: data } }]))
    const texts = await Promise.all(result.objects.map(async object => new TextDecoder().decode(await decryptVaultObject(segmentKey, object))))
    const stored = texts.find(text => text.includes('X-Biset-Encrypted'))!
    expect(stored).toContain('This message is encrypted with OpenPGP.')
    expect(armorOfStoredBody(stored)).toBe(armor.trim())
  })

  test('an encrypted mail without armor is just its notice, and an ordinary one is untouched', async () => {
    const bare = await projector().verifyAndProject(envelope({ content: 'notice only', encryption: 'openpgp' }))
    const plain = await projector().verifyAndProject(envelope({ content: 'hello' }))
    for (const [result, text] of [[bare, 'notice only'], [plain, 'hello']] as const) {
      const texts = await Promise.all(result.objects.map(async object => new TextDecoder().decode(await decryptVaultObject(segmentKey, object))))
      expect(texts.some(entry => entry === text)).toBe(true)
      expect(texts.some(entry => entry.includes('X-Biset-Encrypted'))).toBe(false)
    }
  })
})

describe('the name a DID tells in its own message', () => {
  test('is kept on the sender\'s card as signed by it', async () => {
    const [card] = (await projector().verifyAndProject(envelope({ content: 'hi', fromName: 'Keen Llama' }))).projection.contactCards
    expect(contactDisplayName(card!)).toBe('Keen Llama')
  })

  test('a bridged mail\'s name still needs a DMARC pass', async () => {
    const [card] = (await projector().verifyAndProject(envelope({ content: 'hi', fromName: 'Mallory', auth: { dmarc: 'fail' } }))).projection.contactCards
    expect(card && contactDisplayName(card)).toBeUndefined()
  })
})
