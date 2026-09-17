import { encodeX25519Multikey } from '../../protocol/didcomm/multikey.ts'

export const MAIL_BRIDGE_DID = 'did:web:smtp.did.md'
export const MAIL_BRIDGE_ENDPOINT = 'https://smtp.did.md/v1/mail'

/** The relay's stable X25519 key is the public key in this did:web document.
 * The private half stays exclusively in relay.sqlite. */
export function mailBridgeDidDocument(x25519PublicKey: Uint8Array): Record<string, unknown> {
  return {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'],
    id: MAIL_BRIDGE_DID,
    verificationMethod: [{
      id: '#key-1', type: 'Multikey', controller: MAIL_BRIDGE_DID,
      publicKeyMultibase: encodeX25519Multikey(x25519PublicKey),
    }],
    keyAgreement: ['#key-1'],
    service: [{
      id: '#didcomm', type: 'DIDCommMessaging',
      serviceEndpoint: { uri: MAIL_BRIDGE_ENDPOINT, accept: ['didcomm/v2'], routingKeys: [] },
    }],
  }
}

/** did:web:did.md is discovery-only; its MailBridge endpoint is resolved as
 * did:web:smtp.did.md before a client encrypts a send request. */
export function mailBridgeDiscoveryDocument(): Record<string, unknown> {
  return {
    '@context': ['https://www.w3.org/ns/did/v1'], id: 'did:web:did.md',
    service: [{ id: '#mail', type: 'MailBridge', serviceEndpoint: { uri: 'https://smtp.did.md', accept: ['didcomm/v2'] } }],
  }
}
