// The mediator's DID. Its keys never change, but it can be named two ways:
//
//  - did:web:{host} -- what a recipient's DID document names as its endpoint
//    (DIDComm Messaging v2.1, "Using a DID as an endpoint"). The document
//    lists the mediator's keys and URL, so it can move or rotate without every
//    recipient's DID document being rewritten.
//  - the did:peer:2 of the same keys -- what was published before (a recipient
//    naming the mediator by URL plus a did:peer routing key), and what a
//    private relationship embeds. It stays accepted, and is listed as an
//    `alsoKnownAs` alias of the did:web, so a client holding either works.
import { encodeX25519Multikey } from '../../protocol/didcomm/multikey.ts'
import { encodeMultikey } from '../../protocol/webvh/multikey.ts'
import type { PeerIdentity } from '../../protocol/didcomm/peer.ts'

export interface MediatorIdentity {
  did: string
  /** The key a Forward or a request is encrypted to. */
  xKid: string
  /** The key a signed problem report is signed with. */
  edKid: string
  xPub: Uint8Array
  edPub: Uint8Array
  xPriv: Uint8Array
  edPriv: Uint8Array
  /** What `GET /.well-known/did.json` serves. */
  doc: unknown
  /** Other kids that name the same X25519 key: also accepted when a message is opened. */
  aliasKids: string[]
  /** The did:peer:2 kid of that key (relationships and hop chains embed it). */
  peerKid: string
}

/** `https://host[:port][/path]` -> `did:web:host[%3Aport][:path]` (the did:web
 * method-specific rules). */
export function didWebForUrl(publicUrl: string): string {
  const url = new URL(publicUrl)
  if (url.protocol !== 'https:') throw new TypeError('a did:web mediator needs an https URL')
  const segments = url.pathname.split('/').filter(Boolean)
  return `did:web:${url.hostname}${url.port ? `%3A${url.port}` : ''}${segments.map(segment => `:${segment}`).join('')}`
}

/** A mediator that is its own did:peer (no did:web): what a test, or a mediator
 * deployed without a hostname, is. */
export function peerMediatorIdentity(peer: PeerIdentity): MediatorIdentity {
  return { did: peer.did, xKid: peer.xKid, edKid: peer.edKid, xPub: peer.xPub, edPub: peer.edPub, xPriv: peer.xPriv, edPriv: peer.edPriv, doc: peer.doc, aliasKids: [], peerKid: peer.xKid }
}

/** The same keys, named by the did:web of `publicUrl`; `peer` is their did:peer. */
export function webMediatorIdentity(peer: PeerIdentity, publicUrl: string): MediatorIdentity {
  const did = didWebForUrl(publicUrl)
  const xKid = `${did}#key-1`
  const edKid = `${did}#key-2`
  const doc = {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'],
    id: did,
    alsoKnownAs: [peer.did],
    verificationMethod: [
      { id: '#key-1', type: 'Multikey', controller: did, publicKeyMultibase: encodeX25519Multikey(peer.xPub) },
      { id: '#key-2', type: 'Multikey', controller: did, publicKeyMultibase: encodeMultikey(peer.edPub) },
    ],
    keyAgreement: ['#key-1'],
    authentication: ['#key-2'],
    assertionMethod: ['#key-2'],
    service: [{ id: '#didcomm', type: 'DIDCommMessaging', serviceEndpoint: { uri: new URL(publicUrl).origin + new URL(publicUrl).pathname.replace(/\/$/, ''), accept: ['didcomm/v2'] } }],
  }
  return { did, xKid, edKid, xPub: peer.xPub, edPub: peer.edPub, xPriv: peer.xPriv, edPriv: peer.edPriv, doc, aliasKids: [peer.xKid], peerKid: peer.xKid }
}
