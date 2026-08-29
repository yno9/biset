// Client for Anchor's Mail Address Credential issuance endpoints
// (src/anchor/oid4vp.ts's beginMailAddressChallenge/completeMailAddressIssuance).
// Requires an existing Anchor login session (the OID4VP wallet flow,
// src/oid4vp/wallet.ts) -- both requests carry that session's cookie.
import { ed25519 } from '@noble/curves/ed25519.js'
import { bytesToBase64url } from '../protocol/canonical.ts'
import { defaultFetch } from '../net-fetch.ts'

export interface RequestMailAddressCredentialOptions {
  anchorBaseUrl: string
  /** This identity's own, stable did:webvh -- proven to belong to the
   * logged-in session by Anchor itself (its scid must match the
   * session's rootSubject); never appears in the issued credential. */
  did: string
  relationshipDid: string
  relationshipEdPrivateKey: Uint8Array
  fetch?: typeof fetch
}

export async function requestMailAddressCredential(
  options: RequestMailAddressCredentialOptions,
): Promise<{ credential: string; expiresAt: string }> {
  const fetchImpl = options.fetch ?? defaultFetch()
  const base = options.anchorBaseUrl.replace(/\/$/, '')

  const challengeResponse = await fetchImpl(`${base}/oid4vp/mail-address-credential/challenge`, {
    method: 'POST', credentials: 'include', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ relationship_did: options.relationshipDid }),
  })
  if (!challengeResponse.ok) throw new Error(`mail address credential challenge failed: HTTP ${challengeResponse.status}`)
  const challengeBody = await challengeResponse.json() as { challenge?: unknown }
  if (typeof challengeBody.challenge !== 'string' || !challengeBody.challenge) throw new Error('mail address credential challenge response is invalid')

  const signature = bytesToBase64url(ed25519.sign(new TextEncoder().encode(challengeBody.challenge), options.relationshipEdPrivateKey))
  const issueResponse = await fetchImpl(`${base}/oid4vp/mail-address-credential/issue`, {
    method: 'POST', credentials: 'include', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ did: options.did, relationship_did: options.relationshipDid, challenge: challengeBody.challenge, signature }),
  })
  if (!issueResponse.ok) throw new Error(`mail address credential issuance failed: HTTP ${issueResponse.status}`)
  const issueBody = await issueResponse.json() as { credential?: unknown; expires_at?: unknown }
  if (typeof issueBody.credential !== 'string' || !issueBody.credential || typeof issueBody.expires_at !== 'string') throw new Error('mail address credential issuance response is invalid')
  return { credential: issueBody.credential, expiresAt: issueBody.expires_at }
}
