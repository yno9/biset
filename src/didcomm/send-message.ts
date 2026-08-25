// Outbound DIDComm send: resolve the recipient's routing.json (keyAgreement
// key + DIDCommMessaging service endpoint), pack a Basic Message 2.0 JWE,
// POST it. Network-only, mirroring core/adapters/mail-smtp-client.ts's own
// split (that module dials out; identity/bootstrap.ts's buildMailSubmitter
// does the vault-commit side separately) -- the local "sent" copy is the
// caller's job, via the already-generic local-jmap/vault-mutation-sink.ts's
// commitMailMessage (no DIDComm-specific vault-commit code needed: a chat
// message's local echo is exactly the same message.add shape mail's own
// sendReply already commits).
import { resolveWithRouting } from './webvh-resolve.ts'
import { decodeX25519Multikey } from './multikey.ts'
import { packAuthcrypt } from './crypto.ts'
import { buildPlaintext } from './message.ts'
import { BASIC_MESSAGE } from './basicmessage.ts'
import { defaultFetch } from '../net-fetch.ts'

export type DidCommSendResult = { ok: true } | { ok: false; error: string }

export interface SendDidCommMessageOptions {
  /** This device's own DIDComm kid (identity/bootstrap.ts's `enableDidComm`
   * -- didcomm/devicekid.ts's deviceKidFragment, distinct from the MLS
   * leaf's own deviceKid). */
  fromKid: string
  x25519PrivateKey: Uint8Array
  subject?: string
  fetch?: typeof fetch
}

/** Sends a chat message to `toDid`. Resolves the recipient's CURRENT
 * keyAgreement key fresh on every send (no caching) -- correctness over
 * speed for a message that only sends once. Picks the first published
 * keyAgreement entry when the recipient has more than one (multi-device):
 * PLAN.md §6.1's per-device-fanout ban means this project deliberately does
 * not address every device individually, and the recipient side's own
 * multidevice-ingress handling (any trusted device may claim the resulting
 * ingress item) is what actually delivers it, same as mail addressed to one
 * identity reaches every device that pulls it. */
export async function sendDidCommMessage(toDid: string, content: string, opts: SendDidCommMessageOptions): Promise<DidCommSendResult> {
  const fetchImpl = opts.fetch ?? defaultFetch()
  let doc: Awaited<ReturnType<typeof resolveWithRouting>>
  try {
    doc = await resolveWithRouting(toDid, fetchImpl)
  } catch (error) {
    return { ok: false, error: `could not resolve ${toDid}: ${error instanceof Error ? error.message : String(error)}` }
  }
  if (!doc) return { ok: false, error: `${toDid} does not resolve to a published identity` }

  const service = doc.service.find(s => s.type === 'DIDCommMessaging')
  const serviceEndpoint = service?.serviceEndpoint
  const endpoint = serviceEndpoint && typeof serviceEndpoint === 'object' && !Array.isArray(serviceEndpoint)
    ? (serviceEndpoint as { uri?: unknown }).uri
    : undefined
  if (typeof endpoint !== 'string' || !endpoint) return { ok: false, error: `${toDid} has no DIDComm service endpoint published` }

  const keyAgreementIds = new Set(doc.keyAgreement ?? [])
  const kaVm = doc.verificationMethod.find(v => keyAgreementIds.has(v.id))
  if (!kaVm) return { ok: false, error: `${toDid} has no keyAgreement key published -- they need to enable DIDComm first` }
  let recipientPublicKey: Uint8Array
  try {
    recipientPublicKey = decodeX25519Multikey(kaVm.publicKeyMultibase)
  } catch {
    return { ok: false, error: `${toDid}'s published keyAgreement key is not a valid X25519 key` }
  }

  const plaintext = buildPlaintext(BASIC_MESSAGE, {
    content, sentAt: new Date().toISOString(), ...(opts.subject ? { subject: opts.subject } : {}),
  })
  const jwe = packAuthcrypt(
    new TextEncoder().encode(JSON.stringify(plaintext)),
    { kid: opts.fromKid, privateKey: opts.x25519PrivateKey },
    { kid: kaVm.id, publicKey: recipientPublicKey },
  )
  const response = await fetchImpl(endpoint, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(jwe) })
  if (response.status !== 202) {
    return { ok: false, error: `send failed: HTTP ${response.status} ${(await response.text().catch(() => '')).slice(0, 256)}` }
  }
  return { ok: true }
}
