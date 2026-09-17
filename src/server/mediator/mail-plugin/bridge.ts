// SMTP -> DIDComm bridge: an inbound message accepted for
// `{username}@{apexDomain}` is resolved straight to a Forward-ready
// outbound envelope, with no spool, relationship credential, or VC layer
// (2026-08-30 redesign -- the did:webvh<->mail mapping is already public,
// so there is nothing left to hide from this mediator).
//
// Split into resolve (network -- RCPT TO time, listener.ts's own
// resolveRecipient) and pack (pure -- DATA time, once per accepted
// recipient) so a multi-recipient SMTP transaction resolves each address
// exactly once, at the point this directory's own mail-smtp-protocol.ts's
// SmtpSession already carries a per-recipient `resolution` from RCPT
// through to acceptIngress (that generic parameter's whole reason for
// existing -- see its own header).
import { didCommRouteFromDocument, absoluteKid } from '../../../protocol/didcomm/webvh-route.ts'
import { resolveByDomain } from '../../../protocol/webvh/resolver.ts'
import { decodeX25519Multikey } from '../../../protocol/didcomm/multikey.ts'
import { buildPlaintext } from '../../../protocol/didcomm/message.ts'
import { packForDelivery, type OutboundDelivery, type RouteEndpoint } from '../route-deliver.ts'
import { MAIL_BRIDGE_INBOUND, mailBridgeInboundBodyToWire, mailBridgeRfc5322Attachment, type MailBridgeInboundBody } from './mail-bridge.ts'
import { identityDomainForMailAddress } from '../../../protocol/webvh/identifier.ts'

export interface MailRecipientRoute {
  toAddress: string
  recipientDid: string
  recipientKid: string
  recipientPublicKey: Uint8Array
  endpoint: RouteEndpoint
}

export type ResolveMailRecipientResult = { ok: true; route: MailRecipientRoute } | { ok: false; error: string }

/** Resolves a did.md address through the colocated authority API.  Unlike the
 * legacy public did.jsonl resolver below, this has no DNS/HTTP document cache:
 * the authority reads its current suffix ledger and log in the same trust
 * domain as the relay. */
export async function resolveDidMdMailRecipientRoute(
  toAddress: string,
  authorityUrl: string,
  relaySecret: string,
  fetchImpl: typeof fetch,
): Promise<ResolveMailRecipientResult> {
  const match = /^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)@did\.md$/i.exec(toAddress)
  if (!match) return { ok: false, error: `${toAddress} is not a did.md address` }
  if (!relaySecret) return { ok: false, error: 'did.md mail authority is not configured' }
  let response: Response
  try {
    response = await fetchImpl(`${authorityUrl.replace(/\/$/, '')}/v1/internal/mail/recipients/${match[1]!.toLowerCase()}`, {
      headers: { 'x-did-md-mail-relay-secret': relaySecret },
    })
  } catch (error) {
    return { ok: false, error: `could not query did.md authority: ${error instanceof Error ? error.message : String(error)}` }
  }
  if (response.status === 404) return { ok: false, error: `${toAddress} does not resolve to an active did.md mailbox` }
  if (!response.ok) return { ok: false, error: `did.md authority rejected recipient lookup (HTTP ${response.status})` }
  let value: Record<string, unknown>
  try {
    const parsed: unknown = await response.json()
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error()
    value = parsed as Record<string, unknown>
  } catch { return { ok: false, error: 'did.md authority returned an invalid recipient route' } }
  if (typeof value.did !== 'string' || typeof value.recipientKid !== 'string' || typeof value.publicKeyMultibase !== 'string'
    || value.endpoint === null || typeof value.endpoint !== 'object' || Array.isArray(value.endpoint)) return { ok: false, error: 'did.md authority returned an incomplete recipient route' }
  const endpoint = value.endpoint as Record<string, unknown>
  if (typeof endpoint.uri !== 'string' || !Array.isArray(endpoint.routingKeys) || endpoint.routingKeys.some(key => typeof key !== 'string')) return { ok: false, error: 'did.md authority returned an invalid DIDComm endpoint' }
  try {
    return {
      ok: true,
      route: {
        toAddress,
        recipientDid: value.did,
        recipientKid: value.recipientKid,
        recipientPublicKey: decodeX25519Multikey(value.publicKeyMultibase),
        endpoint: { uri: endpoint.uri, routingKeys: endpoint.routingKeys as string[] },
      },
    }
  } catch { return { ok: false, error: `${toAddress}'s authority keyAgreement key is not a valid X25519 key` } }
}

/** Resolves `toAddress`'s did:webvh document by domain alone -- the signed
 * log at `{domain}/.well-known/did.jsonl`, with no SCID known up front
 * (`identityDomainForMailAddress` is the deterministic inverse of
 * `mailFromForIdentity`). `resolveByDomain` carries the same trust as a
 * full `resolve()`: every entry is verified against the log's OWN embedded
 * scid and hash chain. What an SMTP listener's RCPT TO handler calls: a
 * `{ ok: false }` here is exactly "no such user" (550).
 *
 * Until 2026-09-16 this read `/.well-known/routing.json` instead. That
 * document is retired, and did.md still serves a 200 with pre-2026-08 junk
 * in it (`{"mimiVaultRoom":...}`, nothing else), so reading it would reject
 * EVERY recipient as "no DIDComm service endpoint published". */
export async function resolveMailRecipientRoute(
  toAddress: string,
  apexDomain: string,
  fetchImpl: typeof fetch,
): Promise<ResolveMailRecipientResult> {
  let domain: string
  try {
    domain = identityDomainForMailAddress(toAddress, apexDomain)
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : String(error) }
  }

  let doc: Awaited<ReturnType<typeof resolveByDomain>>
  try {
    doc = await resolveByDomain(domain, undefined, undefined, fetchImpl)
  } catch (error) {
    return { ok: false, error: `could not resolve ${toAddress}: ${error instanceof Error ? error.message : String(error)}` }
  }
  if (!doc) return { ok: false, error: `${toAddress} does not resolve to a published identity` }

  const { endpoint, keyAgreement: kaVm } = didCommRouteFromDocument(doc)
  if (!endpoint || typeof endpoint.uri !== 'string' || !endpoint.uri) {
    return { ok: false, error: `${toAddress} has no DIDComm service endpoint published` }
  }
  if (!kaVm) return { ok: false, error: `${toAddress} has no keyAgreement key published -- they need to enable DIDComm first` }
  let recipientPublicKey: Uint8Array
  try {
    recipientPublicKey = decodeX25519Multikey(kaVm.publicKeyMultibase)
  } catch {
    return { ok: false, error: `${toAddress}'s published keyAgreement key is not a valid X25519 key` }
  }

  return {
    ok: true,
    route: { toAddress, recipientDid: doc.id, recipientKid: absoluteKid(doc, kaVm.id), recipientPublicKey, endpoint: { uri: endpoint.uri, routingKeys: endpoint.routingKeys } },
  }
}

/** Pure (no network): authcrypts a MAIL_BRIDGE_INBOUND message to an
 * already-resolved recipient route -- `sender` identifies this bridge (a
 * persisted did:peer, `SqliteMediatorStore.loadMailPluginIdentity`, kept
 * separate from a real end-user's DIDComm identity, but present because the
 * client's existing mediator-polling pipeline unpacks every queued item as
 * authcrypt (mediator-pickup.ts's `pickupDeliver`) -- an anoncrypt payload
 * would never decode there). Forward-wraps through the recipient's full hop
 * chain when they published one (didcomm/route-deliver.ts). Throws if the
 * route's own routing keys are malformed -- a listener has already resolved
 * the route once by the time it calls this, so that should not happen in
 * practice, but a caller distrusting a stale/cached route should catch it. */
export function packInboundMailForward(
  route: MailRecipientRoute,
  body: MailBridgeInboundBody,
  sender: { kid: string; privateKey: Uint8Array },
): OutboundDelivery {
  const plaintext = buildPlaintext(MAIL_BRIDGE_INBOUND, mailBridgeInboundBodyToWire(body), sender.kid.split('#', 1)[0], route.recipientDid, {
    attachments: [mailBridgeRfc5322Attachment(body.rawRfc5322)],
  })
  const plaintextBytes = new TextEncoder().encode(JSON.stringify(plaintext))
  return packForDelivery(plaintextBytes, sender, route.recipientKid, route.recipientPublicKey, route.endpoint)
}

export type MailBridgeResult = { ok: true; delivery: OutboundDelivery } | { ok: false; error: string }

/** Convenience one-shot: resolve then pack in a single call, for a direct
 * caller that has no reason to resolve ahead of time (tests, a one-off
 * script). The SMTP listener itself calls `resolveMailRecipientRoute` and
 * `packInboundMailForward` separately instead, so RCPT-time resolution and
 * DATA-time packing don't each redo the same did.jsonl fetch. */
export async function buildInboundMailForward(
  toAddress: string,
  apexDomain: string,
  body: MailBridgeInboundBody,
  sender: { kid: string; privateKey: Uint8Array },
  fetchImpl: typeof fetch,
): Promise<MailBridgeResult> {
  const resolved = await resolveMailRecipientRoute(toAddress, apexDomain, fetchImpl)
  if (!resolved.ok) return resolved
  try {
    return { ok: true, delivery: packInboundMailForward(resolved.route, body, sender) }
  } catch (error) {
    return { ok: false, error: `${toAddress}'s registered mediator routing keys are invalid: ${error instanceof Error ? error.message : String(error)}` }
  }
}
