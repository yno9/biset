// External Feed Post -- an anoncrypt-only, anonymous DIDComm message type
// distinct from Basic Message 2.0 (basicmessage.ts). Carries a post from an
// ActivityPub/AT Protocol actor the user follows, relayed by a bridge that
// does not (yet) have a signing identity of its own to authenticate as
// (three-way biset/AP/AT identity binding is future work -- see the
// 2026-09 DIDComm bridge discussion). Basic Message's ingestion path is
// deliberately scoped to 1:1 authenticated chat between two known DIDs
// (confirmed with the user, 2026-08-25) and has no concept of an anonymous,
// many-sources feed, so this is its own message type and its own ingress
// branch rather than a hack on top of that one.
//
// Threaded by `actor_id` (the followed actor's AP actor URI or ATP DID),
// NOT by a resolved sender DID -- there isn't one, and isn't meant to be:
// the whole point of anoncrypt here is that the mediator (and, by
// construction, anyone inspecting the DIDComm envelope alone) never learns
// who is bridging this. The actor identity lives in the plaintext body,
// same trust level as the body text itself -- unauthenticated, exactly what
// anoncrypt promises and nothing more.
export const EXTERNAL_FEED_POST = 'https://biset.md/external-feed/1.0/post'

export function isExternalFeedPost(msg: { type?: string }): boolean {
  return msg.type === EXTERNAL_FEED_POST
}

export interface ExternalFeedPostBody {
  content: string
  /** Which federated protocol this actor was followed through. */
  source: 'activitypub' | 'atproto' | 'rss'
  /** The followed actor's own identifier: an ActivityPub actor URI, an
   * ATP DID, or an RSS/Atom feed URL. Unauthenticated -- see this file's
   * header. */
  actorId: string
  actorName?: string
  title?: string
  url: string
  publishedAt: string
}

export function externalFeedPostBodyOf(msg: { body?: unknown }): ExternalFeedPostBody | null {
  const body = msg.body
  if (typeof body !== 'object' || body === null) return null
  const b = body as Record<string, unknown>
  const { content, source, actor_id: actorId, url, published_at: publishedAt } = b
  if (typeof content !== 'string') return null
  if (source !== 'activitypub' && source !== 'atproto' && source !== 'rss') return null
  if (typeof actorId !== 'string') return null
  if (typeof url !== 'string') return null
  if (typeof publishedAt !== 'string') return null
  const actorName = b.actor_name
  const title = b.title
  return {
    content,
    source,
    actorId,
    url,
    publishedAt,
    ...(typeof actorName === 'string' ? { actorName } : {}),
    ...(typeof title === 'string' ? { title } : {}),
  }
}

/** One thread per followed actor, matching basicmessage.ts's
 * didCommThreadId shape (a stable, order-independent-looking id string) but
 * keyed by `(identityId, source, actorId)` instead of a DID pair -- there is
 * no counterparty DID to sort against here. */
export function externalFeedThreadId(identityId: string, source: string, actorId: string): string {
  return ['external-feed', identityId, source, actorId].join('|')
}
