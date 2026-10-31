// Reply tokens of a mail bridge (didmail PROTOCOL.md §7.1): the proof, kept with a contact, that this identity may write to its address.
// The bridge makes them (one per contact address, the same each time) and keeps nothing; the client keeps one per contact and sends it
// as `body.replyToken` with every message to that contact. It is opaque here: base64url, an epoch byte and 16 bytes of HMAC (23 characters),
// read loosely so a longer token a later bridge makes is kept as it is.
export const REPLY_TOKEN_PATTERN = /^[A-Za-z0-9_-]{16,64}$/

const MAX_REPLY_TOKENS = 4

/** `{ [bridge DID]: token }` as a bridge puts it in `body.replyTokens` and in the answer to an introduction: the entries that are
 * well formed, at most four; undefined when none is. */
export function replyTokensOf(value: unknown): Record<string, string> | undefined {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return undefined
  const tokens: Record<string, string> = {}
  for (const [did, token] of Object.entries(value).slice(0, MAX_REPLY_TOKENS)) {
    if (did.startsWith('did:') && typeof token === 'string' && REPLY_TOKEN_PATTERN.test(token)) tokens[did] = token
  }
  return Object.keys(tokens).length ? tokens : undefined
}
