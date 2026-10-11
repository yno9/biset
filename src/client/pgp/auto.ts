// A new account gets its OpenPGP key without being asked. The address is
// known (`label@apex`), so the only question is whether a key already exists:
// in this Vault (or about to arrive from a sibling device), or published at the
// address's WKD (RFC 9580 / draft-koch-openpgp-webkey-service, direct method).
// The published copy is what makes this safe on a second device: a key made
// elsewhere is found there, so it is never replaced by a second one.

const ZBASE32 = 'ybndrfg8ejkmcpqxot1uwisza345h769'

/** The WKD hash of a local part: z-base-32 of the SHA-1 of its lower-cased UTF-8. */
export async function wkdHash(localPart: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-1', new TextEncoder().encode(localPart.toLowerCase())))
  let out = ''
  let bits = 0
  let value = 0
  for (const byte of digest) {
    value = value << 8 | byte
    bits += 8
    while (bits >= 5) { out += ZBASE32[value >> (bits - 5) & 31]; bits -= 5 }
  }
  return out
}

/** `present`: a key is published for the address; `absent`: the directory answers and has none;
 * `unknown`: no usable answer (network, CORS, a server that is not a WKD). */
export async function publishedKeyState(address: string, fetchImpl: typeof fetch = fetch): Promise<'present' | 'absent' | 'unknown'> {
  const at = address.lastIndexOf('@')
  if (at <= 0) return 'unknown'
  const local = address.slice(0, at)
  const domain = address.slice(at + 1).toLowerCase()
  try {
    const url = `https://${domain}/.well-known/openpgpkey/hu/${await wkdHash(local)}?l=${encodeURIComponent(local)}`
    const response = await fetchImpl(url, { cache: 'no-store', signal: AbortSignal.timeout(8000) })
    if (response.status === 404) return 'absent'
    if (!response.ok) return 'unknown'
    // Only binary key material counts: a catch-all page answering 200 to everything is not a directory.
    if (!(response.headers.get('content-type') ?? '').toLowerCase().startsWith('application/octet-stream')) return 'unknown'
    return (await response.arrayBuffer()).byteLength > 0 ? 'present' : 'absent'
  } catch {
    return 'unknown'
  }
}

export type AutoPgpOutcome = 'have-key' | 'published-elsewhere' | 'generated' | 'unsure'

export interface AutoPgpInput {
  address: string
  /** Whether this Vault has the account's OpenPGP key. */
  hasKey: () => Promise<boolean>
  /** Makes, stores and publishes the key. */
  generate: () => Promise<void>
  /** Resolves when the first Vault pull from the sibling devices has been answered or has failed. */
  vaultPulled: Promise<unknown>
  /** Time for a sibling's key to land after the pull. */
  settleMs?: number
  wkd?: (address: string) => Promise<'present' | 'absent' | 'unknown'>
  sleep?: (ms: number) => Promise<void>
}

/** Makes the account's key when there is none anywhere. Any doubt means no key is made
 * (the account page's Generate stays available): two keys for one address is the worse outcome. */
export async function ensureOwnPgpKey(input: AutoPgpInput): Promise<AutoPgpOutcome> {
  const wkd = input.wkd ?? (address => publishedKeyState(address))
  const sleep = input.sleep ?? (ms => new Promise<void>(resolve => setTimeout(resolve, ms)))
  if (await input.hasKey()) return 'have-key'
  const state = await wkd(input.address)
  if (state === 'present') return 'published-elsewhere'
  if (state === 'unknown') return 'unsure'
  await input.vaultPulled.catch(() => undefined)
  await sleep(input.settleMs ?? 4000)
  // A sibling's key may have arrived while waiting.
  if (await input.hasKey()) return 'have-key'
  if (await wkd(input.address) !== 'absent') return 'unsure'
  await input.generate()
  return 'generated'
}
