// Recovery-phrase login: 24 words → full identity restore, with no password and
// no need to remember which relays or address (DID.md's "restore on any device"
// — the payoff of rotation-less + seed derivation). The seed alone yields the
// JMAP auth token, the DID, and the PGP KEK; resolving the DID yields the relay
// list + address. So the whole identity rebuilds from the phrase.
import { mnemonicToSeed, isValidMnemonic } from './seed.ts'
import { deriveRootKey, didFromRootPublicKey } from './keys.ts'
import { resolve, PUBLIC_PKARR_FALLBACKS } from './resolver.ts'
import { storeDidRecord, type DidRecord } from './store.ts'
import { deriveNostrKey, deriveDidCommKey } from './keys.ts'
import { relayAuth } from '../cryptenv.ts'
import type { StoredAccount, AccountSession } from '../types.ts'

export interface RestoreResult {
  did: string
  primaryAddress: string
  sessions: AccountSession[]
  kek: Uint8Array
}

const bytesToHex = (b: Uint8Array) => [...b].map(x => x.toString(16).padStart(2, '0')).join('')

// Bootstrap gateways for the very first resolve, before we know the identity's
// own relays: the configured home relays (whose gateways we run) + public ones.
function bootstrapGateways(): string[] {
  const cfg = (window as any).__BISET_CONFIG__ || {}
  const host: string | undefined = cfg.hostname
  const mail = cfg.mail_url || (host ? `https://mail.${host}` : '')
  const ap = cfg.ap_url || (host ? `https://ap.${host}` : '')
  const own = [mail, ap].filter(Boolean).map((u: string) => u.replace(/\/$/, '') + '/pkarr')
  return [...new Set([...own, ...PUBLIC_PKARR_FALLBACKS])]
}

function akaMail(addrs: string[]): string | null {
  for (const a of addrs) if (a.startsWith('mailto:')) return a.slice('mailto:'.length)
  return null
}

// Returns a human-readable error string on failure, or the restored identity.
export async function restoreFromMnemonic(mnemonic: string): Promise<RestoreResult | { error: string }> {
  const phrase = mnemonic.trim().toLowerCase().replace(/\s+/g, ' ')
  if (!isValidMnemonic(phrase)) return { error: 'Invalid recovery phrase (check the 24 words and their order).' }

  const masterSecret = mnemonicToSeed(phrase)
  const root = deriveRootKey(masterSecret)
  const did = didFromRootPublicKey(root.publicKey)

  const doc = await resolve(did, bootstrapGateways())
  if (!doc) return { error: 'No published record found for this identity — its relays may be offline, or it was never published.' }
  if (!doc.service.length) return { error: 'This identity has no relays published.' }

  const kek = (await relayAuth(masterSecret, doc.service[0].serviceEndpoint[0] || '')).kek
  const primaryAddress = akaMail(doc.alsoKnownAs) ?? doc.service[0].address ?? ''

  // Persist the DID record (keyed by the primary address) so grouping/publish
  // work after restore without re-deriving.
  const nostr = deriveNostrKey(masterSecret)
  const didComm = deriveDidCommKey(masterSecret)
  const record: DidRecord = {
    email: primaryAddress || did,
    did,
    rootPublicKey: bytesToHex(root.publicKey),
    rootPrivateKey: bytesToHex(root.privateKey),
    nostrPublicKey: bytesToHex(nostr.publicKey),
    nostrPrivateKey: bytesToHex(nostr.privateKey),
    didCommPublicKey: bytesToHex(didComm.publicKey),
    didCommPrivateKey: bytesToHex(didComm.privateKey),
  }
  await storeDidRecord(record)

  // Connect every relay the DID lists, each at its own address (service.address)
  // and its OWN relay-scoped token (derived from the seed for that host).
  const { initSession } = await import('../jmap/client.ts')
  const sessions: AccountSession[] = []
  for (const svc of doc.service) {
    const serverUrl = svc.serviceEndpoint[0]?.replace(/\/$/, '')
    if (!serverUrl) continue
    const email = svc.address || primaryAddress
    if (!email) continue
    const { password } = await relayAuth(masterSecret, serverUrl)
    const stored: StoredAccount = { serverUrl, email, password, did }
    const session = await initSession(stored).catch(() => null)
    if (session) { session.account.did = did; (session as any).kek = kek; sessions.push(session) }
  }
  if (!sessions.length) return { error: 'Found the identity but could not connect to any of its relays.' }

  return { did, primaryAddress: primaryAddress || sessions[0].account.email, sessions, kek }
}
