// What this app says it talks to: whom, why, and what leaves the device in it. The network indicator (lft) matches every request against this and
// flags the one that is not here. It is the app's promise to the person, so it is written for a person and kept next to the places the app is
// configured with.
import type { Rule } from 'lft/net-activity'
import { ditoEmbedOrigin } from '../../identity/wallet/dito-embed.ts'
import { readBisetConfig } from './config.ts'

const hostOf = (url: string): string | undefined => { try { return new URL(url).hostname.toLowerCase() } catch { return undefined } }
const WEBFINGER = /^\/\.well-known\/webfinger$/
const DID_DOCUMENT = /^\/\.well-known\/did\.jsonl?$/

export function networkRules(): Rule[] {
  const config = readBisetConfig()
  const own = location.hostname.toLowerCase()
  const identityDomain = config.identityDomain.toLowerCase()
  const wallet = hostOf(ditoEmbedOrigin() ?? '')
  const mediators = [...config.mediatorUrls, ...config.mediatorOnionUrls].map(hostOf).filter((host): host is string => !!host)
  const watchers = config.vhWatchers.map(hostOf).filter((host): host is string => !!host)
  const rules: Rule[] = []

  // This app and its own server: the page itself, the lookup of identity logs (watcher), the mail bridge.
  rules.push({ host: own, path: /^\/log$/, party: { name: 'Log watcher', role: 'keeps copies of identity logs so that a rolled-back one is noticed', kind: 'app' }, purpose: 'Looks up the log of an identity', sends: 'The identity id (public)' , ok: [404] })
  rules.push({ host: own, path: WEBFINGER, party: { name: 'Address lookup', role: 'finds the identity behind a mail address', kind: 'app' }, purpose: 'Looks up who an address belongs to', sends: 'The address you are looking up' , ok: [404] })
  rules.push({ host: own, path: /^\/v1\/mail$/, party: { name: 'Mail bridge', role: 'carries messages to and from ordinary mail', kind: 'app' }, purpose: 'Delivers a message through the mail bridge', sends: 'An end-to-end encrypted message' })
  rules.push({ host: own, path: /^\/[^/]+\/[^/]+\/did\.json$/, party: { name: 'Mail bridge', role: 'carries messages to and from ordinary mail', kind: 'app' }, purpose: 'Reads the identity the bridge holds for an outside address', sends: 'The outside address you write to' , ok: [404] })
  rules.push({ host: own, path: /^\/sw\.js$/, party: { name: 'App server', role: 'where this app was downloaded from', kind: 'app' }, purpose: 'Looks for a newer version of the app' })
  rules.push({ host: own, party: { name: 'App server', role: 'where this app was downloaded from', kind: 'app' }, purpose: 'Loads the app' })

  // The wallet, in its frame (its own requests arrive through the frame's report).
  if (wallet) rules.push({ host: wallet, party: { name: 'Your wallet', role: 'holds your keys; they never leave it', kind: 'app' }, purpose: 'Loads the wallet in its frame' })

  // Log watchers.
  for (const host of watchers) if (host !== own) rules.push({ host, path: /^\/log$/, party: { name: 'Log watcher', role: 'keeps copies of identity logs so that a rolled-back one is noticed', kind: 'app' }, purpose: 'Looks up the log of an identity', sends: 'The identity id (public)' , ok: [404] })

  // Message relays.
  for (const host of mediators) rules.push({ host, party: { name: 'Message relay', role: 'holds your messages until your device fetches them; it cannot read them', kind: 'app' }, purpose: 'Sends or fetches messages', sends: 'End-to-end encrypted messages' })

  // The host the account's address is on: the log of your identity.
  if (identityDomain) {
    rules.push({ host: identityDomain, path: WEBFINGER, party: { name: 'ID host', role: 'keeps the public log of your identity', kind: 'chosen' }, purpose: 'Looks up who an address belongs to', sends: 'The address you are looking up' , ok: [404] })
    rules.push({ host: `*.${identityDomain}`, path: DID_DOCUMENT, party: { name: 'ID host', role: 'keeps the public log of your identity', kind: 'chosen' }, purpose: 'Reads or publishes an identity\'s log' })
    rules.push({ host: `*.${identityDomain}`, party: { name: 'ID host', role: 'keeps the public log of your identity', kind: 'chosen' } })
  }

  // The servers of the people you write to or sign in with: asked where an address or a sign-in app is published.
  rules.push({ host: /./, path: WEBFINGER, party: { name: 'The other person\'s server', role: 'the server of an address you write to', kind: 'third-party' }, purpose: 'Looks up who an address belongs to', sends: 'The address you are writing to' , ok: [404] })
  rules.push({ host: /./, path: DID_DOCUMENT, party: { name: 'The other person\'s server', role: 'the server of an identity you write to', kind: 'third-party' }, purpose: 'Reads the public log of an identity', sends: 'Which person you are looking up' , ok: [404] })

  return rules
}

/** Lines the log adds after its own. */
export const networkNotes: readonly string[] = [
  'Messages are end-to-end encrypted on this device before they are sent; the relay and the bridge carry what they cannot read.',
  'Your keys stay in the wallet, in its own frame, and are never sent anywhere.',
]
