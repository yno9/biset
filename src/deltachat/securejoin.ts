// ── DeltaChat SecureJoin (setup-contact, protocol v3) ─────────────────────────
//
// Implements the *inviter* (Alice) side of DeltaChat's SecureJoin v3 so a
// DeltaChat / chatmail contact can add biset by opening an invite URL — no
// manual public-key extraction from a DeltaChat DB export.
//
// Reference: deltachat-core-rust src/securejoin.rs (+ bob.rs, qrinvite.rs).
//
// URL (v3): https://i.delta.chat/#<FP>&v=3&i=<invitenumber>&s=<auth>&a=<addr>&n=<name>
//   FP  = biset key fingerprint, uppercase 40-hex (== DeltaChat Fingerprint::hex())
//   inv = InviteNumber token, auth = Auth token (both create_id(): 18B URL-safe b64)
//
// v3 handshake, biset = Alice:
//   1. Bob opens URL, has no key for us → sends `vc-request-pubkey`
//      (symmetric SEIPDv2/OCB/AES128, shared secret `securejoin/<FP>/<auth>`).
//   2. we reply `vc-pubkey` (same symmetric secret, signed, our key in Autocrypt).
//   3. Bob now has our key → sends `vc-request-with-auth` (normal E2E, his key via
//      Autocrypt, Secure-Join-Auth + Secure-Join-Fingerprint).
//   4. we verify auth+fingerprint, learn his key, reply `vc-contact-confirm`
//      (E2E, gossiping his key back so his self-gossip guard passes).
//
// All Secure-Join* headers are *protected* (live inside the encrypted MIME);
// DeltaChat ignores any cleartext copies (securejoin.rs get_secure_join_step).

import type { AccountSession } from '../types.ts'
import * as openpgp from 'openpgp'
import { getKeyRecord } from '../pgp/keys.ts'
import { symmDecryptMime, symmEncryptSignMime, encryptMimeE2E, getRecipientKey, type DecryptedMime } from '../pgp/crypto.ts'
import * as jmapSubmission from '../jmap/submission.ts'
import * as storeIdentities from '../store/identities.ts'
import * as storeMailboxes from '../store/mailboxes.ts'

// ── invite token store (localStorage, per self email) ─────────────────────────

interface Invite { invitenumber: string; auth: string; createdAt: number }

const inviteKey = (email: string) => `biset_securejoin_invites:${email.toLowerCase()}`

function loadInvites(email: string): Invite[] {
  try { return JSON.parse(localStorage.getItem(inviteKey(email)) ?? '[]') as Invite[] } catch { return [] }
}

function saveInvites(email: string, invites: Invite[]): void {
  localStorage.setItem(inviteKey(email), JSON.stringify(invites))
}

// create_id(): 18 random bytes → URL-safe base64, no padding (24 chars).
function createId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(18))
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

async function selfFingerprint(email: string): Promise<string | null> {
  const record = await getKeyRecord(email)
  if (!record) return null
  const key = await openpgp.readKey({ armoredKey: record.publicKey })
  return key.getFingerprint().toUpperCase()
}

async function selfPublicKey(email: string): Promise<openpgp.PublicKey | null> {
  const record = await getKeyRecord(email)
  if (!record) return null
  return openpgp.readKey({ armoredKey: record.publicKey })
}

const sharedSecret = (fpUpper: string, auth: string) => `securejoin/${fpUpper}/${auth}`

// ── invite URL generation ─────────────────────────────────────────────────────

export async function newInviteUrl(email: string, name: string): Promise<string | null> {
  const fp = await selfFingerprint(email)
  if (!fp) return null
  const invitenumber = createId()
  const auth = createId()
  const invites = loadInvites(email)
  invites.push({ invitenumber, auth, createdAt: Date.now() })
  saveInvites(email, invites)
  const a = encodeURIComponent(email)
  const n = encodeURIComponent(name || email).replace(/%20/g, '+')
  return `https://i.delta.chat/#${fp}&v=3&i=${invitenumber}&s=${auth}&a=${a}&n=${n}`
}

// ── Autocrypt / gossip header builders (protected, inside encryption) ──────────

function foldKeydata(prefix: string, key: openpgp.PublicKey): string {
  const b64 = btoa(String.fromCharCode(...key.write()))
  const chunks: string[] = []
  for (let i = 0; i < b64.length; i += 72) chunks.push(b64.slice(i, i + 72))
  return prefix + chunks.join('\r\n ') + '\r\n'
}

const autocryptHeader = (addr: string, key: openpgp.PublicKey) =>
  foldKeydata(`Autocrypt: addr=${addr}; prefer-encrypt=mutual; keydata=`, key)

const gossipHeader = (addr: string, key: openpgp.PublicKey) =>
  foldKeydata(`Autocrypt-Gossip: addr=${addr}; keydata=`, key)

// ── outgoing send (armored PGP body; go-jmapsmtp wraps as PGP/MIME) ────────────

async function sendArmored(session: AccountSession, to: string, armored: string): Promise<boolean> {
  const { jmapClient: client, jmapAccountId: accountId, account } = session
  const mailbox = storeMailboxes.byName(account.email) ?? storeMailboxes.all()[0]
  if (!mailbox) return false
  const identity = storeIdentities.all().find(i => (i.email as string) === account.email) ?? storeIdentities.all()[0]
  if (!identity) return false
  const draft: Record<string, any> = {
    mailboxIds: { [mailbox.id as string]: true },
    keywords: { $draft: true },
    from: [{ email: account.email }],
    to: [{ email: to }],
    subject: 'Secure-Join',
    textBody: [{ partId: '1', type: 'text/plain' }],
    bodyValues: { '1': { value: armored, isEncodingProblem: false, isTruncated: false } },
  }
  try {
    await jmapSubmission.send(client, accountId, draft, identity.id as string)
    return true
  } catch (e) { console.log('[securejoin] send failed', e); return false }
}

// ── step dispatch ─────────────────────────────────────────────────────────────

// Handles an incoming message if it is a SecureJoin handshake step.
// `decrypted` is the E2E-decrypted MIME (or null if PK-decryption failed — the
// symmetric vc-request-pubkey case, retried here with candidate passwords).
// Returns true if the message was a handshake message (caller should not surface
// it in the UI and should delete it from the server).
export async function maybeHandleSecurejoin(
  session: AccountSession,
  from: string,
  rawBody: string,
  decrypted: DecryptedMime | null,
): Promise<boolean> {
  const self = session.account.email

  // E2E steps: vc-request-with-auth (Bob → us). Present only if E2E decrypt worked.
  if (decrypted) {
    const e2eStep = decrypted.headers?.['secure-join']
    if (e2eStep === 'vc-request-with-auth') {
      await handleRequestWithAuth(session, from, decrypted)
      return true
    }
    return false // normal (non-securejoin) mail — leave for the inbox
  }

  // Symmetric step: vc-request-pubkey. Only PGP messages that FAILED E2E decrypt
  // (symmetric SEIPD has no PKESK for our key) are candidates.
  if (!rawBody.includes('-----BEGIN PGP MESSAGE-----')) return false
  const invites = loadInvites(self)
  if (!invites.length) return false
  const fp = await selfFingerprint(self)
  if (!fp) return false
  const passwords = invites.map(inv => sharedSecret(fp, inv.auth))
  const symm = await symmDecryptMime(rawBody, passwords)
  if (!symm) return false
  if (symm.headers?.['secure-join'] === 'vc-request-pubkey') {
    await handleRequestPubkey(session, from, symm)
    return true
  }
  return true // decrypted with our invite secret but unknown step — swallow
}

// Step 2 (Alice): got vc-request-pubkey → reply vc-pubkey (symmetric, our key).
async function handleRequestPubkey(session: AccountSession, from: string, symm: DecryptedMime): Promise<void> {
  const self = session.account.email
  const auth = symm.headers?.['secure-join-auth']
  if (!auth) { console.log('[securejoin] vc-request-pubkey missing auth'); return }
  const invites = loadInvites(self)
  if (!invites.some(inv => inv.auth === auth)) { console.log('[securejoin] bad auth'); return }
  const fp = await selfFingerprint(self)
  const pub = await selfPublicKey(self)
  if (!fp || !pub) return
  const inner =
    'Content-Type: text/plain; charset=utf-8\r\n' +
    autocryptHeader(self, pub) +
    'Secure-Join: vc-pubkey\r\n' +
    `Secure-Join-Auth: ${auth}\r\n` +
    '\r\nSecure-Join'
  const armored = await symmEncryptSignMime(inner, sharedSecret(fp, auth), self)
  if (!armored) { console.log('[securejoin] vc-pubkey encrypt failed'); return }
  const ok = await sendArmored(session, from, armored)
  console.log('[securejoin] vc-pubkey →', from, ok)
}

// Steps 5+6 (Alice): got vc-request-with-auth → verify, reply vc-contact-confirm.
async function handleRequestWithAuth(session: AccountSession, from: string, dec: DecryptedMime): Promise<void> {
  const self = session.account.email
  const { account } = session
  const auth = dec.headers?.['secure-join-auth']
  const fpr = dec.headers?.['secure-join-fingerprint']
  if (!auth || !fpr) { console.log('[securejoin] request-with-auth missing auth/fpr'); return }
  const invites = loadInvites(self)
  if (!invites.some(inv => inv.auth === auth)) { console.log('[securejoin] bad auth (request-with-auth)'); return }

  // Bob's key was learned from the Autocrypt header (session.ts uploadPeerKey).
  const bobKey = await getRecipientKey(from, account.serverUrl, self, account.password)
  if (!bobKey) { console.log('[securejoin] no key for', from); return }
  if (bobKey.getFingerprint().toUpperCase() !== fpr.toUpperCase()) {
    console.log('[securejoin] fingerprint mismatch', from); return
  }

  const inner =
    'Content-Type: text/plain; charset=utf-8\r\n' +
    'Secure-Join: vc-contact-confirm\r\n' +
    gossipHeader(from, bobKey) +
    '\r\nSecure-Join'
  const armored = await encryptMimeE2E(inner, [bobKey], self)
  if (!armored) { console.log('[securejoin] vc-contact-confirm encrypt failed'); return }
  const ok = await sendArmored(session, from, armored)
  console.log('[securejoin] vc-contact-confirm →', from, ok, '(verified)')
}
