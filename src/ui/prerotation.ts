// UI glue for did:webvh pre-rotation (src/did/webvh/prerotation.ts's own
// header has the protocol-level why). Four actions, matching the config
// page's toggle + its two buttons (shown while the toggle is ON):
//   runActivatePreRotation   — toggle OFF -> ON
//   runRotateNow             — "Rotate"
//   runRevokeRootKey         — "Revoke"
//   runDeactivatePreRotation — toggle ON -> OFF
//
// THREE NAMED KEYS, no relative wording anywhere user-facing
// (PLANROTATION.md §1.1 — "current"/"latest" was tried and is unfixable,
// since every activate/rotate shows a newer phrase moments later):
//   Root Key   — `#key-1`. Being this identity: restore, device vouch,
//                DIDComm/MLS. Lives on the device.
//   Sign Key   — current `parameters.updateKeys`. Writing the document.
//                Lives on the device (cached). Asked for by Sync/re-activate.
//   Spare Key  — committed in `parameters.nextKeyHashes`, hash only. The sole
//                key that may append the NEXT log entry, so it must live on
//                paper and nowhere else. Asked for by rotate/deactivate/revoke.
//
// Rotating and deactivating both require the SAVED pre-rotation phrase, not
// just an unlocked session — prerotation.ts's resolver-side rule is that the
// CURRENT root key has no authority left at all once pre-rotation is active,
// not even to turn it back off (this took a live back-and-forth to get right
// — the phrase is the ONLY thing that can act for this identity from that
// point on, exactly as final as losing the main recovery phrase).
import { ed25519 } from '@noble/curves/ed25519.js'
import { seedToMnemonic, mnemonicToSeed } from '../did/seed.ts'
import { showMnemonicOnce, promptForMnemonic } from './mnemonic.ts'
import { encodeMultikey } from '../did/webvh/multikey.ts'
import { multikeyHashBase58 } from '../did/webvh/hash.ts'
import {
  activatePreRotation, rotateToPreRotatedKey, deactivatePreRotation,
} from '../did/webvh/prerotation.ts'
import { fetchCurrentLog } from '../did/webvh/publish.ts'
import { hexToBytes, bytesToHex } from '../utils.ts'

interface SpareKeypair { mnemonic: string; privateKey: Uint8Array; publicKey: Uint8Array }

/** A fresh, independent secret — NOT derived from the identity's own seed.
 * That independence is the entire point (see the design discussion this
 * codebase doesn't otherwise record): deriving it from the same seed the
 * root key already comes from would mean whatever exposes the root key
 * (a compromised device, a bad extension) exposes this too, defeating
 * pre-rotation's actual threat model. The 32 random bytes ARE the Ed25519
 * seed directly, same shape did/seed.ts's mnemonic encoding already assumes
 * (entropyToMnemonic/mnemonicToEntropy is a reversible 32-byte encoding, no
 * PBKDF2 stretching — see that file's own note). */
function generateSpareKeypair(): SpareKeypair {
  const seed = crypto.getRandomValues(new Uint8Array(32))
  return { mnemonic: seedToMnemonic(seed), privateKey: seed, publicKey: ed25519.getPublicKey(seed) }
}

/** Persists whichever key just became (or already was confirmed as) the
 * CURRENT updateKeys holder — did/store.ts's DidRecord.signingPrivateKey/
 * signingPublicKey, revealCurrentSigner's own note on why this is safe.
 * Called after every operation that changes or re-verifies that key
 * (rotate, deactivate, revoke, revealCurrentSigner's own prompt path) so
 * routine publishing (Sync) never needs a phrase re-typed for a key this
 * device already legitimately handled once. Best-effort: a failure here
 * only means the NEXT Sync re-prompts, never that the operation itself
 * (which already landed) is in any doubt. */
async function cacheSigningKey(did: string, privateKey: Uint8Array, publicKey: Uint8Array): Promise<void> {
  try {
    const { getDidRecord, storeDidRecord, withDidLock } = await import('../did/store.ts')
    // Locked (store.ts's withDidLock note) — a full-record IndexedDB put
    // with no compare-and-swap means an unlocked read-modify-write here can
    // lose this write to any OTHER concurrent one for the same identity
    // (a boot-time avatar publish, another Sync click) that started earlier
    // but finishes later with a snapshot that predates this one.
    await withDidLock(did, async () => {
      const rec = await getDidRecord(did)
      if (!rec) return
      await storeDidRecord({ ...rec, signingPrivateKey: bytesToHex(privateKey), signingPublicKey: bytesToHex(publicKey) })
    })
  } catch (e) {
    console.warn('[prerotation] cacheSigningKey failed (non-fatal, Sync will re-prompt):', e instanceof Error ? e.message : e)
  }
}

/** Prompts for the saved phrase, derives its keypair, and verifies it
 * against the identity's CURRENT nextKeyHashes commitment — locally, before
 * either rotateToPreRotatedKey or deactivatePreRotation ever reaches the
 * anchor, so a mistyped phrase fails here with a plain message rather than
 * as an opaque publish rejection. Returns null on cancel, mismatch, or a
 * missing local record — the caller shows nothing further in any of those
 * cases, since promptForMnemonic and the mismatch branch already have. */
async function revealAndVerify(did: string, subtitle: string): Promise<{ revealedPrivateKey: Uint8Array; revealedPublicKey: Uint8Array; identityPublicKey: Uint8Array } | null> {
  // Fetched BEFORE prompting so the box can check the typed words against the
  // commitment live (promptForMnemonic's expectedHashes) rather than only
  // after submit — a wrong paper is the common mistake here, three phrases
  // being in play at once.
  const { last } = await fetchCurrentLog(did)
  const committed = new Set(last.parameters.nextKeyHashes ?? [])

  const phrase = await promptForMnemonic({
    title: 'Enter your Spare Key phrase', subtitle, badges: ['SPARE KEY'],
    expectedHashes: [...committed],
  })
  if (!phrase) return null

  const revealedPrivateKey = mnemonicToSeed(phrase)
  const revealedPublicKey = ed25519.getPublicKey(revealedPrivateKey)

  if (!committed.has(multikeyHashBase58(encodeMultikey(revealedPublicKey)))) {
    const { showSysMsg } = await import('./shell.ts')
    showSysMsg("Those words don't match this identity's current key rotation commitment")
    return null
  }

  // #key-1 (the document's own identity key) is never touched by any of
  // this — see prerotation.ts's header — so it's read straight off the
  // local record rather than derived from anything pre-rotation-related.
  const { getDidRecord } = await import('../did/store.ts')
  const rec = await getDidRecord(did)
  if (!rec) return null
  return { revealedPrivateKey, revealedPublicKey, identityPublicKey: hexToBytes(rec.rootPublicKey) }
}

/** Resolves the phrase controlling the DID's CURRENT updateKeys — needed to
 * re-activate after this identity has already been through a rotate/
 * deactivate cycle, which moves updateKeys to whatever key that cycle last
 * revealed and never moves it back (rotateOrDeactivate's own note), and now
 * also needed for routine publishing (left-pane.ts's Sync) once that's
 * happened. Unlike revealAndVerify (which checks a phrase against a forward
 * COMMITMENT, nextKeyHashes — always fresh, never cached, since spending a
 * spare always needs the human to produce it), this checks a key against
 * the log's current updateKeys directly, and that key is exactly the kind
 * of thing worth remembering: it doesn't get consumed/rotated by being
 * used, so the SAME key answers every future call until something actually
 * moves updateKeys again.
 *
 * Checks the local record FIRST (did/store.ts's DidRecord.signingPrivateKey/
 * signingPublicKey) and only prompts when that's absent or stale — see that
 * field's own note on why persisting it costs nothing beyond what
 * rootPrivateKey already accepts. Persists a freshly-typed one back to the
 * record on success, so this is the ONLY time this particular phrase is
 * ever asked for again on this device. */
export async function revealCurrentSigner(did: string): Promise<{ privateKey: Uint8Array; publicKey: Uint8Array } | null> {
  const { getDidRecord } = await import('../did/store.ts')
  const { last } = await fetchCurrentLog(did)
  const currentUpdateKeys = last.parameters.updateKeys ?? []

  const rec = await getDidRecord(did)
  if (rec?.signingPrivateKey && rec.signingPublicKey) {
    const storedPublicKey = hexToBytes(rec.signingPublicKey)
    if (currentUpdateKeys.includes(encodeMultikey(storedPublicKey))) {
      return { privateKey: hexToBytes(rec.signingPrivateKey), publicKey: storedPublicKey }
    }
  }

  // Three named keys, no relative wording (PLANROTATION.md §1.1): this asks
  // for the SIGN KEY (current updateKeys), never the SPARE KEY (the committed
  // successor revealAndVerify wants). "current"/"latest" phrasing was tried
  // first and could not be made unambiguous — every activate/rotate displays
  // a newer phrase immediately afterwards, so "latest" named the wrong one
  // here while being right for the rotate prompt (2026-08-17). Distinct nouns
  // remove the comparison entirely. The expected multikey is known here (it
  // is in the log's updateKeys) so it is echoed for checking against a
  // labelled paper copy.
  const phrase = await promptForMnemonic({
    title: 'Enter Sign Key phrase',
    subtitle: 'The phrase that currently controls this document. Not the Spare Key phrase (if you have one).',
    badges: ['SIGN KEY'],
    ...(currentUpdateKeys[0] ? { expectedFingerprint: currentUpdateKeys[0] } : {}),
  })
  if (!phrase) return null
  const privateKey = mnemonicToSeed(phrase)
  const publicKey = ed25519.getPublicKey(privateKey)
  if (!currentUpdateKeys.includes(encodeMultikey(publicKey))) {
    const { showSysMsg } = await import('./shell.ts')
    showSysMsg("Those words don't control this identity's current key")
    return null
  }
  await cacheSigningKey(did, privateKey, publicKey)
  return { privateKey, publicKey }
}

/** Turns pre-rotation on. Needs the identity UNLOCKED (its local record is
 * where #key-1 — the identity key, never touched by any of this — always
 * comes from). Who SIGNS this entry depends on whether updateKeys is still
 * the original root key (a first-ever activation) or has already moved to a
 * previously-revealed spare (a re-activation after a prior rotate/
 * deactivate) — either way, it's the last thing that key will ever be
 * authorized to do for this DID. */
export async function runActivatePreRotation(did: string): Promise<boolean> {
  const { getDidRecord, unlockIdentitySecrets, requireRootPrivateKey } = await import('../did/store.ts')
  if (!(await unlockIdentitySecrets())) return false
  const rec = await getDidRecord(did)
  if (!rec) return false
  const identityPublicKey = hexToBytes(rec.rootPublicKey)

  const { last } = await fetchCurrentLog(did)
  if ((last.parameters.nextKeyHashes?.length ?? 0) > 0) {
    const { showSysMsg } = await import('./shell.ts')
    showSysMsg('Key rotation is already active for this identity')
    return false
  }

  let signingPrivateKey: Uint8Array
  let signingPublicKey: Uint8Array
  if ((last.parameters.updateKeys ?? []).includes(encodeMultikey(identityPublicKey))) {
    signingPrivateKey = hexToBytes(requireRootPrivateKey(rec))
    signingPublicKey = identityPublicKey
  } else {
    const revealed = await revealCurrentSigner(did)
    if (!revealed) return false
    signingPrivateKey = revealed.privateKey
    signingPublicKey = revealed.publicKey
  }

  // Shown and confirmed BEFORE publishing, not after: a failed publish here
  // just means the user wrote down a phrase for a commitment that never
  // went live (harmless, just unused) — publishing first and then failing
  // to record the phrase would instead leave a LIVE commitment on the
  // network with no saved successor, which is the identity-bricking
  // failure mode this ordering exists to avoid.
  const spare = generateSpareKeypair()
  // "[SIGN KEY]" distinguishes this from the identity's own recovery phrase
  // (mnemonic.ts's showMnemonic, shown at account creation) — this phrase
  // only ever controls updateKeys, never restores/logs in (2026-08-17,
  // user-requested, after this being unlabelled caused confusion about which
  // phrase a restore needs).
  await showMnemonicOnce(spare.mnemonic, {
    firstTime: true,
    badges: ['SPARE KEY'],
    title: 'New Spare Key phrase',
    subtitle: 'Your successor key. It takes over the next time you rotate, revoke, or turn key rotation off — and it is the only thing that can, so it must exist on paper and nowhere else. Keep your existing Sign Key phrase as well: that is what Sync and a new device still ask for.',
    fingerprint: encodeMultikey(spare.publicKey),
  })

  try {
    await activatePreRotation({
      did, signingPrivateKey, signingPublicKey, identityPublicKey,
      nextKeyHash: multikeyHashBase58(encodeMultikey(spare.publicKey)),
    })
    return true
  } catch (e) {
    const { showSysMsg } = await import('./shell.ts')
    showSysMsg(e instanceof Error ? e.message : 'Could not turn on key rotation')
    return false
  }
}

/** Reveals the committed key, uses it to rotate, and immediately commits a
 * fresh one so pre-rotation stays active — see prerotation.ts's own header
 * on why "rotate" always means "consume one spare, mint the next" as a
 * single operation, never just the first half. */
export async function runRotateNow(did: string): Promise<boolean> {
  const revealed = await revealAndVerify(did, 'Your Spare Key phrase — the one shown when you last activated or rotated. It becomes your new Sign Key.')
  if (!revealed) return false

  const spare = generateSpareKeypair()
  await showMnemonicOnce(spare.mnemonic, {
    firstTime: true,
    badges: ['SPARE KEY'],
    title: 'New Spare Key phrase',
    subtitle: 'Your successor key. It takes over the next time you rotate, revoke, or turn key rotation off — and it is the only thing that can, so it must exist on paper and nowhere else. Keep your existing Sign Key phrase as well: that is what Sync and a new device still ask for.',
    fingerprint: encodeMultikey(spare.publicKey),
  })

  try {
    await rotateToPreRotatedKey({
      did, revealedPrivateKey: revealed.revealedPrivateKey, revealedPublicKey: revealed.revealedPublicKey,
      identityPublicKey: revealed.identityPublicKey,
      nextKeyHash: multikeyHashBase58(encodeMultikey(spare.publicKey)),
    })
    // The just-revealed key IS the new updateKeys now — cache it so Sync
    // doesn't need it re-typed immediately after rotating with it.
    await cacheSigningKey(did, revealed.revealedPrivateKey, revealed.revealedPublicKey)
    return true
  } catch (e) {
    const { showSysMsg } = await import('./shell.ts')
    showSysMsg(e instanceof Error ? e.message : 'Could not rotate')
    return false
  }
}

/** Same underlying operation as runRotateNow — reveal the committed spare,
 * use it, commit a fresh one — but ALSO moves #key-1 (the document's
 * identity key, otherwise never touched by pre-rotation) so it derives from
 * that same revealed phrase. Ordinary rotation only ever retires updateKeys;
 * the ORIGINAL root mnemonic still restores this identity's mail/DIDComm/MLS
 * access forever, since #key-1 never moves (activatePreRotation/
 * rotateOrDeactivate's own notes). This is the one action that actually
 * retires that original mnemonic — for when it's suspected compromised, not
 * routine hygiene, which is why it's a separate, deliberate button rather
 * than folded into every rotate (2026-08-17 design discussion: folding it in
 * would turn every ordinary rotate into an operation where losing the freshly-
 * shown spare phrase bricks the WHOLE identity, not just the DID log).
 *
 * The new #key-1 comes from a FRESHLY MINTED, independent seed, not from the
 * revealed phrase (PLANROTATION.md §3.1 option B): revoking exists to cut a
 * possibly-compromised key loose, and deriving its replacement from a phrase
 * already displayed, copied and typed in would reuse the exposure being
 * escaped. It is `deriveRootKey`'s SLIP-10 output over that seed, never a raw
 * key — restoreFromMnemonic always re-derives before comparing, so a raw
 * #key-1 matches nothing typed into restore ever again (found live,
 * 2026-08-17: broke restore with every phrase, the correct one included).
 *
 * Two phrases are therefore shown, one screen at a time: the new Root Key,
 * then the new Spare Key. The revealed phrase becomes the Sign Key.
 *
 * Also updates this device's own local record: rootPrivateKey/rootPublicKey
 * move to the new root (otherwise this device's own next vouch/restore
 * comparison would keep using the retired key), and masterSeed is SET to the
 * new root seed — see the inline note there on the PGP kek consequence. */
export async function runRevokeRootKey(did: string): Promise<boolean> {
  const revealed = await revealAndVerify(did, 'Your Spare Key phrase. It authorises this change and becomes your new Sign Key. A brand-new Root Key phrase is minted separately and shown next.')
  if (!revealed) return false

  // A BRAND-NEW, independent Root Key — not derived from the phrase just
  // entered (PLANROTATION.md §3.1, option B). Revoking exists to cut a
  // possibly-compromised key loose, so deriving its replacement from a
  // phrase that has already been displayed, copied to a clipboard and typed
  // into an input box reuses exactly the exposure the operation is meant to
  // escape. The 32 random bytes are the new master seed; `#key-1` is
  // `deriveRootKey`'s SLIP-10 output over it, because restoreFromMnemonic
  // always re-derives that way before comparing (using a raw key here is
  // what made every phrase fail restore, 2026-08-17).
  const { deriveRootKey } = await import('../did/keys.ts')
  const newRootSeed = crypto.getRandomValues(new Uint8Array(32))
  const newRoot = deriveRootKey(newRootSeed)
  const spare = generateSpareKeypair()

  // TWO phrases, shown one screen at a time rather than side by side — each
  // gets its own copy-gate, and putting two 24-word grids on one screen
  // invites copying one and calling it done. Root first: it is the one that
  // matters most and the one that is genuinely new here.
  await showMnemonicOnce(seedToMnemonic(newRootSeed), {
    firstTime: true,
    badges: ['ROOT KEY'],
    title: 'New Root Key phrase',
    subtitle: 'This replaces your current Root Key phrase, which stops working the moment this completes. From now on THIS is what restores your identity and logs you in on a new device. Two phrases are shown — this one, then your new Spare Key.',
    fingerprint: encodeMultikey(newRoot.publicKey),
  })
  await showMnemonicOnce(spare.mnemonic, {
    firstTime: true,
    badges: ['SPARE KEY'],
    title: 'New Spare Key phrase',
    subtitle: 'Your successor key, for the next rotate/revoke/deactivate — it does NOT restore your identity. Keep it separate from the Root Key phrase you just saved.',
    fingerprint: encodeMultikey(spare.publicKey),
  })

  try {
    await rotateToPreRotatedKey({
      did, revealedPrivateKey: revealed.revealedPrivateKey, revealedPublicKey: revealed.revealedPublicKey,
      // #key-1 moves to the freshly minted root, independent of both the key
      // that signs this entry (the revealed spare, which becomes updateKeys)
      // and of the successor committed below.
      identityPublicKey: newRoot.publicKey,
      nextKeyHash: multikeyHashBase58(encodeMultikey(spare.publicKey)),
    })
  } catch (e) {
    const { showSysMsg } = await import('./shell.ts')
    showSysMsg(e instanceof Error ? e.message : 'Could not revoke root key')
    return false
  }

  // masterSeed just changed, and with it the PGP kek (cryptenv.ts's
  // deriveKek) — without re-wrapping, every mail relay account's
  // server-side encrypted PGP privkey blob is stuck under the OLD kek, which
  // no device can ever derive again (this file's own note above on the
  // fresh-independent-seed design). Best-effort per account: this device
  // already holds the plaintext PGP key locally regardless of which kek
  // wrapped the server copy, so a rewrap here needs no old-kek derivation at
  // all — see rewrapPgpForNewKek's own note. A failure on one account (relay
  // unreachable) must not block the others or undo the revoke, which has
  // already landed on the DID log.
  try {
    const { deriveKek } = await import('../cryptenv.ts')
    const { rewrapPgpForNewKek } = await import('../pgp/index.ts')
    const { sessions } = await import('../context.ts')
    const newKek = await deriveKek(newRootSeed)
    for (const s of sessions) {
      if (s.account.did !== did) continue
      const ok = await rewrapPgpForNewKek(s, newKek).catch(() => false)
      if (!ok) console.warn('[prerotation] revokeRootKey: PGP rewrap failed for', s.account.email, '— that account will mint a fresh PGP key on its next restore')
    }
  } catch (e) {
    console.warn('[prerotation] revokeRootKey: PGP rewrap step failed:', e instanceof Error ? e.message : e)
  }

  try {
    const { getDidRecord, storeDidRecord } = await import('../did/store.ts')
    const rec = await getDidRecord(did)
    if (rec) {
      // masterSeed is SET to the NEW root seed, not cleared — it's genuinely
      // the seed #key-1 now derives from (localDidRecord/restoreFromMnemonic's
      // own convention), so re-displaying the recovery phrase
      // (showStoredMnemonic) keeps working and shows the phrase that is
      // actually current.
      //
      // Side effect worth knowing: the PGP kek is derived from masterSeed
      // (cryptenv.ts's deriveKek), so revoking rotates it. This device is
      // unaffected (initPGP returns its existing local key record without
      // consulting the kek), but a LATER device restored with the new Root
      // Key phrase cannot decrypt the PGP private key blob stored under the
      // old kek and will mint a fresh PGP key instead. Pre-existing — revoke
      // has always rotated masterSeed — and not made worse by minting the
      // root independently. Recorded in PLANROTATION.md §5.
      const updated = {
        ...rec,
        rootPrivateKey: bytesToHex(newRoot.privateKey),
        rootPublicKey: bytesToHex(newRoot.publicKey),
        masterSeed: bytesToHex(newRootSeed),
        // updateKeys itself holds the RAW revealed key (rotateToPreRotatedKey's
        // own doing), not newRoot's derived one — #key-1 and updateKeys
        // diverge again immediately after a revoke, same as any other
        // rotate/deactivate. Stored here too so Sync doesn't need this
        // phrase re-typed right after revoking with it (revealCurrentSigner's
        // own note).
        signingPrivateKey: bytesToHex(revealed.revealedPrivateKey),
        signingPublicKey: bytesToHex(revealed.revealedPublicKey),
      }
      await storeDidRecord(updated)
    }
  } catch (e) {
    // The publish already landed — the document is correct either way. A
    // failure here only means THIS device's own local record didn't catch
    // up, which would surface later as a broken vouch/restore comparison,
    // not as anything wrong with the identity itself.
    console.warn('[prerotation] revokeRootKey: publish succeeded but local record update failed:', e instanceof Error ? e.message : e)
  }
  return true
}

/** For any OTHER operation that appends a log entry (currently: a domain/
 * username move, ui/edit-identity.ts) and therefore hits the exact same
 * resolver.ts wall a rotate does whenever pre-rotation is active — no
 * inheritance permitted, the signer must match the current nextKeyHashes
 * commitment (migrate.ts's own note, found live 2026-08-17: moves could not
 * complete at all while active, regardless of which key signed). Returns
 * null when pre-rotation is OFF (the caller proceeds with its own normal,
 * Root-Key-signs behavior, untouched) or on cancel/mismatch (the caller
 * should not proceed at all — same as revealAndVerify's own null cases).
 * When active, reveals the current Spare Key exactly like a rotate does and
 * mints+shows a fresh successor, so the move consumes one spare and leaves
 * pre-rotation still armed afterward, same invariant every other operation
 * here maintains. */
export type SpareKeyForMoveResult =
  | { active: false }
  | { active: true; override: { privateKey: Uint8Array; publicKey: Uint8Array; nextKeyHash: string } | null }

export async function resolveSpareKeyForMove(did: string): Promise<SpareKeyForMoveResult> {
  const { last } = await fetchCurrentLog(did)
  if ((last.parameters.nextKeyHashes?.length ?? 0) === 0) return { active: false }

  const revealed = await revealAndVerify(did, 'Key rotation is active for this identity. Your Spare Key phrase authorises this move and becomes your new Sign Key.')
  if (!revealed) return { active: true, override: null }

  const spare = generateSpareKeypair()
  await showMnemonicOnce(spare.mnemonic, {
    firstTime: true,
    badges: ['SPARE KEY'],
    title: 'New Spare Key phrase',
    subtitle: 'Your successor key, unchanged by the move itself — it takes over the next time you rotate, revoke, or turn key rotation off. Keep your existing Sign Key phrase as well.',
    fingerprint: encodeMultikey(spare.publicKey),
  })

  return {
    active: true,
    override: {
      privateKey: revealed.revealedPrivateKey,
      publicKey: revealed.revealedPublicKey,
      nextKeyHash: multikeyHashBase58(encodeMultikey(spare.publicKey)),
    },
  }
}

/** Turns pre-rotation back off. Still needs the saved phrase (see this
 * file's header) — there is no lighter path once pre-rotation is active. */
export async function runDeactivatePreRotation(did: string): Promise<boolean> {
  const revealed = await revealAndVerify(did, 'Your Spare Key phrase. It becomes your new Sign Key, and no further successor is committed.')
  if (!revealed) return false

  try {
    await deactivatePreRotation({
      did, revealedPrivateKey: revealed.revealedPrivateKey, revealedPublicKey: revealed.revealedPublicKey,
      identityPublicKey: revealed.identityPublicKey,
    })
    // Same reasoning as runRotateNow: the just-revealed key becomes the new
    // (now permanent, no further commitment) updateKeys — this is exactly
    // the case the user found Sync kept re-prompting for with no way to
    // ever stop (2026-08-17): deactivating doesn't return authority to
    // root, and this key doesn't get consumed by being used again.
    await cacheSigningKey(did, revealed.revealedPrivateKey, revealed.revealedPublicKey)
    return true
  } catch (e) {
    const { showSysMsg } = await import('./shell.ts')
    showSysMsg(e instanceof Error ? e.message : 'Could not turn off key rotation')
    return false
  }
}
