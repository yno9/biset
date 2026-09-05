// The MLS layer's own guarantees, independent of DIDComm transport: a group
// forms, members join and leave, application messages decrypt, the exporter
// secret agrees across members, and state survives a persistence round trip.
//
// The last two are the load-bearing ones for PLANMLS.md. §3.3's metadata layer
// is only sound if every member derives the SAME exporter key from the SAME
// epoch (otherwise the middle envelope is undecryptable for someone), and a
// browser client that can't reload its group state after a refresh has no
// usable group at all.
import type { ClientState } from '../src/vendor/mls/index.ts'
import { ed25519 } from '@noble/curves/ed25519.js'
import {
  generateOwnKeyPackage, createMlsGroup, addMembers, removeMembers, rekey, joinMlsGroup,
  encryptApplication, processIncoming, exportSecret, memberList, memberDids, memberKids, epochOf,
  encodeKeyPackage, decodeKeyPackage, encodeState, decodeState,
  setRoomMetadata, roomMetadataOf,
  setAppDataComponent,
} from '../src/client/mimi/group.ts'
import { appDataComponent, decodeMlsMessage } from '../src/vendor/mls/index.ts'
import { createMlsDeviceCredential } from '../src/client/mimi/device-credential.ts'

let fails = 0
const ok = (name: string, cond: boolean, detail = '') => {
  console.log(`  ${cond ? 'ok  ' : 'FAIL'}  ${name}${cond || !detail ? '' : '\n          → ' + detail}`)
  if (!cond) fails++
}
const enc = new TextEncoder(), dec = new TextDecoder()
const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((v, i) => v === b[i])

const ALICE_DID = 'did:webvh:example.com:alice'
const BOB_DID = 'did:webvh:example.com:bob'
const CAROL_DID = 'did:webvh:example.com:carol'
const aliceRoot = ed25519.utils.randomSecretKey()
const bobRoot = ed25519.utils.randomSecretKey()
const carolRoot = ed25519.utils.randomSecretKey()
const own = async (did: string, root: Uint8Array) => {
  const leaf = ed25519.utils.randomSecretKey()
  const credential = createMlsDeviceCredential(did, "1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ed25519.getPublicKey(leaf), root, root)
  return { credential, package: await generateOwnKeyPackage(credential, leaf) }
}
const aliceOwn = await own(ALICE_DID, aliceRoot)
const bobOwn = await own(BOB_DID, bobRoot)
const bob2Own = await own(BOB_DID, bobRoot)
const carolOwn = await own(CAROL_DID, carolRoot)
const alice = aliceOwn.package, bob = bobOwn.package, bob2 = bob2Own.package, carol = carolOwn.package
const ALICE = aliceOwn.credential.deviceKid
const BOB = bobOwn.credential.deviceKid
const BOB2 = bob2Own.credential.deviceKid
const CAROL = carolOwn.credential.deviceKid

// KeyPackage wire round trip — this is what the mediator's KeyPackage Store
// holds and hands out, so it must survive encode/decode untouched.
const kpWire = encodeKeyPackage(bob.publicPackage)
ok('key package round trip', same(encodeKeyPackage(decodeKeyPackage(kpWire)), kpWire), `${kpWire.length} bytes`)

let aliceGroup: ClientState = await createMlsGroup(enc.encode('test-group-1'), alice)
ok('new group has one member', memberList(aliceGroup).length === 1 && memberList(aliceGroup)[0]!.kid === ALICE)
ok('new group is epoch 0', epochOf(aliceGroup) === 0n)

// Alice adds both of Bob's devices in ONE commit — one leaf per device
// (identity.ts), and no epoch in which only half of Bob is present.
const added = await addMembers(aliceGroup, [bob.publicPackage, bob2.publicPackage])
aliceGroup = added.state
ok('add produced a welcome', added.welcome !== undefined)
ok('epoch advanced to 1', epochOf(aliceGroup) === 1n)
ok('alice sees 3 leaves', memberList(aliceGroup).length === 3, JSON.stringify(memberList(aliceGroup).map(m => m.kid)))
ok('two distinct identities', memberDids(aliceGroup).length === 2, memberDids(aliceGroup).join(','))
ok('bob has two devices', memberKids(aliceGroup, BOB_DID).length === 2)

let bobGroup = await joinMlsGroup(added.welcome!, bob, aliceGroup.ratchetTree)
let bob2Group = await joinMlsGroup(added.welcome!, bob2, aliceGroup.ratchetTree)
ok('bob joined at the same epoch', epochOf(bobGroup) === epochOf(aliceGroup))
ok('bob sees the same members', memberList(bobGroup).map(m => m.kid).join(',') === memberList(aliceGroup).map(m => m.kid).join(','))

// PLANMLS.md §3.3: the metadata key must agree across members of one epoch.
const label = 'biset-metadata'
const ctx = enc.encode('')
const [ea, eb, eb2] = await Promise.all([
  exportSecret(aliceGroup, label, ctx, 32), exportSecret(bobGroup, label, ctx, 32), exportSecret(bob2Group, label, ctx, 32),
])
ok('exporter secret agrees across all members', same(ea!, eb!) && same(ea!, eb2!), Buffer.from(ea!).toString('hex').slice(0, 16))
ok('exporter is label-scoped', !same(ea!, (await exportSecret(aliceGroup, 'other-label', ctx, 32))))

// Application message, alice → group.
const sent = await encryptApplication(aliceGroup, enc.encode('hello group'))
aliceGroup = sent.state
const gotBob = await processIncoming(bobGroup, sent.wire)
bobGroup = gotBob.state
ok('bob decrypts the application message', gotBob.kind === 'message' && dec.decode(gotBob.message) === 'hello group', `${sent.wire.length} bytes on the wire`)
const gotBob2 = await processIncoming(bob2Group, sent.wire)
bob2Group = gotBob2.state
ok("bob's second device decrypts it too", gotBob2.kind === 'message' && dec.decode(gotBob2.message) === 'hello group')

// Persistence round trip — a browser refresh, in effect. The reloaded state
// must be able to keep decrypting, not merely decode.
const blob = encodeState(bobGroup)
const reloaded = decodeState(blob)
ok('group state round trips', epochOf(reloaded) === epochOf(bobGroup), `${blob.length} bytes`)
const sent2 = await encryptApplication(aliceGroup, enc.encode('after reload'))
aliceGroup = sent2.state
const gotReloaded = await processIncoming(reloaded, sent2.wire)
ok('reloaded state still decrypts', gotReloaded.kind === 'message' && dec.decode(gotReloaded.message) === 'after reload')

// Bob adds Carol: any member can commit, not just the creator. The DS decides
// the ORDER of commits (PLANMLS.md §2), not who may make them.
const bobAdds = await addMembers(bobGroup, [carol.publicPackage])
bobGroup = bobAdds.state
const aliceSeesAdd = await processIncoming(aliceGroup, bobAdds.commit)
aliceGroup = aliceSeesAdd.state
ok("alice applies bob's commit", aliceSeesAdd.kind === 'state' && epochOf(aliceGroup) === 2n && memberDids(aliceGroup).length === 3, memberDids(aliceGroup).join(','))
let carolGroup = await joinMlsGroup(bobAdds.welcome!, carol, bobGroup.ratchetTree)
ok('carol joined at epoch 2', epochOf(carolGroup) === 2n)

// Removing an identity means removing every device it has in the group.
const removal = await removeMembers(aliceGroup, memberKids(aliceGroup, 'did:webvh:example.com:bob'), false)
aliceGroup = removal.state
ok('remove advanced the epoch', epochOf(aliceGroup) === 3n)
ok('both of bobs devices are gone', memberDids(aliceGroup).join(',') === `${ALICE_DID},${CAROL_DID}`, memberDids(aliceGroup).join(','))
const carolSeesRemove = await processIncoming(carolGroup, removal.commit)
carolGroup = carolSeesRemove.state
ok('carol applied the removal', memberDids(carolGroup).length === 2)

// Forward secrecy after removal: a message sent in epoch 3 must not be
// readable by the state bob still holds from epoch 2.
const afterRemoval = await encryptApplication(aliceGroup, enc.encode('bob must not read this'))
aliceGroup = afterRemoval.state
let bobCouldRead = false
try {
  const r = await processIncoming(bobGroup, afterRemoval.wire)
  bobCouldRead = r.kind === 'message'
} catch { /* expected: bob's state can't decrypt a later epoch */ }
ok('removed member cannot read later messages', !bobCouldRead)
const carolReads = await processIncoming(carolGroup, afterRemoval.wire)
carolGroup = carolReads.state
ok('remaining member still can', carolReads.kind === 'message' && dec.decode(carolReads.message) === 'bob must not read this')

// A SINGLE Remove must be as cryptographic as a multiple one. This is the
// regression pin for the fork's reason to exist: upstream ts-mls omits the
// UpdatePath when a commit removes exactly one member (`> 1` where RFC 9420
// §12.4 means `> 0`), leaving the commit secret a zero buffer that the removed
// member derives too — so it keeps reading. The removal above happened to
// remove TWO leaves at once and therefore took the correct path by accident,
// which is exactly why this case is written out separately.
const ERIN_DID = 'did:webvh:example.com:erin'
const erinOwn = await own(ERIN_DID, ed25519.utils.randomSecretKey())
const ERIN = erinOwn.credential.deviceKid
const erin = erinOwn.package
const withErin = await addMembers(aliceGroup, [erin.publicPackage])
aliceGroup = withErin.state
carolGroup = (await processIncoming(carolGroup, withErin.commit)).state
let erinGroup = await joinMlsGroup(withErin.welcome!, erin)
ok('erin joined', memberDids(erinGroup).length === 3)

const soloRemoval = await removeMembers(aliceGroup, [ERIN], false)
aliceGroup = soloRemoval.state
carolGroup = (await processIncoming(carolGroup, soloRemoval.commit)).state
// Erin applies the commit that removes her: she is marked removed, and must
// not advance into the epoch it creates.
erinGroup = (await processIncoming(erinGroup, soloRemoval.commit)).state
ok('a removed member is marked removed', (erinGroup as unknown as { groupActiveState: { kind: string } }).groupActiveState.kind === 'removedFromGroup')

const afterSolo = await encryptApplication(aliceGroup, enc.encode('erin must not read this'))
aliceGroup = afterSolo.state
let erinRead = false
try { erinRead = (await processIncoming(erinGroup, afterSolo.wire)).kind === 'message' } catch { /* expected */ }
ok('a SINGLE remove denies the removed member the next epoch', !erinRead)
const carolStillReads = await processIncoming(carolGroup, afterSolo.wire)
carolGroup = carolStillReads.state
ok('while everyone else reads on', carolStillReads.kind === 'message' && dec.decode(carolStillReads.message) === 'erin must not read this')

// An empty commit is how PCS is actually obtained — it must advance the epoch
// and change the exporter secret even though membership is unchanged.
const beforeRekey = await exportSecret(aliceGroup, label, ctx, 32)
const rekeyed = await rekey(aliceGroup)
aliceGroup = rekeyed.state
ok('rekey advances the epoch with no membership change', epochOf(aliceGroup) === 6n && memberDids(aliceGroup).length === 2, `${epochOf(aliceGroup)} / ${memberDids(aliceGroup).join(',')}`)
ok('rekey changes the exporter secret', !same(beforeRekey, await exportSecret(aliceGroup, label, ctx, 32)))
const carolRekey = await processIncoming(carolGroup, rekeyed.commit)
carolGroup = carolRekey.state
ok('carol follows the rekey', epochOf(carolGroup) === 6n, String(epochOf(carolGroup)))
ok('exporter agrees again after rekey', same(await exportSecret(aliceGroup, label, ctx, 32), await exportSecret(carolGroup, label, ctx, 32)))

// Room metadata (Conversation Group display name, PLAN-mimi.md) -- a
// private-use RFC 9420 group_context_extensions proposal, not yet MIMI's
// own still-unassigned AppSync mechanism (mls/group.ts's own header on why).
ok('a group with no name set has none', roomMetadataOf(aliceGroup) === undefined)
const componentCommit = await setAppDataComponent(aliceGroup, 0x0023, enc.encode('MIMI room metadata'))
aliceGroup = componentCommit.state
const receivedComponentCommit = await processIncoming(carolGroup, componentCommit.commit)
carolGroup = receivedComponentCommit.state
ok('AppDataUpdate advances state without an UpdatePath',
  dec.decode(appDataComponent(aliceGroup.groupContext.extensions, 0x0023)) === 'MIMI room metadata' &&
  dec.decode(appDataComponent(carolGroup.groupContext.extensions, 0x0023)) === 'MIMI room metadata')
const named = await setRoomMetadata(aliceGroup, { name: 'Weekend Trip' })
aliceGroup = named.state
ok('setRoomMetadata advances the epoch', epochOf(aliceGroup) === 8n, String(epochOf(aliceGroup)))
ok('the committer sees the new name immediately', roomMetadataOf(aliceGroup)?.name === 'Weekend Trip')
const carolNamed = await processIncoming(carolGroup, named.commit)
carolGroup = carolNamed.state
ok('carol converges on the same name via the commit', roomMetadataOf(carolGroup)?.name === 'Weekend Trip')
const renamed = await setRoomMetadata(aliceGroup, { name: 'Renamed Trip' })
aliceGroup = renamed.state
ok('the name can be changed again (not a write-once field)', roomMetadataOf(aliceGroup)?.name === 'Renamed Trip')

// removeMembers' wire framing is the caller's choice and must actually reach
// the wire. mimi-vault-room.ts's removeMimiVaultDevice passes `true` because
// the MIMI hub rejects a room-state update that is not a complete
// PublicMessage ("room-state update must be a complete MLS PublicMessage",
// HTTP 400); the deleted self-group/conversation-group callers wanted `false`
// and used to own the (silently wrong for MIMI) default. Both framings are
// pinned here so neither can be quietly re-defaulted.
const carolKids = memberKids(aliceGroup, CAROL_DID)
const publicWire = await removeMembers(aliceGroup, carolKids, true)
const privateWire = await removeMembers(aliceGroup, carolKids, false)
ok('removeMembers(..., true) emits a PublicMessage commit',
  decodeMlsMessage(publicWire.commit, 0)?.[0]?.wireformat === 'mls_public_message',
  String(decodeMlsMessage(publicWire.commit, 0)?.[0]?.wireformat))
ok('removeMembers(..., false) emits a PrivateMessage commit',
  decodeMlsMessage(privateWire.commit, 0)?.[0]?.wireformat === 'mls_private_message',
  String(decodeMlsMessage(privateWire.commit, 0)?.[0]?.wireformat))

// A leaf that isn't a biset DID URL must not be read as a member.
let rejected = false
try { await generateOwnKeyPackage({} as never, new Uint8Array(32)) } catch { rejected = true }
ok('a credential without a key fragment is refused', rejected)

console.log(fails === 0 ? '\nall ok' : `\n${fails} failed`)
process.exit(fails === 0 ? 0 : 1)
