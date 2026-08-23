// End-to-end self-group bootstrap: a real MLS ClientState, a real DS
// (SqliteMlsDeliveryService) behind the real HTTP handler, and
// CoreMlsDeliveryTransport in between -- confirms createSelfGroup and
// joinSelfGroupExternally actually interoperate through the whole stack,
// not just against hand-built fixtures.
import { afterEach, describe, expect, test } from 'bun:test'
import { rmSync } from 'node:fs'
import { ed25519 } from '@noble/curves/ed25519.js'
import { SqliteMlsDeliveryService } from '../../src/core/mediation/mls-delivery-store.ts'
import { Ed25519MlsDsSignatureVerifier } from '../../src/core/mediation/mls-delivery-authorizer.ts'
import { createMlsDeliveryHttpHandler } from '../../src/core/mediation/mls-delivery-http.ts'
import { CoreMlsDeliveryTransport } from '../../src/mls/core-mls-delivery-transport.ts'
import { generateOwnKeyPackage, memberKids } from '../../src/mls/group.ts'
import { ensureSelfGroup } from '../../src/mls/self-group.ts'
import type { LoadedMlsSelfGroup, MlsSelfGroupStateStore } from '../../src/mls/store.ts'
import type { OwnKeyPackage } from '../../src/mls/group.ts'

const path = `/tmp/biset-self-group-bootstrap-${process.pid}-${Date.now()}.sqlite`
const identityId = 'did:web:alice.example'
const deviceAKid = `${identityId}#device-a`
const deviceBKid = `${identityId}#device-b`

afterEach(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { rmSync(`${path}${suffix}`) } catch {}
  }
})

function memoryStore(): MlsSelfGroupStateStore {
  const rows = new Map<string, LoadedMlsSelfGroup>()
  return {
    async save(id, selfGroupId, state) { rows.set(id, { selfGroupId, state }) },
    async load(id) { return rows.get(id) },
  }
}

function signerFor(kp: OwnKeyPackage) {
  return (bytes: Uint8Array) => ed25519.sign(bytes, kp.privatePackage.signaturePrivateKey)
}

/** DS signature verification resolves each device's ACTUAL MLS leaf signature
 * key (KeyPackage.publicPackage.leafNode.signaturePublicKey) — the same key
 * `signerFor` signs with, and the same key PLANMLSDIDCRED.md §2.3 says a
 * device's control-message signature and its MLS credential should share. */
function setup(kids: Record<string, OwnKeyPackage>) {
  const ds = SqliteMlsDeliveryService.open(path)
  const verifier = new Ed25519MlsDsSignatureVerifier({
    async resolveEd25519PublicKey(kid) { return kids[kid]?.publicPackage.leafNode.signaturePublicKey },
  })
  const handle = createMlsDeliveryHttpHandler(ds, verifier, async () => true)
  const transport = new CoreMlsDeliveryTransport({ baseUrl: 'https://core.example', fetch: (input, init) => handle(new Request(input, init)) })
  return { ds, transport }
}

describe('self-group bootstrap (createSelfGroup / joinSelfGroupExternally / ensureSelfGroup)', () => {
  test('first device creates the self group, second device joins externally with no other device online', async () => {
    const kpA = await generateOwnKeyPackage(deviceAKid)
    const kpB = await generateOwnKeyPackage(deviceBKid)
    const { ds, transport } = setup({ [deviceAKid]: kpA, [deviceBKid]: kpB })

    const stateA = await ensureSelfGroup(memoryStore(), transport, identityId, deviceAKid, kpA, signerFor(kpA))
    expect(stateA).toBeDefined()
    expect(memberKids(stateA!, identityId)).toEqual([deviceAKid])

    // Device A is not "online" in any sense the test models -- device B's
    // join reaches only the DS, exactly as an external commit is meant to.
    const stateB = await ensureSelfGroup(memoryStore(), transport, identityId, deviceBKid, kpB, signerFor(kpB))
    expect(stateB).toBeDefined()
    expect(new Set(memberKids(stateB!, identityId))).toEqual(new Set([deviceAKid, deviceBKid]))

    ds.close()
  })

  test('ensureSelfGroup is idempotent: an already-active device never touches the transport again', async () => {
    const kp = await generateOwnKeyPackage(deviceAKid)
    const { ds, transport } = setup({ [deviceAKid]: kp })
    const store = memoryStore()
    const sign = signerFor(kp)
    const first = await ensureSelfGroup(store, transport, identityId, deviceAKid, kp, sign)
    expect(first).toBeDefined()

    const brokenTransport = new CoreMlsDeliveryTransport({ baseUrl: 'https://core.example', fetch: async () => { throw new Error('transport must not be used for an already-active device') } })
    const second = await ensureSelfGroup(store, brokenTransport, identityId, deviceAKid, kp, sign)
    expect(second).toBe(first)
    ds.close()
  })
})
