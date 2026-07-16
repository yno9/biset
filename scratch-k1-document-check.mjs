import { documentToRecords, recordsToDocument } from './src/did/document.ts'
import { deriveRootKey, deriveDidCommKey } from './src/did/keys.ts'
import { didFromRootPublicKey } from './src/did/keys.ts'

const seed = crypto.getRandomValues(new Uint8Array(32))
const root = deriveRootKey(seed)
const k1 = deriveDidCommKey(seed)
const did = didFromRootPublicKey(root.publicKey)

const doc = {
  id: did,
  identityKey: root.publicKey,
  keyAgreementKey: k1.publicKey,
  alsoKnownAs: ['mailto:y@biset.md'],
  service: [
    { id: 'mail', type: 'JMAPRelay', serviceEndpoint: ['https://mail.biset.md'], protocol: 'mail', address: 'y@biset.md' },
    { id: 'didcomm', type: 'DIDCommMessaging', serviceEndpoint: ['https://mediator.biset.md'], accept: ['didcomm/v2'], routingKeys: [`${did}#mediator-key-1`] },
  ],
}

const records = documentToRecords(doc)
console.log('records:')
for (const r of records) console.log(' ', r.name, '->', r.rdata.join(''))

const parsed = recordsToDocument(did, records)

const hex = (u) => Buffer.from(u).toString('hex')
if (hex(parsed.identityKey) !== hex(doc.identityKey)) throw new Error('FAIL: identityKey mismatch')
if (hex(parsed.keyAgreementKey) !== hex(doc.keyAgreementKey)) throw new Error('FAIL: keyAgreementKey mismatch')
console.log('ok   _k0/_k1 round-trip')

const didcommSvc = parsed.service.find(s => s.type === 'DIDCommMessaging')
if (!didcommSvc) throw new Error('FAIL: DIDCommMessaging service missing after round-trip')
if (didcommSvc.serviceEndpoint[0] !== 'https://mediator.biset.md') throw new Error('FAIL: serviceEndpoint mismatch')
if (JSON.stringify(didcommSvc.accept) !== JSON.stringify(['didcomm/v2'])) throw new Error('FAIL: accept mismatch')
if (JSON.stringify(didcommSvc.routingKeys) !== JSON.stringify([`${did}#mediator-key-1`])) throw new Error('FAIL: routingKeys mismatch')
console.log('ok   DIDCommMessaging service (ac=/rk=) round-trip')

// spec.md's own worked example: v=0;vm=k0,k1;auth=k0;asm=k0;agm=k1;inv=k0;del=k0;svc=s0
const root_ = records.find(r => r.name.startsWith('_did.'))
const rootStr = root_.rdata.join('')
console.log('\nroot record:', rootStr)
if (!rootStr.includes('vm=k0,k1')) throw new Error('FAIL: vm= missing k1')
if (!rootStr.includes('agm=k1')) throw new Error('FAIL: agm= missing')
if (!/auth=k0.*asm=k0.*agm=k1.*inv=k0.*del=k0/.test(rootStr)) throw new Error('FAIL: field order does not match did-dht spec.md worked example')
console.log('ok   root record field order matches did-dht spec.md worked example exactly')

console.log('\n_k1 / DIDCommMessaging document encoding verified.')
