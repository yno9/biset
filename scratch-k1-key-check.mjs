import { deriveRootKey, deriveDidCommKey } from './src/did/keys.ts'

const seed = crypto.getRandomValues(new Uint8Array(32))

// determinism: same seed -> same key, twice
const a = deriveDidCommKey(seed)
const b = deriveDidCommKey(seed)
const hex = (u) => Buffer.from(u).toString('hex')
if (hex(a.privateKey) !== hex(b.privateKey)) throw new Error('FAIL: not deterministic')
console.log('ok   deterministic (same seed -> same _k1 key)')

// independence: different seed -> different key
const other = deriveDidCommKey(crypto.getRandomValues(new Uint8Array(32)))
if (hex(a.privateKey) === hex(other.privateKey)) throw new Error('FAIL: collision across seeds')
console.log('ok   different seeds -> different keys')

// key separation: _k1 must NOT equal any birational transform of root — the
// whole point of a separate path. Cheapest check: the raw derived bytes
// (pre-X25519-keygen) differ from root's raw derived bytes for the same seed.
const root = deriveRootKey(seed)
if (hex(root.privateKey) === hex(a.privateKey)) throw new Error('FAIL: _k1 raw key equals root raw key — path collision')
console.log('ok   _k1 derivation path independent of root (m/1\' != m/0\')')

console.log('\n_k1 (DIDComm X25519) key derivation verified.')
