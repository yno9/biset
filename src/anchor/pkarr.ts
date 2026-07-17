// Pkarr relay: a Mainline DHT node reachable over HTTP, so browsers (which
// cannot speak UDP/Kademlia) can read and write did:dht records.
//
//	GET  /pkarr/<z-base-32 pubkey> → wire payload (sig ‖ seq ‖ v), or 404
//	PUT  /pkarr/<z-base-32 pubkey>   body = wire payload → 204, or 400
//
// Ported from go-jmapserver/pkarr (ANCHOR.md decision 1: the DID machinery
// belongs to the anchor, not to every relay). Behaviour-identical to the Go
// gateway on purpose — verified against production by reading a live record
// through both and comparing the bytes.
//
// Records are self-signed and this never signs: PUT verifies the client's
// signature against the key named in the path, so the gateway can neither forge
// a record nor accept one for a key it doesn't match. That is what makes it safe
// to run this for anyone.
//
// Privacy: a gateway sees who looks up whom. It stays sound only because an
// anchor is per-operator by construction (ANCHOR.md non-goals) — the client is
// asking the operator it already trusts with its mail, via its own relay, which
// proxies here. Running ONE anchor for everybody would turn this into a global
// observer of every lookup.
import DHT, { type MutableResult } from 'bittorrent-dht'
import { createHash } from 'node:crypto'
import { mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { lookup } from 'node:dns/promises'
import { ed25519 } from '@noble/curves/ed25519.js'

const SIG_LEN = 64
const SEQ_LEN = 8
const HEADER_LEN = SIG_LEN + SEQ_LEN
const MAX_PACKET_LEN = 1000
const REPUBLISH_MS = 30 * 60 * 1000
const GET_TIMEOUT_MS = 30_000

// Same list anacrolix/dht carries (what the Go gateway bootstrapped from, and
// it worked). bittorrent-dht's own default is only the three classic nodes, and
// two of those stopped answering years ago.
const BOOTSTRAP_HOSTS: [string, number][] = [
  ['dht.transmissionbt.com', 6881],
  ['dht.libtorrent.org', 25401],
  ['router.utorrent.com', 6881],
  ['router.bittorrent.com', 6881],
  ['dht.aelitis.com', 6881],
]

/** Bootstrap addresses as IPv4 literals.
 *
 * The hostnames are NOT passed through: bittorrent-dht resolves them with
 * dns.lookup and no family hint, while k-rpc-socket hardcodes a udp4 socket. A
 * host with an AAAA record (dht.transmissionbt.com has one) then yields an IPv6
 * address that the udp4 socket drops **silently** — no error, no packet, an
 * empty routing table, and every lookup timing out as if the DHT were down.
 * That cost an afternoon; resolving A records ourselves makes it impossible. */
async function bootstrapAddrs(): Promise<string[]> {
  const out: string[] = []
  await Promise.all(BOOTSTRAP_HOSTS.map(async ([host, port]) => {
    try {
      const { address } = await lookup(host, { family: 4 })
      out.push(`${address}:${port}`)
    } catch { /* a dead bootstrap host is ordinary; the others carry it */ }
  }))
  return out
}

/** BEP44 mutable target: SHA1(pubkey ‖ salt), salt empty — matches Go's
 * bep44.MakeMutableTarget(pubkey, nil). */
const mutableTarget = (pubkey: Buffer) => createHash('sha1').update(pubkey).digest()

export interface WirePayload { sig: Buffer; seq: number; v: Buffer }

/** Splits `sig(64) ‖ seq(8, big-endian) ‖ v` — the shape src/did/packet.ts
 * produces and the Pkarr relay spec defines. */
export function splitPayload(payload: Buffer): WirePayload | null {
  if (payload.length < HEADER_LEN) return null
  return {
    sig: payload.subarray(0, SIG_LEN),
    seq: Number(payload.readBigUInt64BE(SIG_LEN)),
    v: payload.subarray(HEADER_LEN),
  }
}

export function joinPayload(sig: Buffer, seq: number, v: Buffer): Buffer {
  const seqBuf = Buffer.alloc(SEQ_LEN)
  seqBuf.writeBigUInt64BE(BigInt(seq))
  return Buffer.concat([sig, seqBuf, v])
}

/** The exact buffer BEP44 signs: "3:seqi<seq>e1:v" ‖ bencode(v), empty salt.
 * bencode of a byte string is "<len>:<bytes>", which is all we need here — no
 * bencode library, because v is always a string and seq always an integer. */
function signedBuffer(seq: number, v: Buffer): Buffer {
  return Buffer.concat([Buffer.from(`3:seqi${seq}e1:v${v.length}:`), v])
}

/** The republish set, kept on disk as `<dataDir>/_pkarr/<hex pubkey>`.
 *
 * **Stored, not derived — and that is not a contradiction of decision 1b.** The
 * DID→address index had to stop being stored because it is a pure function of
 * the identity.fp files: a second copy could only ever drift out of step. A
 * pkarr payload is the opposite. It is a blob the client signed, recomputable
 * from nothing the anchor holds, so keeping it is the only way to keep it.
 *
 * The Go gateway held this in memory alone and got away with it, because every
 * relay ran a gateway — one restarting still left another republishing. One
 * anchor now serves the whole family, so an in-memory set would mean each
 * restart silently stopped republishing every identity until its owner next
 * happened to publish. Worse, a record the DHT had already dropped could never
 * come back: nobody else has the bytes.
 *
 * Its own class so the disk behaviour can be tested without a live DHT — which
 * cannot be faked, and which the thing being tested here does not involve. */
export class PayloadStore {
  constructor(private dir: string) {}

  load(): Map<string, Buffer> {
    const out = new Map<string, Buffer>()
    let entries: string[]
    try {
      entries = readdirSync(this.dir)
    } catch {
      return out // first run — nothing carried over
    }
    for (const hex of entries) {
      try {
        out.set(hex, readFileSync(join(this.dir, hex)))
      } catch { /* skip an unreadable entry rather than refuse to start */ }
    }
    return out
  }

  /** Best-effort: a write that fails costs this record its republishing after
   * the next restart, which must not also cost the caller its request. */
  put(hex: string, payload: Buffer): void {
    try {
      mkdirSync(this.dir, { recursive: true, mode: 0o700 })
      writeFileSync(join(this.dir, hex), payload, { mode: 0o600 })
    } catch (e) {
      console.error(`[pkarr] could not persist ${hex.slice(0, 12)}…:`, e instanceof Error ? e.message : e)
    }
  }

  drop(hex: string): void {
    rmSync(join(this.dir, hex), { force: true })
  }
}

/** Answers "is this key an identity we anchor?" — the claim registry, asked
 * about a raw pubkey rather than a DID. Injected rather than imported so the
 * gateway keeps knowing nothing about claims beyond this one question. */
export type IsAnchored = (pubkey: Buffer) => boolean

export class PkarrGateway {
  private dht: DHT
  private cache = new Map<string, Buffer>() // hex pubkey → last-seen payload, mirrored by store
  private timer: ReturnType<typeof setInterval> | null = null

  private constructor(dht: DHT, private store: PayloadStore, private isAnchored: IsAnchored) {
    this.dht = dht
  }

  static async start(dataDir: string, isAnchored: IsAnchored): Promise<PkarrGateway> {
    const bootstrap = await bootstrapAddrs()
    if (bootstrap.length === 0) throw new Error('pkarr: no bootstrap node resolved')
    const dht = new DHT({
      bootstrap,
      // Required for mutable (BEP44) records; without it bittorrent-dht refuses
      // to store or return them.
      verify: (sig: Buffer, msg: Buffer, pk: Buffer) => {
        try { return ed25519.verify(sig, msg, pk) } catch { return false }
      },
    })
    dht.listen(0)
    await new Promise<void>(resolve => dht.once('ready', () => resolve()))
    const g = new PkarrGateway(dht, new PayloadStore(join(dataDir, '_pkarr')), isAnchored)
    // Entries whose identity is no longer ours are dropped on the way in, not
    // just skipped: a released claim must not leave its record being announced
    // for the life of the process.
    for (const [hex, payload] of g.store.load()) {
      if (isAnchored(Buffer.from(hex, 'hex'))) g.cache.set(hex, payload)
      else g.store.drop(hex)
    }
    if (g.cache.size > 0) console.log(`[pkarr] republishing ${g.cache.size} record(s) carried over from disk`)
    g.timer = setInterval(() => void g.republishAll(), REPUBLISH_MS)
    return g
  }

  close(): void {
    if (this.timer) clearInterval(this.timer)
    this.dht.destroy()
  }

  /** Resolves a mutable record and returns the reassembled wire payload, or
   * null when the DHT has no such record (a stalled traversal is indistinguishable
   * from absence here, and both mean "cannot answer"). */
  async get(pubkey: Buffer): Promise<Buffer | null> {
    const res = await new Promise<MutableResult | null>(resolve => {
      const t = setTimeout(() => resolve(null), GET_TIMEOUT_MS)
      this.dht.get(mutableTarget(pubkey), (err, r) => {
        clearTimeout(t)
        resolve(err ? null : r)
      })
    })
    if (!res?.v) return null
    const payload = joinPayload(Buffer.from(res.sig), Number(res.seq), Buffer.from(res.v))
    this.remember(pubkey, payload)
    return payload
  }

  /** Verifies a payload against pubkey and publishes it. Never signs — the
   * client's signature is forwarded verbatim, so a gateway cannot forge. */
  async put(pubkey: Buffer, payload: Buffer): Promise<void> {
    const p = splitPayload(payload)
    if (!p) throw new Error('pkarr: payload too short')
    if (p.v.length > MAX_PACKET_LEN) throw new Error('pkarr: DNS packet exceeds 1000 bytes')
    if (!ed25519.verify(p.sig, signedBuffer(p.seq, p.v), pubkey)) {
      throw new Error('pkarr: invalid signature')
    }
    await this.publish(pubkey, p)
    this.remember(pubkey, payload)
  }

  private async publish(pubkey: Buffer, p: WirePayload): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      // The client's seq and signature go out as-is: the record is signed for
      // exactly this seq, so letting the library pick one would invalidate it.
      this.dht.put({ v: p.v, k: pubkey, sig: p.sig, seq: p.seq }, err => {
        err ? reject(err) : resolve()
      })
    })
  }

  /** Takes on republishing a record — but only for an identity this anchor
   * actually anchors.
   *
   * Both get() and put() used to remember unconditionally, inherited from the Go
   * gateway. Reading a stranger's DID once was therefore enough to make this
   * republish it for as long as the process lived, and forget() only ever fires
   * when one of our own claims is released — so nothing ever removed it. In Go
   * that leaked memory until the next restart. Persisting the set turned the
   * same code into an unbounded disk leak and a free permanent pinning service
   * for anyone who could name a key.
   *
   * The registry already knows which identities are ours, and the answer bounds
   * the set by the number of accounts. Resolving still works for everyone —
   * strangers' records are fetched and returned, just not adopted.
   *
   * Best-effort on disk: a failed write costs this record its republishing after
   * the next restart, which must not also cost the caller its request. */
  private remember(pubkey: Buffer, payload: Buffer): void {
    if (!this.isAnchored(pubkey)) return
    const hex = pubkey.toString('hex')
    this.cache.set(hex, Buffer.from(payload))
    this.store.put(hex, payload)
  }

  /** Drops a key from the republish set — called when the identity it belongs to
   * is permanently deleted. Without it the loop would re-announce an orphaned
   * record forever: a BEP44 record only fades (~2h) once nothing re-announces
   * it, and this gateway is that re-announcer. Deleting it from disk too, or a
   * restart would resurrect the identity we were asked to forget. */
  forget(pubkey: Buffer): void {
    const hex = pubkey.toString('hex')
    this.cache.delete(hex)
    this.store.drop(hex)
  }

  /** DHT records expire in hours, so anything served here must be refreshed to
   * stay resolvable. Failures are ignored: the next tick tries again, and one
   * unreachable record must not stop the others. */
  private async republishAll(): Promise<void> {
    for (const [hex, payload] of [...this.cache]) {
      const p = splitPayload(payload)
      if (!p) continue
      try { await this.publish(Buffer.from(hex, 'hex'), p) } catch { /* next tick */ }
    }
  }
}
