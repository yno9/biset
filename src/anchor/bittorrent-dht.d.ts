// bittorrent-dht ships no types and @types/bittorrent-dht does not exist. This
// declares only the surface pkarr.ts uses (BEP44 mutable get/put), rather than
// letting the import fall to `any` and lose checking at every call site.
declare module 'bittorrent-dht' {
  export interface DHTOptions {
    /** `host:port` strings. Pass IPv4 LITERALS, not hostnames — see
     * pkarr.ts's bootstrapAddrs for why a hostname can silently produce a
     * routing table of zero nodes. */
    bootstrap?: string[]
    /** Required for mutable (BEP44) records; without it the library will not
     * store or return them. */
    verify?: (signature: Buffer, message: Buffer, publicKey: Buffer) => boolean
    nodeId?: Buffer | string
  }

  /** What a mutable get returns. `seq` may arrive as a number or bigint
   * depending on its magnitude, so callers normalise it. */
  export interface MutableResult {
    v: Buffer
    sig: Buffer
    seq: number | bigint
    k?: Buffer
  }

  export interface PutOpts {
    v: Buffer
    k: Buffer
    sig: Buffer
    seq: number
  }

  export class DHT {
    constructor(opts?: DHTOptions)
    listen(port?: number, onlistening?: () => void): void
    once(event: 'ready', cb: () => void): this
    on(event: 'error' | 'warning', cb: (err: Error) => void): this
    get(target: Buffer, cb: (err: Error | null, res: MutableResult | null) => void): void
    put(opts: PutOpts, cb: (err: Error | null, hash?: Buffer, n?: number) => void): void
    toJSON(): { nodes: unknown[] }
    destroy(cb?: () => void): void
  }

  export default DHT
}
