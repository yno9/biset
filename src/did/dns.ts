// Minimal RFC1035 DNS packet codec for did:dht (encode/decode of the answer-only
// packet that becomes the BEP44 `v` value). did:dht packets carry no question,
// set the Authoritative Answer flag, and use name compression (RFC1035 §4.1.4).
// Only the record types did:dht uses are handled: TXT (record content) and NS
// (gateway designations — decoded and skipped, never emitted by biset).
import type { DnsRecord } from './document.ts'

const TYPE_NS = 2
const TYPE_TXT = 16
const CLASS_IN = 1
const FLAG_QR_AA = 0x8400 // response + authoritative answer

// ── name encoding with compression ───────────────────────────────────────────
class Writer {
  private buf: number[] = []
  // remaining-name (lowercased, no trailing dot) → byte offset, for compression.
  private names = new Map<string, number>()

  get length(): number { return this.buf.length }
  bytes(): Uint8Array { return new Uint8Array(this.buf) }

  u8(v: number): void { this.buf.push(v & 0xff) }
  u16(v: number): void { this.buf.push((v >> 8) & 0xff, v & 0xff) }
  u32(v: number): void { this.buf.push((v >>> 24) & 0xff, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff) }
  raw(bytes: Uint8Array): void { for (const b of bytes) this.buf.push(b) }

  // A character-string: 1-byte length prefix + bytes (≤255).
  charString(s: string): void {
    const b = new TextEncoder().encode(s)
    if (b.length > 255) throw new Error('character-string exceeds 255 bytes')
    this.u8(b.length)
    this.raw(b)
  }

  name(fqdn: string): void {
    const labels = fqdn.replace(/\.$/, '').split('.').filter(l => l.length > 0)
    let i = 0
    while (i < labels.length) {
      const remaining = labels.slice(i).join('.').toLowerCase()
      const ptr = this.names.get(remaining)
      if (ptr !== undefined) {
        this.u16(0xc000 | ptr)
        return
      }
      if (this.buf.length < 0x4000) this.names.set(remaining, this.buf.length)
      const label = new TextEncoder().encode(labels[i])
      if (label.length > 63) throw new Error('label exceeds 63 bytes')
      this.u8(label.length)
      this.raw(label)
      i++
    }
    this.u8(0) // root terminator
  }
}

export function encodePacket(records: DnsRecord[]): Uint8Array {
  const w = new Writer()
  w.u16(0)            // ID
  w.u16(FLAG_QR_AA)   // flags
  w.u16(0)            // QDCOUNT
  w.u16(records.length) // ANCOUNT
  w.u16(0)            // NSCOUNT
  w.u16(0)            // ARCOUNT

  for (const r of records) {
    w.name(r.name)
    w.u16(r.type === 'NS' ? TYPE_NS : TYPE_TXT)
    w.u16(CLASS_IN)
    w.u32(r.ttl)
    // RDATA — measured by encoding into a sub-writer, then length-prefixed.
    if (r.type === 'TXT') {
      const sub = new Writer()
      for (const chunk of r.rdata) sub.charString(chunk)
      const rd = sub.bytes()
      w.u16(rd.length)
      w.raw(rd)
    } else {
      // NS rdata is a domain name. biset never emits NS, but keep it correct:
      // encoded without compression against the outer table for simplicity.
      const sub = new Writer()
      sub.name(r.rdata.join(''))
      const rd = sub.bytes()
      w.u16(rd.length)
      w.raw(rd)
    }
  }
  return w.bytes()
}

// ── decode ───────────────────────────────────────────────────────────────────
class Reader {
  constructor(private view: DataView, public pos = 0) {}
  u8(): number { return this.view.getUint8(this.pos++) }
  u16(): number { const v = this.view.getUint16(this.pos); this.pos += 2; return v }
  u32(): number { const v = this.view.getUint32(this.pos); this.pos += 4; return v }

  name(): string {
    const labels: string[] = []
    let pos = this.pos
    let jumped = false
    // Guard against pointer loops: never follow more pointers than bytes.
    let hops = 0
    for (;;) {
      const len = this.view.getUint8(pos)
      if (len === 0) { pos++; break }
      if ((len & 0xc0) === 0xc0) {
        const ptr = ((len & 0x3f) << 8) | this.view.getUint8(pos + 1)
        if (!jumped) this.pos = pos + 2
        pos = ptr
        jumped = true
        if (++hops > this.view.byteLength) throw new Error('DNS name pointer loop')
        continue
      }
      pos++
      const bytes = new Uint8Array(this.view.buffer, this.view.byteOffset + pos, len)
      labels.push(new TextDecoder().decode(bytes))
      pos += len
    }
    if (!jumped) this.pos = pos
    return labels.length ? labels.join('.') + '.' : '.'
  }

  charStrings(rdlength: number): string[] {
    const end = this.pos + rdlength
    const out: string[] = []
    while (this.pos < end) {
      const len = this.u8()
      const bytes = new Uint8Array(this.view.buffer, this.view.byteOffset + this.pos, len)
      out.push(new TextDecoder().decode(bytes))
      this.pos += len
    }
    this.pos = end
    return out
  }
}

export function decodePacket(packet: Uint8Array): DnsRecord[] {
  const view = new DataView(packet.buffer, packet.byteOffset, packet.byteLength)
  const r = new Reader(view)
  r.u16() // ID
  r.u16() // flags
  const qd = r.u16()
  const an = r.u16()
  r.u16() // NSCOUNT
  r.u16() // ARCOUNT

  // Skip any question entries (did:dht emits none, but be tolerant).
  for (let i = 0; i < qd; i++) { r.name(); r.u16(); r.u16() }

  const records: DnsRecord[] = []
  for (let i = 0; i < an; i++) {
    const name = r.name()
    const type = r.u16()
    r.u16() // class
    const ttl = r.u32()
    const rdlength = r.u16()
    if (type === TYPE_TXT) {
      records.push({ name, type: 'TXT', ttl, rdata: r.charStrings(rdlength) })
    } else if (type === TYPE_NS) {
      records.push({ name, type: 'NS', ttl, rdata: [r.name()] })
    } else {
      r.pos += rdlength // unknown type — skip its rdata
    }
  }
  return records
}
