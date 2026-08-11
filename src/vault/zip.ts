// Minimal ZIP writer — STORED (uncompressed) entries only. No dependency:
// avoids pulling in a DEFLATE implementation for what's fundamentally a data
// export feature, not a bandwidth-sensitive one; any standard unzip tool
// reads STORED entries identically to compressed ones.
export interface ZipEntryInput { path: string; data: Uint8Array }

const CRC_TABLE = (() => {
  const table = new Uint32Array(256)
  for (let n = 0; n < 256; n++) {
    let c = n
    for (let k = 0; k < 8; k++) c = c & 1 ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1)
    table[n] = c >>> 0
  }
  return table
})()

function crc32(data: Uint8Array): number {
  let c = 0xffffffff
  for (let i = 0; i < data.length; i++) c = CRC_TABLE[(c ^ data[i]!) & 0xff]! ^ (c >>> 8)
  return (c ^ 0xffffffff) >>> 0
}

function dosDateTime(): { time: number; date: number } {
  const d = new Date()
  const time = ((d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1)) & 0xffff
  const date = (((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate()) & 0xffff
  return { time, date }
}

class Writer {
  private chunks: Uint8Array[] = []
  private len = 0
  push(b: Uint8Array): void { this.chunks.push(b); this.len += b.length }
  u16(v: number): void { this.push(new Uint8Array([v & 0xff, (v >>> 8) & 0xff])) }
  u32(v: number): void { this.push(new Uint8Array([v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff])) }
  offset(): number { return this.len }
  build(): Uint8Array {
    const out = new Uint8Array(this.len)
    let o = 0
    for (const c of this.chunks) { out.set(c, o); o += c.length }
    return out
  }
}

export function buildZip(entries: ZipEntryInput[]): Uint8Array {
  const enc = new TextEncoder()
  const { time, date } = dosDateTime()
  const w = new Writer()
  const centralOffsets: number[] = []

  for (const entry of entries) {
    const nameBytes = enc.encode(entry.path)
    const crc = crc32(entry.data)
    centralOffsets.push(w.offset())
    w.u32(0x04034b50) // local file header signature
    w.u16(20) // version needed
    w.u16(0) // flags
    w.u16(0) // compression: stored
    w.u16(time)
    w.u16(date)
    w.u32(crc)
    w.u32(entry.data.length) // compressed size
    w.u32(entry.data.length) // uncompressed size
    w.u16(nameBytes.length)
    w.u16(0) // extra field length
    w.push(nameBytes)
    w.push(entry.data)
  }

  const centralStart = w.offset()
  entries.forEach((entry, i) => {
    const nameBytes = enc.encode(entry.path)
    const crc = crc32(entry.data)
    w.u32(0x02014b50) // central directory file header signature
    w.u16(20) // version made by
    w.u16(20) // version needed
    w.u16(0) // flags
    w.u16(0) // compression: stored
    w.u16(time)
    w.u16(date)
    w.u32(crc)
    w.u32(entry.data.length)
    w.u32(entry.data.length)
    w.u16(nameBytes.length)
    w.u16(0) // extra field length
    w.u16(0) // comment length
    w.u16(0) // disk number start
    w.u16(0) // internal attributes
    w.u32(0) // external attributes
    w.u32(centralOffsets[i]!)
    w.push(nameBytes)
  })
  const centralSize = w.offset() - centralStart

  w.u32(0x06054b50) // end of central directory signature
  w.u16(0) // disk number
  w.u16(0) // disk with central dir
  w.u16(entries.length)
  w.u16(entries.length)
  w.u32(centralSize)
  w.u32(centralStart)
  w.u16(0) // comment length

  return w.build()
}

/** Reads back a ZIP built by buildZip above (or any other STORED-only,
 * non-streamed zip — sizes present in the local file header itself, no data
 * descriptor). Walks local file headers sequentially from the start rather
 * than via the central directory at the end: buildZip's headers already carry
 * the real compressed/uncompressed size (STORE never needs the streaming
 * "size unknown yet" flag), so there's nothing the central directory would
 * tell us that the local headers don't already have. Throws on a compressed
 * (non-zero method) entry rather than silently returning corrupt bytes — this
 * reader has no DEFLATE, matching buildZip's own "STORE only" scope note. */
export function readZip(data: Uint8Array): ZipEntryInput[] {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength)
  const entries: ZipEntryInput[] = []
  let o = 0
  while (o + 4 <= data.length && view.getUint32(o, true) === 0x04034b50) {
    const method = view.getUint16(o + 8, true)
    const compressedSize = view.getUint32(o + 18, true)
    const nameLen = view.getUint16(o + 26, true)
    const extraLen = view.getUint16(o + 28, true)
    const nameStart = o + 30
    const dataStart = nameStart + nameLen + extraLen
    if (method !== 0) throw new Error(`readZip: entry uses compression method ${method}, only STORE (0) is supported`)
    const path = new TextDecoder().decode(data.subarray(nameStart, nameStart + nameLen))
    entries.push({ path, data: data.slice(dataStart, dataStart + compressedSize) })
    o = dataStart + compressedSize
  }
  return entries
}
