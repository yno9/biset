import { decodeRecoveryArchive, encodeRecoveryArchive, type RecoveryArchiveV1 } from './recovery-archive.ts'

export const RECOVERY_ARCHIVE_MEDIA_TYPE = 'application/vnd.biset.recovery-archive+json;version=1'

/** Browser-facing encrypted archive body; safe to give to a download UI. */
export function recoveryArchiveBlob(archive: RecoveryArchiveV1): Blob {
  return new Blob([arrayBuffer(encodeRecoveryArchive(archive))], { type: RECOVERY_ARCHIVE_MEDIA_TYPE })
}

/** Reads a user-selected File/Blob without ever treating it as plaintext vault data. */
export async function readRecoveryArchiveFile(file: Blob): Promise<RecoveryArchiveV1> {
  if (!(file instanceof Blob) || file.size === 0) throw new TypeError('recovery archive file is empty or invalid')
  return decodeRecoveryArchive(new Uint8Array(await file.arrayBuffer()))
}

/** Avoids leaking an identity string into a filename while retaining a useful date. */
export function recoveryArchiveFileName(archive: RecoveryArchiveV1): string {
  const date = archive.createdAt.slice(0, 10)
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) throw new TypeError('recovery archive creation time is invalid')
  return `biset-recovery-${date}.biset-recovery.json`
}

function arrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.length)
  copy.set(bytes)
  return copy.buffer
}
