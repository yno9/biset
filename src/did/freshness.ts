// Rollback/stale-record defense (DID.md freshness rule): remember the highest
// seq seen per DID and reject anything lower. A gateway can serve an old but
// validly-signed record; without this a downgrade would silently succeed. Stored
// in localStorage (tiny — one integer per known DID) rather than IndexedDB, to
// avoid a schema/version migration on the shared DID DB.
const PREFIX = 'biset_did_seq:'

export function seenSeq(did: string): number {
  const v = localStorage.getItem(PREFIX + did)
  return v ? Number(v) : -1
}

// Records seq as the new floor when it advances. Returns false if seq is a
// rollback (strictly lower than what we've already trusted) — the caller must
// then reject the record.
export function noteSeq(did: string, seq: number): boolean {
  if (seq < seenSeq(did)) return false
  localStorage.setItem(PREFIX + did, String(seq))
  return true
}
