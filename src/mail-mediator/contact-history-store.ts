// Pure state machine: which counterpart addresses has THIS address ever
// received DKIM-verified mail from. Backs the outbound recipient
// allowlist (server.ts's SUBMIT handler) -- an address may send to
// anyone under an allowed domain, or to anyone it has previously
// received mail FROM (one-directional: receiving establishes trust,
// sending does not, so a cold-outreach spam target can't be added to the
// list just by being mailed).
//
// DKIM verification (not the raw, unauthenticated envelope MAIL FROM) is
// what decides whether an entry is recorded at all -- smtp-listener.ts
// only calls record() after verifyDkimSignatures() found the sender
// domain aligned, so a plain spoofed From cannot plant an entry here.

const MAX_CONTACTS_PER_ADDRESS = 10_000

export class ContactHistoryFullError extends Error {}

export interface MailContactHistoryStore {
  record(address: string, counterpartyAddress: string): void
  hasContact(address: string, counterpartyAddress: string): boolean
}

export class ContactHistoryStore implements MailContactHistoryStore {
  private known = new Map<string, Set<string>>()

  record(address: string, counterpartyAddress: string): void {
    const key = counterpartyAddress.toLowerCase()
    const set = this.known.get(address) ?? new Set()
    if (!set.has(key) && set.size >= MAX_CONTACTS_PER_ADDRESS) {
      throw new ContactHistoryFullError(`mail-mediator: too many known contacts for ${address}`)
    }
    set.add(key)
    this.known.set(address, set)
  }

  hasContact(address: string, counterpartyAddress: string): boolean {
    return this.known.get(address)?.has(counterpartyAddress.toLowerCase()) ?? false
  }
}
