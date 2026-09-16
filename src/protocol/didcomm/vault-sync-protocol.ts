// Biset-specific DIDComm extensions.  They are not DIF-registered message
// types; standard DIDComm routing and Pickup 3.0 still carry them unchanged.
export const VAULT_SYNC_UPDATE = 'https://biset.md/vault-sync/1.0/update'
export const VAULT_SYNC_STATE_REQUEST = 'https://biset.md/vault-sync/1.0/state-request'
export const VAULT_SYNC_STATE_RESPONSE = 'https://biset.md/vault-sync/1.0/state-response'
