# Mediation

This module is the bounded delivery data plane.

It owns short-lived ingress and vault-delivery buffers, ACK/cursor state, gap records, and opaque push/control notifications. Its stores have independent TTL and quota policies. They must never become mailbox, search, blob archive, or restore-history storage.
