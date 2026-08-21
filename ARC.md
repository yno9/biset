# Biset Architecture

*Status: skeleton. The implementation plan is authoritative until this document is expanded.*

## 1. Purpose

## 2. Design Principles

- Endpoint-owned vaults are the long-term source of truth.
- The core provides bounded delivery, not a mailbox archive.
- JMAP remains the client data API.
- Device membership and vault key epochs are managed by MLS self groups.

## 3. System Artifacts

### 3.1 Biset Client

### 3.2 Biset Core / Anchor

### 3.3 Protocol Schemas

## 4. Trust and Identity Model

### 4.1 Identity

### 4.2 Devices

### 4.3 MLS Self Group

### 4.4 Revocation and Restore

## 5. Vault Model

### 5.1 Events and Objects

### 5.2 Manifests and Projections

### 5.3 Segment Keys and Epoch Keys

### 5.4 Local Persistence and Garbage Collection

## 6. Delivery Model

### 6.1 Ingress Buffer

### 6.2 Shared Vault Delivery Buffer

### 6.3 Acknowledgements, Cursors, and TTL

### 6.4 Restore

## 7. Client Data API

### 7.1 Local JMAP Gateway

### 7.2 Remote JMAP Accounts

### 7.3 Account Routing

## 8. Transport Adapters

### 8.1 DIDComm

### 8.2 Mail, Autocrypt, and OpenPGP

### 8.3 ActivityPub

### 8.4 Adapter Host Boundary

## 9. Security and Privacy Properties

## 10. Availability and Failure Semantics

## 11. Protocol Versioning and Compatibility

## 12. Deployment and Operations

## 13. Development Workflow

## 14. Migration from the Legacy Relay

## 15. Decision Record

## 16. Open Questions

---

For concrete schemas, state machines, migration phases, and release gates, see [PLANIMPLEMENTATION.md](PLANIMPLEMENTATION.md).
