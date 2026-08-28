# PLANIMPLEMENTATION.md — Biset service decomposition implementation plan

> Status: architecture and migration plan
> 改訂日: 2026-08-28
> 実装順の正本は[PLAN.md](PLAN.md)。本書は共通contract、移行、検証方法を定義する。

## 1. Goal

現行`biset-core`を解体し、次の四つの主要コンポーネントへ責務を固定する。

```text
1. Anchor      — identity provider
2. Mediator    — transport protocols
3. Vault       — local storage in Client
4. Coordinator — cross-device persistence and convergence
```

DIDCommとMailはMediator内部でwire/storage/failure domainを分離する。現在は別binaryで稼働させ、公開上は同じMediator componentとして扱う。

Milestone 3で複数local Vaultの収束性を先に確立し、そのClient-side workflowを前提にMilestone 4のMail Mediatorをproductionへcutoverする。RelayとMail Mediatorの間にserver-to-server依存は作らない。

## 2. Trust and knowledge matrix

| Component | Trusts/holds | Must not know |
|---|---|---|
| Anchor | DID/address/key transition/OIDC issuer | vaultId、MLS、message、Vault route |
| DIDComm Mediator | registered kid、opaque JWE、queue/ACK | Vault、mail、plaintext、human identity mapping |
| Mail Mediator | address、SMTP、mail holder、spool | vaultId、MLS、Vault member |
| Vault Coordinator | vaultId、MLS routing view、opaque pack、ACK、OIDC issuer/JWKS、pairwise subject | DID、SCID、domain、address、message semantics |
| Vault / Client | all local bindings/secrets/plaintext、暗号化長期正本 | — |

Knowledge separationはコメントではなく、protocol identifier、DB schema、import graph、network ACL、testsで保証する。

## 3. Identifiers

### Public identity identifiers

- DID / did:webvh SCID
- domain
- mail address
- identity operational key IDs

Anchor/Mail/DIDComm public routingでのみ使う。

### Vault identifiers

- random 256-bit `vaultId`
- Vault-local MLS group ID
- random Vault member ID
- delivery sequence

Vault Coordinator外側でのみ使う。DID/SCID/addressから導出しない。

### Local binding

Client IndexedDBだけが次を持てる。

```ts
interface LocalIdentityVaultBinding {
  localAccountId: string
  currentDid: string
  vaultId: string
  coordinatorRoute?: string
}
```

このrecordをserverへそのまま送らない。

## 4. Authentication profile（外側OIDC + 内側OpenID4VP、2026-08-28決定）

### Anchor / third party login

- 公開ログインprotocolはOpenID Connectに統一する。
- Nextcloud、Forgejo、一般third partyはOIDC clientとして接続する。
- Authorization Code + PKCE、Discovery、JWKS、pairwise subjectをbaselineとする。
- Anchorのinteractive loginはOpenID4VP 1.0のDCQL + `direct_post`とし、device-local holder keyにbindingしたopaque Login Credentialを提示する。
- OpenID4VPの認証結果interfaceと外向きOIDC wireを分離する。ATProto OAuth adapterは将来追加するが、現時点では実装しない。
- Login CredentialにDID/SCID/domain/address/Vault情報を入れない。初回bootstrap時だけcurrent did:webvh `authentication` proofをAnchorが検証する。
- Anchor public document updateは引き続きself-certifying DID/WebVH proofで検証する。

### DIDComm

- DIDComm authcrypt/anoncrypt
- Coordinate Mediation key ownership
- Pickup 3.0 ACK
- OIDC/OAuthをinner DIDComm wireへ重ねない

### Vault Coordinator

- Anchorが発行する短命JWT access tokenを受け付けるOAuth Resource Serverとする。
- `iss`、Coordinator専用`aud`、`exp`、operation scopeを検証する。ID TokenをAPI tokenとして受け付けない。
- `sub`はCoordinator専用pairwise subjectとし、DID、SCID、domain、mail addressをtoken/DBへ入れない。
- Vault作成時にpairwise subjectとrandom `vaultId`をCoordinator内だけでbindingする。Anchorは`vaultId`を知らない。
- Vault member/epochのapplication authorizationはVaultGroupViewで別途検証する。
- DPoP sender constraintはtoken bearer利用をなくす次のhardening phaseで追加する。

Custom authorization projectionをcross-service credentialとして使わない。

## 5. Local Vault

Local Vaultは全messageの長期正本である。

- encrypted immutable objects
- signed events
- SegmentKey/wrap
- Local JMAP projection/state
- ingress receipts
- external ACK outbox
- optional Vault delivery outbox
- credential rotation outbox
- restore state/archive metadata

### Atomic ingress commit

```text
receipt
objects/events
projection/JMAP state
mediator ACK outbox
optional Vault delivery outbox
```

を一transactionで保存する。commit成功後にのみMail/DIDComm ACKを送る。

Vault Coordinator未設定時はdelivery outboxを作らなくてもよい。これがsingle-device pathを独立させる。

## 6. MLS / Vault cryptography

MLSはVault所属とする。

- private MLS state: Client
- MLS DS/public log/KeyPackage: Vault Coordinator
- member roster: Vault-local VaultGroupView
- group ID: vaultId系
- credential: random Vault BasicCredential
- exporter→VEK→SegmentKey wrap

Public DIDをMLS credentialへ入れない。domain moveはVault group/credential/cursorへ影響しない。

## 7. External ingress semantics

### DIDComm

```text
sender → blind mediator queue → Client pickup
       → authcrypt verify/decrypt → local Vault commit → ACK
```

### Mail

```text
SMTP → durable mail spool → one-of-N Client pickup
     → mail verify/project → local Vault commit → ACK
```

### Multi-device extension

```text
local commit → encrypted VaultDeliveryPack → Vault Coordinator
             → all append-time Vault members pull/commit/ACK
```

MediatorからCoordinatorへのdirect bridgeは作らない。

## 8. Shared protocol refactoring

`src/protocol/`をtransport-neutral schema/signing bytesの置き場として維持するが、identifierを明確に分ける。

- IdentityId: public identity plane only
- VaultId: Vault plane only
- MailSpoolId: Mail plane only
- DIDComm queue ID/kid: DIDComm plane only

禁止する型:

- Vault requestに`identityId`
- Identity credentialに`vaultId`/MLS member
- Mail routeにVault roster
- DIDComm queue recordにmail/Vault metadata

Compile-time branded typeとexact-key validatorでcross-plane混入を検出する。

## 9. Milestone 1 implementation — Anchor

### Extract

- `core/webvh/*`
- address allocation/resolution
- public document hosting
- identity control verification

### Remove from composition

- roster/MLS DS
- ingress/Vault delivery/restore
- SMTP/mail submission
- legacy DIDComm ingress

### Add

- dedicated entrypoint/package/build target
- dedicated DB/data directory
- OAuth AS metadata/JWKS
- OIDC Discovery/JWKS/authorization/token/userinfo endpoint
- key status/rotation
- health/readiness/metrics

### Migration

- public document/address recordsだけをcopyする
- count/hash/domain ownershipを検証する
- dual-read後にwrite endpointを切り替える
- rollback時にkey transitionを二重適用しない

## 10. Milestone 2 implementation — DIDComm Mediator

### Preserve

- mediator did:peer identity
- Coordinate/Forward/Pickup wire
- Client mediator libraries
- relationship key design

### Replace/harden

- JSON queue/connections → transactional DB
- in-memory replay → durable bounded replay store
- count-only quota → byte/rate/global quota
- best-effort persistence → commit-before-accept
- silent corrupt-file reset → readiness failure/recovery

### Production

- HTTPS/reverse proxy
- secret/data permissions
- backup/restore/schema migration
- metrics/alerts/log redaction
- load/restart/soak tests
- canary and runbook

## 11. Milestone 3 implementation — Vault Coordinator

### New protocol

- VaultId branded type
- signed VaultGroupView（group ID / transcript hash / previous-view hash / member key / floor）
- member-signed vaultId-based append/pull/ACK
- OAuth Resource Server + pairwise subject owner binding
- restore signaling（未実装）
- DPoP sender constraint（後続hardening）

### Move

- MLS DS/KeyPackage/log
- roster/floor
- Vault delivery/restore stores

### Migrate

- SCID-derived self-group → random Vault group
- did:webvh credential → Vault BasicCredential
- identity-keyed queue → vaultId queue
- existing SegmentKey wrap → new epoch VEK wrap

### Client

- create/store vaultId
- boot/poll Vault delivery
- durable ACK flush
- restoreRequired UI

### 現在の実装境界（2026-08-28）

- 独立binary、OIDC Discovery/JWKS access-token検証、operation scopeを実装済み。
- SQLiteのopaque payload fan-out、冪等append、非破壊pull、ACK、完全暗号化checkpointを実装済み。ACKだけでは本文を削除せず、checkpointがcoverしたdeliveryだけをcompactする。未checkpoint正本はTTL/quotaで破壊しない。
- signed group viewのhash chainとAdd/Remove/floor/recipient retirementを実装済み。
- OIDC owner tokenを持つだけのmember ID偽装を、current member Ed25519署名検証で拒否する。
- Browser transportと、既存local Vaultのatomic outbox/cursor/ACKをvaultId外側wireへ変換するbridgeを実装済み。identityIdはlocal partition keyから外へ出ない。
- local Vault DB v7にAnchor↔Vault↔Coordinator bindingを追加し、remote accepted hash確認後だけlocal group headを進めるlifecycleを実装済み。
- Anchor側のDiscovery/JWKS、Code + PKCE、pairwise subject、ES256 JWT発行、OpenID4VP Verifier/Login Credential/session、durable SQLite stateと永続provider compositionを実装済み。token endpointは`file://` Clientから交換できるCORS responseを返すが、`file:` redirect URI自体は許可しない。
- Client側はdevice-local Login Wallet、did:webvh proof enrollment、presentation、HTTPS popup/callback bridge、PKCE token providerを実装済み。restore login時はOIDC owner subjectから単一Vaultを自動発見し、root phrase由来KEKで完全checkpointを復元してからKeyPackageをpublishする。既存端末はfresh token中のpollでAddを自動承認する。one-time招待・手動承認UIはfallbackとして残す。pending joinのprivate KeyPackageはLocal Vault DB v9へ送信前に保存し、再起動後のresumeとbinding保存時のatomic削除を実装済みである。
- `Connect coordinator`はbinding未作成なら256-bit random `vaultId`/`vmb_…`を生成し、`vaultId`からdomain-separatedに導出したgroup IDを持つ実MLS genesis stateを作る。Coordinatorがsigned genesis viewのexact hashを受理した後だけ、private MLS stateを含むlocal bindingを有効化する。
- binding有効後はlegacy identity-keyed Coreへfallbackせず、token失効中はdurable delivery outboxを保持する。再ログイン後にopaque Coordinator routeへflushする。
- 残る暗号移行は、既存Local VaultのSegmentKey/VEK生成元をSCID-derived self-groupから新Vault MLS stateへ切り替えることである。KeyPackage/Commit/WelcomeのCoordinator DSとcheckpoint retention/GCは実装済みだが、全既存member不在時のMLS recovery join、Remove workflowは残る。

## 12. Milestone 4 implementation — Mail Mediator

### Extract

- SMTP listener/protocol
- recipient handling
- outbound SMTP client
- submission state

### Replace

- roster-backed device auth → mail固有authcrypt（OIDC採用の要否はMail milestoneで再評価）
- shared core ingress → mail-specific spool/claim/ACK
- identity device projection → address credential holder route

### Production

- port 25/587 policy
- TLS/cert/DNS/MX
- retry/DSN
- spam/rate/quota
- partial recipient result
- backup/restore/upgrade
- single-device Client receive/send E2E

- second-device onboarding
- Remove→external credential rotation

## 13. Testing strategy

### Boundary tests

- forbidden imports per service
- forbidden schema fields
- DB table inventory
- no server-to-server Identity↔Vault network calls
- log redaction

### Durability tests

- crash at every commit/ACK boundary
- response loss and idempotent retry
- restart with pending queue/outbox
- disk full/corrupt DB
- backup/restore/upgrade

### Security tests

- invalid issuer/audience/nonce/holder/DPoP
- wrong Vault member/cross-vault replay
- removed member/new epoch denial
- unregistered DIDComm kid pickup
- SMTP open relay/duplicate submission
- domain move without Vault change

### E2E gates

1. Identity create/update/move/credential issue
2. DIDComm Forward→restart→pickup→local commit→ACK
3. SMTP receive→restart→pickup→local commit→ACK
4. SMTP local send→submission→external delivery→result
5. Vault A append→B/C pull→commit→ACK
6. Vault Remove→new epoch→external credential rotation

## 14. Deployment and operations definition

「稼働」はbinaryが起動するだけを意味しない。各serviceについて次を完了条件とする。

- production domain/TLS/network policy
- persistent volume/permissions
- schema migrations
- backup and restore rehearsal
- health/readiness/metrics/alerts
- structured redacted logs
- graceful shutdown/restart
- resource limits/rate limits
- upgrade/rollback runbook
- canary and incident procedure

## 15. Compatibility and cutover

- 同一protocol version内でunknown fieldを黙って無視しない。
- Breaking wire changeはversionを上げる。
- migration中はold/new identifierを曖昧に自動変換しない。
- one-time mappingはClient migration stateで保持する。
- appendId/message IDをcutover後も冪等にreconcileする。
- old write endpoint停止前にpending outboxを確認する。
- rollback window終了後にlegacy mixed tables/routesを削除する。

## 16. Known current gaps

- current coreはIdentity/MLS/roster/Vault/Mailを同一SQLite/processへcompositionする。
- current Vault delivery outer wireはidentityId/SCID partitionである。
- current MLS group/credentialはpublic identityへ結び付く。
- current ClientはVault delivery appendを行うがnormal pull loopが未配線である。
- current DIDComm mediator persistenceはJSON fileでproduction durabilityが弱い。
- current Mail authはcore roster-backedである。
- current daily device storageにroot/master materialが残る。

これらを一度に変更せず、[PLAN.md](PLAN.md)のmilestone順に切る。

## 17. Release principles

- Milestone 1〜2はsingle-deviceで独立releaseできる。
- second-device supportをMilestone 3のrelease gateより前にproduction claimしない。
- Mail MediatorはMilestone 3のVault orchestration確認後にproduction cutoverする。
- 一方、multi-device UIを早期開放して未同期dataを作らない。
- privacy boundaryとdurability invariantをfeature数より優先する。
