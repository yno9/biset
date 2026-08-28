# Biset 再構築ロードマップ

> 2026-08-29更新: CoordinatorはSelf Groupとは別のVault MLSを持たない。端末membershipはSelf Groupへ統合し、Coordinator v2はOIDC owner-scoped ordered log + checkpointに限定する。Vault at-rest鍵はroot由来の安定KEKであり、MLS epochから独立する。詳細は`PLAN_biset-coordinator.md`と`PLANMLSARCH.md`冒頭を正本とする。

> Status: Milestone 2 production live / 次はMilestone 3 Vault Coordinator
> 改訂日: 2026-08-28
> 実装開始は各milestoneの設計未決事項を解消してから行う。

## 1. 実装順

順番を次で固定する。

1. `biset-core`から`biset-anchor`を抽出・実装する。（公開文書service抽出済み、OIDC ProviderはVault Coordinatorと並行実装）
2. `biset-didcomm-mediator`をproduction稼働まで持っていく。（完了: `https://mediator.biset.md`）
3. `biset-coordinator`を実装し、複数local Vaultのオーケストレーションをproduction配線する。（次）
4. `biset-mail-mediator`をproduction稼働まで持っていく。

理由:

- Anchorは公開DID/domain/addressのidentity providerであり、他transportに先行する。
- DIDComm mediatorは既存実装があり、production hardeningまでの距離が最も短い。
- DIDCommで確認したlocal Vault commitを複数端末へ拡張し、Vaultのappend/pull/ACK/restoreが本当に収束するかをMail抽出より先に検証する。
- Mail MediatorはVault Coordinatorを直接知らないが、Client側の「外部受信→local commit→複数端末同期」が先に確立していればmail pathの完成条件を明確にできる。
- MailはSMTP/DNS/abuse/DSNを含む運用範囲が大きいため、Vault orchestrationを固めた後の最後のservice milestoneとして集中する。

## 2. Architectural invariants

- `biset-anchor`と`biset-coordinator`はVault/公開identityのidentifierとdataを相互共有しない。Coordinatorが知るAnchor情報は標準OIDC issuer/JWKSとCoordinator専用pairwise subjectだけである。
- Anchorは`vaultId`、MLS group、Vault memberを知らない。
- Vault CoordinatorはDID、SCID、domain、mail addressを知らない。
- 両planeを結ぶのはBiset Clientのlocal durable workflowだけである。
- MLS、device membership、VEK、SegmentKey lifecycleはVault側が所有する。
- Vault Coordinator outer routingはrandom `vaultId`を使い、`identityId`を使わない。
- Mail/DIDComm mediatorはVault Coordinatorへ直接送らない。
- Clientが外部messageを検証・local commitした後、必要ならVault Coordinatorへappendする。
- third party向け公開ログインprotocolはOpenID Connectに統一し、Anchorのinteractive loginはOpenID4VP 1.0にする。内部の認証結果interfaceとwire adapterを分離し、ATProto OAuth adapterは将来追加できる構造にする。
- Vault CoordinatorはOAuth Resource Serverとして、Anchor発行の短命JWT access tokenを`iss`/`aud`/scopeで検証する。tokenの`sub`はCoordinator固有pairwise subjectとし、DID/SCIDを含めない。
- Anchorはtoken発行時にも`vaultId`、MLS group、Vault memberを知らず、CoordinatorからAnchorへのruntime RPCやprojection installを作らない。

## 3. Target topology

Bisetは次の四つの主要コンポーネントで構成する。

1. **Anchor** (`biset-anchor`): identity provider。公開identity、domain/address、OIDCを担当する。
2. **Mediator** (`biset-mediator`): transport protocols。外部通信の一時配送を担当する。
3. **Vault**: Client内local storage。暗号化された長期正本とprojectionを保持する。
4. **Coordinator** (`biset-coordinator`): 複数端末間でVaultの永続性と収束を保証する。

Mediatorを一つの製品名にまとめても、DIDComm queueとMail spoolのwire、認証、storage、failure domainは混ぜない。現在の個別binaryを一つのprocessへcomposeするかはMail milestoneで決める。

```text
                         External peers
                    SMTP              DIDComm
                      │                  │
           ┌──────────▼───────┐ ┌──────▼────────────┐
           │ Mail Mediator    │ │ DIDComm Mediator  │
           └──────────┬───────┘ └──────┬────────────┘
                      │ pickup          │ pickup
                      └────────┬─────────┘
                               ▼
                         Biset Client
                         Local Vault
                         Local JMAP
                        ┌──────┴──────┐
                        │             │ optional: multi-device
                        │             ▼
                        │       Vault Coordinator + MLS DS
                        │
                        ▼
                  Biset Anchor
             DID/domain/address control

AnchorとCoordinatorの間にserver-to-server edgeはない。両者を結ぶVault bindingはClientだけが保持する。
```

## 4. Milestone 1 — Biset Anchor

正本: [PLAN_biset-anchor.md](PLAN_biset-anchor.md)

### Scope

- webvh/public document/address codeをcoreから抽出する
- Anchor専用entrypoint、DB、config、healthを作る
- MLS/roster/ingress/Vault/mail storageを含めない
- OIDC Provider（Authorization Code + PKCE、Discovery、JWKS、pairwise subject）を追加する
- OpenID4VP Verifier、holder-bound Login Credential、Anchor sessionを追加する
- root/recovery keyとdaily operational keyを分離する
- domain moveを維持する

### Done

- standalone production-shaped deploymentが起動する
- existing identity create/resolve/update/moveが新serviceで通る
- public identity文書serviceがVault/transport stateなしで単独稼働できる
- DB/API/import graphにVault/MLS/message stateがない
- migration/rollback/runbookがある

## 5. Milestone 2 — DIDComm Mediator production

正本: [PLAN_biset-didcomm-mediator.md](PLAN_biset-didcomm-mediator.md)

### Scope

- 既存Coordinate/Forward/Pickup実装のwireを固定する
- JSON file persistenceをtransactional durable storeへ置換する
- queue bytes/rate/replay/expiryを有界化する
- accepted Forwardのdurabilityを保証する
- health/readiness/metrics/log redactionを実装する
- HTTPS/TLS/reverse proxy、backup/restore/upgradeを整備する
- staging、canary、production Client E2Eを通す

### Done

- public HTTPS endpointが稼働している
- offline recipient宛Forwardがrestart後もpickupできる
- local Vault commit後にだけACKされる
- mediatorがAnchor/Vault/Mail stateを知らない
- operator runbookとalertがある

## 6. Milestone 3 — Vault Coordinator / multi-device

正本: [PLAN_biset-coordinator.md](PLAN_biset-coordinator.md)、[PLANMLSARCH.md](PLANMLSARCH.md)

### Scope

- random vaultIdとnew Vault MLS groupを導入する
- MLS DS/KeyPackage/group viewをVault Coordinatorへ移す
- did:webvh MLS credentialをopaque Vault credentialへ置換する
- delivery/restore protocolをidentityIdからvaultIdへ移行する
- Client append/pull/commit/ACK loopをproduction配線する
- new member/Remove/restore/failoverを完成する

### Done

- Client Aのlocal mutationがB/Cへ収束する
- Coordinator DB/logからDID/SCID/domain/addressを得られない
- Remove後memberがnew epoch/data/APIへアクセスできない
- new member/TTL gapが明示的restoreへ移る
- Anchorの停止/移転がVault syncへ影響しない

## 7. Milestone 4 — Mail Mediator production

正本: [PLAN_biset-mail-mediator.md](PLAN_biset-mail-mediator.md)

### Scope

- SMTP listener/client/submissionをcoreから抽出する
- pickup/submissionをMail Mediator固有のauthcrypt relationshipで検証する
- OAuth/DPoP pickup/submissionを実装する
- mail専用durable spool/claim/ACK/DSNを作る
- SMTP DNS/TLS/MX、abuse/rate/quotaをproduction化する
- Client receive/sendと既に確立したVault同期workflowを接続する

### Done

- external SMTP→spool→pickup→local Vault→ACKが通る
- local Vault→submit→external SMTP→result commitが通る
- Mailでlocal commitしたmessageがVault Coordinator経由で別端末へ収束する
- `250 OK`後のsilent lossがない
- Mail MediatorがVault/MLSを知らない
- production利用できる

## 8. Single-device product boundary

Milestone 1〜2完了時点で提供するもの:

- public identity/domain/address
- DIDComm receive/send
- local encrypted Vault
- Local JMAP UI
- recovery archive

提供しないもの:

- sibling device history sync
- automatic multi-device restore
- Vault Coordinatorによるdelivery cursor/ACK
- MLS member add/removeを使った複数端末運用

二台目追加UIはMilestone 3のrelease gateを通るまでdisabledまたはexperimentalとし、「Anchorへログインできる」ことと「同じVault historyを持つ」ことを混同しない。SMTP receive/sendはMilestone 4で独立Mail Mediatorへcutoverする。

## 9. Cross-plane Client workflow

Clientだけが次を実行する。

```text
External pickup
  → verify/decrypt
  → local Vault atomic commit
  → mediator ACK
  → (Coordinator設定時のみ) Vault delivery outbox flush
```

```text
Vault MLS Remove
  → new epoch / new group view
  → identity/mail/DIDComm credential rotation intent commit
  → each serviceへidempotent publish
```

Server同士を直接接続してこのbridgeを代行させない。

## 10. Work rules

- milestoneを飛ばして後続serviceの実装を始めない。
- production稼働の定義にdeploy、monitoring、backup、restore、upgrade、runbookを含める。
- protocolとstorage migrationにはdual-read/write期間とrollback条件を置く。
- local durable commitより先にexternal ACKを送らない。
- accepted payloadへdurabilityがない状態でSMTP `250` / DIDComm acceptを返さない。
- existing codeを移動する前にboundary interfaceとfailure testを固定する。
- unrelated user changesを上書きしない。

## 11. Deferred work

- Vault Coordinator multi-primary/CRDT
- multi-coordinator consensus
- ActivityPub mediator
- arbitrary plugin runtime
- server-side mailbox/search/history
- permanent server archive
- traffic-analysis-resistant pickup

## 12. Immediate next design decisions

1. OpenID4VP consent/account chooser policy
2. 実装済みのClient側opaque KeyPackage/Add/WelcomeとCoordinator DSを、招待情報の安全な端末間受渡しおよび二台目参加UIへ接続
3. production OIDC client registrationとpairwise sector policy
4. issuer trustとdid:webvh binding
5. root/recovery/operational key migration
6. legacy coreからのpublic document/address migration
7. single-device Client configと二台目UI制限
