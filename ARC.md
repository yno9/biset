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

### 4.3 MLS

bisetにおけるMLS(RFC 9420)は、複数人でのメッセージング用途では**ない**。使い道は1つだけ:
1つのidentityが持つ複数端末間の「roster(どの端末が信頼されているか)」と「鍵導出境界(vault epoch key)」を、暗号学的に正しく管理するための土台。実際のメール本文等はvaultイベント経由でMLS epoch外に別途配送される(§5)。MLS groupが1つ存在する=1つのidentity、というシンプルな対応関係。

**レイヤー構成**(下から上):
- `mls/vendor/` — `ts-mls` v1.6.2 (RFC 9420実装)をフォークしたもの。理由は2つ: (1) upstreamにセキュリティ上の欠落がある(1名だけをRemoveするコミットにUpdatePathを付けない実装になっており、RFC 9420 §12.4違反——修正しないと除名した端末が引き続き読めてしまう)、(2) サイズ(bisetは単一HTMLファイル配布、`@hpke/*`だけで無圧縮687KB、使わない14暗号スイート分を削れる)。差分は全部`// biset:`とコメントし、`vendor/VENDOR.md`に台帳として記録(現在3件——上記のUpdatePath修正、self-remove時の無限ループ修正、今セッションで追加したcredential差し替え用の追加パラメータ)。
- `mls/group.ts` — vendorの生プリミティブをbiset語彙(create/join/rekey/remove/self-remove/updateOwnCredential等)に包んだ層。
- `mls/self-group.ts` — さらに1段上、identityごとに1つだけ存在する「self group」の管理(§4.3.1)。

**認証は独立した3箇所にある**——これが2026-08-26のdomain move調査で判明した一番の発見。「この署名は本当に名乗っている本人か」を検証する場所が、biset独自のDSレベルHTTP認証(`core/identity/webvh-signing-key-resolver.ts`)、MLS自身のAuthentication Service(`mls/webvh-authentication-service.ts`、RFC 9750、vendorライブラリがcredentialの新規/変更時に自動で呼ぶ)、DIDComm送信者検証(`didcomm/webvh-resolve.ts`)の3箇所に分かれて存在し、しかも当初は3箇所とも別々に実装されていた。did:webvhのdomain move(文書全体のdidプレフィックス一括書き換え)と組み合わさると、moveしていない端末自身のkidまで巻き添えで検証不能になるバグが3箇所全部にあり、今は3箇所とも「`#fragment`だけで照合する」方式に統一して修正済み(詳細は§4.6・§4.7、英語)。

domain move自体の詳しい経緯・設計判断は§4.6(英語)、実装状況の総括は§4.7(英語)を参照。

#### 4.3.1 Self Group

self groupのid(DSに送るネットワーク上の識別子)は`sha256("biset-self-group/1 " + key)`で、`key`はidentityの**SCID**であり、did:webvh文字列全体ではない(`mls/self-group.ts`の`selfGroupIdentityKey`)。これは2026-08-26まで実在したバグだった: 完全なDID(ドメインを含む)でキーイングしていたため、domain move(§4.6、`identity/webvh/migrate.ts`)が起きると——did:webvh v1.0のportability機構によりSCIDは維持されるにもかかわらず——group idが黙って別物として計算されてしまい、MLS group自体と、そこから導出されるvault epoch key chainが、既に同期済みの全端末で孤立してしまう。当時まだ本番identityが存在しなかったため、移行パスを用意せず導出方法自体を直接変更できた。

**group自体のライフサイクル**(`mls/self-group.ts`が提供):
- `createSelfGroup` — 最初の端末がidentityを作る時に1回だけ、group自体を新規作成
- `joinSelfGroupExternally` / `ensureSelfGroupWithRosterInstall` — 2台目以降の端末が、既存groupにexternal commitで参加
- `reflectPendingSelfGroupCommits` — 起動のたびに実行、DSに溜まっている他端末発のコミットを取り込んで自分の状態を追いつかせる。roster(信頼済み端末一覧)projectionもここで反映される
- `removeDeviceFromSelfGroup` — 端末のrevoke。RFC 9420の性質により、除名された端末は次epoch以降のexporter secret(=vault epoch key)を計算できなくなる——これがMLS採用の主目的そのもの
- `migrateSelfGroupCredential` — domain move時、moveした本人の端末が自分のleaf credentialを新didへ差し替えるコミット(§4.6参照)

roster(どの端末が信頼されているか)はSCID基準で一貫してキーイングされている(`mls/group.ts`の`memberKids`、core側の`device-roster.ts`/`vault-delivery-store.ts`含め、2026-08-26にDID文字列基準からSCID基準へ全面的に修正済み)——domain moveでDID文字列が変わっても、同じidentityの端末は同じrosterのまま扱われる。

### 4.4 Revocation and Restore

### 4.5 Key Inventory

システム内に存在する鍵/秘密それぞれについて、どこで生成され、秘密鍵がどこに(どんな形で)保管され、公開鍵があるならどこに公開され、同一identityの他端末へどう伝わり、どう更新(rotation)されるかをまとめる。

| 鍵 | 単位 | 生成元 | 秘密鍵の保管場所 | 公開鍵の公開先 | 端末間の伝播 | Rotation |
|---|---|---|---|---|---|---|
| Root Key (ed25519) | identityごとに1つ | `identity/seed.ts`/`slip10.ts`、BIP39ニーモニックから決定論的に導出 | `identity/record-store.ts`、`biset-identity` DB(平文——PRF-at-rest封印は設計済みだが未移植) | did:webvhログの`updateKeys`(did.jsonl)、routing.jsonのPUT署名にも使用 | 同期しない——全端末が同じニーモニックから同一の鍵を再導出する(`restoreIdentity`) | 単独では不変(BIP39ニーモニックそのものの再発行手段は無い)。ただし下のSpare/Sign Keyへ`updateKeys`権限自体を移す(=事実上のrotation)ことは`identity/webvh/prerotation.ts`で実装済み——`deactivatePreRotation`で権限をRoot Keyへ戻すことも可能 |
| Spare Key / Sign Key (ed25519、pre-rotation用) | pre-rotationが有効な間、常に「次の1回分」が1つ | ユーザー操作(`ui/account-page.ts`の`activateKeyRotation`/`rotateKeyRotation`)、独立した32バイト乱数から`spareKeyFromSeed`——Root Keyのニーモニック階層とは無関係の別系統 | システム側には一切保存しない。ミューモニックフレーズとして生成時に1回だけ画面表示され、以後biset側は二度と保持しない(`account-page.ts`のコメント: "biset never retains a copy... once shown")——ユーザーがアプリ外で書き留めるのが唯一の控え | 実鍵は明かさず、ハッシュだけを`nextKeyHashes`としてdid:webvhログのparametersに事前コミット(`activatePreRotation`)——盗まれたRoot Keyでは「持ってもいない鍵」への差し替えを偽装できないのがpre-rotationの狙い(did:webvh v1.0 "Pre-Rotation Key Hash") | 同期しない——フレーズを知っている人だけが使える、Root Keyと同じ扱い | これ自体がrotationの主体: `rotateToPreRotatedKey`でフレーズを明かすと、その場で`updateKeys`(署名権限)がRoot Keyからこの鍵へ差し替わり、同時に次回分の新しいSpare Keyのハッシュを再コミットする。フレーズは一度使うと二度と使えない(使い捨て) |
| MLS Device Key / leaf key (ed25519) | 端末ごとに1つ | `mls/group.ts`の`generateOwnKeyPackage` | `mls/keypackage-store.ts`(`biset-mls-keypackages`) + `mls/store.ts`(`biset-mls-self-group`) | did:webvh文書の`verificationMethod`の`#device-{hex}`(`identity/webvh/add-device-verification-method.ts`)、MLS KeyPackageとしてDSにも提出 | 端末の外に出ることはない——共有すると端末単位のrevocationが意味をなさなくなる | 自動: MLSコミットのたびにUpdatePathでleafがrekeyされる(self-groupのforward secrecy)。加えて2026-08-26以降、domain move時は`updateOwnCredential`によりleafのcredential自体(did部分)も明示的に差し替わる(§4.6) |
| DIDComm keyAgreement Key (X25519) | 端末ごとに1つ | `identity/bootstrap.ts`の`enableDidComm` | `identity/record-store.ts`の`didCommX25519PrivateKey`(同じ`biset-identity` DB) | routing.jsonの`keyAgreementVerificationMethod` | 端末ローカルのみ、vault同期しない | 無し——DIDComm送信者側は安定した宛先を必要とするため。MLS leaf keyとは独立させている理由はPLANMLSDIDCRED.mdの議論を参照 |
| deviceKid ↔ didCommKid のペアリング | 端末ごとに1レコード | `main.ts`、`enableDidComm`が鍵を発行した直後 | vaultイベント`didcomm.device-key.set`(`vault/didcomm-device-key.ts`) | 公開しない——意図的に非公開(このセッションでのrouting.json vs vault設計議論を参照) | 通常のvault配送パイプライン経由で信頼済み全端末に同期 | 該当なし——`revokeDevice`が参照するだけの読み取り専用ルックアップで、これ自体がrevokeされることはない |
| OpenPGPメール credential(秘密鍵) | identityで1つを共有 | `mail/openpgp-credential.ts`の`generateOpenPgpPrivateCredential` | vaultイベント`credential.openpgp.set`(`vault/openpgp-credential.ts`) | (公開鍵のみ、次の行) | identity全体で1つの同じ秘密鍵を、vault配送経由で信頼済み全端末に同期——端末ごとのDIDComm鍵と違い、従来のPGPには複数端末を扱う仕組みが元々ないため | スキーマ上`supersedesFingerprint`のチェーンは存在するが、rotationを起動するUIやトリガーはまだ配線されていない |
| OpenPGPメール公開鍵 | identityごとに1つ | 上の行から`publishableOpenPgpPublicKey`経由で導出 | — (公開鍵なので該当なし) | routing.jsonの`openpgpPublicKey` | `fetchRouting(did)`経由で誰でも取得可能 | 秘密鍵側の(未実装の)rotationにそのまま追従する |
| Vault Segment Key | セグメント(vaultオブジェクトのまとまり)ごとに1つ | `vault/objects.ts`の`createSegmentKey` | 生の形では一切保存しない——復号済みの状態でメモリ上にのみ存在 | — | 現在のMLS Vault Epoch Keyでラップした`SegmentKeyWrapV1`としてのみ伝播(`vault/crypto.ts`の`createSegmentKeyWrap`) | 鍵自体は不変——epochが変わるたびに新しいwrapが発行される |
| MLS Vault Epoch Key (VEK) | self-groupのepochごとに1つ | MLSの`exporter_secret`からその都度導出(`mls/vault-epoch.ts`) | 永続化しない——resolve/sign/verifyのたびに現在の`ClientState`から都度再導出(`buildVaultCryptoBoundary`) | — | 直接伝播するものはなく、同じepochに達した端末がそれぞれローカルで導出する | epochが進むたびに構造的に変わる(これがvaultのforward secrecyの源) |
| Recovery Key | エクスポートしたアーカイブごとに1つ、オプトイン | `vault/recovery-archive.ts`の`createRecoveryKey`(32バイトの乱数) | システム側には一切保存しない——ユーザーがアプリ外で保持する | — | 同期しない——モジュール自身の定義により「MLSの秘密でも端末鍵でもない」扱い | ユーザーが新しいアーカイブを作るたびに新しい鍵になる |

### 4.6 Domain Move

`identity/webvh/move.ts` moves a did:webvh identity to a new domain
(same SCID — did:webvh v1.0's own portability guarantee,
`identity/webvh/migrate.ts`'s abstract core). Four independent problems had
to be found and fixed before this could work for a device that already has
an MLS self group (2026-08-26):

1. **Self-group id was DID-keyed, not SCID-keyed** (§4.3) — fixed first;
   without it the group itself would be silently orphaned by any move.
2. **Local storage (18 vault object stores, the self-group row) was keyed
   by the raw did:webvh string** — `vault/store.ts`'s `rekeyIdentity` and
   `mls/store.ts`'s `delete` move/drop these rows across the same move.
3. **This device's own MLS leaf credential still names the old DID**
   (`${did}#device-hex}`) after (1) and (2) — unverifiable the moment the
   move's document substitution lands, permanently locking the device out
   of its own group. Two approaches were tried and abandoned before landing
   on the one that works:
   - *External-commit resync* (RFC 9420 §11: remove the old leaf, add a new
     one) — hits a bug in the vendored MLS tree code
     (`vendor/ratchetTree.ts`'s `extendRatchetTree`) for a single-member
     group, when the tree briefly goes fully blank between the remove and
     the add.
   - *A bundled Update proposal* — RFC 9420 forbids a committer from
     including their own self-authored Update proposal in their own commit
     (`vendor/clientState.ts`'s `validateProposals`).
   - **What works**: every commit already carries an UpdatePath for the
     committer's own leaf (this is what `rekey` already used, with no
     proposals at all) — RFC 9420 restricts what a *proposal* may contain,
     not what a committer's own path update may contain. The vendored
     `createUpdatePath` just never exposed a way to change credential
     there; `vendor/updatePath.ts`/`vendor/createCommit.ts` gained an
     additive, default-preserving `newCredential`/`ownCredentialUpdate`
     parameter (both marked `// biset:`, per `vendor/VENDOR.md`'s own
     convention), and `mls/group.ts`'s `updateOwnCredential` is the one
     caller. `test/mls-core.test.ts` and `test/mls-crypto.test.ts` (the
     RFC 9420 vector suite) both still pass unmodified.
4. **Ordering**: the migration commit's own DS submission must be signed
   under the OLD kid (core's `submitCommit` authorizes by current roster
   membership), which is only resolvable in the narrow window between the
   NEW location's did.jsonl existing and the OLD location being told about
   the move — `migrateWebvhLocation`'s `afterNewLocationWritten` hook is
   exactly that window.
5. **A second, uninvolved device's roster/vault-delivery projections were
   DID-keyed too, and its own DS authentication broke** — found via
   `test/protocol/mls-self-group-move-multidevice.test.ts` (device B, which
   never participates in A's move). Two distinct bugs, fixed separately:
   - `mls/group.ts`'s `memberKids` used exact-string `did ===` matching, so
     the migration commit's own roster projection (`memberKids(result.state,
     newIdentityId)`) silently dropped every device still on the old DID.
     Fixed with `identity/idkey.ts`'s `sameIdentity` (SCID comparison), and
     extended the same fix to `core/mediation/mls-delivery-store.ts`
     (`groupInfoFor`/`submitExternalCommit`), `core/identity/device-roster.ts`
     (memory + SQLite), and `core/mediation/vault-delivery-store.ts` (memory
     + SQLite) — all were keyed by the mutable did:webvh string and would
     silently split one identity's roster/delivery state in two the moment
     any one device migrated.
   - Separately, **B's own routine DS requests started failing with 403**
     even after the above: verifying B's signature requires resolving B's
     *own* kid, and `migrateWebvhLocation`'s whole-document string
     substitution rewrites every id in the document — not just the mover's —
     so B's long-unchanged kid stops matching any `verificationMethod.id` in
     the newly-resolved document the instant *A* moves. This is not a
     roster-keying problem; it is DS-level HTTP authentication
     (`Ed25519MlsDsSignatureVerifier`/`Ed25519DeviceControlSignatureVerifier`,
     both backed by `WebvhSigningKeyResolver`) depending on a live resolve of
     a kid whose validity a *different* device's move can invalidate through
     no action of the kid owner's own.

     This is the actual did:webvh-portability ↔ MLS-per-device-credential
     conflict named up front: did:webvh's move mechanism is a
     *whole-document* rewrite (one atomic log entry renames every embedded
     id at once), while MLS's per-device credentials update independently
     and asynchronously — so between any two devices' moves, the group
     legitimately contains credentials naming two different domains for the
     SAME identity. Naively re-resolving a kid by treating it as an opaque,
     exact string to look up in the CURRENT document conflates "current" with
     "still prefixed the way it was when this kid was minted," which is
     false the instant a SIBLING device moves.

     **Root fix, not a workaround**: `WebvhSigningKeyResolver` now matches a
     kid's `#fragment` against the resolved document's OWN current id
     (`${doc.id}${fragment}`), not the caller's original, possibly-stale
     `did` prefix. This is safe because `resolve(did)` already re-verifies
     the ENTIRE hash-chained, signed log from genesis (`resolveEntries`) —
     confirming the returned document is the SAME SCID's own legitimate
     current continuation — and a domain move's whole-document substitution
     rewrites every id's did-PREFIX but never touches the `#fragment`
     SUFFIX, which is what actually names one device for the identity's
     whole lifetime. Fragment matching fixes both the observed case (B's own
     unchanged kid, after A moves) and a case the earlier fix below could
     not: a device contacting a given resolver for the very first time,
     using a kid minted before an already-completed move it never witnessed.
     No domain-independent resolution layer (DHT/Pkarr, or a
     biset-original SCID registry) is needed for this — did:webvh's own log
     already carries everything required, and the identity's dual-write on
     move (`migrateWebvhLocation` PUTs the moved log to BOTH the new
     location and, last, the old one) keeps the old `did` prefix resolvable
     to that same current document.

     On top of the fragment-matching fix, `WebvhSigningKeyResolver` also
     keeps a small in-memory cache pinning successfully resolved `(kid,
     key)` pairs for its lifetime. This is now a genuine
     performance/resilience layer rather than the primary fix: a signing key
     id is never legitimately rebound to a different key (a replaced device
     credential gets a new fragment, not a reused one), so caching is sound,
     and it additionally survives a transient failure to reach the DID's
     host at all — a case fragment matching cannot help with, since there is
     no document to search fragments in if resolution itself fails outright.
     `test/protocol/webvh-signing-key-resolver.test.ts`'s
     "a never-moved device's old kid still resolves after the identity
     moves" test isolates the fragment-matching fix from the whole
     self-group/DS stack, on top of the full end-to-end
     `mls-self-group-move-multidevice.test.ts` coverage.

     **The identical bug also lived in MLS's OWN Authentication Service**
     (`mls/webvh-authentication-service.ts`'s `validateCredential`) — a
     second, independent implementation of the exact same full-kid-string
     match, not shared with `WebvhSigningKeyResolver` at all. This matters
     because the vendored MLS library's `validateRatchetTree`
     (`vendor/clientState.ts`) re-validates EVERY leaf's credential — not
     only a changed one — whenever a device joins externally or processes a
     Welcome. Left unfixed, a still-unmoved device's long-static credential
     would fail that whole-tree check the moment ANY new device tries to
     join the self-group after ANY other device has moved, even though the
     DS-level fix above already made ordinary requests work fine. Fixed with
     the same fragment-based match (`${doc.id}${fragment}`, no cache needed
     here since AS validation isn't a hot path the way per-request DS auth
     is). `test/protocol/mls-webvh-authentication-service.test.ts`'s "a
     never-moved device's unchanged credential still validates after the
     identity moves" test guards this directly.

6. **The same bug a third time, plus a genuinely different one, in the
   DIDComm path** (`didcomm/webvh-resolve.ts`). `resolveDidCommSenderKey`
   (verifies an incoming DIDComm message's sender against its published
   X25519 keyAgreement key) had the identical exact-kid-string match, fixed
   the same way (`${doc.id}${fragment}`). But fixing the match alone wasn't
   enough here, because routing.json (where keyAgreement entries live,
   unlike MLS device keys which live in the signed did:webvh log itself) has
   **no old-location dual-write at all**: `identity/webvh/move.ts`'s
   `afterNewLocationWritten` hook carries the migrated routing.json to the
   NEW location only, never touching the old one — unlike
   `migrateWebvhLocation` itself, which appends the moved log entry to BOTH
   locations. So `resolveWithRouting`'s own `fetchRouting(did, ...)` call,
   when handed an old-prefixed `did`, was fetching routing.json from the OLD
   location and getting back a permanently stale, never-updated document —
   fragment-matching against it would still fail, because the fetch itself
   reached the wrong document, not because the match was too strict. Fixed
   by having `resolveWithRouting` fetch routing.json from `doc.id` (the
   FRESHLY resolved, current did) instead of the caller's original `did`
   argument — sound because `resolve()` just re-verified the entire
   hash-chained log to produce `doc.id`, so it is already known-current at
   that point. `test/protocol/webvh-resolve-sender-key.test.ts` guards both
   halves together (fragment match + correct-location routing fetch).

7. **Passive devices never learned a move happened at all.** All six items
   above make a SIBLING device's move harmless to authenticate through, but
   none of them give a device that didn't perform the move any way to
   update its OWN bookkeeping (`IdentityRecord.did`/`deviceKid`/`didCommKid`,
   the local self-group row). Left alone, such a device would keep writing
   to the OLD did:webvh location forever for anything IT initiates — adding
   a device, revoking one, publishing routing.json — permanently forking
   the did:webvh log away from the real (moved) identity, and, worse, making
   any revocation that device issues silently never reach anyone resolving
   the actual current document. Fixed with `identity/webvh/adopt-move.ts`'s
   `adoptPendingMove`, the passive counterpart to `move.ts`: run once at
   boot (`main.ts`'s `bootClient`, before anything reads a record's `.did`),
   it resolves the identity's OLD did, and if `doc.id` differs, adopts the
   new location locally the same way `move.ts` does for the device that
   actually performed the move (rewrite `IdentityRecord`, re-key the vault
   store, move the self-group row, clear the KeyPackage pool) — WITHOUT
   re-issuing this device's own MLS credential, which the fixes above make
   unnecessary for correctness. Converges one domain-hop per call (each
   `migrateWebvhLocation` only dual-writes to the immediately preceding
   location, not every historical one), so a device offline across two or
   more moves catches up fully after that many boots, provided each
   intermediate domain stays resolvable in the meantime. A domain
   decommissioned before a straggler device catches up through it is an
   explicitly accepted gap here, not solved by retrying harder — the
   existing restore flow (a new-device join by another name) is the
   intended fallback for that case, chosen over building this device to
   auto-heal through an unreachable intermediate hop because domain moves
   are expected to be rare, not routine, for this identity model.
   `test/protocol/webvh-adopt-move.test.ts` covers the move/no-move/
   unresolvable-right-now cases.

Vault content continuity across a domain move (re-wrapping existing
`SegmentKeyWrapV1`s from the old self-group's epoch to the new one) is a
separate, not-yet-addressed concern — this device's own self-group state
never changes group id (§4.3), so an existing device's already-synced vault
content is unaffected by (1)-(7) above; this note is about a scenario that
was considered (recreating a fresh self-group instead of migrating
credentials in place) and rejected in favor of the above.

### 4.7 MLS Implementation Status

A snapshot (2026-08-26) of what the self-group / MLS layer actually does,
after the domain-move investigation in §4.6 above prompted a full pass
looking for anything else in the same family.

**Layering.** `mls/vendor/` is a forked, size-trimmed subset of ts-mls
v1.6.2 (RFC 9420) — see `vendor/VENDOR.md` for the three documented
divergences: (1) a security fix upstream is missing (a single-Remove commit
needs an UpdatePath or the removed member can still derive the next epoch),
(2) a self-removal infinite-loop fix plus `senderLeafIndex` attribution on
application messages, (3) an additive `newCredential`/`ownCredentialUpdate`
parameter on `createUpdatePath`/`createCommit` (added this session, for
domain-move credential migration — no existing caller's behavior changes
when it's omitted). `mls/group.ts` wraps the vendored primitives into
biset's own vocabulary (create/join/rekey/remove/self-remove/
update-own-credential, GroupInfo encode/decode, member introspection).
`mls/self-group.ts` is the one layer above that: biset does not use MLS for
messaging content at all — every identity has exactly ONE MLS group, whose
sole purpose is to be a roster + key-derivation boundary for that
identity's OWN devices (`createSelfGroup`, `joinSelfGroupExternally`,
`ensureSelfGroupWithRosterInstall`, `reflectPendingSelfGroupCommits`,
`removeDeviceFromSelfGroup`, `migrateSelfGroupCredential`). The vault's
per-epoch encryption key (VEK, §5.3) is derived on demand from this group's
`exporter_secret` — nothing MLS-specific ever reaches the vault layer
except that one derived key.

**Two separate authentication points, now consistently fragment-based.**
This session's investigation surfaced that "is this request/credential
genuinely from who it claims" is answered in THREE independent places, not
one: `core/identity/webvh-signing-key-resolver.ts` (DS-level HTTP request
auth, both for roster/vault-delivery control and MLS DS control-plane
messages), `mls/webvh-authentication-service.ts` (MLS's own RFC 9750
Authentication Service, invoked by the vendored library itself whenever a
credential is new or changes), and `didcomm/webvh-resolve.ts` (DIDComm
sender verification). All three used to match a signing key id against a
resolved did:webvh document by exact string equality; all three are now
fixed to match by `#fragment` against the resolved document's OWN current
id, because a did:webvh domain move rewrites every verificationMethod's did
PREFIX at once but never the fragment suffix (§4.6, points 1-2 and 6). The
DS-level resolver additionally keeps a permanent per-kid cache as a
resilience layer against transient host unavailability, which the other two
don't need (not hot paths the way per-request DS auth is).

**Domain move is the only scenario that has needed real design work** — see
§4.6 for the full account (self-group id keying, local storage re-keying,
the credential-migration commit itself via the vendored UpdatePath
extension, the three authentication fixes above, and `adopt-move.ts`'s
passive-device self-heal). Every other MLS operation (add/remove a device,
self-removal, rekey, external join) has no did:webvh-specific complexity —
they operate purely on MLS's own SCID-independent group state.

**Test coverage.** `test/mls-core.test.ts` and `test/mls-crypto.test.ts`
(the RFC 9420 vector suite plus the removal-property test) are the
"upstream is still upstream" safety net for the vendor fork itself.
Above that, `test/protocol/mls-self-group-*.test.ts` covers bootstrap,
roster install, revoke, and — the two heaviest — `mls-self-group-move.test.ts`
(single device, real anchor + real core, real AS validation) and
`mls-self-group-move-multidevice.test.ts` (an uninvolved second device
catching up through a sibling's move via the ordinary sync path).
`webvh-signing-key-resolver.test.ts`, `mls-webvh-authentication-service.test.ts`,
`webvh-resolve-sender-key.test.ts`, and `webvh-adopt-move.test.ts` each
isolate one of the fixes above from the whole self-group/DS stack, so a
regression in the matching logic specifically fails fast without needing
the full integration test to catch it.

**Known, accepted gaps** (not bugs — deliberate scope cuts, revisit if the
assumption behind them stops holding):
- Vault segment re-wrapping across a domain move (§4.6's closing note) —
  not yet implemented; doesn't affect already-synced content since the
  self-group id itself never changes.
- `adopt-move.ts` converges one domain-hop per boot; a device offline
  across 2+ moves needs that many boots, and a domain decommissioned before
  a straggler device gets through it is not auto-healed — the existing
  restore flow is the intended fallback, accepted because domain moves are
  expected to be rare for this identity model, not routine.

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

#### Private relationship front door (2026-08-27)

The identity-shared X25519 key published in `routing.json` is now a
discoverable front door only. A first contact sends `RELATIONSHIP_INIT` to
that public kid. Before doing so, the initiator creates and registers a fresh
service-bearing `did:peer:2` identity whose service names the selected blind
mediator. Embedding the mediator route in the private peer DID makes the route
durable without publishing it or adding another cleartext identity mapping.

The recipient registers its own fresh peer identity, stores both sides of the
relationship as an encrypted `contact-key.set` vault credential, and returns
`RELATIONSHIP_ACCEPT` to the already-registered initiator kid. The initiator
then stores the matching credential. Subsequent authcrypt sender and recipient
kids, mediator registration, and pickup all use these relationship peer
identities; neither public did:webvh kid appears in continuing JWE traffic.
Every trusted device receives the private credential through ordinary vault
delivery and restores one polling loop per current relationship at boot.

Registration must precede INIT: otherwise ACCEPT would target an unenrolled
kid and the mediator would correctly refuse to queue it. The standalone
mediator authenticates coordinate/pickup requests with DIDComm authcrypt's
X25519 sender key; the Ed25519 key is part of the self-certifying peer DID but
is not a separate signature on those requests. The mediator stores each
relationship key under its own peer DID connection, never under either
participant's public did:webvh identity. `test/mediator-relationship-handshake.test.ts`
guards both the ordering and this non-correlation property end to end.

### 8.2 Mail, Autocrypt, and OpenPGP

Mail adapters preserve raw RFC 5322 / MIME as opaque ingress and never receive
or interpret OpenPGP private keys. A Biset identity's OpenPGP private key is
an endpoint-vault credential: normal new-device recovery comes from an
authorised peer restore, while full-device-loss recovery is possible only from
an opt-in, user-managed encrypted recovery archive. The core does not retain a
durable key blob.

MLS device removal cannot retract an already received OpenPGP private key.
Device compromise therefore requires both MLS Remove and OpenPGP key rotation /
revocation; a stale correspondent may still encrypt to an old public key.

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
