// Verifies src/did/didcomm/crypto.ts's ConcatKDF/ECDH-1PU/ECDH-ES derivation
// against known-answer test vectors from hyperledger/aries-askar's
// askar-crypto (the crate didcomm-rust itself uses), not just self-consistency.
import { __internal } from './src/did/didcomm/crypto.ts'
const { concatKDF, deriveEcdh1PU, deriveEcdhEs, ecdh, utf8 } = __internal

function hexToBytes(hex) {
  const clean = hex.replace(/\s+/g, '')
  return Uint8Array.from(clean.match(/.{2}/g).map(b => parseInt(b, 16)))
}
function bytesToHex(b) { return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('') }
function assertEq(actual, expected, label) {
  const a = bytesToHex(actual), e = bytesToHex(expected)
  if (a !== e) throw new Error(`FAIL ${label}\n  got:      ${a}\n  expected: ${e}`)
  console.log(`ok   ${label}`)
}

// concat.rs `expected_1pu_output` — direct ConcatKDF test, no ECDH involved.
{
  const z = hexToBytes(`9e56d91d817135d372834283bf84269cfb316ea3da806a48f6daa7798cfe90c4
    e3ca3474384c9f62b30bfd4c688b3e7d4110a1b4badc3cc54ef7b81241efd50d`)
  const pubInfo = new Uint8Array(4); new DataView(pubInfo.buffer).setUint32(0, 256, false)
  const out = concatKDF(z, utf8('A256GCM'), utf8('Alice'), utf8('Bob'), pubInfo, 32)
  assertEq(out, hexToBytes('6caf13723d14850ad4b42cd6dde935bffd2fff00a9ba70de05c203a5e1722ca7').slice(0, 32), 'ConcatKDF direct (concat.rs)')
}

// draft-madden-jose-ecdh-1pu-04 Appendix B — real X25519 keys, ECDH-1PU KW mode with cc_tag.
{
  // JWK 'd' values below are the raw private scalars (base64url) from the draft.
  const b64urlToBytes = (s) => {
    const pad = (4 - (s.length % 4)) % 4
    const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(pad)
    return Uint8Array.from(atob(b64), c => c.charCodeAt(0))
  }
  const aliceSk = b64urlToBytes('i9KuFhSzEBsiv3PKVL5115OCdsqQai5nj_Flzfkw5jU')
  const bobPk = b64urlToBytes('BT7aR0ItXfeDAldeeOlXL_wXqp-j5FltT0vRSG16kRw')
  const ephemSk = b64urlToBytes('x8EVZH4Fwk673_mUujnliJoSrLz0zYzzCWp5GUX2fc8')

  const ze = ecdh(ephemSk, bobPk)
  const zs = ecdh(aliceSk, bobPk)
  const ccTag = hexToBytes('1cb6f87d3966f2ca469a28f74723acda02780e91cce21855470745fe119bdd64')
  const out = deriveEcdh1PU(ze, zs, 'ECDH-1PU+A128KW', utf8('Alice'), utf8('Bob and Charlie'), ccTag, 128)
  assertEq(out, hexToBytes('df4c37a0668306a11e3d6b0074b5d8df'), 'ECDH-1PU wrapped mode (draft appendix B)')
}

// ECDH-ES direct test (ecdh_es.rs, RFC 8037 Appendix A.6 keys).
{
  const b64urlToBytes = (s) => {
    const pad = (4 - (s.length % 4)) % 4
    const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(pad)
    return Uint8Array.from(atob(b64), c => c.charCodeAt(0))
  }
  const ephemSk = b64urlToBytes('dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo')
  const bobPk = b64urlToBytes('3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08')

  const xk = ecdh(ephemSk, bobPk)
  assertEq(xk, hexToBytes('4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742').slice(0, 32), 'raw X25519 ECDH (RFC 8037 A.6)')

  const out = deriveEcdhEs(xk, 'A256GCM', utf8('Alice'), utf8('Bob'), 256)
  assertEq(out, hexToBytes('2f3636918ddb57fe0b3569113f19c4b6c518c2843f8930f05db25cd55dee53c1').slice(0, 32), 'ECDH-ES direct mode (ecdh_es.rs)')
}

console.log('\nAll RFC/askar-crypto test vectors passed.')
