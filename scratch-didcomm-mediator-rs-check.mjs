import * as didcomm from "didcomm-node";
import { x25519, ed25519 } from "@noble/curves/ed25519.js";

function b64url(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlDecodeToString(s) {
  const pad = (4 - (s.length % 4)) % 4;
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(pad);
  return atob(b64);
}

const MEDIATOR_BASE = process.argv[2] || "http://localhost:8021";

const wellKnownResp = await fetch(`${MEDIATOR_BASE}/.well-known/did.json`);
const mediatorDoc = await wellKnownResp.json();
const mediatorDid = mediatorDoc.id;
console.log("mediator DID:", mediatorDid);
console.log("mediator service:", JSON.stringify(mediatorDoc.service));

// this server's DID doc uses fragment-only ids ("#key-1") — expand them to
// fully-qualified DID URLs, which is what didcomm-node's DIDDoc type expects.
function expandDidDoc(doc) {
  const full = (ref) => (ref.startsWith("#") ? doc.id + ref : ref);
  return {
    id: doc.id,
    keyAgreement: (doc.keyAgreement ?? []).map(full),
    authentication: (doc.authentication ?? []).map(full),
    verificationMethod: (doc.verificationMethod ?? []).map((vm) => ({ ...vm, id: full(vm.id), controller: full(vm.controller) })),
    service: doc.service ?? [],
  };
}
const mediatorDocExpanded = expandDidDoc(mediatorDoc);

const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58Encode(bytes) {
  let num = 0n;
  for (const b of bytes) num = num * 256n + BigInt(b);
  let out = "";
  while (num > 0n) { out = B58_ALPHABET[Number(num % 58n)] + out; num = num / 58n; }
  let leadingZeros = 0;
  for (const b of bytes) { if (b === 0) leadingZeros++; else break; }
  return B58_ALPHABET[0].repeat(leadingZeros) + out;
}
// Alice needs a real did:peer:2 with BOTH keyAgreement (E) and authentication
// (V) segments — the mediator rejects senders whose DID method it can't
// resolve, and its did:peer parser requires a non-empty `authentication`.
function makeIdentity() {
  const xPriv = x25519.utils.randomSecretKey(); const xPub = x25519.getPublicKey(xPriv);
  const edPriv = ed25519.utils.randomSecretKey(); const edPub = ed25519.getPublicKey(edPriv);
  const eSeg = "E" + "z" + base58Encode(new Uint8Array([0xec, 0x01, ...xPub]));
  const vSeg = "V" + "z" + base58Encode(new Uint8Array([0xed, 0x01, ...edPub]));
  // dummy service segment, matching the mediator's own nested "s" object
  // shape exactly (reverse-engineered from its /.well-known/did.json output):
  // {"id":"#x","t":"dm","s":{"uri":...,"a":[...],"r":[...]}}
  const sVal = { id: "#didcomm", t: "dm", s: { uri: "https://example.invalid", a: ["didcomm/v2"], r: [] } };
  const sSeg = "S" + btoa(JSON.stringify(sVal)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const did = `did:peer:2.${eSeg}.${vSeg}.${sSeg}`;
  // this server's did:peer parser uses "#key-N" (positional, 1-indexed) as
  // the kid convention, not the segment's own multibase value (confirmed by
  // inspecting its own /.well-known/did.json) — match that exactly.
  const xKid = `${did}#key-1`; const edKid = `${did}#key-2`;
  return {
    did, kid: xKid,
    doc: {
      id: did, keyAgreement: [xKid], authentication: [edKid],
      verificationMethod: [
        { id: xKid, type: "JsonWebKey2020", controller: did, publicKeyJwk: { kty: "OKP", crv: "X25519", x: b64url(xPub) } },
        { id: edKid, type: "JsonWebKey2020", controller: did, publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: b64url(edPub) } },
      ], service: [],
    },
    secret: { id: xKid, type: "JsonWebKey2020", privateKeyJwk: { kty: "OKP", crv: "X25519", x: b64url(xPub), d: b64url(xPriv) } },
  };
}
const alice = makeIdentity();

const docs = { [mediatorDid]: mediatorDocExpanded, [alice.did]: alice.doc };
const didResolver = { async resolve(did) { return docs[did] ?? null; } };
const secrets = { [alice.kid]: alice.secret };
const secretsResolver = {
  async get_secret(id) { return secrets[id] ?? null; },
  async find_secrets(ids) { return ids.filter((id) => secrets[id]); },
};

const mediateRequest = new didcomm.Message({
  id: crypto.randomUUID(), typ: "application/didcomm-plain+json",
  type: "https://didcomm.org/coordinate-mediation/2.0/mediate-request",
  body: {}, from: alice.did, to: [mediatorDid],
  return_route: "all",
});
const [packed] = await mediateRequest.pack_encrypted(mediatorDid, alice.did, null, didResolver, secretsResolver, { forward: false });

console.log("\nPOSTing authcrypt mediate-request...");
const res = await fetch(MEDIATOR_BASE, { method: "POST", body: packed, headers: { "content-type": "application/didcomm-encrypted+json" } });
console.log("response status:", res.status);
const body = await res.text();
console.log("raw response (first 400 chars):", body.slice(0, 400));

if (res.ok) {
  const [unpacked, meta] = await didcomm.Message.unpack(body, didResolver, secretsResolver, {});
  console.log("\n*** unpacked reply ***");
  console.log("type:", unpacked.as_value().type);
  console.log("body:", JSON.stringify(unpacked.as_value().body));
  console.log("authenticated:", meta.authenticated);
}
