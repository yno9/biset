// Full flow against the REAL third-party adorsys/didcomm-mediator-rs (Rust):
// Bob registers (mediate-request -> grant), publishes a routed public DID,
// Alice sends via automatic forward wrapping, Bob picks up via Pickup 3.0.
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
function base58Decode(str) {
  let num = 0n;
  for (const ch of str) { const idx = B58_ALPHABET.indexOf(ch); num = num * 58n + BigInt(idx); }
  let hex = num.toString(16); if (hex.length % 2) hex = "0" + hex;
  const bytes = Uint8Array.from(hex.match(/.{2}/g)?.map((b) => parseInt(b, 16)) ?? []);
  let leadingZeros = 0;
  for (const ch of str) { if (ch === "1") leadingZeros++; else break; }
  return new Uint8Array([...new Array(leadingZeros).fill(0), ...bytes]);
}

const MEDIATOR_BASE = process.argv[2];
if (!MEDIATOR_BASE) { console.error("usage: bun run scratch-didcomm-mediator-rs-fullflow.mjs <mediator-url>"); process.exit(1); }

// --- identity helper: did:peer:2 with E + V segments, "#key-N" kid
// convention (this server's own convention, learned earlier), optional
// service segment matching its nested {uri,a,r} shape. ---
function makeIdentity({ service } = {}) {
  const xPriv = x25519.utils.randomSecretKey(); const xPub = x25519.getPublicKey(xPriv);
  const edPriv = ed25519.utils.randomSecretKey(); const edPub = ed25519.getPublicKey(edPriv);
  const eSeg = "E" + "z" + base58Encode(new Uint8Array([0xec, 0x01, ...xPub]));
  const vSeg = "V" + "z" + base58Encode(new Uint8Array([0xed, 0x01, ...edPub]));
  let did = `did:peer:2.${eSeg}.${vSeg}`;
  if (service) {
    const sVal = { id: "#didcomm", t: "dm", s: { uri: service.uri, a: service.accept ?? ["didcomm/v2"], r: service.routingKeys ?? [] } };
    did += `.S${btoa(JSON.stringify(sVal)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")}`;
  } else {
    // even senders that don't need a real service seem to require the field
    // internally on this server — a dummy one satisfies it.
    const sVal = { id: "#didcomm", t: "dm", s: { uri: "https://example.invalid", a: ["didcomm/v2"], r: [] } };
    did += `.S${btoa(JSON.stringify(sVal)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")}`;
  }
  const xKid = `${did}#key-1`; const edKid = `${did}#key-2`; // positional convention: E first => key-1, V second => key-2... but see note below
  // NOTE: this server assigns "#key-N" strictly by the ORDER segments appear
  // in the DID string. We always emit E before V, so E=key-1, V=key-2 here.
  return {
    did, xKid, edKid, xPub, edPub, xPriv, edPriv,
    doc: {
      id: did, keyAgreement: [xKid], authentication: [edKid],
      verificationMethod: [
        { id: xKid, type: "JsonWebKey2020", controller: did, publicKeyJwk: { kty: "OKP", crv: "X25519", x: b64url(xPub) } },
        { id: edKid, type: "JsonWebKey2020", controller: did, publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: b64url(edPub) } },
      ], service: [],
    },
    secrets: {
      [xKid]: { id: xKid, type: "JsonWebKey2020", privateKeyJwk: { kty: "OKP", crv: "X25519", x: b64url(xPub), d: b64url(xPriv) } },
      [edKid]: { id: edKid, type: "JsonWebKey2020", privateKeyJwk: { kty: "OKP", crv: "Ed25519", x: b64url(edPub), d: b64url(edPriv) } },
    },
  };
}

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

const wellKnownResp = await fetch(`${MEDIATOR_BASE}/.well-known/did.json`);
const mediatorDoc = expandDidDoc(await wellKnownResp.json());
const mediatorDid = mediatorDoc.id;
console.log("mediator DID:", mediatorDid);

// --- shared resolver across all parties in this scratch: mediator resolves
// via HTTP (real server), everyone else resolves via local did:peer decode. ---
function decodePeerDid2(did) {
  const rest = did.replace(/^did:peer:2\./, "");
  const segments = rest.split(".");
  const verificationMethod = []; const keyAgreement = []; const authentication = [];
  let idx = 0;
  let service = null;
  for (const seg of segments) {
    const purpose = seg[0]; const body = seg.slice(1);
    if (purpose === "S") { continue; } // not needed for resolving local test identities
    const decoded = base58Decode(body.slice(1));
    const raw = decoded.slice(2);
    idx++;
    const kid = `${did}#key-${idx}`;
    const isX25519 = decoded[0] === 0xec;
    verificationMethod.push({ id: kid, type: "JsonWebKey2020", controller: did, publicKeyJwk: isX25519 ? { kty: "OKP", crv: "X25519", x: b64url(raw) } : { kty: "OKP", crv: "Ed25519", x: b64url(raw) } });
    if (purpose === "E") keyAgreement.push(kid);
    if (purpose === "V") authentication.push(kid);
  }
  return { id: did, keyAgreement, authentication, verificationMethod, service: [] };
}
const localIdentities = {}; // did -> doc, populated as we create Alice/Bob/BobPublic
const didResolver = {
  async resolve(did) {
    if (did === mediatorDid) return mediatorDoc;
    if (localIdentities[did]) return localIdentities[did];
    try { return decodePeerDid2(did); } catch { return null; }
  },
};

// --- Bob registers with the mediator ---
const bob = makeIdentity();
localIdentities[bob.did] = bob.doc;
const bobSecretsResolver = { async get_secret(id) { return bob.secrets[id] ?? null; }, async find_secrets(ids) { return ids.filter((id) => bob.secrets[id]); } };

const mediateRequest = new didcomm.Message({
  id: crypto.randomUUID(), typ: "application/didcomm-plain+json",
  type: "https://didcomm.org/coordinate-mediation/2.0/mediate-request",
  body: {}, from: bob.did, to: [mediatorDid], return_route: "all",
});
const [mrPacked] = await mediateRequest.pack_encrypted(mediatorDid, bob.did, null, didResolver, bobSecretsResolver, { forward: false });
const grantRes = await fetch(MEDIATOR_BASE, { method: "POST", body: mrPacked, headers: { "content-type": "application/didcomm-encrypted+json" } });
const grantBody = await grantRes.text();
console.log("mediate-request POST status:", grantRes.status);
const [grantMsg] = await didcomm.Message.unpack(grantBody, didResolver, bobSecretsResolver, {});
const grant = grantMsg.as_value();
const routingDid = grant.body.routing_did;
console.log("Bob's routing_did from mediator:", routingDid);

// --- Bob publishes a public DID whose service routes through the mediator's routing_did ---
// reuse Bob's actual keys for the public DID so the same secrets apply
const bobPublicDid = (() => {
  const eSeg = "E" + "z" + base58Encode(new Uint8Array([0xec, 0x01, ...bob.xPub]));
  const vSeg = "V" + "z" + base58Encode(new Uint8Array([0xed, 0x01, ...bob.edPub]));
  const sVal = { id: "#didcomm", t: "dm", s: { uri: routingDid, a: ["didcomm/v2"], r: [] } };
  const sSeg = "S" + btoa(JSON.stringify(sVal)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `did:peer:2.${eSeg}.${vSeg}.${sSeg}`;
})();
const bobPublicXKid = `${bobPublicDid}#key-1`;
localIdentities[bobPublicDid] = {
  id: bobPublicDid, keyAgreement: [bobPublicXKid], authentication: [`${bobPublicDid}#key-2`],
  verificationMethod: [
    { id: bobPublicXKid, type: "JsonWebKey2020", controller: bobPublicDid, publicKeyJwk: { kty: "OKP", crv: "X25519", x: b64url(bob.xPub) } },
    { id: `${bobPublicDid}#key-2`, type: "JsonWebKey2020", controller: bobPublicDid, publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: b64url(bob.edPub) } },
  ],
  service: [{ id: `${bobPublicDid}#didcomm`, type: "DIDCommMessaging", serviceEndpoint: { uri: routingDid, accept: ["didcomm/v2"], routing_keys: [] } }],
};
// bobPublic's keyAgreement kid reuses bob's actual secret (#key-1 on both DIDs happens to share the same underlying key material)
bob.secrets[bobPublicXKid] = bob.secrets[bob.xKid];
console.log("\nBob's public DID (routes through mediator):", bobPublicDid);

// --- NOW register bobPublicXKid (not bob.xKid!) in the mediator's keylist —
// `next` in the forwarded message will literally be bobPublicXKid (the
// keyAgreement kid pack_encrypted resolved against bobPublicDid), and the
// server's forward handler string-matches `next` against the keylist
// (discovered by reading forward/src/handler.rs — mismatches surface as a
// bare 500 "Internal server error", not the more specific UncoordinatedSender). ---
const keylistUpdate = new didcomm.Message({
  id: crypto.randomUUID(), typ: "application/didcomm-plain+json",
  type: "https://didcomm.org/coordinate-mediation/2.0/keylist-update",
  body: { updates: [{ recipient_did: bobPublicXKid, action: "add" }] },
  from: bob.did, to: [mediatorDid], return_route: "all",
});
console.log("registering bobPublicXKid:", bobPublicXKid);
const [kuPacked] = await keylistUpdate.pack_encrypted(mediatorDid, bob.did, null, didResolver, bobSecretsResolver, { forward: false });
const kuRes = await fetch(MEDIATOR_BASE, { method: "POST", body: kuPacked, headers: { "content-type": "application/didcomm-encrypted+json" } });
console.log("keylist-update POST status:", kuRes.status);
const kuBody = await kuRes.text();
if (kuRes.ok) {
  const [kuReplyMsg] = await didcomm.Message.unpack(kuBody, didResolver, bobSecretsResolver, {});
  console.log("keylist-update reply:", JSON.stringify(kuReplyMsg.as_value().body));
} else {
  console.log("keylist-update error:", kuBody);
}

// --- Alice sends to bobPublicDid; pack_encrypted resolves the routing_did
// chain (bobPublicDid -> routingDid -> mediator's real HTTP endpoint) and
// wraps in Forward automatically. ---
const alice = makeIdentity();
localIdentities[alice.did] = alice.doc;
const aliceSecretsResolver = { async get_secret(id) { return alice.secrets[id] ?? null; }, async find_secrets(ids) { return ids.filter((id) => alice.secrets[id]); } };

// the routing_did itself must resolve too — it's the mediator's pairwise DID for Bob
localIdentities[routingDid] = decodePeerDid2(routingDid);
// but its REAL serviceEndpoint lives with the mediator's main did doc's service — reuse it
localIdentities[routingDid].service = mediatorDoc.service;

const innerMsg = new didcomm.Message({
  id: crypto.randomUUID(), typ: "application/didcomm-plain+json",
  type: "https://example.com/test-message", body: { hello: "from Alice, via a REAL third-party mediator" },
  from: alice.did, to: [bobPublicDid],
});
const [forwardPacked, meta] = await innerMsg.pack_encrypted(bobPublicDid, alice.did, null, didResolver, aliceSecretsResolver, {});
console.log("\npack_encrypted metadata:", JSON.stringify(meta));

const sendRes = await fetch(MEDIATOR_BASE, { method: "POST", body: forwardPacked, headers: { "content-type": "application/didcomm-encrypted+json" } });
console.log("forward POST status:", sendRes.status);
if (!sendRes.ok) console.log("forward POST error:", await sendRes.text());

// --- Bob checks status, then picks up ---
async function bobRequest(type, body = {}) {
  const msg = new didcomm.Message({ id: crypto.randomUUID(), typ: "application/didcomm-plain+json", type, body, from: bob.did, to: [mediatorDid], return_route: "all" });
  const [packed] = await msg.pack_encrypted(mediatorDid, bob.did, null, didResolver, bobSecretsResolver, { forward: false });
  const res = await fetch(MEDIATOR_BASE, { method: "POST", body: packed, headers: { "content-type": "application/didcomm-encrypted+json" } });
  const text = await res.text();
  if (!res.ok) { console.log(`${type} error:`, text); return null; }
  const [unpacked] = await didcomm.Message.unpack(text, didResolver, bobSecretsResolver, {});
  return unpacked.as_value();
}

const status = await bobRequest("https://didcomm.org/messagepickup/3.0/status-request");
console.log("\nstatus:", JSON.stringify(status?.body));

const delivery = await bobRequest("https://didcomm.org/messagepickup/3.0/delivery-request", { limit: 10 });
console.log("delivery type:", delivery?.type, "attachments:", delivery?.attachments?.length ?? 0);

if (delivery?.attachments?.length) {
  const inner = JSON.stringify(delivery.attachments[0].data.json ?? delivery.attachments[0].data);
  const [finalMsg, finalMeta] = await didcomm.Message.unpack(inner, didResolver, bobSecretsResolver, {});
  console.log("\n*** Bob decrypted Alice's message via the REAL third-party mediator ***");
  console.log("body:", JSON.stringify(finalMsg.as_value().body));
  console.log("authenticated:", finalMeta.authenticated);
} else {
  console.log("\n!!! no attachments delivered !!!");
}
process.exit(0);
