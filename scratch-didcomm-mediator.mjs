import * as didcomm from "didcomm-node";
import { x25519, ed25519 } from "@noble/curves/ed25519.js";

// --- base64url ---
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

// --- base58btc ---
const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58Decode(str) {
  let num = 0n;
  for (const ch of str) {
    const idx = B58_ALPHABET.indexOf(ch);
    if (idx < 0) throw new Error(`invalid base58 char ${ch}`);
    num = num * 58n + BigInt(idx);
  }
  let hex = num.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  const bytes = Uint8Array.from(hex.match(/.{2}/g)?.map((b) => parseInt(b, 16)) ?? []);
  // leading zero bytes (represented as leading '1's in base58)
  let leadingZeros = 0;
  for (const ch of str) { if (ch === "1") leadingZeros++; else break; }
  return new Uint8Array([...new Array(leadingZeros).fill(0), ...bytes]);
}

// --- base58btc encode (inverse of base58Decode) ---
function base58Encode(bytes) {
  let num = 0n;
  for (const b of bytes) num = num * 256n + BigInt(b);
  let out = "";
  while (num > 0n) {
    out = B58_ALPHABET[Number(num % 58n)] + out;
    num = num / 58n;
  }
  let leadingZeros = 0;
  for (const b of bytes) { if (b === 0) leadingZeros++; else break; }
  return B58_ALPHABET[0].repeat(leadingZeros) + out;
}

// --- did:peer numalgo 2 encoder: build a fresh did:peer for our test identity ---
function encodePeerDid2({ x25519Pub, ed25519Pub }) {
  const eSeg = "E" + "z" + base58Encode(new Uint8Array([0xec, 0x01, ...x25519Pub]));
  const vSeg = "V" + "z" + base58Encode(new Uint8Array([0xed, 0x01, ...ed25519Pub]));
  return `did:peer:2.${eSeg}.${vSeg}`;
}

// --- did:peer numalgo 2 decoder (just enough for our purposes) ---
function decodePeerDid2(did) {
  const rest = did.replace(/^did:peer:2\./, "");
  const segments = rest.split(".");
  const verificationMethod = [];
  const keyAgreement = [];
  const authentication = [];
  let service = null;
  let idx = 0;
  for (const seg of segments) {
    const purpose = seg[0];
    const body = seg.slice(1);
    if (purpose === "S") {
      service = JSON.parse(b64urlDecodeToString(body));
      continue;
    }
    // multibase 'z' + base58btc(multicodec-prefix + raw key)
    if (body[0] !== "z") throw new Error(`unsupported multibase prefix in ${seg}`);
    const decoded = base58Decode(body.slice(1));
    // multicodec varint prefix: 0xec 0x01 = X25519-pub, 0xed 0x01 = Ed25519-pub
    const raw = decoded.slice(2);
    // NB: RootsID mediator's server-side kid convention drops the leading
    // multibase 'z' from the fragment (verified against its MongoDB records) —
    // match that exactly, not the more common "#key-N" convention.
    idx++;
    const kid = `${did}#${body.slice(1)}`;
    const isX25519 = decoded[0] === 0xec;
    verificationMethod.push({
      id: kid,
      type: "JsonWebKey2020",
      controller: did,
      publicKeyJwk: isX25519
        ? { kty: "OKP", crv: "X25519", x: b64url(raw) }
        : { kty: "OKP", crv: "Ed25519", x: b64url(raw) },
    });
    if (purpose === "E") keyAgreement.push(kid);
    if (purpose === "V" || purpose === "A") authentication.push(kid);
  }
  const doc = {
    id: did,
    keyAgreement,
    authentication,
    verificationMethod,
    service: [],
  };
  if (service) {
    doc.service.push({
      id: `${did}#${service.id ?? "service"}`,
      type: "DIDCommMessaging",
      serviceEndpoint: { uri: service.s, accept: service.a ?? ["didcomm/v2"], routing_keys: [] },
    });
  }
  return doc;
}

// --- fetch mediator's OOB invitation ---
const MEDIATOR_BASE = "https://wheat-java-horse-trade.trycloudflare.com";
const oobUrlResp = await fetch(`${MEDIATOR_BASE}/oob_url`);
const oobUrl = await oobUrlResp.text();
const oobParam = new URL(oobUrl.trim()).searchParams.get("_oob");
const oobMsg = JSON.parse(b64urlDecodeToString(oobParam));
console.log("mediator OOB invitation:", JSON.stringify(oobMsg, null, 2));

const mediatorDid = oobMsg.from;
const mediatorDoc = decodePeerDid2(mediatorDid);
console.log("decoded mediator DID doc:", JSON.stringify(mediatorDoc, null, 2));

// --- Alice: a fresh did:peer identity (the mediator rejects non-did:peer senders) ---
function makeAlicePeerIdentity() {
  const xPriv = x25519.utils.randomSecretKey();
  const xPub = x25519.getPublicKey(xPriv);
  const edPriv = ed25519.utils.randomSecretKey();
  const edPub = ed25519.getPublicKey(edPriv);
  const did = encodePeerDid2({ x25519Pub: xPub, ed25519Pub: edPub });
  // match the mediator's own kid convention: fragment = multibase value minus leading 'z'
  const [, eSeg, vSeg] = did.split(".");
  const xKid = `${did}#${eSeg.slice(2)}`;
  const edKid = `${did}#${vSeg.slice(2)}`;
  return {
    did,
    kid: xKid,
    doc: {
      id: did,
      keyAgreement: [xKid],
      authentication: [edKid],
      verificationMethod: [
        { id: xKid, type: "JsonWebKey2020", controller: did, publicKeyJwk: { kty: "OKP", crv: "X25519", x: b64url(xPub) } },
        { id: edKid, type: "JsonWebKey2020", controller: did, publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: b64url(edPub) } },
      ],
      service: [],
    },
    secrets: {
      [xKid]: { id: xKid, type: "JsonWebKey2020", privateKeyJwk: { kty: "OKP", crv: "X25519", x: b64url(xPub), d: b64url(xPriv) } },
      [edKid]: { id: edKid, type: "JsonWebKey2020", privateKeyJwk: { kty: "OKP", crv: "Ed25519", x: b64url(edPub), d: b64url(edPriv) } },
    },
  };
}
const alice = makeAlicePeerIdentity();
console.log("\nAlice's fresh did:peer:", alice.did);

const docs = { [mediatorDid]: mediatorDoc, [alice.did]: alice.doc };
const secrets = { ...alice.secrets };
const didResolver = { async resolve(did) { return docs[did] ?? null; } };
const secretsResolver = {
  async get_secret(id) { return secrets[id] ?? null; },
  async find_secrets(ids) { return ids.filter((id) => secrets[id]); },
};

// --- build & pack mediate-request ---
const mediateRequest = new didcomm.Message({
  id: crypto.randomUUID(),
  typ: "application/didcomm-plain+json",
  type: "https://didcomm.org/coordinate-mediation/2.0/mediate-request",
  body: {},
  from: alice.did,
  to: [mediatorDid],
});

const [packed] = await mediateRequest.pack_encrypted(
  mediatorDid, alice.did, null, didResolver, secretsResolver, { forward: false },
);

console.log("\nPOSTing mediate-request to mediator...");
const res = await fetch(MEDIATOR_BASE, {
  method: "POST",
  body: packed,
  headers: { "content-type": "application/didcomm-encrypted+json" },
});
console.log("response status:", res.status);
const responseBody = await res.text();
console.log("raw response (first 300 chars):", responseBody.slice(0, 300));

if (res.status === 200 || res.status === 202) {
  try {
    const [unpacked, meta] = await didcomm.Message.unpack(responseBody, didResolver, secretsResolver, {});
    console.log("\nunpacked mediate-grant/deny:", JSON.stringify(unpacked.as_value(), null, 2));
    console.log("unpack meta:", meta);
  } catch (e) {
    console.log("\ncould not unpack response as DIDComm message:", e.message);
  }
}
