// Minimal DIDComm v2 Mediator (Coordination 2.0 + Pickup 3.0 + Routing 2.0) for
// scratch verification. In-memory only. Exports startMediator() so the
// full-flow test script can spin it up in-process.
import * as didcomm from "didcomm-node";
import { x25519, ed25519 } from "@noble/curves/ed25519.js";

export function b64url(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
export function b64urlDecodeToString(s) {
  const pad = (4 - (s.length % 4)) % 4;
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(pad);
  return atob(b64);
}

const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
export function base58Encode(bytes) {
  let num = 0n;
  for (const b of bytes) num = num * 256n + BigInt(b);
  let out = "";
  while (num > 0n) { out = B58_ALPHABET[Number(num % 58n)] + out; num = num / 58n; }
  let leadingZeros = 0;
  for (const b of bytes) { if (b === 0) leadingZeros++; else break; }
  return B58_ALPHABET[0].repeat(leadingZeros) + out;
}
export function base58Decode(str) {
  let num = 0n;
  for (const ch of str) { const idx = B58_ALPHABET.indexOf(ch); num = num * 58n + BigInt(idx); }
  let hex = num.toString(16); if (hex.length % 2) hex = "0" + hex;
  const bytes = Uint8Array.from(hex.match(/.{2}/g)?.map((b) => parseInt(b, 16)) ?? []);
  let leadingZeros = 0;
  for (const ch of str) { if (ch === "1") leadingZeros++; else break; }
  return new Uint8Array([...new Array(leadingZeros).fill(0), ...bytes]);
}

// did:peer numalgo 2, own convention: kid fragment = multibase value MINUS the
// leading 'z' (matches what RootsID mediator does server-side, verified
// against its MongoDB records during earlier investigation).
export function encodePeerDid2({ x25519Pub, ed25519Pub, service }) {
  const eSeg = "E" + "z" + base58Encode(new Uint8Array([0xec, 0x01, ...x25519Pub]));
  const vSeg = "V" + "z" + base58Encode(new Uint8Array([0xed, 0x01, ...ed25519Pub]));
  let did = `did:peer:2.${eSeg}.${vSeg}`;
  if (service) {
    const s = { t: "dm", s: service.uri, a: service.accept ?? ["didcomm/v2"], r: service.routingKeys ?? [] };
    did += `.S${btoa(JSON.stringify(s)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")}`;
  }
  return did;
}
export function decodePeerDid2(did) {
  const rest = did.replace(/^did:peer:2\./, "");
  const segments = rest.split(".");
  const verificationMethod = []; const keyAgreement = []; const authentication = [];
  let service = null;
  for (const seg of segments) {
    const purpose = seg[0]; const body = seg.slice(1);
    if (purpose === "S") { service = JSON.parse(b64urlDecodeToString(body)); continue; }
    const decoded = base58Decode(body.slice(1));
    const raw = decoded.slice(2);
    const kid = `${did}#${body.slice(1)}`;
    const isX25519 = decoded[0] === 0xec;
    verificationMethod.push({ id: kid, type: "JsonWebKey2020", controller: did, publicKeyJwk: isX25519 ? { kty: "OKP", crv: "X25519", x: b64url(raw) } : { kty: "OKP", crv: "Ed25519", x: b64url(raw) } });
    if (purpose === "E") keyAgreement.push(kid);
    if (purpose === "V" || purpose === "A") authentication.push(kid);
  }
  const doc = { id: did, keyAgreement, authentication, verificationMethod, service: [] };
  if (service) doc.service.push({ id: `${did}#${service.id ?? "service"}`, type: "DIDCommMessaging", serviceEndpoint: { uri: service.s, accept: service.a ?? ["didcomm/v2"], routing_keys: service.r ?? [] } });
  return doc;
}

export function makePeerIdentity() {
  const xPriv = x25519.utils.randomSecretKey(); const xPub = x25519.getPublicKey(xPriv);
  const edPriv = ed25519.utils.randomSecretKey(); const edPub = ed25519.getPublicKey(edPriv);
  const did = encodePeerDid2({ x25519Pub: xPub, ed25519Pub: edPub });
  const [, eSeg, vSeg] = did.split(".");
  const xKid = `${did}#${eSeg.slice(2)}`; const edKid = `${did}#${vSeg.slice(2)}`;
  return {
    did, xKid, edKid, xPub, edPub, xPriv, edPriv,
    doc: { id: did, keyAgreement: [xKid], authentication: [edKid],
      verificationMethod: [
        { id: xKid, type: "JsonWebKey2020", controller: did, publicKeyJwk: { kty: "OKP", crv: "X25519", x: b64url(xPub) } },
        { id: edKid, type: "JsonWebKey2020", controller: did, publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: b64url(edPub) } },
      ], service: [] },
    secrets: {
      [xKid]: { id: xKid, type: "JsonWebKey2020", privateKeyJwk: { kty: "OKP", crv: "X25519", x: b64url(xPub), d: b64url(xPriv) } },
      [edKid]: { id: edKid, type: "JsonWebKey2020", privateKeyJwk: { kty: "OKP", crv: "Ed25519", x: b64url(edPub), d: b64url(edPriv) } },
    },
  };
}

// Build a second DID string for an existing identity that additionally
// carries a service segment. did:peer:2 embeds the DID itself in each kid, so
// this is a *different* DID (and different kids) for the *same* keypair —
// the caller must register the new kids' secrets alongside the original ones.
export function withService(identity, service) {
  const did = encodePeerDid2({ x25519Pub: identity.xPub, ed25519Pub: identity.edPub, service });
  const [, eSeg, vSeg] = did.split(".");
  const xKid = `${did}#${eSeg.slice(2)}`; const edKid = `${did}#${vSeg.slice(2)}`;
  return {
    did, xKid, edKid,
    secrets: {
      [xKid]: { id: xKid, type: "JsonWebKey2020", privateKeyJwk: { kty: "OKP", crv: "X25519", x: b64url(identity.xPub), d: b64url(identity.xPriv) } },
      [edKid]: { id: edKid, type: "JsonWebKey2020", privateKeyJwk: { kty: "OKP", crv: "Ed25519", x: b64url(identity.edPub), d: b64url(identity.edPriv) } },
    },
  };
}

// Shared multi-party DID resolver: every identity created via makePeerIdentity
// is self-describing (did:peer), so resolution is pure local decoding — no
// network round-trip, matching the "peer DIDs resolve from the DID itself"
// property this whole scratch relies on.
export function sharedDidResolver() {
  return { async resolve(did) { try { return decodePeerDid2(did); } catch { return null; } } };
}

export function startMediator({ port = 0 } = {}) {
  const mediator = makePeerIdentity();
  const secrets = { ...mediator.secrets };
  const didResolver = sharedDidResolver();
  const secretsResolver = {
    async get_secret(id) { return secrets[id] ?? null; },
    async find_secrets(ids) { return ids.filter((id) => secrets[id]); },
  };

  // key id (recipient's keyAgreement kid) -> array of packed JWE strings
  const queues = new Map();
  // set of dids that have successfully mediate-request'd (not enforced strictly, just tracked)
  const mediationClients = new Set();

  function queueFor(kid) {
    if (!queues.has(kid)) queues.set(kid, []);
    return queues.get(kid);
  }

  async function packReply(body, type, toDid) {
    const msg = new didcomm.Message({
      id: crypto.randomUUID(), typ: "application/didcomm-plain+json",
      type, body, from: mediator.did, to: [toDid],
    });
    const [packed] = await msg.pack_encrypted(toDid, mediator.did, null, didResolver, secretsResolver, { forward: false });
    return packed;
  }

  const server = Bun.serve({
    port,
    async fetch(req) {
      if (req.method !== "POST") return new Response("only POST", { status: 405 });
      let unpacked, meta;
      try {
        const raw = await req.text();
        [unpacked, meta] = await didcomm.Message.unpack(raw, didResolver, secretsResolver, {});
      } catch (e) {
        return new Response(JSON.stringify({ error: String(e) }), { status: 400 });
      }
      const msg = unpacked.as_value();
      const fromDid = msg.from;

      if (msg.type === "https://didcomm.org/coordinate-mediation/2.0/mediate-request") {
        mediationClients.add(fromDid);
        const reply = await packReply(
          { routing_did: [mediator.did] },
          "https://didcomm.org/coordinate-mediation/2.0/mediate-grant",
          fromDid,
        );
        return new Response(reply, { status: 200, headers: { "content-type": "application/didcomm-encrypted+json" } });
      }

      if (msg.type === "https://didcomm.org/routing/2.0/forward") {
        const parsed = unpacked.try_parse_forward();
        const { next, forwarded_msg } = parsed.as_value();
        queueFor(next).push(JSON.stringify(forwarded_msg));
        return new Response(null, { status: 202 });
      }

      if (msg.type === "https://didcomm.org/messagepickup/3.0/status-request") {
        const kid = msg.body?.recipient_did ?? fromDid;
        const count = queueFor(kid).length;
        const reply = await packReply(
          { recipient_did: kid, message_count: count },
          "https://didcomm.org/messagepickup/3.0/status",
          fromDid,
        );
        return new Response(reply, { status: 200, headers: { "content-type": "application/didcomm-encrypted+json" } });
      }

      if (msg.type === "https://didcomm.org/messagepickup/3.0/delivery-request") {
        const kid = msg.body?.recipient_did ?? fromDid;
        const limit = msg.body?.limit ?? 10;
        const q = queueFor(kid);
        const batch = q.splice(0, limit).map((packedStr, i) => ({
          id: `msg-${i}-${crypto.randomUUID()}`,
          data: { json: JSON.parse(packedStr) },
        }));
        if (batch.length === 0) {
          const reply = await packReply({ recipient_did: kid }, "https://didcomm.org/messagepickup/3.0/status", fromDid);
          return new Response(reply, { status: 200, headers: { "content-type": "application/didcomm-encrypted+json" } });
        }
        const deliveryMsg = new didcomm.Message({
          id: crypto.randomUUID(), typ: "application/didcomm-plain+json",
          type: "https://didcomm.org/messagepickup/3.0/delivery",
          body: { recipient_did: kid }, from: mediator.did, to: [fromDid],
          attachments: batch,
        });
        const [packed] = await deliveryMsg.pack_encrypted(fromDid, mediator.did, null, didResolver, secretsResolver, { forward: false });
        return new Response(packed, { status: 200, headers: { "content-type": "application/didcomm-encrypted+json" } });
      }

      return new Response(JSON.stringify({ error: "unsupported type", type: msg.type }), { status: 400 });
    },
  });

  return { server, mediator, url: `http://localhost:${server.port}` };
}
