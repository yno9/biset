// Full flow: Alice -> (self-hosted Mediator) -> Bob, using Coordination 2.0 +
// Routing 2.0 (forward) + Pickup 3.0. Verifies the "goal 2" scenario end to
// end without depending on any third-party mediator implementation.
import * as didcomm from "didcomm-node";
import {
  startMediator, makePeerIdentity, encodePeerDid2, sharedDidResolver, b64url,
} from "./scratch-didcomm-mediator-server.mjs";

const { url: MEDIATOR_URL, mediator } = startMediator();
console.log("mediator started at", MEDIATOR_URL);
console.log("mediator DID:", mediator.did);

const didResolver = sharedDidResolver();

async function postDidcomm(url, packedMsg) {
  const res = await fetch(url, { method: "POST", body: packedMsg, headers: { "content-type": "application/didcomm-encrypted+json" } });
  return res;
}

// --- Bob registers with the mediator ---
const bob = makePeerIdentity();
console.log("\nBob's long-term-ish DID:", bob.did);

const bobSecretsResolver = {
  async get_secret(id) { return bob.secrets[id] ?? null; },
  async find_secrets(ids) { return ids.filter((id) => bob.secrets[id]); },
};

const mediateRequest = new didcomm.Message({
  id: crypto.randomUUID(), typ: "application/didcomm-plain+json",
  type: "https://didcomm.org/coordinate-mediation/2.0/mediate-request",
  body: {}, from: bob.did, to: [mediator.did],
});
const [mediateRequestPacked] = await mediateRequest.pack_encrypted(
  mediator.did, bob.did, null, didResolver, bobSecretsResolver, { forward: false },
);
const grantRes = await postDidcomm(MEDIATOR_URL, mediateRequestPacked);
const grantBody = await grantRes.text();
const [grantMsg] = await didcomm.Message.unpack(grantBody, didResolver, bobSecretsResolver, {});
const grant = grantMsg.as_value();
console.log("mediate-grant received:", JSON.stringify(grant.body));
const routingDid = grant.body.routing_did[0];
console.log("routing DID (== mediator):", routingDid, routingDid === mediator.did);

// --- Bob publishes a "reachable" DID that points at the mediator + his own keyAgreement kid as routing key ---
const bobPublicDid = encodePeerDid2({
  x25519Pub: (() => {
    // reconstruct Bob's raw X25519 pubkey from his doc's JWK for reuse in the new did:peer
    const jwk = bob.doc.verificationMethod.find((v) => v.id === bob.xKid).publicKeyJwk;
    const pad = (4 - (jwk.x.length % 4)) % 4;
    const b64 = jwk.x.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(pad);
    return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  })(),
  ed25519Pub: (() => {
    const jwk = bob.doc.verificationMethod.find((v) => v.id === bob.edKid).publicKeyJwk;
    const pad = (4 - (jwk.x.length % 4)) % 4;
    const b64 = jwk.x.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(pad);
    return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  })(),
  // routingKeys must be the MEDIATOR's keyAgreement key (forward wrapping's
  // outer layer is anoncrypt'd to the mediator), not Bob's own key — the
  // library derives `next` (Bob's real kid) from resolving bobPublicDid itself.
  service: { uri: MEDIATOR_URL, routingKeys: [mediator.xKid] },
});
console.log("\nBob's public (mediator-routed) DID:", bobPublicDid);

// --- Alice resolves Bob's public DID, encrypts to Bob, wraps in forward for the mediator ---
const alice = makePeerIdentity();
console.log("\nAlice's DID:", alice.did);
const aliceSecretsResolver = {
  async get_secret(id) { return alice.secrets[id] ?? null; },
  async find_secrets(ids) { return ids.filter((id) => alice.secrets[id]); },
};

// Extend the shared resolver so it can resolve bobPublicDid too (it carries a
// service segment our sharedDidResolver already decodes generically).
const innerMsg = new didcomm.Message({
  id: crypto.randomUUID(), typ: "application/didcomm-plain+json",
  type: "https://example.com/test-message",
  body: { hello: "from Alice, via mediator" },
  from: alice.did, to: [bobPublicDid],
});
// pack_encrypted with forward:true (the default) resolves bobPublicDid's
// service.routingKeys itself and builds the Forward envelope automatically —
// no need to call wrap_in_forward separately.
const [forwardPacked, packMeta] = await innerMsg.pack_encrypted(
  bobPublicDid, alice.did, null, didResolver, aliceSecretsResolver, {},
);
console.log("\npacked with automatic forward wrapping. metadata:", JSON.stringify(packMeta));

const forwardRes = await postDidcomm(MEDIATOR_URL, forwardPacked);
console.log("forward POST status:", forwardRes.status);
if (forwardRes.status !== 202) console.log("forward POST error body:", await forwardRes.text());

// --- Bob checks status, then picks up ---
async function bobRequest(type, body = {}) {
  const msg = new didcomm.Message({ id: crypto.randomUUID(), typ: "application/didcomm-plain+json", type, body, from: bob.did, to: [mediator.did] });
  const [packed] = await msg.pack_encrypted(mediator.did, bob.did, null, didResolver, bobSecretsResolver, { forward: false });
  const res = await postDidcomm(MEDIATOR_URL, packed);
  const respBody = await res.text();
  const [unpacked] = await didcomm.Message.unpack(respBody, didResolver, bobSecretsResolver, {});
  return unpacked.as_value();
}

const status = await bobRequest("https://didcomm.org/messagepickup/3.0/status-request", { recipient_did: bob.xKid });
console.log("\nstatus:", JSON.stringify(status.body));

const delivery = await bobRequest("https://didcomm.org/messagepickup/3.0/delivery-request", { recipient_did: bob.xKid, limit: 10 });
console.log("delivery message type:", delivery.type);
console.log("attachments:", delivery.attachments?.length ?? 0);

if (delivery.attachments?.length) {
  const packedInner = JSON.stringify(delivery.attachments[0].data.json);
  const [finalMsg, finalMeta] = await didcomm.Message.unpack(packedInner, didResolver, bobSecretsResolver, {});
  console.log("\n*** Bob successfully decrypted Alice's message ***");
  console.log("body:", JSON.stringify(finalMsg.as_value().body));
  console.log("authenticated:", finalMeta.authenticated, "encrypted:", finalMeta.encrypted);
} else {
  console.log("\n!!! no attachments delivered — flow did not complete !!!");
}

process.exit(0);
