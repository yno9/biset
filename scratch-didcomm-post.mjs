import * as didcomm from "didcomm-node";
import { x25519 } from "@noble/curves/ed25519.js";

function b64url(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function makeIdentity(did) {
  const priv = x25519.utils.randomSecretKey();
  const pub = x25519.getPublicKey(priv);
  const kid = `${did}#key-1`;
  return {
    did,
    kid,
    doc: {
      id: did,
      keyAgreement: [kid],
      authentication: [],
      verificationMethod: [
        { id: kid, type: "JsonWebKey2020", controller: did, publicKeyJwk: { kty: "OKP", crv: "X25519", x: b64url(pub) } },
      ],
      service: [],
    },
    secret: {
      id: kid,
      type: "JsonWebKey2020",
      privateKeyJwk: { kty: "OKP", crv: "X25519", x: b64url(pub), d: b64url(priv) },
    },
  };
}

const alice = makeIdentity("did:example:alice");
const bob = makeIdentity("did:example:bob");
const docs = { [alice.did]: alice.doc, [bob.did]: bob.doc };
const secrets = { [alice.kid]: alice.secret, [bob.kid]: bob.secret };
const didResolver = { async resolve(did) { return docs[did] ?? null; } };
const makeSecretsResolver = (mine) => ({
  async get_secret(id) { return mine[id] ?? null; },
  async find_secrets(ids) { return ids.filter((id) => mine[id]); },
});

// --- Bob side: a tiny local HTTP server acting as Bob's direct receiving endpoint ---
let received = null;
const server = Bun.serve({
  port: 0,
  async fetch(req) {
    if (req.method !== "POST") return new Response("only POST", { status: 405 });
    const body = await req.text();
    received = body;
    return new Response("ok", { status: 200 });
  },
});
const bobEndpoint = `http://localhost:${server.port}/didcomm`;
console.log("Bob's endpoint:", bobEndpoint);

// --- Alice side: pack and POST directly to Bob's endpoint ---
const plaintext = new didcomm.Message({
  id: "test-post-1",
  typ: "application/didcomm-plain+json",
  type: "https://example.com/test",
  body: { hello: "direct post from alice" },
  from: alice.did,
  to: [bob.did],
});

const [packed] = await plaintext.pack_encrypted(
  bob.did, alice.did, null, didResolver, makeSecretsResolver(secrets), { forward: false },
);

const res = await fetch(bobEndpoint, { method: "POST", body: packed, headers: { "content-type": "application/didcomm-encrypted+json" } });
console.log("POST response status:", res.status);

// --- Bob side: unpack what was received over the wire ---
if (!received) throw new Error("Bob never received anything");
const [unpacked, meta] = await didcomm.Message.unpack(received, didResolver, makeSecretsResolver(secrets), {});
console.log("Bob unpacked body:", unpacked.as_value().body);
console.log("authenticated:", meta.authenticated, "encrypted:", meta.encrypted);

server.stop();
