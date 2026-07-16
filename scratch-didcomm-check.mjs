import * as didcomm from "didcomm";
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
        {
          id: kid,
          type: "JsonWebKey2020",
          controller: did,
          publicKeyJwk: { kty: "OKP", crv: "X25519", x: b64url(pub) },
        },
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

const didResolver = {
  async resolve(did) {
    return docs[did] ?? null;
  },
};
const makeSecretsResolver = (mine) => ({
  async get_secret(id) {
    return mine[id] ?? null;
  },
  async find_secrets(ids) {
    return ids.filter((id) => mine[id]);
  },
});

const plaintext = new didcomm.Message({
  id: "test-1",
  typ: "application/didcomm-plain+json",
  type: "https://example.com/test",
  body: { hello: "world" },
  from: alice.did,
  to: [bob.did],
});

const [packed, meta] = await plaintext.pack_encrypted(
  bob.did,
  alice.did,
  null,
  didResolver,
  makeSecretsResolver(secrets),
  { forward: false },
);
console.log("packed metadata:", meta);
console.log("packed message (first 200 chars):", packed.slice(0, 200));

const [unpacked, unpackMeta] = await didcomm.Message.unpack(
  packed,
  didResolver,
  makeSecretsResolver(secrets),
  {},
);
console.log("unpacked body:", unpacked.as_value().body);
console.log("unpack metadata:", unpackMeta);
