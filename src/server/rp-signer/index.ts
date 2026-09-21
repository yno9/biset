/**
 * biset-rp-signer (PLAN6, did.md repo): a minimal, stateless service whose
 * only job is to hold biset's own did:webvh RP signing key and sign JAR
 * (RFC 9101) Authorization Request objects on demand, so that
 * `https://t.biset.md` can authenticate itself to did.md by DID rather than
 * a DCR client_id/secret embedded in the public browser bundle (see
 * ~/did.md/PLAN6-rp-did-authentication.md §0.1bis, §0.5).
 *
 * Deliberately holds no state and requires no caller authentication: the
 * only thing this service will ever sign a request for is biset's own
 * fixed redirect_uri (REDIRECT_URI below, never accepted from the caller),
 * so nothing is gained by restricting who may call it -- the worst an
 * unrelated caller can do is obtain a JAR that, if used, would send a
 * did.md wallet-authorize consent screen's result back to biset's own real
 * callback URL. That's already possible today by simply linking to
 * `/authorize` directly, JAR or not.
 *
 * The private key file is produced once by
 * ~/did.md/scripts/create-rp-did.ts and must never be served or logged.
 */
import { ed25519 } from "@noble/curves/ed25519.js";

const PORT = Number(Bun.env.PORT ?? 8794);
const KEY_FILE = Bun.env.RP_DID_KEY_FILE ?? "./data/biset-rp-did-key.json";
const REDIRECT_URI = Bun.env.RP_REDIRECT_URI ?? "https://t.biset.md/wallet/callback";
const ALLOWED_ORIGIN = Bun.env.RP_SIGNER_ALLOWED_ORIGIN ?? "https://t.biset.md";

type Key = { did: string; verificationMethod: string; privateKey: string };
const key: Key = await Bun.file(KEY_FILE).json();
if (!key.did?.startsWith("did:webvh:") || !key.verificationMethod?.startsWith(`${key.did}#`) || typeof key.privateKey !== "string") {
  throw new Error(`${KEY_FILE} does not contain a valid RP DID key`);
}
const privateKey = new Uint8Array(Buffer.from(key.privateKey, "base64url"));
if (privateKey.length !== 32) throw new Error(`${KEY_FILE}'s privateKey must be a 32-byte Ed25519 key`);

const encoder = new TextEncoder();
function base64url(bytes: Uint8Array): string { return Buffer.from(bytes).toString("base64url"); }

// Only the claims a relying party is actually meant to choose per request.
// iss/client_id (always `key.did`) and redirect_uri (always REDIRECT_URI,
// never caller-supplied) are added here, not accepted from the request body.
const ALLOWED_CLAIMS = ["state", "code_challenge", "code_challenge_method", "nonce", "dpop_jkt", "login_hint", "authorization_details", "dcql_query", "scope"] as const;

function sign(payload: Record<string, unknown>): string {
  const header = base64url(encoder.encode(JSON.stringify({ alg: "EdDSA", typ: "JWT", kid: key.verificationMethod })));
  const body = base64url(encoder.encode(JSON.stringify(payload)));
  const signature = ed25519.sign(encoder.encode(`${header}.${body}`), privateKey);
  return `${header}.${body}.${base64url(signature)}`;
}

function cors(): Record<string, string> {
  return { "access-control-allow-origin": ALLOWED_ORIGIN, "access-control-allow-methods": "POST", "access-control-allow-headers": "content-type", vary: "origin" };
}

Bun.serve({
  port: PORT,
  async fetch(request) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors() });
    if (url.pathname === "/healthz" && request.method === "GET") return Response.json({ ok: true, did: key.did }, { headers: cors() });
    if (url.pathname !== "/sign" || request.method !== "POST") return new Response("not found\n", { status: 404, headers: cors() });
    try {
      const body = await request.json();
      if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("request body must be a JSON object");
      for (const field of Object.keys(body)) if (!ALLOWED_CLAIMS.includes(field as any)) throw new Error(`unexpected field: ${field}`);
      // PLAN7: pure SIOPv2/OID4VP direct delivery -- did.md hands the signed
      // capability/id_token straight back to REDIRECT_URI (fragment), no
      // api.did.md code+token round trip. redirect_uri/client_id/
      // response_type are still fixed here, never accepted from the caller
      // (see this module's own header comment).
      const payload = { ...body, iss: key.did, client_id: key.did, client_id_scheme: "did", response_type: "vp_token id_token", redirect_uri: REDIRECT_URI };
      return Response.json({ jwt: sign(payload) }, { headers: cors() });
    } catch (error) {
      return new Response(`${error instanceof Error ? error.message : "invalid request"}\n`, { status: 400, headers: cors() });
    }
  },
});

console.log(`biset-rp-signer listening on ${PORT}`);
console.log(`rp did: ${key.did}`);
