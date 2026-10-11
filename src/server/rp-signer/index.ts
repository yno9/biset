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
import { createPrivateKey, sign as cryptoSign } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";

// Runs on plain Node (>= 24, which strips TypeScript types itself); no Bun
// APIs and no third-party dependencies. Binds to loopback by default -- the
// reverse proxy (Caddy) is the only public entry point.
const HOST = process.env.HOST ?? "127.0.0.1";
const PORT = Number(process.env.PORT ?? 8794);
const KEY_FILE = process.env.RP_DID_KEY_FILE ?? "./data/biset-rp-did-key.json";
const REDIRECT_URI = process.env.RP_REDIRECT_URI ?? "https://t.biset.md/wallet/callback";
const ALLOWED_ORIGIN = process.env.RP_SIGNER_ALLOWED_ORIGIN ?? "https://t.biset.md";
const MAX_BODY_BYTES = 64 * 1024;

type Key = { did: string; verificationMethod: string; privateKey: string };
const key: Key = JSON.parse(readFileSync(KEY_FILE, "utf8"));
if (!key.did?.startsWith("did:webvh:") || !key.verificationMethod?.startsWith(`${key.did}#`) || typeof key.privateKey !== "string") {
  throw new Error(`${KEY_FILE} does not contain a valid RP DID key`);
}
const seed = Buffer.from(key.privateKey, "base64url");
if (seed.length !== 32) throw new Error(`${KEY_FILE}'s privateKey must be a 32-byte Ed25519 key`);
// A raw Ed25519 seed is wrapped in the fixed PKCS#8 prefix so node:crypto can load it.
const privateKey = createPrivateKey({
  key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]),
  format: "der",
  type: "pkcs8",
});

function base64url(bytes: Uint8Array | string): string { return Buffer.from(bytes).toString("base64url"); }

// Only the claims a relying party is actually meant to choose per request.
// iss/client_id (always `key.did`) and redirect_uri (always REDIRECT_URI,
// never caller-supplied) are added here, not accepted from the request body.
const ALLOWED_CLAIMS = ["state", "code_challenge", "code_challenge_method", "nonce", "dpop_jkt", "login_hint", "authorization_details", "dcql_query", "scope"];

function sign(payload: Record<string, unknown>): string {
  const header = base64url(JSON.stringify({ alg: "EdDSA", typ: "JWT", kid: key.verificationMethod }));
  const body = base64url(JSON.stringify(payload));
  const signature = cryptoSign(null, Buffer.from(`${header}.${body}`), privateKey);
  return `${header}.${body}.${base64url(signature)}`;
}

function cors(): Record<string, string> {
  return { "access-control-allow-origin": ALLOWED_ORIGIN, "access-control-allow-methods": "POST", "access-control-allow-headers": "content-type", vary: "origin" };
}

async function readJson(request: import("node:http").IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY_BYTES) throw new Error("request body too large");
    chunks.push(chunk as Buffer);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

createServer(async (request, response) => {
  const send = (status: number, contentType: string, body: string | null) => {
    response.writeHead(status, { ...cors(), ...(body === null ? {} : { "content-type": contentType }) });
    response.end(body ?? undefined);
  };
  const sendJson = (status: number, value: unknown) => send(status, "application/json", JSON.stringify(value));
  const url = new URL(request.url ?? "/", "http://localhost");
  if (request.method === "OPTIONS") return send(204, "", null);
  if (url.pathname === "/healthz" && request.method === "GET") return sendJson(200, { ok: true, did: key.did });
  if (url.pathname !== "/sign" || request.method !== "POST") return send(404, "text/plain;charset=UTF-8", "not found\n");
  try {
    const body = await readJson(request);
    if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("request body must be a JSON object");
    for (const field of Object.keys(body)) if (!ALLOWED_CLAIMS.includes(field)) throw new Error(`unexpected field: ${field}`);
    // PLAN7: pure SIOPv2/OID4VP direct delivery -- did.md hands the signed
    // capability/id_token straight back to REDIRECT_URI (fragment), no
    // api.did.md code+token round trip. redirect_uri/client_id/
    // response_type are still fixed here, never accepted from the caller
    // (see this module's own header comment).
    const payload = { ...body, iss: key.did, client_id: key.did, client_id_scheme: "did", response_type: "vp_token id_token", redirect_uri: REDIRECT_URI };
    return sendJson(200, { jwt: sign(payload) });
  } catch (error) {
    return send(400, "text/plain;charset=UTF-8", `${error instanceof Error ? error.message : "invalid request"}\n`);
  }
}).listen(PORT, HOST, () => {
  console.log(`biset-rp-signer listening on ${HOST}:${PORT}`);
  console.log(`rp did: ${key.did}`);
});
