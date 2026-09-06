// Local OIDC "probe issuer": generates a keypair, publishes a JWKS, and mints
// RS256 id_tokens with arbitrary claims so that a workload-identity trust
// policy can be exercised against the real Google STS endpoint.
import { createPrivateKey, createPublicKey, createSign, generateKeyPairSync } from "node:crypto";
import { readFileSync, writeFileSync, existsSync, chmodSync } from "node:fs";

const KID = "c10-probe-1";
const KEY = "probe_key.pem";

if (!existsSync(KEY)) {
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  writeFileSync(KEY, privateKey.export({ type: "pkcs8", format: "pem" }));
  chmodSync(KEY, 0o600);
  const jwk = createPublicKey(privateKey).export({ format: "jwk" });
  writeFileSync("probe_jwks.json",
    JSON.stringify({ keys: [{ ...jwk, use: "sig", alg: "RS256", kid: KID }] }, null, 2));
  // A second, UNTRUSTED key: used as a negative control for signature checking.
  const { privateKey: rogue } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  writeFileSync("rogue_key.pem", rogue.export({ type: "pkcs8", format: "pem" }));
  chmodSync("rogue_key.pem", 0o600);
  console.error("generated probe_key.pem, rogue_key.pem, probe_jwks.json");
}

const b64u = (o) => Buffer.from(typeof o === "string" ? o : JSON.stringify(o))
  .toString("base64url");

const claims = JSON.parse(process.argv[2]);
const keyFile = process.argv[3] || KEY;
const now = Math.floor(Date.now() / 1000);
const payload = { iat: now, nbf: now, exp: now + 300, jti: String(now) + "-" + Math.random().toString(36).slice(2), ...claims };
const header = { alg: "RS256", typ: "JWT", kid: KID, x5t: undefined };
const signingInput = b64u(header) + "." + b64u(payload);
const sig = createSign("RSA-SHA256").update(signingInput)
  .sign(createPrivateKey(readFileSync(keyFile))).toString("base64url");
process.stdout.write(signingInput + "." + sig);
