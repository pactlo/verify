// Prints the public key list served at
// https://pactlo.com/.well-known/pactlo-audit-keys.json, generated from
// src/trust.ts so the published list and the verifier never differ.
//   tsx scripts/keys-json.ts > ../../../pactlo-landing/public/.well-known/pactlo-audit-keys.json
import { SIGNING_KEYS, TSA_ROOTS } from "../src/trust"

const document = {
  format: "pactlo-audit-keys",
  version: 1,
  about:
    "Keys that sign Pactlo audit blocks, and the roots each timestamp authority must chain to. Keys are only ever added. Specification: SPEC.md in the @pactlo/verify package.",
  signing_keys: Object.entries(SIGNING_KEYS).map(([keyId, key]) => ({
    key_id: keyId,
    algorithm: "Ed25519",
    public_key_spki_base64: key.publicKey,
    environment: key.environment,
    since: key.since,
  })),
  timestamp_authorities: Object.entries(TSA_ROOTS).map(([provider, root]) => ({
    provider,
    root_name: root.name,
    root_sha256: root.sha256,
    root_pem: root.pem,
  })),
}
console.log(JSON.stringify(document, null, 2))
