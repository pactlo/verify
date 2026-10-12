import { sha256 } from "@noble/hashes/sha2.js"
import * as pkijs from "pkijs"
import { equalBytes } from "./bytes"
import { pemToDer } from "./trust"

// Checks an RFC 3161 timestamp token: the authority's signature, a
// certificate path to the pinned root, a timestamping certificate, and that
// the token covers SHA-256 of `data`. Throws if anything is off.

const SHA256_OID = "2.16.840.1.101.3.4.2.1"
const TIMESTAMPING_EKU = "1.3.6.1.5.5.7.3.8"

export type CheckedTimestamp = { genTime: Date; authority: string; serial: string }

const ab = (bytes: Uint8Array): ArrayBuffer => new Uint8Array(bytes).buffer

export async function verifyTimestamp(input: {
  token: Uint8Array
  data: Uint8Array
  rootPem: string
}): Promise<CheckedTimestamp> {
  const info = pkijs.ContentInfo.fromBER(ab(input.token))
  if (info.contentType !== pkijs.ContentInfo.SIGNED_DATA) throw new Error("not a timestamp token")
  const signed = new pkijs.SignedData({ schema: info.content })
  const content = signed.encapContentInfo.eContent
  if (!content) throw new Error("timestamp token has no content")
  const tst = pkijs.TSTInfo.fromBER(ab(new Uint8Array(content.valueBlock.valueHexView)))

  if (tst.messageImprint.hashAlgorithm.algorithmId !== SHA256_OID) {
    throw new Error("timestamp is not over SHA-256")
  }
  const imprint = new Uint8Array(tst.messageImprint.hashedMessage.valueBlock.valueHexView)
  if (!equalBytes(imprint, sha256(input.data))) throw new Error("timestamp covers other data")

  const root = pkijs.Certificate.fromBER(ab(pemToDer(input.rootPem)))
  const rootKey = new Uint8Array(root.subjectPublicKeyInfo.toSchema().toBER(false))
  // Tokens may carry their own copy of the root, cross-signed by an older
  // one; without it the path ends at the pinned root.
  signed.certificates = (signed.certificates ?? []).filter(
    (cert) =>
      !(cert instanceof pkijs.Certificate) ||
      !equalBytes(new Uint8Array(cert.subjectPublicKeyInfo.toSchema().toBER(false)), rootKey),
  )
  const signer = signed.certificates.find(
    (cert): cert is pkijs.Certificate =>
      cert instanceof pkijs.Certificate &&
      Boolean(
        cert.extensions
          ?.find((e) => e.extnID === "2.5.29.37")
          ?.parsedValue?.keyPurposes?.includes(TIMESTAMPING_EKU),
      ),
  )
  if (!signer) throw new Error("timestamp signer is not a timestamping certificate")

  const result = await signed.verify({
    signer: 0,
    data: ab(input.data),
    checkChain: true,
    trustedCerts: [root],
    extendedMode: true,
  })
  if (!result.signatureVerified) throw new Error("timestamp signature does not verify")

  const cn = signer.subject.typesAndValues.find((tv) => tv.type === "2.5.4.3")
  return {
    genTime: tst.genTime,
    authority: String(cn?.value.valueBlock.value ?? "unknown"),
    serial: tst.serialNumber.toString(),
  }
}
