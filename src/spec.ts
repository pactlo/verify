import { sha256 } from "@noble/hashes/sha2.js"
import canonicalize from "canonicalize"
import { concatBytes, equalBytes, i64, u32, u64, utf8ToBytes, uuidToBytes } from "./bytes"

// The Pactlo audit trail hash specification, version 1 (SPEC.md). This is an
// independent implementation: Pactlo's servers compute the same values with
// other code, and the test suites check the two agree byte for byte.

const ZERO = new Uint8Array([0x00])
const ONE = new Uint8Array([0x01])
const label = (text: string) => concatBytes(utf8ToBytes(text), ZERO)

// RFC 8785 JSON Canonicalization Scheme.
export function canonical(value: unknown): string {
  const text = canonicalize(value)
  if (text === undefined) throw new Error("value cannot be canonicalized")
  return text
}

export const payloadHash = (payloadJcs: string): Uint8Array => sha256(utf8ToBytes(payloadJcs))

export const genesisHash = (chainId: string): Uint8Array =>
  sha256(concatBytes(label("PACTLO-AUDIT-GENESIS-v1"), uuidToBytes(chainId)))

export function eventHash(input: {
  chainId: string
  seq: bigint
  prevHash: Uint8Array
  recordedAtMicros: bigint
  payloadHash: Uint8Array
}): Uint8Array {
  return sha256(
    concatBytes(
      label("PACTLO-AUDIT-EVENT-v1"),
      uuidToBytes(input.chainId),
      u64(input.seq),
      input.prevHash,
      i64(input.recordedAtMicros),
      input.payloadHash,
    ),
  )
}

export const piiCommitment = (salt: Uint8Array, piiJcs: string): Uint8Array =>
  sha256(concatBytes(label("PACTLO-PII-v1"), salt, utf8ToBytes(piiJcs)))

// RFC 6962 Merkle tree.
export const leafHash = (data: Uint8Array): Uint8Array => sha256(concatBytes(ZERO, data))
export const nodeHash = (left: Uint8Array, right: Uint8Array): Uint8Array =>
  sha256(concatBytes(ONE, left, right))

export function merkleRoot(leafHashes: readonly Uint8Array[]): Uint8Array {
  if (leafHashes.length === 0) throw new Error("a Merkle tree needs at least one leaf")
  let level = [...leafHashes]
  while (level.length > 1) {
    const next: Uint8Array[] = []
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i] as Uint8Array
      const right = level[i + 1]
      next.push(right ? nodeHash(left, right) : left)
    }
    level = next
  }
  return level[0] as Uint8Array
}

// RFC 9162 section 2.1.3.2.
export function verifyInclusion(
  leaf: Uint8Array,
  index: number,
  treeSize: number,
  proof: readonly Uint8Array[],
  root: Uint8Array,
): boolean {
  if (!Number.isInteger(index) || index < 0 || index >= treeSize) return false
  let fn = index
  let sn = treeSize - 1
  let hash = leaf
  for (const sibling of proof) {
    if (sn === 0) return false
    if (fn % 2 === 1 || fn === sn) {
      hash = nodeHash(sibling, hash)
      if (fn % 2 === 0) {
        while (fn % 2 === 0 && fn !== 0) {
          fn >>= 1
          sn >>= 1
        }
      }
    } else {
      hash = nodeHash(hash, sibling)
    }
    fn >>= 1
    sn >>= 1
  }
  return sn === 0 && equalBytes(hash, root)
}

export const BLOCK_GENESIS_HASH: Uint8Array = sha256(utf8ToBytes("PACTLO-AUDIT-BLOCK-GENESIS-v1"))

export type BlockHeader = {
  blockNo: bigint
  firstLeaf: bigint
  leafCount: number
  merkleRoot: Uint8Array
  prevBlockHash: Uint8Array
  createdAtMicros: bigint
}

export function blockHash(header: BlockHeader): Uint8Array {
  if (header.merkleRoot.length !== 32 || header.prevBlockHash.length !== 32) {
    throw new Error("block hashes must be 32 bytes")
  }
  return sha256(
    concatBytes(
      label("PACTLO-AUDIT-BLOCK-v1"),
      u64(header.blockNo),
      u64(header.firstLeaf),
      u32(header.leafCount),
      header.merkleRoot,
      header.prevBlockHash,
      i64(header.createdAtMicros),
    ),
  )
}

// What the signing key signs for a block.
export const signatureMessage = (hash: Uint8Array): Uint8Array =>
  concatBytes(label("PACTLO-AUDIT-BLOCK-SIG-v1"), hash)
