import { base64ToBytes, equalBytes, hexToBytes } from "./bytes"
import { BLOCK_GENESIS_HASH, blockHash } from "./spec"
import { type CheckedTimestamp, verifyTimestamp } from "./timestamp"
import { type SigningKey, type TsaRoot, verifyBlockSignature } from "./trust"

// Blocks and their timestamps, as carried by bundles and receipts (SPEC.md
// section 4): each block recomputed and signed by a pinned key, linked to the
// one before when both are present, and each timestamp checked against the
// block it covers.

export type BlockRecord = {
  block_no: string
  first_leaf: string
  leaf_count: number
  merkle_root: string
  prev_block_hash: string
  created_at_micros: string
  block_hash: string
  key_id: string
  signature: string
}

export type TimestampRecord = { block_no: string; provider: string; token: string }

// Clocks drift; an authority may not date a block before it existed by more than this.
const CLOCK_SKEW_MICROS = 5n * 60n * 1_000_000n

export function checkBlocks(
  blocks: readonly BlockRecord[],
  keys: Record<string, SigningKey>,
): { ok: boolean; environments: Set<string>; problems: string[] } {
  const byNo = new Map(blocks.map((b) => [b.block_no, b]))
  const problems: string[] = []
  const environments = new Set<string>()
  for (const block of blocks) {
    const where = `block ${block.block_no}`
    const hash = blockHash({
      blockNo: BigInt(block.block_no),
      firstLeaf: BigInt(block.first_leaf),
      leafCount: block.leaf_count,
      merkleRoot: hexToBytes(block.merkle_root),
      prevBlockHash: hexToBytes(block.prev_block_hash),
      createdAtMicros: BigInt(block.created_at_micros),
    })
    if (!equalBytes(hash, hexToBytes(block.block_hash))) {
      problems.push(`${where}: hash does not match its header`)
    }
    const key = keys[block.key_id]
    if (!key || !verifyBlockSignature(hash, block.key_id, base64ToBytes(block.signature), keys)) {
      problems.push(
        `${where}: signature ${key ? "is invalid" : `is by an unknown key (${block.key_id})`}`,
      )
    } else {
      environments.add(key.environment)
    }
    const before = byNo.get((BigInt(block.block_no) - 1n).toString())
    if (before && block.prev_block_hash !== before.block_hash) {
      problems.push(`${where}: does not link to block ${before.block_no}`)
    }
    if (
      block.block_no === "1" &&
      !equalBytes(hexToBytes(block.prev_block_hash), BLOCK_GENESIS_HASH)
    ) {
      problems.push("block 1: does not start from the genesis")
    }
  }
  return { ok: problems.length === 0, environments, problems }
}

export async function checkTimestamps(
  blocks: readonly BlockRecord[],
  timestamps: readonly TimestampRecord[],
  roots: Record<string, TsaRoot>,
): Promise<{ ok: boolean; stamps: Map<string, CheckedTimestamp[]>; problems: string[] }> {
  const byNo = new Map(blocks.map((b) => [b.block_no, b]))
  const stamps = new Map<string, CheckedTimestamp[]>()
  const problems: string[] = []
  for (const stamp of timestamps) {
    const block = byNo.get(stamp.block_no)
    const root = roots[stamp.provider]
    if (!block || !root) {
      problems.push(
        `timestamp on block ${stamp.block_no}: ${block ? `unknown authority ${stamp.provider}` : "block not in bundle"}`,
      )
      continue
    }
    try {
      const checked = await verifyTimestamp({
        token: base64ToBytes(stamp.token),
        data: hexToBytes(block.block_hash),
        rootPem: root.pem,
      })
      const genMicros = BigInt(checked.genTime.getTime()) * 1000n
      if (genMicros + CLOCK_SKEW_MICROS < BigInt(block.created_at_micros)) {
        throw new Error("dated before the block was made")
      }
      stamps.set(stamp.block_no, [...(stamps.get(stamp.block_no) ?? []), checked])
    } catch (error) {
      problems.push(
        `${stamp.provider} timestamp on block ${stamp.block_no}: ${(error as Error).message}`,
      )
    }
  }
  return { ok: problems.length === 0, stamps, problems }
}

// The earliest independent time for something in block `blockNo`: the first
// timestamped block at or after it, reached through unbroken links.
export function existedBy(
  blockNo: string,
  blocks: readonly BlockRecord[],
  stamps: Map<string, CheckedTimestamp[]>,
): { time: string; authorities: string[] } | undefined {
  const byNo = new Map(blocks.map((b) => [b.block_no, b]))
  let at = BigInt(blockNo)
  for (let steps = 0; steps < 10_000; steps++) {
    const found = stamps.get(at.toString())
    if (found?.length) {
      const earliest = found.reduce((a, b) => (a.genTime <= b.genTime ? a : b))
      return { time: earliest.genTime.toISOString(), authorities: found.map((f) => f.authority) }
    }
    const next = byNo.get((at + 1n).toString())
    const current = byNo.get(at.toString())
    if (!next || !current || next.prev_block_hash !== current.block_hash) return undefined
    at++
  }
  return undefined
}
