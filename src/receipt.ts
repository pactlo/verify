import { z } from "zod"
import { checkBlocks, checkTimestamps, existedBy } from "./blocks"
import { equalBytes, hexToBytes } from "./bytes"
import { canonical, eventHash, leafHash, payloadHash, verifyInclusion } from "./spec"
import { SIGNING_KEYS, type SigningKey, TSA_ROOTS, type TsaRoot } from "./trust"

// Receipt, format version 1 (SPEC.md section 6): proof that one event is in
// Pactlo's audit log, without the rest of its chain or any personal data.
// Public pages use it: the "agreement.sealed" event names the fingerprints of
// the signed copy and the certificate, so a receipt for it shows that Pactlo
// recorded those files, in a signed block, timestamped by independent
// authorities.

const hex32 = z.string().regex(/^[0-9a-f]{64}$/)
const uint = z.string().regex(/^(0|[1-9][0-9]{0,18})$/)
const int = z.string().regex(/^-?(0|[1-9][0-9]{0,18})$/)
const base64 = z.string().regex(/^[A-Za-z0-9+/]*={0,2}$/)

export const receiptSchema = z.strictObject({
  format: z.literal("pactlo-receipt"),
  version: z.literal(1),
  issued_at: z.iso.datetime(),
  environment: z.enum(["production", "dev", "test"]),
  chain: z.strictObject({
    id: z.uuid(),
    kind: z.enum(["agreement", "organization", "user", "platform"]),
  }),
  event: z.strictObject({
    seq: uint,
    recorded_at_micros: int,
    prev_hash: hex32,
    payload_jcs: z.string(),
    event_hash: hex32,
    block_no: uint.nullable(),
    leaf_index: uint.nullable(),
    proof: z.array(hex32).nullable(),
  }),
  blocks: z.array(
    z.strictObject({
      block_no: uint,
      first_leaf: uint,
      leaf_count: z.number().int().min(1).max(10_000),
      merkle_root: hex32,
      prev_block_hash: hex32,
      created_at_micros: int,
      block_hash: hex32,
      key_id: z.string().min(1).max(300),
      signature: base64,
    }),
  ),
  timestamps: z.array(
    z.strictObject({ block_no: uint, provider: z.string().min(1).max(40), token: base64 }),
  ),
})

export type Receipt = z.infer<typeof receiptSchema>

export type ReceiptReport = {
  // verified: in a signed block that an authority timestamped. incomplete:
  // everything present checks out, but the event isn't sealed or timestamped
  // yet (within the hour). failed: don't rely on it.
  result: "verified" | "incomplete" | "failed"
  environment: string
  checks: { name: string; ok: boolean; detail?: string }[]
  problems: string[]
  event?: {
    type: string
    recordedAt: string
    data: unknown
    blockNo?: string
    existedBy?: { time: string; authorities: string[] }
  }
}

export async function verifyReceipt(
  input: unknown,
  options: { keys?: Record<string, SigningKey>; roots?: Record<string, TsaRoot> } = {},
): Promise<ReceiptReport> {
  const keys = options.keys ?? SIGNING_KEYS
  const roots = options.roots ?? TSA_ROOTS
  const checks: ReceiptReport["checks"] = []
  const problems: string[] = []
  const check = (name: string, ok: boolean, okDetail: string, failDetail = "failed") => {
    checks.push({ name, ok, detail: ok ? okDetail : failDetail })
    if (!ok && failDetail !== "see problems") problems.push(`${name}: ${failDetail}`)
    return ok
  }

  const parsed = receiptSchema.safeParse(input)
  if (!parsed.success) {
    check(
      "receipt format",
      false,
      "",
      parsed.error.issues
        .map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`)
        .slice(0, 5)
        .join("; "),
    )
    return { result: "failed", environment: "unknown", checks, problems }
  }
  const receipt = parsed.data
  check("receipt format", true, "pactlo-receipt v1")

  // The event: its hash from its contents (the chain before it is not here;
  // its previous hash is part of what is hashed).
  const { event } = receipt
  let payload: Record<string, unknown> = {}
  let eventOk = true
  try {
    payload = JSON.parse(event.payload_jcs)
    if (canonical(payload) !== event.payload_jcs) eventOk = false
  } catch {
    eventOk = false
  }
  const computed = eventHash({
    chainId: receipt.chain.id,
    seq: BigInt(event.seq),
    prevHash: hexToBytes(event.prev_hash),
    recordedAtMicros: BigInt(event.recorded_at_micros),
    payloadHash: payloadHash(event.payload_jcs),
  })
  check(
    "event",
    eventOk && equalBytes(computed, hexToBytes(event.event_hash)),
    `event ${event.seq} of its chain, hash matches its contents`,
    "the event's hash does not match its contents",
  )

  // In its block.
  const block = receipt.blocks.find((b) => b.block_no === event.block_no)
  if (event.block_no !== null) {
    const index =
      event.leaf_index === null ? -1n : BigInt(event.leaf_index) - BigInt(block?.first_leaf ?? "0")
    check(
      "Merkle proof",
      !!block &&
        !!event.proof &&
        index >= 0n &&
        verifyInclusion(
          leafHash(hexToBytes(event.event_hash)),
          Number(index),
          block.leaf_count,
          event.proof.map(hexToBytes),
          hexToBytes(block.merkle_root),
        ),
      `sealed in block ${event.block_no}`,
      `not proven to be in block ${event.block_no}`,
    )
  }

  const blockCheck = checkBlocks(receipt.blocks, keys)
  problems.push(...blockCheck.problems)
  check(
    "blocks",
    blockCheck.ok,
    `${receipt.blocks.length} blocks recomputed and signed by Pactlo`,
    "see problems",
  )
  const envs = blockCheck.environments
  check(
    "signing environment",
    envs.size === 0 || (envs.size === 1 && envs.has(receipt.environment)),
    envs.size === 0 ? "no trusted signatures to compare" : `${receipt.environment} keys`,
    `the receipt says ${receipt.environment}, but its keys are ${[...envs].join(", ")}`,
  )
  const stampCheck = await checkTimestamps(receipt.blocks, receipt.timestamps, roots)
  problems.push(...stampCheck.problems)
  check(
    "timestamps",
    stampCheck.ok,
    `${receipt.timestamps.length} RFC 3161 timestamps from pinned authorities`,
    "see problems",
  )

  const time = event.block_no
    ? existedBy(event.block_no, receipt.blocks, stampCheck.stamps)
    : undefined
  const recordedAt = microsToIso(BigInt(event.recorded_at_micros))
  if (time && Date.parse(time.time) + 5 * 60_000 < Date.parse(recordedAt)) {
    check("independent time", false, "", "timestamped before it was recorded")
  }
  const failed = problems.length > 0
  return {
    result: failed ? "failed" : time ? "verified" : "incomplete",
    environment: receipt.environment,
    checks,
    problems,
    event: {
      type: String(payload.type ?? ""),
      recordedAt,
      data: payload.data,
      ...(event.block_no ? { blockNo: event.block_no } : {}),
      ...(time ? { existedBy: time } : {}),
    },
  }
}

function microsToIso(micros: bigint): string {
  const ms = micros / 1000n
  const rest = (micros % 1000n).toString().padStart(3, "0")
  return new Date(Number(ms)).toISOString().replace("Z", `${rest}Z`)
}
