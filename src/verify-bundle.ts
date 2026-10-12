import { bundleSchema, type EvidenceBundle } from "./bundle"
import { base64ToBytes, bytesToHex, equalBytes, hexToBytes } from "./bytes"
import {
  BLOCK_GENESIS_HASH,
  blockHash,
  canonical,
  eventHash,
  genesisHash,
  leafHash,
  payloadHash,
  piiCommitment,
  verifyInclusion,
} from "./spec"
import { type CheckedTimestamp, verifyTimestamp } from "./timestamp"
import {
  SIGNING_KEYS,
  type SigningKey,
  TSA_ROOTS,
  type TsaRoot,
  verifyBlockSignature,
} from "./trust"

// Verifies an evidence bundle offline, trusting only the keys and roots
// pinned in trust.ts. Every check is listed in the report; any failure makes
// the whole bundle fail. A bundle whose newest events are not yet covered by
// a timestamp is "incomplete": everything present checks out, but those
// events have no independent time yet (ask for a new bundle an hour later).

export type Check = { name: string; ok: boolean; detail?: string }

export type VerifiedEvent = {
  seq: string
  type: string
  recordedAt: string
  actor: { type: string; id?: string }
  subject: { type: string; id: string }
  data: unknown
  country?: string
  // The personal data recorded with the event, checked against its
  // commitment; "erased" after a privacy request.
  personalData?: Record<string, string> | "erased"
  blockNo?: string
  // The earliest independent timestamp covering this event.
  existedBy?: { time: string; authorities: string[] }
}

export type Report = {
  result: "verified" | "incomplete" | "failed"
  environment: string
  chain?: { kind: string; scopeId: string; id: string; events: number }
  checks: Check[]
  problems: string[]
  events: VerifiedEvent[]
}

export type VerifyOptions = {
  keys?: Record<string, SigningKey>
  roots?: Record<string, TsaRoot>
}

// Clocks drift; an authority may not date a block before it existed by more than this.
const CLOCK_SKEW_MICROS = 5n * 60n * 1_000_000n

export async function verifyBundle(input: unknown, options: VerifyOptions = {}): Promise<Report> {
  const keys = options.keys ?? SIGNING_KEYS
  const roots: Record<string, TsaRoot> = options.roots ?? TSA_ROOTS
  const checks: Check[] = []
  const problems: string[] = []
  // A check that fails with no specific problem recorded adds its own line.
  const check = (name: string, ok: boolean, okDetail: string, failDetail = "failed") => {
    checks.push({ name, ok, detail: ok ? okDetail : failDetail })
    if (!ok && failDetail !== "see problems") problems.push(`${name}: ${failDetail}`)
    return ok
  }

  // 1. Format.
  const parsed = bundleSchema.safeParse(input)
  if (!parsed.success) {
    check(
      "bundle format",
      false,
      "",
      parsed.error.issues
        .map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`)
        .slice(0, 5)
        .join("; "),
    )
    return { result: "failed", environment: "unknown", checks, problems, events: [] }
  }
  const bundle: EvidenceBundle = parsed.data
  check("bundle format", true, "pactlo-evidence v1")

  // 2. The event chain, from its genesis.
  const chainId = bundle.chain.id
  let prev = genesisHash(chainId)
  let lastMicros = -1n
  let chainOk = true
  const payloads: Record<string, unknown>[] = []
  bundle.events.forEach((event, i) => {
    const where = `event ${event.seq}`
    const fail = (why: string) => {
      chainOk = false
      problems.push(`${where}: ${why}`)
    }
    if (BigInt(event.seq) !== BigInt(i + 1))
      fail(`expected seq ${i + 1} (missing or reordered event)`)
    if (!equalBytes(hexToBytes(event.prev_hash), prev)) fail("does not link to the previous event")
    const micros = BigInt(event.recorded_at_micros)
    if (micros <= lastMicros) fail("time went backwards")
    let payload: Record<string, unknown> = {}
    try {
      payload = JSON.parse(event.payload_jcs)
      if (canonical(payload) !== event.payload_jcs) fail("payload is not canonical JSON")
    } catch {
      fail("payload is not JSON")
    }
    payloads.push(payload)
    const computed = eventHash({
      chainId,
      seq: BigInt(event.seq),
      prevHash: hexToBytes(event.prev_hash),
      recordedAtMicros: micros,
      payloadHash: payloadHash(event.payload_jcs),
    })
    if (!equalBytes(computed, hexToBytes(event.event_hash)))
      fail("hash does not match its contents")
    prev = hexToBytes(event.event_hash)
    lastMicros = micros
  })
  check(
    "event chain",
    chainOk && bundle.events.length > 0,
    `${bundle.events.length} events, each linked to the one before`,
    bundle.events.length === 0 ? "no events" : "see problems",
  )

  // 3. The chain head named in the bundle is the last event: none left out.
  const last = bundle.events.at(-1)
  check(
    "complete chain",
    !!last && last.seq === bundle.chain.head_seq && last.event_hash === bundle.chain.head_hash,
    `head is event ${bundle.chain.head_seq}`,
    `the bundle says the chain ends at event ${bundle.chain.head_seq}; its last event is ${last?.seq ?? "none"}`,
  )

  // 4. Personal data behind commitments.
  const disclosures = new Map(bundle.disclosures.map((d) => [d.commitment, d]))
  let piiOk = true
  const personal: (Record<string, string> | "erased" | undefined)[] = payloads.map((payload, i) => {
    const commitment = typeof payload.pii === "string" ? payload.pii : null
    if (!commitment) return undefined
    const disclosure = disclosures.get(commitment)
    if (!disclosure) return "erased"
    const ok = equalBytes(
      piiCommitment(hexToBytes(disclosure.salt), disclosure.pii_jcs),
      hexToBytes(commitment),
    )
    if (!ok) {
      piiOk = false
      problems.push(`event ${bundle.events[i]?.seq}: personal data does not match its commitment`)
      return undefined
    }
    return JSON.parse(disclosure.pii_jcs) as Record<string, string>
  })
  const erased = personal.filter((p) => p === "erased").length
  check(
    "personal data",
    piiOk,
    `${bundle.disclosures.length} disclosures match their commitments${erased ? `; ${erased} erased on request` : ""}`,
    "see problems",
  )

  // 5. Each sealed event is in its block.
  const blocks = new Map(bundle.blocks.map((b) => [b.block_no, b]))
  let proofsOk = true
  let sealed = 0
  for (const event of bundle.events) {
    if (event.block_no === null) continue
    sealed++
    const block = blocks.get(event.block_no)
    const index =
      event.leaf_index === null ? -1n : BigInt(event.leaf_index) - BigInt(block?.first_leaf ?? "0")
    const ok =
      !!block &&
      !!event.proof &&
      index >= 0n &&
      verifyInclusion(
        leafHash(hexToBytes(event.event_hash)),
        Number(index),
        block.leaf_count,
        event.proof.map(hexToBytes),
        hexToBytes(block.merkle_root),
      )
    if (!ok) {
      proofsOk = false
      problems.push(`event ${event.seq}: not proven to be in block ${event.block_no}`)
    }
  }
  check(
    "Merkle proofs",
    proofsOk,
    `${sealed} of ${bundle.events.length} events sealed in blocks`,
    "see problems",
  )

  // 6. Blocks: recomputed, signed by a pinned key, linked to each other.
  let blocksOk = true
  const environments = new Set<string>()
  for (const block of bundle.blocks) {
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
      blocksOk = false
      problems.push(`${where}: hash does not match its header`)
    }
    const key = keys[block.key_id]
    if (!key || !verifyBlockSignature(hash, block.key_id, base64ToBytes(block.signature), keys)) {
      blocksOk = false
      problems.push(
        `${where}: signature ${key ? "is invalid" : `is by an unknown key (${block.key_id})`}`,
      )
    } else {
      environments.add(key.environment)
    }
    const before = blocks.get((BigInt(block.block_no) - 1n).toString())
    if (before && block.prev_block_hash !== before.block_hash) {
      blocksOk = false
      problems.push(`${where}: does not link to block ${before.block_no}`)
    }
    if (
      block.block_no === "1" &&
      !equalBytes(hexToBytes(block.prev_block_hash), BLOCK_GENESIS_HASH)
    ) {
      blocksOk = false
      problems.push("block 1: does not start from the genesis")
    }
  }
  check(
    "blocks",
    blocksOk,
    `${bundle.blocks.length} blocks recomputed and signed by Pactlo`,
    "see problems",
  )
  const envOk =
    environments.size === 0 || (environments.size === 1 && environments.has(bundle.environment))
  check(
    "signing environment",
    envOk,
    environments.size === 0 ? "no trusted signatures to compare" : `${bundle.environment} keys`,
    `the bundle says ${bundle.environment}, but its keys are ${[...environments].join(", ")}`,
  )

  // 7. Timestamps from independent authorities.
  const stamps = new Map<string, CheckedTimestamp[]>()
  let stampsOk = true
  for (const stamp of bundle.timestamps) {
    const block = blocks.get(stamp.block_no)
    const root = roots[stamp.provider]
    if (!block || !root) {
      stampsOk = false
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
      stampsOk = false
      problems.push(
        `${stamp.provider} timestamp on block ${stamp.block_no}: ${(error as Error).message}`,
      )
    }
  }
  check(
    "timestamps",
    stampsOk,
    `${bundle.timestamps.length} RFC 3161 timestamps from pinned authorities`,
    "see problems",
  )

  // Each event's earliest independent time: the first timestamped block at or
  // after its own, reached through unbroken links.
  const events: VerifiedEvent[] = bundle.events.map((event, i) => {
    const payload = payloads[i] ?? {}
    const verified: VerifiedEvent = {
      seq: event.seq,
      type: String(payload.type ?? ""),
      recordedAt: microsToIso(BigInt(event.recorded_at_micros)),
      actor: (payload.actor ?? {}) as VerifiedEvent["actor"],
      subject: (payload.subject ?? {}) as VerifiedEvent["subject"],
      data: payload.data,
      ...(typeof payload.country === "string" ? { country: payload.country } : {}),
      ...(personal[i] ? { personalData: personal[i] } : {}),
      ...(event.block_no ? { blockNo: event.block_no } : {}),
    }
    if (event.block_no === null) return verified
    let at = BigInt(event.block_no)
    for (let steps = 0; steps < 10_000; steps++) {
      const found = stamps.get(at.toString())
      if (found?.length) {
        const earliest = found.reduce((a, b) => (a.genTime <= b.genTime ? a : b))
        verified.existedBy = {
          time: earliest.genTime.toISOString(),
          authorities: found.map((f) => f.authority),
        }
        break
      }
      const next = blocks.get((at + 1n).toString())
      const current = blocks.get(at.toString())
      if (!next || !current || next.prev_block_hash !== current.block_hash) break
      at++
    }
    return verified
  })
  const covered = events.filter((e) => e.existedBy).length
  // An event cannot be timestamped before it was recorded.
  const impossible = events.filter(
    (e) => e.existedBy && Date.parse(e.existedBy.time) + 5 * 60_000 < Date.parse(e.recordedAt),
  )
  check(
    "independent time",
    impossible.length === 0,
    `${covered} of ${events.length} events covered by a timestamp`,
    `events ${impossible.map((e) => e.seq).join(", ")} timestamped before they were recorded`,
  )

  const failed = problems.length > 0
  return {
    result: failed ? "failed" : covered === events.length ? "verified" : "incomplete",
    environment: bundle.environment,
    chain: {
      kind: bundle.chain.kind,
      scopeId: bundle.chain.scope_id,
      id: chainId,
      events: bundle.events.length,
    },
    checks,
    problems,
    events,
  }
}

function microsToIso(micros: bigint): string {
  const ms = micros / 1000n
  const rest = (micros % 1000n).toString().padStart(3, "0")
  return new Date(Number(ms)).toISOString().replace("Z", `${rest}Z`)
}

export const _internal = { microsToIso, bytesToHex }
