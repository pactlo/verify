import { z } from "zod"

// Evidence bundle, format version 1 (SPEC.md section 5). One JSON file,
// serialised with RFC 8785, that carries everything needed to check one
// chain of events without Pactlo: the events, the personal data behind their
// commitments, Merkle proofs into signed blocks, the blocks up to one that an
// independent authority timestamped, and those timestamps.

const hex32 = z.string().regex(/^[0-9a-f]{64}$/)
const uint = z.string().regex(/^(0|[1-9][0-9]{0,18})$/)
const int = z.string().regex(/^-?(0|[1-9][0-9]{0,18})$/)
const base64 = z.string().regex(/^[A-Za-z0-9+/]*={0,2}$/)

export const bundleSchema = z.strictObject({
  format: z.literal("pactlo-evidence"),
  version: z.literal(1),
  issued_at: z.iso.datetime(),
  environment: z.enum(["production", "dev", "test"]),
  chain: z.strictObject({
    id: z.uuid(),
    kind: z.enum(["agreement", "organization", "user", "platform"]),
    scope_id: z.string().min(1).max(200),
    head_seq: uint,
    head_hash: hex32,
  }),
  events: z.array(
    z.strictObject({
      seq: uint,
      recorded_at_micros: int,
      prev_hash: hex32,
      payload_jcs: z.string(),
      event_hash: hex32,
      // Where the event sits in the block log, once sealed.
      block_no: uint.nullable(),
      leaf_index: uint.nullable(),
      // Sibling hashes from the leaf up to the block's Merkle root (RFC 9162).
      proof: z.array(hex32).nullable(),
    }),
  ),
  // The personal data behind each commitment, unless erased.
  disclosures: z.array(z.strictObject({ commitment: hex32, salt: hex32, pii_jcs: z.string() })),
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
      // Where copies live in write-once storage (informational).
      copies: z.array(
        z.strictObject({ kind: z.string(), provider: z.string(), location: z.string() }),
      ),
    }),
  ),
  timestamps: z.array(
    z.strictObject({ block_no: uint, provider: z.string().min(1).max(40), token: base64 }),
  ),
  // Documents the chain is about, by hash (the files travel separately).
  documents: z.array(z.strictObject({ name: z.string().max(500), sha256: hex32 })),
})

export type EvidenceBundle = z.infer<typeof bundleSchema>
