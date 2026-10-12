# Pactlo audit trail and evidence bundles — specification v1

Status: v1, 2026-10-12. This document is normative for `@pactlo/verify`.
Pactlo's servers implement it independently; both implementations are
tested against each other byte for byte.

## 1. Goals

Anyone holding an evidence bundle can check, offline and without trusting
Pactlo, that:

1. the recorded events are complete and unchanged since they were recorded;
2. Pactlo committed to them in signed blocks;
3. an independent timestamp authority saw those blocks by a given time.

Notation: `||` is concatenation; integers are big-endian; `SHA256` is
SHA-256; text is UTF-8; `label(s) = UTF8(s) || 0x00`.

## 2. Events and chains

Every event belongs to exactly one chain: an agreement, a workspace
(organization), a user, or the platform. A chain has a random UUID `chain_id`.

- `payload_jcs`: the event as JSON canonicalized with RFC 8785 (JCS). Numbers
  are integers only; decimals are strings.
- `payload_hash = SHA256(payload_jcs)`
- `genesis = SHA256(label("PACTLO-AUDIT-GENESIS-v1") || chain_id[16])`
- `event_hash = SHA256(label("PACTLO-AUDIT-EVENT-v1") || chain_id[16] || seq[8]
  || prev_hash[32] || recorded_at_unix_micros[8, signed] || payload_hash[32])`

`seq` starts at 1 and has no gaps; `prev_hash` of event 1 is `genesis`, of
event n the `event_hash` of event n−1. `recorded_at` strictly increases.

Payload fields: `v` (1), `type`, `org` (workspace or null), `actor`
`{type, id?}`, `subject` `{type, id}`, `data` (per type; never personal
data), `occurred_at`, `request_id`, optional `country`, optional `pii`.

## 3. Personal data

IP addresses, user agents, emails and names never enter a payload. They are
stored separately, and the payload carries a salted commitment:

- `pii = SHA256(label("PACTLO-PII-v1") || salt[32] || pii_jcs)` (hex)

where `pii_jcs` is the JCS of the personal data and `salt` is 32 random bytes.
Erasing the stored data (a privacy request) leaves every hash valid; the
commitment then reveals nothing.

## 4. Blocks

Every minute with new events, they are sealed into a block.

- Leaves are the events' `event_hash` values in leaf order; the tree is the
  Merkle tree of RFC 6962 / RFC 9162:
  `leaf = SHA256(0x00 || event_hash)`, `node = SHA256(0x01 || left || right)`.
- Leaf indexes are global, gapless, and continue from block to block
  (`first_leaf` of block n = `first_leaf + leaf_count` of block n−1).
- `block_genesis = SHA256(UTF8("PACTLO-AUDIT-BLOCK-GENESIS-v1"))`
- `block_hash = SHA256(label("PACTLO-AUDIT-BLOCK-v1") || block_no[8] ||
  first_leaf[8] || leaf_count[4] || merkle_root[32] || prev_block_hash[32] ||
  created_at_unix_micros[8, signed])`; `prev_block_hash` of block 1 is
  `block_genesis`.
- Signature: Ed25519 (RFC 8032, strict verification) over
  `label("PACTLO-AUDIT-BLOCK-SIG-v1") || block_hash`, made in AWS KMS. Keys
  are identified by their KMS key ARN.
- Copies of every block go to write-once storage (AWS S3 Object Lock in
  compliance mode, and a locked Cloudflare R2 bucket).
- Each hour, the latest block is timestamped by DigiCert and by Sectigo
  (RFC 3161, SHA-256): the token's message imprint is `SHA256(block_hash)`.
  Because blocks are chained, a timestamp on block n covers every block
  before it.

Trusted keys and timestamp roots are pinned in `src/trust.ts` and published
at `https://pactlo.com/.well-known/pactlo-audit-keys.json`. Keys are only
ever added. Each day the latest block (number, hash, signature) is also
published to the public repository `pactlo/audit-checkpoints`, so Pactlo
cannot show different histories to different people.

## 5. Evidence bundle (format v1)

One JSON file (serialized with JCS). Fields are defined in `src/bundle.ts`;
unknown fields are rejected.

- `chain`: `id`, `kind`, `scope_id`, `head_seq`, `head_hash` (the chain's last
  event when the bundle was made).
- `events`: every event of the chain, in order, with `block_no`, `leaf_index`
  and `proof` (sibling hashes, RFC 9162 audit path) once sealed.
- `disclosures`: `{commitment, salt, pii_jcs}` for each commitment not erased.
- `blocks`: for each block holding an event, that block and every block up
  to the first timestamped block after it, with signature and copy locations.
- `timestamps`: RFC 3161 tokens (DER, base64) for those timestamped blocks.
- `documents`: `{name, sha256}` of the documents the chain is about.

## 6. Verification

A verifier MUST, in order:

1. Validate the format.
2. Recompute every `event_hash` from `genesis`, checking `seq` and time order.
3. Check the last event is `chain.head_seq` / `chain.head_hash`.
4. For each commitment with a disclosure, recompute it.
5. For each sealed event, verify its inclusion proof against its block's
   `merkle_root` (index = `leaf_index − first_leaf`, size = `leaf_count`).
6. For each block, recompute `block_hash`, verify the signature with a pinned
   key, and check `prev_block_hash` against the previous block when present.
7. For each timestamp: check the imprint, the signature, a certificate path to
   the authority's pinned root, a time-stamping certificate, and that it is
   not dated more than five minutes before its block.
8. For each event, find the first timestamped block at or after its own,
   reached through consecutive linked blocks; the earliest authority time is
   the time by which the event provably existed.

Result: `verified` (every check passes, every event timestamped),
`incomplete` (every check passes; some events not yet sealed or timestamped),
or `failed`.

## 7. Long-term validity

Hourly timestamps re-cover the whole history, so timestamps renew themselves
(RFC 4998's renewal) as long as the authorities' certificates and SHA-256 stay
sound. If SHA-256 or an authority's algorithm weakens, Pactlo will timestamp
the latest block with a stronger hash and publish a v2 of this specification;
existing bundles stay checkable with their v1 timestamps until then.

## 8. Legal note

Bundles are designed to support authentication of electronic records (for
example US Federal Rule of Evidence 902(14), and record retention under ESIGN
§101(d) and UETA §12). This is not legal advice, and no outcome is guaranteed.
