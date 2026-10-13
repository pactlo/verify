import type { EvidenceBundle } from "./bundle"

// A certificate carries the evidence bundle as it was when the agreement
// completed: its newest events are usually not sealed or timestamped yet.
// Later, Pactlo can hand out an update of the same chain (without personal
// data). Merging keeps everything the original carries and adds what the
// update proves; it refuses an update that disagrees with the original on any
// event, so a merged bundle is never weaker than the one embedded.

export function mergeBundles(base: EvidenceBundle, update: EvidenceBundle): EvidenceBundle {
  if (base.chain.id !== update.chain.id || base.environment !== update.environment)
    throw new Error("the update is for another chain")
  if (BigInt(update.chain.head_seq) < BigInt(base.chain.head_seq))
    throw new Error("the update is older than the bundle")
  const newer = new Map(update.events.map((e) => [e.seq, e]))
  const events = base.events.map((event) => {
    const later = newer.get(event.seq)
    if (!later) throw new Error(`the update leaves out event ${event.seq}`)
    if (
      later.event_hash !== event.event_hash ||
      later.prev_hash !== event.prev_hash ||
      later.payload_jcs !== event.payload_jcs ||
      later.recorded_at_micros !== event.recorded_at_micros
    )
      throw new Error(`the update disagrees about event ${event.seq}`)
    if (event.block_no !== null && later.block_no !== event.block_no)
      throw new Error(`the update puts event ${event.seq} in another block`)
    return event.block_no !== null ? event : later
  })
  const known = new Set(base.events.map((e) => e.seq))
  events.push(...update.events.filter((e) => !known.has(e.seq)))

  const blocks = new Map(base.blocks.map((b) => [b.block_no, b]))
  for (const block of update.blocks) {
    const had = blocks.get(block.block_no)
    if (had && had.block_hash !== block.block_hash)
      throw new Error(`the update disagrees about block ${block.block_no}`)
    if (!had) blocks.set(block.block_no, block)
  }
  const stampKey = (t: EvidenceBundle["timestamps"][number]) =>
    `${t.block_no}:${t.provider}:${t.token}`
  const stamps = new Map(base.timestamps.map((t) => [stampKey(t), t]))
  for (const t of update.timestamps) stamps.set(stampKey(t), t)
  const disclosures = new Map(base.disclosures.map((d) => [d.commitment, d]))
  for (const d of update.disclosures)
    if (!disclosures.has(d.commitment)) disclosures.set(d.commitment, d)
  const documents = new Map(base.documents.map((d) => [d.sha256, d]))
  for (const d of update.documents) if (!documents.has(d.sha256)) documents.set(d.sha256, d)

  return {
    ...update,
    events,
    disclosures: [...disclosures.values()],
    blocks: [...blocks.values()].sort((a, b) => (BigInt(a.block_no) < BigInt(b.block_no) ? -1 : 1)),
    timestamps: [...stamps.values()],
    documents: [...documents.values()],
  }
}
