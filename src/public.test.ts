import { deflateSync } from "node:zlib"
import { describe, expect, it } from "vitest"
import { bundleSchema, type EvidenceBundle } from "./bundle"
import bundleFile from "./fixtures/bundle-v1.json"
import fixtureKey from "./fixtures/fixture-key.json"
import { mergeBundles } from "./merge"
import { embeddedBundle, fingerprints } from "./pdf"
import { verifyReceipt } from "./receipt"
import type { SigningKey } from "./trust"
import { verifyBundle } from "./verify-bundle"

const keys = fixtureKey as Record<string, SigningKey>
const fresh = () => bundleSchema.parse(structuredClone(bundleFile))
const ascii = (s: string) => new TextEncoder().encode(s)
const join = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let at = 0
  for (const p of parts) {
    out.set(p, at)
    at += p.length
  }
  return out
}
function* chunksOf(bytes: Uint8Array, size: number) {
  for (let i = 0; i < bytes.length; i += size) yield bytes.subarray(i, i + size)
}

describe("fingerprints", () => {
  const original = ascii("%PDF-1.7\n1 0 obj << >> endobj\ntrailer << >>\n%%EOF\n")
  const appended = join(original, ascii("2 0 obj << /Changed true >> endobj\n%%EOF\n"))

  it("are the same however the file arrives, and find where it could have been cut", async () => {
    const whole = await fingerprints([appended])
    for (const size of [1, 3, 7, 64]) {
      expect(await fingerprints(chunksOf(appended, size))).toEqual(whole)
    }
    const plain = await fingerprints([original])
    expect(whole.size).toBe(appended.length)
    // The original, unchanged, is one of the prefixes of the appended file.
    expect(whole.prefixes).toContainEqual({ length: original.length, sha256: plain.sha256 })
    expect(whole.prefixes.every((p) => p.length < appended.length)).toBe(true)
  })
})

describe("the bundle attached to a certificate", () => {
  const attach = (json: Uint8Array, dict: string) =>
    join(
      ascii("%PDF-1.7\n5 0 obj << /Type /Filespec /F (pactlo-evidence.json) >> endobj\n"),
      ascii(`6 0 obj ${dict.replace("LEN", String(json.length))}\nstream\n`),
      json,
      ascii("\nendstream\nendobj\n%%EOF\n"),
    )

  it("is found and read, compressed or not", async () => {
    const json = ascii(JSON.stringify(bundleFile))
    const flate = new Uint8Array(deflateSync(json))
    const dict = "<< /Type /EmbeddedFile /Subtype /application#2Fjson /Length LEN"
    expect(await embeddedBundle(attach(flate, `${dict} /Filter /FlateDecode >>`))).toEqual(fresh())
    expect(await embeddedBundle(attach(json, `${dict} >>`))).toEqual(fresh())
    // As qpdf writes it: keys sorted, a nested dictionary before /Subtype.
    expect(
      await embeddedBundle(
        attach(
          flate,
          "<< /Filter /FlateDecode /Length LEN /Params << /Size 9 >> /Subtype /application#2fjson /Type /EmbeddedFile >>",
        ),
      ),
    ).toEqual(fresh())
  })

  it("is absent from other files, and not read when it isn't a bundle", async () => {
    expect(await embeddedBundle(ascii("%PDF-1.7\n%%EOF\n"))).toBeNull()
    const other = ascii('{"hello":"world"}')
    expect(
      await embeddedBundle(
        attach(other, "<< /Type /EmbeddedFile /Subtype /application#2Fjson /Length LEN >>"),
      ),
    ).toBeNull()
  })
})

describe("updating an embedded bundle", () => {
  // As embedded at completion: the events, not yet sealed.
  const unsealed = (): EvidenceBundle => {
    const b = fresh()
    return {
      ...b,
      events: b.events.map((e) => ({ ...e, block_no: null, leaf_index: null, proof: null })),
      blocks: [],
      timestamps: [],
    }
  }
  // The public update: everything sealed, no personal data.
  const update = (): EvidenceBundle => ({ ...fresh(), disclosures: [] })

  it("completes the proof and keeps the personal data the original carries", async () => {
    expect((await verifyBundle(unsealed(), { keys })).result).toBe("incomplete")
    const merged = mergeBundles(unsealed(), update())
    const report = await verifyBundle(merged, { keys })
    expect(report.problems).toEqual([])
    expect(report.result).toBe("verified")
    expect(report.events[0]?.personalData).toMatchObject({ email: "signer@example.com" })
  })

  it("refuses an update that disagrees with the original", () => {
    const changed = update()
    const first = changed.events[0]
    if (first) first.payload_jcs = first.payload_jcs.replace("user.created", "user.deleted")
    expect(() => mergeBundles(unsealed(), changed)).toThrow(/disagrees about event 1/)
    const shorter = update()
    shorter.events.pop()
    expect(() => mergeBundles(unsealed(), shorter)).toThrow()
  })
})

describe("receipts", () => {
  const receiptFor = (seq: number) => {
    const b = fresh()
    const event = b.events[seq - 1]
    if (!event) throw new Error("no event")
    return {
      format: "pactlo-receipt",
      version: 1,
      issued_at: b.issued_at,
      environment: b.environment,
      chain: { id: b.chain.id, kind: b.chain.kind },
      event,
      blocks: b.blocks.map(({ copies: _copies, ...block }) => block),
      timestamps: b.timestamps,
    }
  }

  it("prove one event without the rest of the chain or any personal data", async () => {
    const report = await verifyReceipt(receiptFor(2), { keys })
    expect(report.problems).toEqual([])
    expect(report.result).toBe("verified")
    expect(report.event?.existedBy?.authorities).toHaveLength(2)
    expect(JSON.stringify(receiptFor(2))).not.toContain("signer@example.com")
  })

  it("fail when the event was changed, and wait when it isn't sealed yet", async () => {
    const changed = receiptFor(2)
    changed.event.payload_jcs = changed.event.payload_jcs.replace("1", "2")
    expect((await verifyReceipt(changed, { keys })).result).toBe("failed")
    const pending = receiptFor(2)
    pending.event = { ...pending.event, block_no: null, leaf_index: null, proof: null }
    pending.blocks = []
    pending.timestamps = []
    expect((await verifyReceipt(pending, { keys })).result).toBe("incomplete")
    expect((await verifyReceipt(receiptFor(2))).result).toBe("failed") // test key not trusted
  })
})
