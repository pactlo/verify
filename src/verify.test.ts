import { describe, expect, it } from "vitest"
import bundleFile from "./fixtures/bundle-v1.json"
import fixtureKey from "./fixtures/fixture-key.json"
import type { SigningKey } from "./trust"
import { verifyBundle } from "./verify-bundle"

// A real bundle: three events with personal data, a block signed with the
// test-only fixture key, and RFC 3161 timestamps from DigiCert and Sectigo.
const keys = fixtureKey as Record<string, SigningKey>
const fresh = () => structuredClone(bundleFile) as typeof bundleFile
const flip = (hex: string) => (hex[0] === "0" ? "1" : "0") + hex.slice(1)

describe("verifyBundle", () => {
  it("verifies a real bundle end to end", async () => {
    const report = await verifyBundle(fresh(), { keys })
    expect(report.problems).toEqual([])
    expect(report.result).toBe("verified")
    expect(report.checks.every((c) => c.ok)).toBe(true)
    expect(report.events).toHaveLength(3)
    const [created] = report.events
    expect(created?.type).toBe("user.created")
    expect(created?.personalData).toMatchObject({ email: "signer@example.com", ip: "203.0.113.7" })
    expect(created?.existedBy?.authorities).toHaveLength(2)
    expect(Date.parse(created?.existedBy?.time ?? "")).toBeGreaterThanOrEqual(
      Date.parse(created?.recordedAt ?? "") - 5 * 60_000,
    )
  })

  it("does not trust a test key by default", async () => {
    const report = await verifyBundle(fresh())
    expect(report.result).toBe("failed")
    expect(report.problems.join()).toMatch(/unknown key/)
  })

  const tampered: [string, (b: ReturnType<typeof fresh>) => void, RegExp][] = [
    [
      "an edited event",
      (b) => {
        b.events[1]!.payload_jcs = b.events[1]!.payload_jcs.replace("email_otp", "passkey")
      },
      /event 2: hash does not match/,
    ],
    [
      "a removed event",
      (b) => {
        b.events.splice(1, 1)
      },
      /event 3: expected seq 2/,
    ],
    [
      "a dropped last event",
      (b) => {
        b.events.pop()
      },
      /complete chain/,
    ],
    [
      "reordered events",
      (b) => {
        b.events.reverse()
      },
      /expected seq 1/,
    ],
    [
      "changed personal data",
      (b) => {
        b.disclosures[0]!.pii_jcs = b.disclosures[0]!.pii_jcs.replace("203.0.113.7", "198.51.100.1")
      },
      /personal data does not match/,
    ],
    [
      "a forged block root",
      (b) => {
        b.blocks[0]!.merkle_root = flip(b.blocks[0]!.merkle_root)
      },
      /hash does not match its header|not proven/,
    ],
    [
      "a forged signature",
      (b) => {
        b.blocks[0]!.signature = `A${b.blocks[0]!.signature.slice(1)}`
      },
      /signature is invalid/,
    ],
    [
      "a wrong Merkle proof",
      (b) => {
        b.events[0]!.proof = b.events[0]!.proof && [flip(b.events[0]!.proof[0] ?? "00".repeat(32))]
      },
      /event 1: not proven/,
    ],
    [
      "a timestamp moved to another block",
      (b) => {
        b.timestamps[0]!.token = b.timestamps[1]!.token
      },
      /timestamp on block/,
    ],
    [
      "a production label on test keys",
      (b) => {
        b.environment = "production"
      },
      /signing environment/,
    ],
    [
      "an unknown field",
      (b) => {
        ;(b as Record<string, unknown>).extra = 1
      },
      /bundle format/,
    ],
  ]
  for (const [name, mutate, problem] of tampered) {
    it(`catches ${name}`, async () => {
      const bundle = fresh()
      mutate(bundle)
      const report = await verifyBundle(bundle, { keys })
      expect(report.result).toBe("failed")
      expect(report.problems.join("\n")).toMatch(problem)
    })
  }

  it("calls a bundle without timestamps incomplete, not failed", async () => {
    const bundle = fresh()
    bundle.timestamps = []
    const report = await verifyBundle(bundle, { keys })
    expect(report.problems).toEqual([])
    expect(report.result).toBe("incomplete")
    expect(report.events.every((e) => !e.existedBy)).toBe(true)
  })

  it("keeps the chain valid when personal data was erased", async () => {
    const bundle = fresh()
    bundle.disclosures = []
    const report = await verifyBundle(bundle, { keys })
    expect(report.result).toBe("verified")
    expect(report.events[0]?.personalData).toBe("erased")
  })
})
