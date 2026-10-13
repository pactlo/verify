#!/usr/bin/env node
import { readFile } from "node:fs/promises"
import { bundleSchema } from "./bundle"
import { mergeBundles } from "./merge"
import { embeddedBundle, fingerprints } from "./pdf"
import { formatReport } from "./report"
import { verifyBundle } from "./verify-bundle"

// pactlo-verify <bundle.json | certificate.pdf> [update.json] [--json]
// A certificate of completion carries its evidence bundle; an update (from
// pactlo.com/verify, "Download the latest proof") adds what was sealed and
// timestamped after it.
// Exit codes: 0 verified, 3 incomplete (not timestamped yet), 1 failed, 2 usage error.

async function main(argv: string[]): Promise<number> {
  const args = argv.filter((a) => !a.startsWith("--"))
  const json = argv.includes("--json")
  if (args.length < 1 || args.length > 2 || argv.includes("--help")) {
    console.error(
      "Usage: pactlo-verify <bundle.json | certificate.pdf> [update.json] [--json]\nChecks Pactlo evidence offline.",
    )
    return 2
  }
  let input: unknown
  try {
    const bytes = new Uint8Array(await readFile(args[0] as string))
    if (new TextDecoder().decode(bytes.subarray(0, 5)) === "%PDF-") {
      const prints = await fingerprints([bytes])
      if (!json) console.log(`SHA-256 of ${args[0]}: ${prints.sha256}`)
      input = await embeddedBundle(bytes)
      if (!input) {
        console.error(
          "This PDF carries no Pactlo evidence. Check its SHA-256 at pactlo.com/verify.",
        )
        return 1
      }
    } else {
      input = JSON.parse(new TextDecoder().decode(bytes))
    }
    if (args[1]) {
      const base = bundleSchema.parse(input)
      const update = bundleSchema.parse(JSON.parse(await readFile(args[1], "utf8")))
      input = mergeBundles(base, update)
    }
  } catch (error) {
    console.error(`Cannot read the evidence: ${(error as Error).message}`)
    return 2
  }
  const report = await verifyBundle(input)
  console.log(json ? JSON.stringify(report, null, 2) : formatReport(report))
  return report.result === "verified" ? 0 : report.result === "incomplete" ? 3 : 1
}

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (error: unknown) => {
    console.error(error)
    process.exit(1)
  },
)
