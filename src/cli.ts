#!/usr/bin/env node
import { readFile } from "node:fs/promises"
import { formatReport } from "./report"
import { verifyBundle } from "./verify-bundle"

// pactlo-verify <bundle.json> [--json]
// Exit codes: 0 verified, 3 incomplete (not timestamped yet), 1 failed, 2 usage error.

async function main(argv: string[]): Promise<number> {
  const args = argv.filter((a) => !a.startsWith("--"))
  const json = argv.includes("--json")
  if (args.length !== 1 || argv.includes("--help")) {
    console.error(
      "Usage: pactlo-verify <bundle.json> [--json]\nChecks a Pactlo evidence bundle offline.",
    )
    return 2
  }
  let input: unknown
  try {
    input = JSON.parse(await readFile(args[0] as string, "utf8"))
  } catch (error) {
    console.error(`Cannot read ${args[0]}: ${(error as Error).message}`)
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
