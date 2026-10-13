import type { Report } from "./verify-bundle"

// The report as plain text, for people.
export function formatReport(report: Report): string {
  const lines: string[] = []
  const verdict = {
    verified: "VERIFIED: every event is intact and independently timestamped.",
    incomplete:
      "INCOMPLETE: everything present is intact, but the newest events are not timestamped yet. Ask for a new bundle in an hour.",
    failed: "FAILED: this bundle does not check out. Do not rely on it.",
  }[report.result]
  lines.push(verdict, "")
  if (report.chain) {
    lines.push(
      `Chain: ${report.chain.kind} ${report.chain.scopeId} (${report.chain.events} events)`,
    )
  }
  if (report.environment !== "production") {
    lines.push(`Note: signed in the ${report.environment} environment, not a production record.`)
  }
  lines.push("")
  for (const check of report.checks) {
    lines.push(`${check.ok ? "✓" : "✗"} ${check.name}${check.detail ? `: ${check.detail}` : ""}`)
  }
  if (report.problems.length > 0) {
    lines.push("", "Problems:")
    for (const problem of report.problems) lines.push(`  - ${problem}`)
  }
  if (report.events.length > 0) {
    lines.push("", "Events:")
    for (const event of report.events) {
      const by = event.existedBy
        ? `existed by ${event.existedBy.time} (${event.existedBy.authorities.join(", ")})`
        : "not timestamped yet"
      lines.push(`  ${event.seq}. ${event.recordedAt}  ${event.type}  [${by}]`)
      if (event.personalData === "withheld")
        lines.push("      personal data: not included (a public proof, or erased on request)")
      else if (event.personalData) {
        lines.push(
          `      ${Object.entries(event.personalData)
            .map(([k, v]) => `${k}: ${v}`)
            .join(", ")}`,
        )
      }
    }
  }
  return lines.join("\n")
}
