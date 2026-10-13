import { sha256 } from "@noble/hashes/sha2.js"
import { bundleSchema, type EvidenceBundle } from "./bundle"
import { bytesToHex } from "./bytes"

// Files, as people hold them. Nothing here renders or interprets a PDF: a
// fingerprint is computed over the bytes, and the one thing read from inside
// a PDF is the evidence bundle Pactlo attaches to its certificates (SPEC.md
// section 7), found by its fixed name.

// Where a PDF could have been cut before something was appended to it:
// right after each "%%EOF" marker, with or without the line break after it.
// Each incremental update ends with one, so a signed copy with changes
// appended still has the signed copy, unchanged, as one of these prefixes.
export type Fingerprints = {
  size: number
  sha256: string
  prefixes: { length: number; sha256: string }[]
}

const EOF = [0x25, 0x25, 0x45, 0x4f, 0x46] // "%%EOF"
const MAX_PREFIXES = 32

export async function fingerprints(
  chunks: AsyncIterable<Uint8Array> | Iterable<Uint8Array>,
  onProgress?: (bytes: number) => void,
): Promise<Fingerprints> {
  const hash = sha256.create()
  const cuts = new Set<number>()
  const prefixes: { length: number; sha256: string }[] = []
  let offset = 0
  // The last bytes of the previous chunk, to find markers split across chunks.
  let tail = new Uint8Array(0)
  let pending: number[] = []
  for await (const chunk of chunks) {
    const window = new Uint8Array(tail.length + chunk.length)
    window.set(tail)
    window.set(chunk, tail.length)
    const start = offset - tail.length
    for (let i = 0; i + EOF.length <= window.length; i++) {
      if (EOF.every((b, k) => window[i + k] === b)) {
        const end = start + i + EOF.length
        pending.push(end, end + 1, end + 2)
      }
    }
    // Hash up to each candidate cut that falls in this chunk, snapshotting.
    let consumed = 0
    pending.sort((a, b) => a - b)
    const later: number[] = []
    for (const cut of pending) {
      if (cut > offset + chunk.length) {
        later.push(cut)
        continue
      }
      if (cut < offset + consumed || cuts.has(cut) || cut <= 0) continue
      hash.update(chunk.subarray(consumed, cut - offset))
      consumed = cut - offset
      cuts.add(cut)
      if (prefixes.length < MAX_PREFIXES)
        prefixes.push({ length: cut, sha256: bytesToHex(hash.clone().digest()) })
    }
    pending = later
    hash.update(chunk.subarray(consumed))
    offset += chunk.length
    tail = window.subarray(Math.max(0, window.length - (EOF.length - 1)))
    onProgress?.(offset)
  }
  const whole = bytesToHex(hash.digest())
  return {
    size: offset,
    sha256: whole,
    prefixes: prefixes.filter((p) => p.length < offset),
  }
}

// The evidence bundle attached to a Pactlo certificate, or null. Bounded:
// a hostile file can't make this read or inflate without limit.
const BUNDLE_NAME = "pactlo-evidence.json"
const MAX_COMPRESSED = 20 * 1024 * 1024
const MAX_INFLATED = 64 * 1024 * 1024

export async function embeddedBundle(pdf: Uint8Array): Promise<EvidenceBundle | null> {
  const text = latin1(pdf)
  if (!text.includes(BUNDLE_NAME)) return null
  // Stream dictionaries are never inside object streams, so the attached
  // file's dictionary is plain text in the file.
  const marker = /\/Type\s*\/EmbeddedFile\b/g
  for (let match = marker.exec(text); match; match = marker.exec(text)) {
    // From the object's start: the dictionary may hold others (/Params).
    const dictStart = text.lastIndexOf(" obj", match.index)
    const streamAt = text.indexOf("stream", match.index)
    if (dictStart < 0 || streamAt < 0 || streamAt - dictStart > 4096) continue
    const dict = text.slice(dictStart, streamAt)
    if (!/\/Subtype\s*\/application#2Fjson\b/i.test(dict)) continue
    const length = /\/Length\s+(\d+)(?!\s+\d+\s+R)/.exec(dict)
    if (!length) continue
    const size = Number(length[1])
    if (size <= 0 || size > MAX_COMPRESSED) continue
    let bodyStart = streamAt + "stream".length
    if (text[bodyStart] === "\r") bodyStart++
    if (text[bodyStart] === "\n") bodyStart++
    const body = pdf.subarray(bodyStart, bodyStart + size)
    const flate = /\/Filter\s*\/FlateDecode\b/.test(dict)
    try {
      const json = new TextDecoder().decode(flate ? await inflate(body) : body)
      const parsed = bundleSchema.safeParse(JSON.parse(json))
      if (parsed.success) return parsed.data
    } catch {
      // Not ours, or damaged: keep looking.
    }
  }
  return null
}

async function inflate(data: Uint8Array): Promise<Uint8Array> {
  const stream = new Blob([data as BlobPart])
    .stream()
    .pipeThrough(new DecompressionStream("deflate"))
  const reader = stream.getReader()
  const parts: Uint8Array[] = []
  let total = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    total += value.length
    if (total > MAX_INFLATED) {
      await reader.cancel()
      throw new Error("too large")
    }
    parts.push(value)
  }
  const out = new Uint8Array(total)
  let at = 0
  for (const part of parts) {
    out.set(part, at)
    at += part.length
  }
  return out
}

function latin1(bytes: Uint8Array): string {
  let out = ""
  for (let i = 0; i < bytes.length; i += 0x8000) {
    out += String.fromCharCode(...bytes.subarray(i, i + 0x8000))
  }
  return out
}
