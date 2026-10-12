import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js"

// Byte helpers that work the same in Node and in browsers.

export { bytesToHex, concatBytes, hexToBytes, utf8ToBytes }

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0)
  return diff === 0
}

export function base64ToBytes(text: string): Uint8Array {
  const binary = atob(text)
  const out = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i)
  return out
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = ""
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary)
}

export function u64(value: bigint): Uint8Array {
  if (value < 0n || value >= 1n << 64n) throw new Error("value out of range for 8 bytes")
  const out = new Uint8Array(8)
  new DataView(out.buffer).setBigUint64(0, value)
  return out
}

export function i64(value: bigint): Uint8Array {
  const out = new Uint8Array(8)
  new DataView(out.buffer).setBigInt64(0, value)
  return out
}

export function u32(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff)
    throw new Error("value out of range for 4 bytes")
  const out = new Uint8Array(4)
  new DataView(out.buffer).setUint32(0, value)
  return out
}

// A UUID as its 16 bytes.
export function uuidToBytes(uuid: string): Uint8Array {
  const hex = uuid.replaceAll("-", "")
  if (!/^[0-9a-f]{32}$/i.test(hex)) throw new Error(`not a UUID: ${uuid}`)
  return hexToBytes(hex.toLowerCase())
}
