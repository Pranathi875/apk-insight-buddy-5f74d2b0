/**
 * DEX reader: extracts class descriptors and a filtered subset of the string
 * pool. We deliberately do not decompile: signature-based capability and
 * library detection only needs type descriptors and referenced strings.
 */

import type { DexFacts } from "./types";

const DEX_MAGIC = [0x64, 0x65, 0x78, 0x0a]; // "dex\n"
const MAX_STRINGS_SCANNED = 400_000;
const MAX_MATCHES = 4_000;

export interface DexScanOptions {
  /** Lowercased tokens; a string is retained only when it contains one. */
  tokens: string[];
}

export function isDex(bytes: Uint8Array): boolean {
  return DEX_MAGIC.every((byte, index) => bytes[index] === byte);
}

export function scanDex(
  buffers: Uint8Array[],
  options: DexScanOptions,
): DexFacts {
  const matchedStrings = new Set<string>();
  const matchedClasses = new Set<string>();
  const packagePrefixes = new Set<string>();
  let classCount = 0;
  let truncated = false;
  let parsedAny = false;
  let error: string | null = null;

  const tokens = options.tokens.map((token) => token.toLowerCase()).filter(Boolean);

  for (const bytes of buffers) {
    try {
      if (!isDex(bytes)) continue;
      const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      const stringIdsSize = view.getUint32(56, true);
      const stringIdsOff = view.getUint32(60, true);
      const typeIdsSize = view.getUint32(64, true);
      const typeIdsOff = view.getUint32(68, true);
      parsedAny = true;

      const scanCount = Math.min(stringIdsSize, MAX_STRINGS_SCANNED);
      if (scanCount < stringIdsSize) truncated = true;

      const readStringAt = (index: number): string | null => {
        const pointerOffset = stringIdsOff + index * 4;
        if (pointerOffset + 4 > bytes.length) return null;
        let dataOffset = view.getUint32(pointerOffset, true);
        const size = readUleb128(bytes, dataOffset);
        dataOffset = size.next;
        let end = dataOffset;
        while (end < bytes.length && bytes[end] !== 0) end += 1;
        return decodeMutf8(bytes.subarray(dataOffset, end));
      };

      for (let i = 0; i < scanCount; i += 1) {
        if (matchedStrings.size >= MAX_MATCHES) {
          truncated = true;
          break;
        }
        const value = readStringAt(i);
        if (!value || value.length < 4 || value.length > 300) continue;
        const lower = value.toLowerCase();
        if (tokens.some((token) => lower.includes(token))) matchedStrings.add(value);
      }

      classCount += typeIdsSize;
      for (let i = 0; i < typeIdsSize; i += 1) {
        const pointerOffset = typeIdsOff + i * 4;
        if (pointerOffset + 4 > bytes.length) break;
        const stringIndex = view.getUint32(pointerOffset, true);
        const descriptor = readStringAt(stringIndex);
        if (!descriptor || !descriptor.startsWith("L")) continue;
        const dotted = descriptor.slice(1, -1).replace(/\//g, ".");
        const parts = dotted.split(".");
        if (parts.length >= 3) packagePrefixes.add(parts.slice(0, 3).join("."));
        const lower = dotted.toLowerCase();
        if (matchedClasses.size < MAX_MATCHES && tokens.some((token) => lower.includes(token))) {
          matchedClasses.add(dotted);
        }
      }
    } catch (cause) {
      error = cause instanceof Error ? cause.message : "Unknown DEX parse failure";
    }
  }

  return {
    parsed: parsedAny,
    dexFiles: buffers.length,
    classCount,
    packagePrefixes: [...packagePrefixes].sort().slice(0, 500),
    matchedStrings: [...matchedStrings].sort(),
    matchedClasses: [...matchedClasses].sort(),
    truncated,
    error,
  };
}

export function readUleb128(bytes: Uint8Array, offset: number): { value: number; next: number } {
  let result = 0;
  let shift = 0;
  let cursor = offset;
  for (let i = 0; i < 5; i += 1) {
    const byte = bytes[cursor] ?? 0;
    cursor += 1;
    result |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) break;
    shift += 7;
  }
  return { value: result >>> 0, next: cursor };
}

/** MUTF-8 is UTF-8 for the ASCII/BMP range we care about. */
function decodeMutf8(bytes: Uint8Array): string {
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}