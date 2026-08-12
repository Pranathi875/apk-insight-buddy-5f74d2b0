/**
 * Minimal, dependency-free ZIP reader used to inspect APK containers.
 *
 * An APK is a ZIP archive. We read the central directory to enumerate
 * entries and inflate individual entries on demand with the platform
 * `DecompressionStream` (available in modern browsers and Workers).
 *
 * The reader never executes anything from the archive and never writes to
 * disk. Entry names are validated so a crafted archive cannot be used to
 * drive path traversal in any consumer of this module.
 */

export interface ZipEntry {
  name: string;
  compressedSize: number;
  uncompressedSize: number;
  compressionMethod: number;
  localHeaderOffset: number;
  crc32: number;
}

export class ZipError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ZipError";
  }
}

const EOCD_SIGNATURE = 0x06054b50;
const CENTRAL_SIGNATURE = 0x02014b50;
const ZIP64_EOCD_LOCATOR = 0x07064b50;
const ZIP64_EOCD = 0x06064b50;

/** Entry names must be relative, POSIX-ish and free of traversal segments. */
export function isSafeEntryName(name: string): boolean {
  if (name.length === 0 || name.length > 1024) return false;
  if (name.startsWith("/") || name.includes("\\")) return false;
  if (name.includes("\0")) return false;
  return !name.split("/").some((segment) => segment === "..");
}

export class ApkZip {
  private readonly view: DataView;
  readonly bytes: Uint8Array;
  readonly entries: ZipEntry[];

  private constructor(bytes: Uint8Array, entries: ZipEntry[]) {
    this.bytes = bytes;
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    this.entries = entries;
  }

  static open(bytes: Uint8Array): ApkZip {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const eocd = findEocd(view);
    if (eocd < 0) throw new ZipError("Not a ZIP/APK container: end-of-central-directory record not found");

    let entryCount = view.getUint16(eocd + 10, true);
    let centralOffset = view.getUint32(eocd + 16, true);

    // ZIP64 fallback for archives with >65535 entries or >4GB offsets.
    if (entryCount === 0xffff || centralOffset === 0xffffffff) {
      const locator = eocd - 20;
      if (locator >= 0 && view.getUint32(locator, true) === ZIP64_EOCD_LOCATOR) {
        const zip64Offset = Number(view.getBigUint64(locator + 8, true));
        if (view.getUint32(zip64Offset, true) === ZIP64_EOCD) {
          entryCount = Number(view.getBigUint64(zip64Offset + 32, true));
          centralOffset = Number(view.getBigUint64(zip64Offset + 48, true));
        }
      }
    }

    const entries: ZipEntry[] = [];
    let cursor = centralOffset;
    for (let i = 0; i < entryCount; i += 1) {
      if (cursor + 46 > bytes.length) break;
      if (view.getUint32(cursor, true) !== CENTRAL_SIGNATURE) break;
      const compressionMethod = view.getUint16(cursor + 10, true);
      const crc32 = view.getUint32(cursor + 16, true);
      const compressedSize = view.getUint32(cursor + 20, true);
      const uncompressedSize = view.getUint32(cursor + 24, true);
      const nameLength = view.getUint16(cursor + 28, true);
      const extraLength = view.getUint16(cursor + 30, true);
      const commentLength = view.getUint16(cursor + 32, true);
      const localHeaderOffset = view.getUint32(cursor + 42, true);
      const name = decodeUtf8(bytes.subarray(cursor + 46, cursor + 46 + nameLength));
      entries.push({
        name,
        compressionMethod,
        crc32,
        compressedSize,
        uncompressedSize,
        localHeaderOffset,
      });
      cursor += 46 + nameLength + extraLength + commentLength;
    }

    if (entries.length === 0) throw new ZipError("ZIP central directory is empty or malformed");
    return new ApkZip(bytes, entries);
  }

  has(name: string): boolean {
    return this.entries.some((entry) => entry.name === name);
  }

  find(predicate: (entry: ZipEntry) => boolean): ZipEntry[] {
    return this.entries.filter(predicate);
  }

  /** Reads and, when needed, inflates a single entry. */
  async read(nameOrEntry: string | ZipEntry, maxBytes = 128 * 1024 * 1024): Promise<Uint8Array> {
    const entry =
      typeof nameOrEntry === "string"
        ? this.entries.find((candidate) => candidate.name === nameOrEntry)
        : nameOrEntry;
    if (!entry) throw new ZipError(`Entry not found: ${String(nameOrEntry)}`);
    if (!isSafeEntryName(entry.name)) throw new ZipError(`Unsafe entry name rejected: ${entry.name}`);
    if (entry.uncompressedSize > maxBytes) {
      throw new ZipError(`Entry ${entry.name} exceeds the ${maxBytes} byte read limit`);
    }

    const headerOffset = entry.localHeaderOffset;
    if (headerOffset + 30 > this.bytes.length) throw new ZipError("Truncated local file header");
    if (this.view.getUint32(headerOffset, true) !== 0x04034b50) {
      throw new ZipError(`Bad local header signature for ${entry.name}`);
    }
    const nameLength = this.view.getUint16(headerOffset + 26, true);
    const extraLength = this.view.getUint16(headerOffset + 28, true);
    const dataStart = headerOffset + 30 + nameLength + extraLength;
    const dataEnd = dataStart + entry.compressedSize;
    if (dataEnd > this.bytes.length) throw new ZipError(`Truncated data for ${entry.name}`);
    const raw = this.bytes.subarray(dataStart, dataEnd);

    if (entry.compressionMethod === 0) return raw.slice();
    if (entry.compressionMethod !== 8) {
      throw new ZipError(`Unsupported compression method ${entry.compressionMethod} for ${entry.name}`);
    }
    return inflateRaw(raw);
  }
}

export async function inflateRaw(data: Uint8Array): Promise<Uint8Array> {
  if (typeof DecompressionStream === "undefined") {
    throw new ZipError("DecompressionStream is unavailable in this runtime");
  }
  const stream = new Blob([data as BlobPart]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
  const buffer = await new Response(stream).arrayBuffer();
  return new Uint8Array(buffer);
}

function findEocd(view: DataView): number {
  const maxBack = Math.min(view.byteLength, 66000);
  for (let i = view.byteLength - 22; i >= view.byteLength - maxBack && i >= 0; i -= 1) {
    if (view.getUint32(i, true) === EOCD_SIGNATURE) return i;
  }
  return -1;
}

function decodeUtf8(bytes: Uint8Array): string {
  return new TextDecoder("utf-8").decode(bytes);
}