/**
 * Parser for Android's binary XML format (AXML), used by AndroidManifest.xml
 * inside a compiled APK.
 *
 * Reference: the public AOSP ResourceTypes.h chunk layout. Implemented from
 * the documented on-disk structure; no third-party or proprietary code.
 */

export interface AxmlAttribute {
  namespace: string | null;
  name: string;
  /** Best-effort human readable value. */
  value: string;
  rawType: number;
  rawData: number;
}

export interface AxmlNode {
  name: string;
  namespace: string | null;
  attributes: AxmlAttribute[];
  children: AxmlNode[];
}

export class AxmlError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AxmlError";
  }
}

const CHUNK_STRING_POOL = 0x0001;
const CHUNK_XML = 0x0003;
const CHUNK_START_ELEMENT = 0x0102;
const CHUNK_END_ELEMENT = 0x0103;
const CHUNK_START_NAMESPACE = 0x0100;

const TYPE_REFERENCE = 0x01;
const TYPE_STRING = 0x03;
const TYPE_FLOAT = 0x04;
const TYPE_INT_DEC = 0x10;
const TYPE_INT_HEX = 0x11;
const TYPE_INT_BOOLEAN = 0x12;

export function parseAxml(bytes: Uint8Array): AxmlNode {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (bytes.length < 8) throw new AxmlError("Binary XML too small");
  if (view.getUint16(0, true) !== CHUNK_XML) throw new AxmlError("Not a binary XML chunk");

  let strings: string[] = [];
  const namespaceUris = new Map<string, string>();
  const root: AxmlNode = { name: "#document", namespace: null, attributes: [], children: [] };
  const stack: AxmlNode[] = [root];

  let offset = view.getUint16(4, true) || 8;
  while (offset + 8 <= bytes.length) {
    const chunkType = view.getUint16(offset, true);
    const headerSize = view.getUint16(offset + 2, true);
    const chunkSize = view.getUint32(offset + 4, true);
    if (chunkSize < 8 || offset + chunkSize > bytes.length) break;

    if (chunkType === CHUNK_STRING_POOL) {
      strings = parseStringPool(bytes, view, offset);
    } else if (chunkType === CHUNK_START_NAMESPACE) {
      const prefix = readString(strings, view.getInt32(offset + headerSize, true));
      const uri = readString(strings, view.getInt32(offset + headerSize + 4, true));
      if (uri) namespaceUris.set(uri, prefix ?? "");
    } else if (chunkType === CHUNK_START_ELEMENT) {
      const base = offset + headerSize;
      const nsIndex = view.getInt32(base, true);
      const nameIndex = view.getInt32(base + 4, true);
      const attributeStart = view.getUint16(base + 8, true);
      const attributeSize = view.getUint16(base + 10, true);
      const attributeCount = view.getUint16(base + 12, true);

      const node: AxmlNode = {
        name: readString(strings, nameIndex) ?? "",
        namespace: readString(strings, nsIndex),
        attributes: [],
        children: [],
      };

      for (let i = 0; i < attributeCount; i += 1) {
        const attrOffset = base + attributeStart + i * (attributeSize || 20);
        if (attrOffset + 20 > bytes.length) break;
        const attrNs = readString(strings, view.getInt32(attrOffset, true));
        const attrName = readString(strings, view.getInt32(attrOffset + 4, true)) ?? "";
        const rawValueIndex = view.getInt32(attrOffset + 8, true);
        const dataType = view.getUint8(attrOffset + 15);
        const data = view.getInt32(attrOffset + 16, true);
        node.attributes.push({
          namespace: attrNs,
          name: attrName,
          rawType: dataType,
          rawData: data,
          value: formatValue(strings, rawValueIndex, dataType, data),
        });
      }

      stack[stack.length - 1]!.children.push(node);
      stack.push(node);
    } else if (chunkType === CHUNK_END_ELEMENT) {
      if (stack.length > 1) stack.pop();
    }

    offset += chunkSize;
  }

  if (root.children.length === 0) throw new AxmlError("No XML elements decoded");
  return root;
}

function formatValue(strings: string[], rawValueIndex: number, dataType: number, data: number): string {
  switch (dataType) {
    case TYPE_STRING:
      return readString(strings, rawValueIndex >= 0 ? rawValueIndex : data) ?? "";
    case TYPE_INT_BOOLEAN:
      return data === 0 ? "false" : "true";
    case TYPE_INT_HEX:
      return `0x${(data >>> 0).toString(16)}`;
    case TYPE_REFERENCE:
      return `@${(data >>> 0).toString(16)}`;
    case TYPE_FLOAT:
      return String(new DataView(new ArrayBuffer(4)).getFloat32(0));
    case TYPE_INT_DEC:
    default: {
      const asString = readString(strings, rawValueIndex);
      if (asString !== null && dataType !== TYPE_INT_DEC) return asString;
      return String(data);
    }
  }
}

function readString(strings: string[], index: number): string | null {
  if (index < 0 || index >= strings.length) return null;
  return strings[index] ?? null;
}

function parseStringPool(bytes: Uint8Array, view: DataView, offset: number): string[] {
  const stringCount = view.getUint32(offset + 8, true);
  const flags = view.getUint32(offset + 16, true);
  const stringsStart = view.getUint32(offset + 20, true);
  const isUtf8 = (flags & (1 << 8)) !== 0;
  const out: string[] = [];
  const utf8Decoder = new TextDecoder("utf-8");
  const utf16Decoder = new TextDecoder("utf-16le");

  for (let i = 0; i < stringCount; i += 1) {
    const indexOffset = offset + 28 + i * 4;
    if (indexOffset + 4 > bytes.length) break;
    const stringOffset = offset + stringsStart + view.getUint32(indexOffset, true);
    if (stringOffset + 2 > bytes.length) {
      out.push("");
      continue;
    }
    if (isUtf8) {
      let cursor = stringOffset;
      // Two length fields: UTF-16 length, then UTF-8 byte length.
      cursor += readUtf8Length(view, cursor).consumed;
      const byteLength = readUtf8Length(view, cursor);
      cursor += byteLength.consumed;
      out.push(utf8Decoder.decode(bytes.subarray(cursor, cursor + byteLength.value)));
    } else {
      let length = view.getUint16(stringOffset, true);
      let cursor = stringOffset + 2;
      if ((length & 0x8000) !== 0) {
        length = ((length & 0x7fff) << 16) | view.getUint16(cursor, true);
        cursor += 2;
      }
      out.push(utf16Decoder.decode(bytes.subarray(cursor, cursor + length * 2)));
    }
  }
  return out;
}

function readUtf8Length(view: DataView, offset: number): { value: number; consumed: number } {
  const first = view.getUint8(offset);
  if ((first & 0x80) !== 0) {
    return { value: ((first & 0x7f) << 8) | view.getUint8(offset + 1), consumed: 2 };
  }
  return { value: first, consumed: 1 };
}

/** Depth-first search for all elements with a given tag name. */
export function findElements(node: AxmlNode, tag: string): AxmlNode[] {
  const out: AxmlNode[] = [];
  const walk = (current: AxmlNode) => {
    if (current.name === tag) out.push(current);
    current.children.forEach(walk);
  };
  walk(node);
  return out;
}

export function attr(node: AxmlNode, name: string): string | null {
  const found = node.attributes.find((candidate) => candidate.name === name);
  return found ? found.value : null;
}

export function attrBool(node: AxmlNode, name: string): boolean | null {
  const value = attr(node, name);
  if (value === null) return null;
  return value === "true" || value === "1";
}

export function attrInt(node: AxmlNode, name: string): number | null {
  const found = node.attributes.find((candidate) => candidate.name === name);
  if (!found) return null;
  if (found.rawType === TYPE_INT_DEC || found.rawType === TYPE_INT_HEX) return found.rawData;
  const parsed = Number.parseInt(found.value, 10);
  return Number.isFinite(parsed) ? parsed : null;
}