export type ZipEntry = { name: string; size: bigint; offset: bigint; extra: Uint8Array };

export class ZipIndex {
  #entries: ZipEntry[] = [];
  add(entry: ZipEntry) { this.#entries.push(entry); }
  list() { return this.#entries.slice(); }
  find(name: string) { return this.#entries.find(entry => entry.name === name); }
}

export function readUint64LE(data: Uint8Array, offset = 0): bigint {
  let value = 0n;
  for (let i = 0; i < 8; i++) value |= BigInt(data[offset + i] ?? 0) << (8n * BigInt(i));
  return value;
}

// ---------------------------------------------------------------------------
// ZIP extra field handling (APPNOTE 4.5):
//   each field is  id: uint16 LE, size: uint16 LE, payload: size bytes
// Local-header and central-directory extras are independent byte ranges; an
// overrun in one must never consume bytes belonging to the other.
// ---------------------------------------------------------------------------

export type ExtraSource = 'local' | 'central';

/** Well-known header ids used by the type-aware merge/decoders. */
export const EXTRA_ID_ZIP64 = 0x0001;
export const EXTRA_ID_EXTENDED_TIMESTAMP = 0x5455;
export const EXTRA_ID_NTFS_TIMESTAMP = 0x000a;
export const EXTRA_ID_UNIX_UID_GID = 0x7875;
export const EXTRA_ID_UNICODE_PATH = 0x7075;

const FIELD_HEADER_SIZE = 4;
const MAX_PAYLOAD_SIZE = 0xffff;
const EMPTY = new Uint8Array(0);

/** One parsed extra field. `data` is an owned copy of the exact payload bytes. */
export interface ExtraField {
  readonly id: number;
  readonly size: number;
  readonly data: Uint8Array;
  readonly source: ExtraSource;
  /** Ordinal position of this field within its own extra area. */
  readonly index: number;
}

export interface ExtraArea {
  readonly source: ExtraSource;
  readonly fields: ExtraField[];
  /** True when the area ended on a header/payload that crossed its boundary. */
  readonly truncated: boolean;
  /** Raw trailing bytes that could not be parsed as a complete field. */
  readonly tail: Uint8Array;
  /** Length, in bytes, of the area as originally presented to the parser. */
  readonly length: number;
}

function readUint16LE(data: Uint8Array, offset: number): number {
  return data[offset]! | (data[offset + 1]! << 8);
}

/**
 * Parse one bounded extra-field area (local header or central directory).
 *
 * The cursor is a plain full-precision number and every read is checked
 * against the area boundary (`end - pos >= n`); there is deliberately no
 * 16-bit masking, so a malicious size value can never wrap the cursor into
 * the following field or past the buffer. A field that does not fit only
 * fails this area: preceding fields stay available and the leftover bytes
 * are preserved verbatim in `tail`.
 */
export function parseExtraArea(source: ExtraSource, buffer: Uint8Array): ExtraArea {
  const end = buffer.length;
  let pos = 0;
  const fields: ExtraField[] = [];
  let tail: Uint8Array = EMPTY;
  let truncated = false;

  while (pos < end) {
    // Fewer than 4 bytes left: the field header itself is truncated.
    if (end - pos < FIELD_HEADER_SIZE) {
      truncated = true;
      tail = buffer.slice(pos, end);
      break;
    }

    const id = readUint16LE(buffer, pos);
    const size = readUint16LE(buffer, pos + 2);
    const payloadStart = pos + FIELD_HEADER_SIZE;
    const payloadEnd = payloadStart + size; // no masking: 0xffff + 4 stays exact

    if (size > end - payloadStart) {
      // Declared payload crosses the area boundary: stop here and keep the
      // whole partial field (header + available payload bytes) untouched.
      truncated = true;
      tail = buffer.slice(pos, end);
      break;
    }

    fields.push({
      id,
      size,
      data: buffer.slice(payloadStart, payloadEnd),
      source,
      index: fields.length,
    });
    pos = payloadEnd;
  }

  return { source, fields, truncated, tail, length: end };
}

/** Serialize an area back to bytes. Unknown/unedited fields round-trip exactly. */
export function serializeExtraArea(area: ExtraArea): Uint8Array {
  let total = area.tail.length;
  for (const field of area.fields) {
    if (!Number.isInteger(field.id) || field.id < 0 || field.id > MAX_PAYLOAD_SIZE) {
      throw new RangeError(`extra field id ${field.id} is outside uint16`);
    }
    if (field.data.length > MAX_PAYLOAD_SIZE) {
      throw new RangeError(`extra field ${field.id.toString(16)} payload exceeds uint16 length`);
    }
    total += FIELD_HEADER_SIZE + field.data.length;
  }

  const out = new Uint8Array(total);
  let pos = 0;
  for (const field of area.fields) {
    out[pos] = field.id & 0xff;
    out[pos + 1] = (field.id >>> 8) & 0xff;
    out[pos + 2] = field.data.length & 0xff;
    out[pos + 3] = (field.data.length >>> 8) & 0xff;
    out.set(field.data, pos + FIELD_HEADER_SIZE);
    pos += FIELD_HEADER_SIZE + field.data.length;
  }
  out.set(area.tail, pos);
  return out;
}

/** Return a copy of an area with one field's payload replaced (id/order kept). */
export function setFieldData(area: ExtraArea, index: number, data: Uint8Array): ExtraArea {
  if (index < 0 || index >= area.fields.length) {
    throw new RangeError(`extra field index ${index} does not exist in ${area.source} area`);
  }
  if (data.length > MAX_PAYLOAD_SIZE) {
    throw new RangeError('extra field payload exceeds uint16 length');
  }
  const previous = area.fields[index]!;
  const fields = area.fields.slice();
  fields[index] = { ...previous, size: data.length, data: data.slice() };
  return { ...area, fields };
}

// ---------------------------------------------------------------------------
// Type-aware merge of the local and central areas.
// ---------------------------------------------------------------------------

/**
 * - keep-all:       every instance is retained; no single effective value.
 * - prefer-local:   local-header instance wins when present.
 * - prefer-central: central-directory instance wins when present.
 */
export type MergeStrategy = 'keep-all' | 'prefer-local' | 'prefer-central';

/**
 * Per-id defaults. The central directory is authoritative for metadata, but
 * Zip64 is keep-all because the two locations legitimately carry different
 * members (sizes in the local header, offset in the central directory).
 */
export const DEFAULT_MERGE_STRATEGIES: Readonly<Record<number, MergeStrategy>> = Object.freeze({
  [EXTRA_ID_ZIP64]: 'keep-all',
  [EXTRA_ID_NTFS_TIMESTAMP]: 'prefer-central',
  [EXTRA_ID_EXTENDED_TIMESTAMP]: 'prefer-central',
  [EXTRA_ID_UNIX_UID_GID]: 'prefer-central',
  [EXTRA_ID_UNICODE_PATH]: 'prefer-central',
});

export interface FieldGroup {
  readonly id: number;
  readonly strategy: MergeStrategy;
  /** Every occurrence, in first-seen order; source/index are preserved. */
  readonly instances: ExtraField[];
  /** The instance chosen by the strategy, or null for keep-all. */
  readonly effective: ExtraField | null;
  /** True when instances of the same id disagree on their decoded value. */
  readonly conflict: boolean;
}

export interface MergeOptions {
  strategies?: Readonly<Record<number, MergeStrategy>>;
  defaultStrategy?: MergeStrategy;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/** Value-level comparison so missing optional members (e.g. atime) do not clash. */
function fieldsConflict(id: number, instances: ExtraField[]): boolean {
  if (instances.length < 2) return false;

  if (id === EXTRA_ID_EXTENDED_TIMESTAMP) {
    const decoded = instances.map(decodeExtendedTimestamp);
    if (decoded.every((t): t is ExtendedTimestamp => t !== null)) {
      return decoded.some(t =>
        (t.mtime !== null && decoded.some(o => o !== t && o.mtime !== null && o.mtime !== t.mtime)) ||
        (t.atime !== null && decoded.some(o => o !== t && o.atime !== null && o.atime !== t.atime)) ||
        (t.ctime !== null && decoded.some(o => o !== t && o.ctime !== null && o.ctime !== t.ctime)));
    }
  }

  if (id === EXTRA_ID_UNICODE_PATH) {
    const decoded = instances.map(decodeUnicodePath);
    if (decoded.every((p): p is UnicodePath => p !== null)) {
      return decoded.some(p => decoded.some(o => o !== p && (o.name !== p.name || o.nameCrc32 !== p.nameCrc32)));
    }
  }

  const first = instances[0]!.data;
  return instances.some(f => !bytesEqual(f.data, first));
}

function pickEffective(strategy: MergeStrategy, instances: ExtraField[]): ExtraField | null {
  if (strategy === 'keep-all') return null;
  const wanted: ExtraSource = strategy === 'prefer-local' ? 'local' : 'central';
  return instances.find(f => f.source === wanted) ?? instances[0]!;
}

/**
 * Merge the two areas. Groups appear in first-seen order (local area order,
 * then new ids from the central area); every duplicate instance and its
 * origin are retained. Unknown ids use `keep-all`, so they survive
 * losslessly even if this library is older than the data.
 */
export function mergeExtraAreas(
  local: ExtraArea,
  central: ExtraArea,
  options: MergeOptions = {},
): FieldGroup[] {
  const strategies = options.strategies ?? DEFAULT_MERGE_STRATEGIES;
  const defaultStrategy = options.defaultStrategy ?? 'keep-all';
  const groups = new Map<number, FieldGroup>();
  const order: number[] = [];

  for (const field of [...local.fields, ...central.fields]) {
    let group = groups.get(field.id);
    if (!group) {
      const strategy = strategies[field.id] ?? defaultStrategy;
      group = { id: field.id, strategy, instances: [], effective: null, conflict: false };
      groups.set(field.id, group);
      order.push(field.id);
    }
    group.instances.push(field);
  }

  return order.map(id => {
    const group = groups.get(id)!;
    return {
      ...group,
      effective: pickEffective(group.strategy, group.instances),
      conflict: fieldsConflict(group.id, group.instances),
    };
  });
}

// ---------------------------------------------------------------------------
// Decoders for the field types exercised by the type-aware merge.
// ---------------------------------------------------------------------------

export interface UnicodePath {
  readonly version: number;
  readonly nameCrc32: number;
  readonly name: string;
}

/** Decode a 0x7075 Unicode path field; returns null for a malformed payload. */
export function decodeUnicodePath(field: ExtraField): UnicodePath | null {
  if (field.id !== EXTRA_ID_UNICODE_PATH || field.data.length < 5) return null;
  const version = field.data[0]!;
  const nameCrc32 = readUint32LE(field.data, 1);
  try {
    const name = new TextDecoder('utf-8', { fatal: true }).decode(field.data.subarray(5));
    return { version, nameCrc32, name };
  } catch {
    return null;
  }
}

export interface ExtendedTimestamp {
  readonly flags: number;
  readonly mtime: number | null;
  readonly atime: number | null;
  readonly ctime: number | null;
}

/** Decode a 0x5455 extended-timestamp field; returns null if internally truncated. */
export function decodeExtendedTimestamp(field: ExtraField): ExtendedTimestamp | null {
  if (field.id !== EXTRA_ID_EXTENDED_TIMESTAMP || field.data.length < 1) return null;
  const flags = field.data[0]!;
  let pos = 1;
  const read = (present: boolean): number | null => {
    if (!present) return null;
    if (field.data.length - pos < 4) throw new Error('truncated timestamp');
    const value = readUint32LE(field.data, pos);
    pos += 4;
    return value;
  };
  try {
    const mtime = read((flags & 0x01) !== 0);
    const atime = read((flags & 0x02) !== 0);
    const ctime = read((flags & 0x04) !== 0);
    return { flags, mtime, atime, ctime };
  } catch {
    return null;
  }
}

function readUint32LE(data: Uint8Array, offset: number): number {
  return (
    (data[offset]! |
      (data[offset + 1]! << 8) |
      (data[offset + 2]! << 16) |
      (data[offset + 3]! << 24)) >>>
    0
  );
}
