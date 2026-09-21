// ZIP extra field parsing, merging and serialization.
//
// Every read is performed through a byte cursor whose reachable window is
// clamped to the bounds of the source buffer. A malformed field therefore
// fails only the current extra area: no byte past the end of the buffer (or
// past the declared end of the area) is ever read, and the bytes that could
// not be parsed are retained opaquely so an untouched area round-trips
// byte-for-byte.

export const EXTRAFIELD_EXTENDED_TIMESTAMP = 0x5455;
export const EXTRAFIELD_INFOZIP_UNICODE_PATH = 0x7078;

export type ExtraSource = 'local' | 'central';

export interface RawExtraField {
  id: number;
  /** Raw payload exactly as it appeared on the wire (a view into the source). */
  data: Uint8Array;
  source: ExtraSource;
  /** Zero-based position of the field within its extra area. */
  index: number;
}

export interface ExtraParseError {
  /** Offset, relative to the start of the area, where parsing stopped. */
  offset: number;
  reason: 'truncated-header' | 'truncated-payload';
  fieldId: number | null;
  /** Bytes from `offset` to the end of the area, kept verbatim. */
  tail: Uint8Array;
}

export interface ParsedExtraArea {
  fields: RawExtraField[];
  /** Present once a field cannot be fully read; all following bytes are in tail. */
  error: ExtraParseError | null;
  /** Bytes after the last successfully parsed field, including malformed tail. */
  trailing: Uint8Array;
  source: ExtraSource;
}

/** 4-byte TLV header: uint16 id, uint16 size. */
export const EXTRA_HEADER_SIZE = 4;
/** An extra area itself is described by a uint16, hence 65535 is the hard cap. */
export const MAX_EXTRA_AREA_SIZE = 0xffff;

/**
 * Read a uint16 LE value through the bounded window. Returns null if fewer
 * than two bytes remain. Note: arithmetic is performed on 32-bit unsigned
 * values in this file; positions are *never* folded with 16-bit operations,
 * so a declared length cannot wrap around and alias a later field.
 */
function readU16(window: Uint8Array, pos: number): number | null {
  if (pos + 2 > window.length) return null;
  return window[pos]! | (window[pos + 1]! << 8);
}

/**
 * Parse one extra area.
 *
 * `length` is the declared size of the area; the reachable window is the
 * intersection of [offset, offset+length) with the buffer itself. Any
 * mismatch means a truncated field and is reported rather than read through.
 */
export function parseExtraArea(
  buffer: Uint8Array,
  offset = 0,
  length: number = buffer.length - offset,
  source: ExtraSource = 'local',
): ParsedExtraArea {
  const fields: RawExtraField[] = [];

  let start = Math.trunc(offset);
  let len = Math.trunc(length);
  if (Number.isNaN(start)) start = 0;
  if (!Number.isFinite(start) || start < 0) {
    const trailing = buffer.subarray(0, 0);
    return {
      fields,
      source,
      trailing,
      error: {
        offset: 0,
        reason: 'truncated-header',
        fieldId: null,
        tail: trailing,
      },
    };
  }
  // Remember geometry problems before the values are clamped for iteration.
  const areaExceedsBuffer =
    !Number.isFinite(len) || start + Math.max(len, 0) > buffer.length;
  if (!Number.isFinite(len) || len < 0) len = 0;

  // Clamp the declared window to the actual buffer. Negative offset case
  // above already returned; here end cannot exceed buffer.length.
  const declaredEnd = start + len;
  const end = Math.min(buffer.length, declaredEnd);
  const safeStart = Math.min(Math.max(start, 0), buffer.length);
  const window = buffer.subarray(safeStart, end);

  let pos = 0;
  let fieldIndex = 0;

  while (pos < window.length) {
    const id = readU16(window, pos);
    if (id === null) {
      const tail = window.subarray(pos);
      return {
        fields,
        source,
        trailing: tail,
        error: { offset: pos, reason: 'truncated-header', fieldId: null, tail },
      };
    }

    const declaredSize = readU16(window, pos + 2);
    if (declaredSize === null) {
      const tail = window.subarray(pos);
      return {
        fields,
        source,
        trailing: tail,
        error: { offset: pos, reason: 'truncated-header', fieldId: id, tail },
      };
    }

    // Plain 32-bit addition: a declared size up to 65535 cannot make us skip
    // outside the window because we compare against the bounded length.
    const payloadStart = pos + EXTRA_HEADER_SIZE;
    const payloadEnd = payloadStart + declaredSize;
    if (payloadEnd > window.length) {
      const tail = window.subarray(pos);
      return {
        fields,
        source,
        trailing: tail,
        error: {
          offset: pos,
          reason: 'truncated-payload',
          fieldId: id,
          tail,
        },
      };
    }

    fields.push({
      id,
      data: window.subarray(payloadStart, payloadEnd),
      source,
      index: fieldIndex++,
    });
    pos = payloadEnd;
  }

  // The declared area runs past the end of the buffer: the area itself is
  // truncated even though every byte that existed formed complete fields.
  if (areaExceedsBuffer) {
    const tail = window.subarray(window.length);
    return {
      fields,
      source,
      trailing: tail,
      error: { offset: window.length, reason: 'truncated-header', fieldId: null, tail },
    };
  }

  return { fields, error: null, trailing: window.subarray(0, 0), source };
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

function writeU16(out: number[], value: number): void {
  out.push(value & 0xff, (value >>> 8) & 0xff);
}

export interface SerializeOptions {
  /**
   * When true (default), verify the serialized area fits the 16-bit length
   * prefix that precedes every extra area. Set false to serialize exactly as
   * given (used by round-trip checks).
   */
  checkSize?: boolean;
}

/** Serialize one area back into bytes; untouched fields keep identical bytes. */
export function serializeExtraArea(area: ParsedExtraArea, options: SerializeOptions = {}): Uint8Array {
  const checkSize = options.checkSize ?? true;
  const out: number[] = [];

  for (const field of area.fields) {
    if (field.data.length > MAX_EXTRA_AREA_SIZE) {
      throw new RangeError(`extra field ${field.id.toString(16)} payload exceeds 65535 bytes`);
    }
    writeU16(out, field.id);
    writeU16(out, field.data.length);
    for (let i = 0; i < field.data.length; i++) out.push(field.data[i]!);
  }

  for (let i = 0; i < area.trailing.length; i++) out.push(area.trailing[i]!);

  if (checkSize && out.length > MAX_EXTRA_AREA_SIZE) {
    throw new RangeError(`extra area of ${out.length} bytes exceeds the 65535-byte limit`);
  }
  return Uint8Array.from(out);
}

// ---------------------------------------------------------------------------
// Known field codecs
// ---------------------------------------------------------------------------

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder('utf-8', { fatal: true });

// --- Info-ZIP Unicode Path (0x7078) ---------------------------------------

export interface UnicodePathValue {
  crc32: number;
  name: string;
}

export function decodeUnicodePath(field: RawExtraField): UnicodePathValue | null {
  const d = field.data;
  if (d.length < 5) return null;
  if (d[0] !== 1) return null;
  const crc32 = d[1]! | (d[2]! << 8) | (d[3]! << 16) | (d[4]! << 24);
  let name: string;
  try {
    name = textDecoder.decode(d.subarray(5));
  } catch {
    return null;
  }
  return { crc32, name };
}

export function encodeUnicodeField(
  id: number,
  crc32: number,
  text: string,
  source: ExtraSource,
  index = 0,
): RawExtraField {
  const nameBytes = textEncoder.encode(text);
  const payload = new Uint8Array(5 + nameBytes.length);
  payload[0] = 1;
  payload[1] = crc32 & 0xff;
  payload[2] = (crc32 >>> 8) & 0xff;
  payload[3] = (crc32 >>> 16) & 0xff;
  payload[4] = (crc32 >>> 24) & 0xff;
  payload.set(nameBytes, 5);
  return { id, data: payload, source, index };
}

export function encodeUnicodePath(
  name: string,
  crc32OfStandardName: number,
  source: ExtraSource = 'local',
  index = 0,
): RawExtraField {
  return encodeUnicodeField(EXTRAFIELD_INFOZIP_UNICODE_PATH, crc32OfStandardName, name, source, index);
}

// --- Extended timestamp (0x5455) ------------------------------------------

export interface ExtendedTimestampValue {
  /** Bit0 = mtime present, bit1 = atime, bit2 = ctime. */
  flags: number;
  mtime?: number;
  atime?: number;
  ctime?: number;
}

export function decodeExtendedTimestamp(field: RawExtraField): ExtendedTimestampValue | null {
  const d = field.data;
  if (d.length < 1) return null;
  const flags = d[0]!;
  const value: ExtendedTimestampValue = { flags };
  let pos = 1;
  const readTime = (): number | null => {
    if (pos + 4 > d.length) return null;
    const t =
      (d[pos]! |
        (d[pos + 1]! << 8) |
        (d[pos + 2]! << 16) |
        (d[pos + 3]! << 24)) >>>
      0;
    pos += 4;
    return t;
  };
  if (flags & 0x01) {
    const t = readTime();
    if (t === null) return null;
    value.mtime = t;
  }
  if (flags & 0x02) {
    const t = readTime();
    if (t === null) return null;
    value.atime = t;
  }
  if (flags & 0x04) {
    const t = readTime();
    if (t === null) return null;
    value.ctime = t;
  }
  // Unknown flag bits or trailing bytes are tolerated: the field still decodes
  // with everything the spec defines, and raw bytes remain available.
  return value;
}

export function encodeExtendedTimestamp(
  value: ExtendedTimestampValue,
  source: ExtraSource = 'local',
  index = 0,
): RawExtraField {
  // Central-directory records carry mtime only per APPNOTE 4.6.3, and the
  // flags byte likewise only advertises mtime there.
  const includeAtime = source === 'local' && value.atime !== undefined;
  const includeCtime = source === 'local' && value.ctime !== undefined;
  const flags =
    (value.mtime === undefined ? 0 : 0x01) |
    (includeAtime ? 0x02 : 0) |
    (includeCtime ? 0x04 : 0);
  const out: number[] = [flags];
  const push = (t: number) => {
    out.push(t & 0xff, (t >>> 8) & 0xff, (t >>> 16) & 0xff, (t >>> 24) & 0xff);
  };
  if (value.mtime !== undefined) push(value.mtime >>> 0);
  if (includeAtime) push(value.atime! >>> 0);
  if (includeCtime) push(value.ctime! >>> 0);
  return {
    id: EXTRAFIELD_EXTENDED_TIMESTAMP,
    data: Uint8Array.from(out),
    source,
    index,
  };
}

// ---------------------------------------------------------------------------
// CRC-32 (the checksum referenced by the Unicode path extra field)
// ---------------------------------------------------------------------------

const CRC_TABLE: Uint32Array = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

export function crc32(data: Uint8Array): number {
  let crc = 0xffffffff;
  for (let i = 0; i < data.length; i++) {
    crc = CRC_TABLE[(crc ^ data[i]!) & 0xff]! ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

// ---------------------------------------------------------------------------
// Merging local and central areas
// ---------------------------------------------------------------------------

/**
 * Strategy for a field id:
 * - "prefer-central": structurally a singleton; central wins, local is kept as
 *   provenance, disagreement is surfaced as a conflict.
 * - "collect": the field legitimately repeats (or is unknown); every instance
 *   from both sources is preserved, in order.
 */
export type MergeStrategy = 'prefer-central' | 'collect';

const SINGLETON_IDS = new Set<number>([EXTRAFIELD_EXTENDED_TIMESTAMP, EXTRAFIELD_INFOZIP_UNICODE_PATH]);

export function strategyForField(id: number): MergeStrategy {
  return SINGLETON_IDS.has(id) ? 'prefer-central' : 'collect';
}

export interface MergeConflict {
  id: number;
  kind: 'timestamp-mtime' | 'unicode-name' | 'singleton-payload';
  local: RawExtraField;
  central: RawExtraField;
  /** Values extracted from both sides when a codec understood the field. */
  localValue?: unknown;
  centralValue?: unknown;
}

export interface MergedExtra {
  /** Every field, in area order, local first then central; nothing is dropped. */
  fields: RawExtraField[];
  /** Errors detected while parsing either source area. */
  errors: { source: ExtraSource; error: ExtraParseError }[];
  /** Disagreements between same-id singleton fields. */
  conflicts: MergeConflict[];
  /** Unparsed tail bytes per source, retained verbatim for lossless output. */
  trailing: { local: Uint8Array | null; central: Uint8Array | null };
}

function samePayload(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/**
 * Merge the local-header and central-directory views of one entry's extra
 * data. Fields are never unconditionally overwritten: duplicates are kept
 * with their source, and same-id singleton fields are compared according to
 * the field's type policy.
 */
export function mergeExtraAreas(local: ParsedExtraArea | null, central: ParsedExtraArea | null): MergedExtra {
  const fields: RawExtraField[] = [];
  if (local) fields.push(...local.fields);
  if (central) fields.push(...central.fields);

  const errors: MergedExtra['errors'] = [];
  if (local?.error) errors.push({ source: 'local', error: local.error });
  if (central?.error) errors.push({ source: 'central', error: central.error });

  const conflicts: MergeConflict[] = [];
  if (local && central) {
    const localById = new Map<number, RawExtraField[]>();
    const centralById = new Map<number, RawExtraField[]>();
    for (const f of local.fields) {
      const list = localById.get(f.id) ?? [];
      list.push(f);
      localById.set(f.id, list);
    }
    for (const f of central.fields) {
      const list = centralById.get(f.id) ?? [];
      list.push(f);
      centralById.set(f.id, list);
    }

    for (const id of new Set([...localById.keys(), ...centralById.keys()])) {
      if (strategyForField(id) !== 'prefer-central') continue;
      const l = localById.get(id)?.[0];
      const c = centralById.get(id)?.[0];
      if (!l || !c || samePayload(l.data, c.data)) continue;

      if (id === EXTRAFIELD_EXTENDED_TIMESTAMP) {
        const lv = decodeExtendedTimestamp(l);
        const cv = decodeExtendedTimestamp(c);
        if (lv && cv && lv.mtime !== undefined && cv.mtime !== undefined && lv.mtime !== cv.mtime) {
          conflicts.push({
            id,
            kind: 'timestamp-mtime',
            local: l,
            central: c,
            localValue: lv,
            centralValue: cv,
          });
        } else {
          conflicts.push({
            id,
            kind: 'singleton-payload',
            local: l,
            central: c,
            localValue: lv ?? undefined,
            centralValue: cv ?? undefined,
          });
        }
      } else if (id === EXTRAFIELD_INFOZIP_UNICODE_PATH) {
        const lv = decodeUnicodePath(l);
        const cv = decodeUnicodePath(c);
        if (lv && cv && lv.name !== cv.name) {
          conflicts.push({
            id,
            kind: 'unicode-name',
            local: l,
            central: c,
            localValue: lv,
            centralValue: cv,
          });
        } else {
          conflicts.push({
            id,
            kind: 'singleton-payload',
            local: l,
            central: c,
            localValue: lv ?? undefined,
            centralValue: cv ?? undefined,
          });
        }
      } else {
        conflicts.push({ id, kind: 'singleton-payload', local: l, central: c });
      }
    }
  }

  return {
    fields,
    errors,
    conflicts,
    trailing: {
      local: local && local.trailing.length ? local.trailing : null,
      central: central && central.trailing.length ? central.trailing : null,
    },
  };
}

/** All occurrences of an id, local first then central, each in area order. */
export function getFields(merged: MergedExtra, id: number): RawExtraField[] {
  return merged.fields.filter((f) => f.id === id);
}

/**
 * Effective singleton field for an id: central wins (it is written last and
 * reflects any streaming-rewrite), local is the fallback. For collect
 * strategies this is simply the first occurrence (local order wins).
 */
export function getEffectiveField(merged: MergedExtra, id: number): RawExtraField | null {
  const all = getFields(merged, id);
  if (all.length === 0) return null;
  if (strategyForField(id) === 'prefer-central') {
    return all.find((f) => f.source === 'central') ?? all[0]!;
  }
  return all[0]!;
}

// ---------------------------------------------------------------------------
// Editing
// ---------------------------------------------------------------------------

/** Split a merged list back into per-source areas; relative order is kept. */
export function fieldsBySource(fields: RawExtraField[], source: ExtraSource): RawExtraField[] {
  return reindex(fields.filter((f) => f.source === source));
}

/**
 * Serialize one source's slice of a merged list. The source's unparsed tail
 * (if any) is appended unchanged, so an unedited area is byte-identical.
 */
export function serializeMergedSource(
  merged: MergedExtra,
  source: ExtraSource,
  options: SerializeOptions = {},
): Uint8Array {
  return serializeExtraArea(
    {
      fields: fieldsBySource(merged.fields, source),
      error: null,
      trailing: merged.trailing[source] ?? new Uint8Array(0),
      source,
    },
    options,
  );
}

function reindex(fields: RawExtraField[]): RawExtraField[] {
  return fields.map((f, i) => (f.index === i ? f : { ...f, index: i }));
}

/**
 * Return a new field list with `field` (matched by source + index) replaced.
 * Every other field keeps the exact same object, bytes and relative order, so
 * untouched unknown fields serialize identically.
 */
export function replaceField(
  fields: RawExtraField[],
  field: RawExtraField,
  nextData: Uint8Array,
): RawExtraField[] {
  const at = fields.findIndex((f) => f.source === field.source && f.index === field.index);
  if (at === -1) throw new RangeError('field to replace is not present in the list');
  const copy = fields.slice();
  copy[at] = { ...field, data: nextData };
  return reindex(copy);
}

/** Replace a singleton field for one source, or append it in source order. */
export function upsertField(
  fields: RawExtraField[],
  id: number,
  data: Uint8Array,
  source: ExtraSource,
): RawExtraField[] {
  const strategy = strategyForField(id);
  const at = strategy === 'prefer-central'
    ? fields.findIndex((f) => f.id === id && f.source === source)
    : -1;
  const copy = fields.slice();
  if (at !== -1 && strategy === 'prefer-central') {
    copy[at] = { ...copy[at]!, data };
  } else {
    const field: RawExtraField = { id, data, source, index: 0 };
    // Append after the last field of the same source to preserve local-before
    // central ordering.
    let insertAt = copy.length;
    if (source === 'local') {
      let lastLocal = -1;
      for (let i = 0; i < copy.length; i++) if (copy[i]!.source === 'local') lastLocal = i;
      insertAt = lastLocal + 1;
    }
    copy.splice(insertAt, 0, field);
  }
  return reindex(copy);
}
