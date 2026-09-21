import { describe, expect, it } from 'vitest';
import {
  crc32,
  decodeExtendedTimestamp,
  decodeUnicodePath,
  encodeExtendedTimestamp,
  encodeUnicodePath,
  EXTRAFIELD_EXTENDED_TIMESTAMP,
  EXTRAFIELD_INFOZIP_UNICODE_PATH,
  fieldsBySource,
  getEffectiveField,
  getFields,
  mergeExtraAreas,
  parseExtraArea,
  replaceField,
  serializeExtraArea,
  serializeMergedSource,
  strategyForField,
  upsertField,
  type ExtraSource,
  type ParsedExtraArea,
  type RawExtraField,
} from '../src/index.js';

/** Build an extra area from [id, payload] pairs. */
function area(pairs: ReadonlyArray<readonly [number, Uint8Array]>): Uint8Array {
  const out: number[] = [];
  for (const [id, data] of pairs) {
    out.push(id & 0xff, (id >>> 8) & 0xff, data.length & 0xff, (data.length >>> 8) & 0xff);
    for (const b of data) out.push(b);
  }
  return Uint8Array.from(out);
}

function u8(...bytes: number[]): Uint8Array {
  return Uint8Array.from(bytes);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

describe('parseExtraArea boundary handling', () => {
  it('accepts a zero-length payload', () => {
    const raw = area([[0x1234, new Uint8Array(0)]]);
    const parsed = parseExtraArea(raw, 0, raw.length, 'local');
    expect(parsed.error).toBeNull();
    expect(parsed.fields).toHaveLength(1);
    expect(parsed.fields[0]!.id).toBe(0x1234);
    expect(parsed.fields[0]!.data.length).toBe(0);
  });

  it('accepts an entirely empty area', () => {
    const parsed = parseExtraArea(new Uint8Array(0), 0, 0, 'local');
    expect(parsed.error).toBeNull();
    expect(parsed.fields).toEqual([]);
  });

  it('accepts the maximum 65535-byte payload', () => {
    const payload = new Uint8Array(0xffff);
    payload.fill(0xab);
    const raw = area([[0x9999, payload]]);
    expect(raw.length).toBe(4 + 0xffff);
    const parsed = parseExtraArea(raw, 0, raw.length, 'local');
    expect(parsed.error).toBeNull();
    expect(parsed.fields).toHaveLength(1);
    expect(parsed.fields[0]!.data.length).toBe(0xffff);
    expect(parsed.fields[0]!.data[0]).toBe(0xab);
    expect(parsed.fields[0]!.data[0xffff - 1]).toBe(0xab);
  });

  it('flags a truncated 4-byte header (3, 2 and 1 byte remnants)', () => {
    for (const remnant of [u8(0x55), u8(0x55, 0x54), u8(0x55, 0x54, 0x01)]) {
      const parsed = parseExtraArea(remnant, 0, remnant.length, 'central');
      expect(parsed.error).not.toBeNull();
      expect(parsed.error!.reason).toBe('truncated-header');
      expect(parsed.fields).toEqual([]);
      expect(bytesEqual(parsed.error!.tail, remnant)).toBe(true);
      expect(bytesEqual(parsed.trailing, remnant)).toBe(true);
    }
  });

  it('flags a truncated payload and keeps the offending bytes in tail', () => {
    // id=0x5455 declares 8 bytes but only 3 follow.
    const raw = u8(0x55, 0x54, 0x08, 0x00, 0x01, 0x02, 0x03);
    const parsed = parseExtraArea(raw, 0, raw.length, 'local');
    expect(parsed.error).not.toBeNull();
    expect(parsed.error!.reason).toBe('truncated-payload');
    expect(parsed.error!.fieldId).toBe(0x5455);
    expect(bytesEqual(parsed.error!.tail, raw)).toBe(true);
  });

  it('does not consume a later field when an earlier payload is truncated', () => {
    // Two valid fields would look like ...; here field 1 claims 10 bytes,
    // which under the old 16-bit arithmetic could alias field 2's bytes.
    const field2 = area([[0x2222, u8(9, 9, 9)]]);
    const raw = Uint8Array.from([
      ...u8(0x11, 0x11, 12, 0, 1, 2, 3, 4), // claims 12, has 4 + 7 bytes of field2
      ...field2,
    ]);
    const parsed = parseExtraArea(raw, 0, raw.length, 'local');
    expect(parsed.error?.reason).toBe('truncated-payload');
    expect(parsed.fields).toHaveLength(0);
    // Every byte from the bogus field onward is retained; nothing after is parsed.
    expect(bytesEqual(parsed.trailing, raw)).toBe(true);
  });

  it('parses fields at a nonzero offset and ignores surrounding bytes', () => {
    const inner = area([[0x4321, u8(7, 8)]]);
    const wrapped = Uint8Array.from([...u8(0xaa, 0xbb), ...inner, ...u8(0xcc)]);
    const parsed = parseExtraArea(wrapped, 2, inner.length, 'local');
    expect(parsed.error).toBeNull();
    expect(parsed.fields).toHaveLength(1);
    expect(parsed.fields[0]!.id).toBe(0x4321);
  });

  it('fails the area (not the process) when the declared length passes buffer end', () => {
    const raw = area([[0x0001, u8(1)]]);
    const parsed = parseExtraArea(raw, 0, raw.length + 5, 'local');
    expect(parsed.error).not.toBeNull();
    expect(parsed.fields).toHaveLength(1);
  });

  it('never reads outside the buffer regardless of declared length', () => {
    // A SharedArrayBuffer-backed view with a guard page-like neighbor would be
    // ideal; at minimum assert the reachable window is clamped.
    const raw = new Uint8Array([0x78, 0x70, 0xff, 0xff]); // claims 65535 bytes
    const parsed = parseExtraArea(raw, 0, raw.length, 'local');
    expect(parsed.error?.reason).toBe('truncated-payload');
    expect(parsed.fields).toHaveLength(0);
  });
});

describe('malicious overflow values', () => {
  it('treats 0xffff length near end of buffer as truncated, not wrapped', () => {
    // The historical bug: (uint16)(pos + 4 + 0xffff) wraps to pos-1 etc.,
    // causing the parser to read the following file bytes as a new field.
    const bogus = u8(0x78, 0x70, 0xff, 0xff);
    const nextRecordBytes = u8(0x50, 0x4b, 0x01, 0x02, 0xde, 0xad);
    const raw = Uint8Array.from([...bogus, ...nextRecordBytes]);
    const parsed = parseExtraArea(raw, 0, raw.length, 'local');
    expect(parsed.error?.reason).toBe('truncated-payload');
    expect(parsed.fields).toHaveLength(0);
    expect(bytesEqual(parsed.trailing, raw)).toBe(true);
  });

  it('does not alias fields when length+pos would wrap at 16 bits', () => {
    // Construct payload end position that, folded with 0xffff arithmetic,
    // lands inside the area: header at 65530 requires buffer >= 65539, so
    // instead place the field at offset 0xfffc within the declared area.
    const padding = new Uint8Array(0xfffc).fill(0x00);
    const header = u8(0x34, 0x12, 0x10, 0x00); // declares 16 bytes
    const onlyFour = u8(1, 2, 3, 4); // only 4 present, then buffer ends
    const raw = Uint8Array.from([...padding, ...header, ...onlyFour]);
    const parsed = parseExtraArea(raw, 0, raw.length, 'local');
    // All-zero padding parses as fields with id=0, size=0 until the header.
    expect(parsed.error).not.toBeNull();
    expect(parsed.error!.reason).toBe('truncated-payload');
    expect(parsed.error!.fieldId).toBe(0x1234);
  });

  it('rejects non-finite and negative geometry without throwing', () => {
    const raw = area([[1, u8(9)]]);
    expect(() => parseExtraArea(raw, 0, NaN, 'local')).not.toThrow();
    expect(() => parseExtraArea(raw, 0, Infinity, 'local')).not.toThrow();
    expect(() => parseExtraArea(raw, -5, 3, 'local')).not.toThrow();
    expect(parseExtraArea(raw, 0, Infinity, 'local').error).not.toBeNull();
  });

  it('does not wrap when a huge offset plus length would overflow', () => {
    // offset near Number.MAX_SAFE_INTEGER: offset+length must not wrap to a
    // small, in-range position; the reachable window is simply empty/truncated.
    const raw = area([[1, u8(9)]]);
    const huge = Number.MAX_SAFE_INTEGER - 2;
    const parsed = parseExtraArea(raw, huge, 10, 'local');
    expect(parsed.error).not.toBeNull();
    expect(parsed.fields).toEqual([]);
  });

  it('rejects a 0xffff payload starting near offset 0xffff (classic 16-bit wrap)', () => {
    // 0xfffc + 4 + 0xffff = 0x200fff; folded to 16 bits that is 0x0fff, which
    // a buggy parser treats as a small consumed length. The reachable buffer
    // only extends 4 bytes past the header, so the field must fail truncated.
    const buffer = new Uint8Array(0xfffc + 8);
    // Prefix is all zeros: 16383 well-formed (id=0, size=0) fields.
    buffer[0xfffc] = 0x78;
    buffer[0xfffd] = 0x70;
    buffer[0xfffe] = 0xff;
    buffer[0xffff] = 0xff;
    const parsed = parseExtraArea(buffer, 0, buffer.length, 'local');
    expect(parsed.error?.reason).toBe('truncated-payload');
    expect(parsed.fields).toHaveLength(0xfffc / 4);
    expect(parsed.error!.fieldId).toBe(0x7078);
    // Everything from the bogus header onward is retained as tail.
    expect(parsed.trailing.length).toBe(8);
  });
});

describe('duplicate ids and unknown fields', () => {
  it('preserves repeated ids in order with provenance', () => {
    const raw = area([
      [0xbeef, u8(1)],
      [0xbeef, u8(2, 3)],
      [0x0001, u8(4)],
      [0xbeef, u8()],
    ]);
    const parsed = parseExtraArea(raw, 0, raw.length, 'local');
    expect(parsed.fields.map((f) => f.id)).toEqual([0xbeef, 0xbeef, 0x0001, 0xbeef]);
    expect(parsed.fields.map((f) => f.index)).toEqual([0, 1, 2, 3]);
    expect(parsed.fields.every((f) => f.source === 'local')).toBe(true);
  });

  it('round-trips unknown fields byte-for-byte and in order', () => {
    const raw = area([
      [0x00ff, u8(0, 1, 2, 3, 255)],
      [0xffff, new Uint8Array(300).fill(0x7e)],
      [0x0001, new Uint8Array(0)],
    ]);
    const parsed = parseExtraArea(raw, 0, raw.length, 'central');
    const out = serializeExtraArea(parsed);
    expect(bytesEqual(out, raw)).toBe(true);
  });

  it('round-trips malformed tails without alteration', () => {
    const good = area([[0x0001, u8(1, 2)]]);
    const tail = u8(0x99, 0x88, 0x77); // 3-byte remnant: header truncated
    const raw = Uint8Array.from([...good, ...tail]);
    const parsed = parseExtraArea(raw, 0, raw.length, 'local');
    expect(parsed.error?.reason).toBe('truncated-header');
    expect(bytesEqual(serializeExtraArea(parsed), raw)).toBe(true);
  });
});

describe('Unicode path field 0x7078', () => {
  it('encodes and decodes a UTF-8 name with crc32', () => {
    const standard = new TextEncoder().encode('hello.txt');
    const field = encodeUnicodePath('héllo→世界.txt', crc32(standard), 'local');
    expect(field.id).toBe(EXTRAFIELD_INFOZIP_UNICODE_PATH);
    const decoded = decodeUnicodePath(field);
    expect(decoded).not.toBeNull();
    expect(decoded!.name).toBe('héllo→世界.txt');
    expect(decoded!.crc32).toBe(crc32(standard));
  });

  it('matches known crc32 vectors', () => {
    expect(crc32(new TextEncoder().encode(''))).toBe(0x00000000);
    expect(crc32(new TextEncoder().encode('123456789'))).toBe(0xcbf43926);
    expect(crc32(new TextEncoder().encode('hello.txt'))).toBe(crc32(new TextEncoder().encode('hello.txt')));
  });

  it('returns null for too-short or wrong-version payloads and bad utf-8', () => {
    const mk = (data: Uint8Array): RawExtraField => ({ id: 0x7078, data, source: 'local', index: 0 });
    expect(decodeUnicodePath(mk(u8()))).toBeNull();
    expect(decodeUnicodePath(mk(u8(1, 0, 0, 0)))).toBeNull();
    expect(decodeUnicodePath(mk(u8(2, 0, 0, 0, 0, 0x41)))).toBeNull();
    // 0xff 0xfe is never valid UTF-8.
    expect(decodeUnicodePath(mk(u8(1, 0, 0, 0, 0, 0xff, 0xfe)))).toBeNull();
  });

  it('surfaces unicode name conflicts between local and central while keeping both', () => {
    const crc = crc32(new TextEncoder().encode('fallback'));
    const l = parseExtraArea(
      area([[EXTRAFIELD_INFOZIP_UNICODE_PATH, encodeUnicodePath('a.txt', crc, 'local').data]]),
      0,
      undefined,
      'local',
    );
    const c = parseExtraArea(
      area([[EXTRAFIELD_INFOZIP_UNICODE_PATH, encodeUnicodePath('b.txt', crc, 'central').data]]),
      0,
      undefined,
      'central',
    );
    const merged = mergeExtraAreas(l, c);
    expect(merged.conflicts).toHaveLength(1);
    expect(merged.conflicts[0]!.kind).toBe('unicode-name');
    expect(getFields(merged, EXTRAFIELD_INFOZIP_UNICODE_PATH)).toHaveLength(2);
    expect(getEffectiveField(merged, EXTRAFIELD_INFOZIP_UNICODE_PATH)!.source).toBe('central');
  });
});

describe('extended timestamp field 0x5455', () => {
  it('decodes local (three times) and central (mtime only) layouts', () => {
    const local = encodeExtendedTimestamp({ flags: 0, mtime: 100, atime: 200, ctime: 300 }, 'local');
    const d = decodeExtendedTimestamp(local)!;
    expect(d.mtime).toBe(100);
    expect(d.atime).toBe(200);
    expect(d.ctime).toBe(300);
    expect(local.data.length).toBe(13);

    const central = encodeExtendedTimestamp({ flags: 0, mtime: 100, atime: 200, ctime: 300 }, 'central');
    const dc = decodeExtendedTimestamp(central)!;
    expect(dc.mtime).toBe(100);
    expect(dc.atime).toBeUndefined();
    expect(central.data.length).toBe(5);
  });

  it('reports mtime conflicts but not equal mtimes', () => {
    const enc = (mtime: number, source: ExtraSource) =>
      area([[EXTRAFIELD_EXTENDED_TIMESTAMP, encodeExtendedTimestamp({ flags: 1, mtime }, source).data]]);
    const mergedConflict = mergeExtraAreas(
      parseExtraArea(enc(111, 'local'), 0, undefined, 'local'),
      parseExtraArea(enc(222, 'central'), 0, undefined, 'central'),
    );
    expect(mergedConflict.conflicts).toHaveLength(1);
    expect(mergedConflict.conflicts[0]!.kind).toBe('timestamp-mtime');

    const mergedEqual = mergeExtraAreas(
      parseExtraArea(enc(111, 'local'), 0, undefined, 'local'),
      parseExtraArea(enc(111, 'central'), 0, undefined, 'central'),
    );
    expect(mergedEqual.conflicts).toHaveLength(0);
  });

  it('rejects truncated timestamp bodies', () => {
    const mk = (data: Uint8Array) =>
      decodeExtendedTimestamp({ id: 0x5455, data, source: 'local', index: 0 });
    expect(mk(u8())).toBeNull();
    expect(mk(u8(0x01, 0, 0, 0))).toBeNull(); // flags promise mtime, only 3 bytes
    expect(mk(u8(0x07, 0, 0, 0, 0, 0, 0, 0, 0))).toBeNull(); // 9 bytes can't hold 3 times
  });
});

describe('merge policy by field type', () => {
  it('uses prefer-central for singletons and collect for unknown fields', () => {
    expect(strategyForField(EXTRAFIELD_EXTENDED_TIMESTAMP)).toBe('prefer-central');
    expect(strategyForField(EXTRAFIELD_INFOZIP_UNICODE_PATH)).toBe('prefer-central');
    expect(strategyForField(0x0001)).toBe('collect');
    expect(strategyForField(0x9999)).toBe('collect');
  });

  it('keeps every unknown occurrence from both sources with provenance', () => {
    const l = parseExtraArea(area([[0x9999, u8(1)], [0x9999, u8(2)]]), 0, undefined, 'local');
    const c = parseExtraArea(area([[0x9999, u8(3)]]), 0, undefined, 'central');
    const merged = mergeExtraAreas(l, c);
    expect(merged.conflicts).toEqual([]);
    const all = getFields(merged, 0x9999);
    expect(all.map((f) => f.source)).toEqual(['local', 'local', 'central']);
    expect(all.map((f) => [...f.data])).toEqual([[1], [2], [3]]);
  });

  it('records parse errors per source but still merges good fields', () => {
    const l = parseExtraArea(u8(0x01, 0x00), 0, 2, 'local');
    const c = parseExtraArea(area([[0x1234, u8(9)]]), 0, undefined, 'central');
    const merged = mergeExtraAreas(l, c);
    expect(merged.errors).toHaveLength(1);
    expect(merged.errors[0]!.source).toBe('local');
    expect(getFields(merged, 0x1234)).toHaveLength(1);
  });

  it('does not throw when a singleton id appears on only one side', () => {
    const localOnly = parseExtraArea(
      area([[EXTRAFIELD_EXTENDED_TIMESTAMP, encodeExtendedTimestamp({ flags: 1, mtime: 7 }, 'local').data]]),
      0,
      undefined,
      'local',
    );
    const mergedL = mergeExtraAreas(localOnly, null);
    const mergedC = mergeExtraAreas(null, localOnly);
    expect(mergedL.conflicts).toEqual([]);
    expect(mergedC.conflicts).toEqual([]);
    expect(getEffectiveField(mergedL, EXTRAFIELD_EXTENDED_TIMESTAMP)!.source).toBe('local');
  });

  it('keeps duplicate singleton occurrences on both sides instead of collapsing', () => {
    const mk = (mtime: number, source: ExtraSource) =>
      area([
        [EXTRAFIELD_EXTENDED_TIMESTAMP, encodeExtendedTimestamp({ flags: 1, mtime }, source).data],
        [EXTRAFIELD_EXTENDED_TIMESTAMP, encodeExtendedTimestamp({ flags: 1, mtime: mtime + 1 }, source).data],
      ]);
    const merged = mergeExtraAreas(
      parseExtraArea(mk(1, 'local'), 0, undefined, 'local'),
      parseExtraArea(mk(2, 'central'), 0, undefined, 'central'),
    );
    expect(getFields(merged, EXTRAFIELD_EXTENDED_TIMESTAMP)).toHaveLength(4);
    // One conflict for the first-vs-first comparison; raw duplicates survive.
    expect(merged.conflicts).toHaveLength(1);
    expect(merged.conflicts[0]!.kind).toBe('timestamp-mtime');
  });
});

describe('serialization after edits', () => {
  it('does not change bytes or order of unedited unknown fields', () => {
    const rawLocal = area([
      [0xaaaa, u8(1, 2)],
      [0xbbbb, u8(3)],
      [0xcccc, u8(4, 5, 6)],
    ]);
    const rawCentral = area([[0xdddd, u8(7)]]);
    const l = parseExtraArea(rawLocal, 0, undefined, 'local');
    const c = parseExtraArea(rawCentral, 0, undefined, 'central');
    const merged = mergeExtraAreas(l, c);

    // Edit the unicode... not present; instead upsert a known singleton and
    // verify the unknown local fields remain byte-identical and first.
    const ts = encodeExtendedTimestamp({ flags: 1, mtime: 42 }, 'local');
    const edited: typeof merged = {
      ...merged,
      fields: upsertField(merged.fields, EXTRAFIELD_EXTENDED_TIMESTAMP, ts.data, 'local'),
    };
    const outLocal = serializeMergedSource(edited, 'local');
    const expectedLocal = area([
      [0xaaaa, u8(1, 2)],
      [0xbbbb, u8(3)],
      [0xcccc, u8(4, 5, 6)],
      [EXTRAFIELD_EXTENDED_TIMESTAMP, ts.data],
    ]);
    expect(bytesEqual(outLocal, expectedLocal)).toBe(true);
    expect(bytesEqual(serializeMergedSource(edited, 'central'), rawCentral)).toBe(true);
  });

  it('replaceField preserves identity and order of siblings', () => {
    const raw = area([
      [0xaaaa, u8(1)],
      [0xbbbb, u8(2)],
      [0xcccc, u8(3)],
    ]);
    const parsed = parseExtraArea(raw, 0, undefined, 'local');
    const target = parsed.fields[1]!;
    const next = replaceField(parsed.fields, target, u8(9, 9, 9));
    expect(next[0]).toBe(parsed.fields[0]);
    expect(next[2]).toBe(parsed.fields[2]);
    expect(bytesEqual(next[1]!.data, u8(9, 9, 9))).toBe(true);
    expect(bytesEqual(serializeExtraArea({ ...parsed, fields: next }), area([
      [0xaaaa, u8(1)],
      [0xbbbb, u8(9, 9, 9)],
      [0xcccc, u8(3)],
    ]))).toBe(true);
  });

  it('upsertField replaces a singleton and appends collected duplicates', () => {
    let fields: RawExtraField[] = [];
    fields = upsertField(fields, EXTRAFIELD_EXTENDED_TIMESTAMP, u8(1), 'local');
    fields = upsertField(fields, 0x9999, u8(2), 'local');
    fields = upsertField(fields, EXTRAFIELD_EXTENDED_TIMESTAMP, u8(3), 'central');
    fields = upsertField(fields, EXTRAFIELD_EXTENDED_TIMESTAMP, u8(4), 'local'); // replaces
    fields = upsertField(fields, 0x9999, u8(5), 'local'); // appends
    expect(fields.map((f) => [f.id, f.source, [...f.data]])).toEqual([
      [EXTRAFIELD_EXTENDED_TIMESTAMP, 'local', [4]],
      [0x9999, 'local', [2]],
      [0x9999, 'local', [5]],
      [EXTRAFIELD_EXTENDED_TIMESTAMP, 'central', [3]],
    ]);
  });

  it('rejects output above 65535 bytes in strict mode only', () => {
    const huge = new Uint8Array(0xffff);
    const parsed: ParsedExtraArea = {
      fields: [
        { id: 1, data: huge, source: 'local', index: 0 },
        { id: 2, data: u8(1), source: 'local', index: 1 },
      ],
      error: null,
      trailing: new Uint8Array(0),
      source: 'local',
    };
    expect(() => serializeExtraArea(parsed)).toThrow(RangeError);
    expect(() => serializeExtraArea(parsed, { checkSize: false })).not.toThrow();
  });
});

describe('randomized round trips', () => {
  it('fuzz: untouched parsed areas reserialize to identical bytes', () => {
    let seed = 0x12345678;
    const rnd = () => {
      seed = (seed * 1103515245 + 12345) >>> 0;
      return seed / 0x100000000;
    };
    for (let iter = 0; iter < 200; iter++) {
      const pairs: Array<[number, Uint8Array]> = [];
      for (let n = 0; n < 1 + Math.floor(rnd() * 6); n++) {
        const id = Math.floor(rnd() * 0x10000);
        const size = Math.floor(rnd() * 40);
        pairs.push([id, Uint8Array.from({ length: size }, () => Math.floor(rnd() * 256))]);
      }
      const raw = area(pairs);
      const parsed = parseExtraArea(raw, 0, raw.length, iter % 2 ? 'local' : 'central');
      expect(parsed.error).toBeNull();
      expect(bytesEqual(serializeExtraArea(parsed, { checkSize: false }), raw)).toBe(true);
      // Split by source and reassemble through merge -> identical as well.
      const merged = mergeExtraAreas(parsed, null);
      expect(bytesEqual(serializeMergedSource(merged, parsed.source, { checkSize: false }), raw)).toBe(true);
      expect(fieldsBySource(merged.fields, parsed.source)).toHaveLength(pairs.length);
    }
  });
});
