import { describe, expect, it } from 'vitest';
import {
  decodeExtendedTimestamp,
  decodeUnicodePath,
  DEFAULT_MERGE_STRATEGIES,
  EXTRA_ID_EXTENDED_TIMESTAMP,
  EXTRA_ID_UNICODE_PATH,
  EXTRA_ID_ZIP64,
  mergeExtraAreas,
  parseExtraArea,
  readUint64LE,
  serializeExtraArea,
  setFieldData,
  type ExtraField,
  type ExtraSource,
} from '../src/index.js';

it('reads 64 bits', () =>
  expect(readUint64LE(Uint8Array.from([1, 0, 0, 0, 1, 0, 0, 0]))).toBe(4294967297n));

/** Build an extra-area blob from [id, payload] pairs. */
function encode(fields: Array<[number, Uint8Array]>, tail: Uint8Array = new Uint8Array(0)): Uint8Array {
  const total = fields.reduce((n, [, data]) => n + 4 + data.length, tail.length);
  const out = new Uint8Array(total);
  let pos = 0;
  for (const [id, data] of fields) {
    out[pos] = id & 0xff;
    out[pos + 1] = (id >>> 8) & 0xff;
    out[pos + 2] = data.length & 0xff;
    out[pos + 3] = (data.length >>> 8) & 0xff;
    out.set(data, pos + 4);
    pos += 4 + data.length;
  }
  out.set(tail, pos);
  return out;
}

function field(source: ExtraSource, id: number, data: number[], index = 0): ExtraField {
  return { id, size: data.length, data: Uint8Array.from(data), source, index };
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  expect(Array.from(a)).toEqual(Array.from(b));
  return true;
}

/** A buffer that fails the test if bytes past its end are ever read. */
function guarded(bytes: number[]): Uint8Array {
  const real = Uint8Array.from(bytes);
  return new Proxy(real, {
    get(target, prop, receiver) {
      if (prop === 'length') return target.length;
      if (typeof prop === 'string' && /^\d+$/.test(prop)) {
        const i = Number(prop);
        if (i >= target.length || i < 0) throw new Error(`out-of-bounds read at index ${i}`);
      }
      const value = Reflect.get(target, prop, receiver);
      return typeof value === 'function' ? value.bind(target) : value;
    },
  }) as unknown as Uint8Array;
}

describe('parseExtraArea boundary handling', () => {
  it('accepts a zero-length field', () => {
    const area = parseExtraArea('central', encode([[0x4321, new Uint8Array(0)]]));
    expect(area.truncated).toBe(false);
    expect(area.fields).toHaveLength(1);
    expect(area.fields[0]!.id).toBe(0x4321);
    expect(area.fields[0]!.size).toBe(0);
    expect(area.tail).toHaveLength(0);
  });

  it('accepts a maximum-length (0xffff) payload', () => {
    const payload = new Uint8Array(0xffff);
    for (let i = 0; i < payload.length; i++) payload[i] = i & 0xff;
    const area = parseExtraArea('local', encode([[0x0001, payload]]));
    expect(area.truncated).toBe(false);
    expect(area.fields).toHaveLength(1);
    expect(area.fields[0]!.size).toBe(0xffff);
    expect(area.fields[0]!.data.length).toBe(0xffff);
    expect(area.fields[0]!.data[0xffff - 1]).toBe(payload[0xffff - 1]);
  });

  it('reports a truncated header (1-3 stray bytes) without inventing a field', () => {
    for (const stray of [1, 2, 3]) {
      const area = parseExtraArea('local', new Uint8Array(stray).fill(0xab));
      expect(area.truncated).toBe(true);
      expect(area.fields).toHaveLength(0);
      expect(Array.from(area.tail)).toEqual(new Array(stray).fill(0xab));
    }
  });

  it('reports a truncated payload and keeps prior fields plus the partial tail', () => {
    // Field A is complete; field B declares 10 bytes but only provides 3.
    const a = encode([[0x1234, Uint8Array.from([1, 2])]]);
    const b = [0x56, 0x78, 10, 0x00, 0xaa, 0xbb, 0xcc];
    const area = parseExtraArea('central', new Uint8Array([...a, ...b]));
    expect(area.fields.map(f => f.id)).toEqual([0x1234]);
    expect(area.truncated).toBe(true);
    expect(Array.from(area.tail)).toEqual(b);
  });

  it('does not read past the buffer for a payload ending exactly at the boundary', () => {
    const blob = encode([[0x9999, Uint8Array.from([9, 8, 7])]]);
    const area = parseExtraArea('local', guarded(Array.from(blob)));
    expect(area.truncated).toBe(false);
    expect(area.fields).toHaveLength(1);
  });

  it('contains a malicious overflow size without wrapping the 16-bit cursor', () => {
    // Header claims 0xffff bytes; only four payload bytes follow, and a
    // valid second field sits after them. A `(pos + size) & 0xffff`
    // implementation would wrap and misparse the second field's bytes.
    const secondField = encode([[0x0001, Uint8Array.from([0, 0, 0, 0])]]);
    const malicious = Uint8Array.from([
      0xee, 0xbe, // id
      0xff, 0xff, // size = 65535
      1, 2, 3, 4, // only 4 of 65535 payload bytes available
      ...secondField,
    ]);
    const area = parseExtraArea('local', guarded(Array.from(malicious)));
    expect(area.fields).toHaveLength(0);
    expect(area.truncated).toBe(true);
    // The entire remainder (partial field + the following field's bytes)
    // is treated as the unparseable tail of THIS area; nothing is read as
    // a new field and no byte beyond the buffer is touched.
    expect(area.tail.length).toBe(malicious.length - 0);
    expect(Array.from(area.tail)).toEqual(Array.from(malicious));
  });

  it('isolates a failed area from the independently parsed other area', () => {
    const good = parseExtraArea('local', encode([[0x0001, Uint8Array.from([0x11])]]));
    const bad = parseExtraArea('central', new Uint8Array([0xab]));
    expect(good.truncated).toBe(false);
    expect(good.fields).toHaveLength(1);
    expect(bad.truncated).toBe(true);
    expect(bad.fields).toHaveLength(0);
  });
});

describe('lossless serialization', () => {
  it('round-trips zero-length, maximal-length, unknown and trailing bytes unchanged', () => {
    const maxPayload = new Uint8Array(0xffff).fill(0x5a);
    maxPayload[0] = 0x01;
    maxPayload[0xffff - 1] = 0x02;
    const original = encode(
      [
        [0x4321, new Uint8Array(0)],
        [0x9abc, Uint8Array.from([0xde, 0xad, 0xbe, 0xef])],
        [0x0001, maxPayload],
      ],
      Uint8Array.from([0x77, 0x88]), // truncated tail
    );
    const area = parseExtraArea('central', original);
    bytesEqual(serializeExtraArea(area), original);
  });

  it('never reorders or rewrites unknown fields when a known field is edited', () => {
    const original = encode([
      [0x9abc, Uint8Array.from([1, 2, 3])],
      [EXTRA_ID_EXTENDED_TIMESTAMP, Uint8Array.from([0x01, 0x04, 0x03, 0x02, 0x01])],
      [0xdef0, Uint8Array.from([9, 9])],
    ]);
    const area = parseExtraArea('local', original);
    const updated = setFieldData(
      area,
      1,
      Uint8Array.from([0x01, 0xaa, 0xbb, 0xcc, 0xdd]),
    );
    const out = Array.from(serializeExtraArea(updated));
    // Unknown neighbors keep exact bytes and relative positions.
    expect(out.slice(0, 7)).toEqual(Array.from(encode([[0x9abc, Uint8Array.from([1, 2, 3])]])));
    expect(out.slice(-6)).toEqual(Array.from(encode([[0xdef0, Uint8Array.from([9, 9])]])));
  });
});

describe('mergeExtraAreas', () => {
  it('keeps every duplicate id instance with its source and area index', () => {
    const local = parseExtraArea('local', encode([
      [0x9abc, Uint8Array.from([1])],
      [0x9abc, Uint8Array.from([2])],
    ]));
    const central = parseExtraArea('central', encode([[0x9abc, Uint8Array.from([3])]]));
    const groups = mergeExtraAreas(local, central);
    const group = groups.find(g => g.id === 0x9abc)!;
    expect(group.strategy).toBe('keep-all');
    expect(group.effective).toBeNull();
    expect(group.instances.map(f => [f.source, f.index, f.data[0]])).toEqual([
      ['local', 0, 1],
      ['local', 1, 2],
      ['central', 0, 3],
    ]);
  });

  it('prefers the central Unicode path while retaining the local copy', () => {
    const localName = new TextEncoder().encode('café/répertoire/local.txt');
    const centralName = new TextEncoder().encode('café/répertoire/central.txt');
    const unicodeField = (name: Uint8Array): Uint8Array => {
      const payload = new Uint8Array(5 + name.length);
      payload[0] = 1;
      payload[1] = 0x11;
      payload[2] = 0x22;
      payload[3] = 0x33;
      payload[4] = 0x44;
      payload.set(name, 5);
      return payload;
    };
    const local = parseExtraArea('local', encode([[EXTRA_ID_UNICODE_PATH, unicodeField(localName)]]));
    const central = parseExtraArea('central', encode([[EXTRA_ID_UNICODE_PATH, unicodeField(centralName)]]));

    const group = mergeExtraAreas(local, central).find(g => g.id === EXTRA_ID_UNICODE_PATH)!;
    expect(group.instances).toHaveLength(2);
    expect(group.effective!.source).toBe('central');
    expect(group.conflict).toBe(true);
    expect(decodeUnicodePath(group.effective!)!.name).toBe('café/répertoire/central.txt');
    // The losing local copy is still available byte-for-byte.
    expect(decodeUnicodePath(group.instances[0]!)!.name).toBe('café/répertoire/local.txt');
  });

  it('flags timestamp conflicts and resolves them per prefer-central', () => {
    const local = parseExtraArea('local', encode([
      [EXTRA_ID_EXTENDED_TIMESTAMP, Uint8Array.from([0x01, 0x00, 0x00, 0x00, 0x10])],
    ]));
    const central = parseExtraArea('central', encode([
      [EXTRA_ID_EXTENDED_TIMESTAMP, Uint8Array.from([0x01, 0x00, 0x00, 0x00, 0x20])],
    ]));
    const group = mergeExtraAreas(local, central).find(g => g.id === EXTRA_ID_EXTENDED_TIMESTAMP)!;
    expect(group.strategy).toBe('prefer-central');
    expect(group.conflict).toBe(true);
    expect(group.effective!.source).toBe('central');
    expect(decodeExtendedTimestamp(group.effective!)!.mtime).toBe(0x20000000);
  });

  it('does not flag a timestamp conflict when local only carries extra optional members', () => {
    // Central: flags + mtime; local: flags + mtime + atime, same mtime.
    const local = parseExtraArea('local', encode([
      [EXTRA_ID_EXTENDED_TIMESTAMP, Uint8Array.from([0x03, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x40])],
    ]));
    const central = parseExtraArea('central', encode([
      [EXTRA_ID_EXTENDED_TIMESTAMP, Uint8Array.from([0x01, 0x00, 0x00, 0x00, 0x10])],
    ]));
    const group = mergeExtraAreas(local, central).find(g => g.id === EXTRA_ID_EXTENDED_TIMESTAMP)!;
    expect(group.conflict).toBe(false);
  });

  it('uses keep-all for Zip64 since local and central carry different members', () => {
    const local = parseExtraArea('local', encode([[EXTRA_ID_ZIP64, Uint8Array.from([1, 2, 3, 4])]]));
    const central = parseExtraArea('central', encode([[EXTRA_ID_ZIP64, Uint8Array.from([5, 6, 7, 8, 9, 10, 11, 12])]]));
    const group = mergeExtraAreas(local, central).find(g => g.id === EXTRA_ID_ZIP64)!;
    expect(DEFAULT_MERGE_STRATEGIES[EXTRA_ID_ZIP64]).toBe('keep-all');
    expect(group.effective).toBeNull();
    expect(group.instances).toHaveLength(2);
    expect(group.conflict).toBe(true); // raw payloads differ, but both are retained
  });

  it('preserves group order: local first-seen order then central-only ids', () => {
    const local = parseExtraArea('local', encode([
      [0x1111, Uint8Array.from([1])],
      [0x2222, Uint8Array.from([1])],
    ]));
    const central = parseExtraArea('central', encode([
      [0x2222, Uint8Array.from([2])],
      [0x3333, Uint8Array.from([1])],
    ]));
    expect(mergeExtraAreas(local, central).map(g => g.id)).toEqual([0x1111, 0x2222, 0x3333]);
  });

  it('round-trips a merged view back from the untouched areas', () => {
    const localBytes = encode([[0x9abc, Uint8Array.from([0xaa])]]);
    const centralBytes = encode([[0x9abc, Uint8Array.from([0xbb])]]);
    const local = parseExtraArea('local', localBytes);
    const central = parseExtraArea('central', centralBytes);
    mergeExtraAreas(local, central); // merge must not mutate either area
    bytesEqual(serializeExtraArea(local), localBytes);
    bytesEqual(serializeExtraArea(central), centralBytes);
  });
});
