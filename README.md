# ZIP archive core

TypeScript library for archive records and entries.

Run `npm install`, then `npm test` and `npm run build`.

## Extra fields

`src/extra.ts` parses ZIP extra-field areas (local header and central
directory) with a bounds-clamped byte cursor:

- `parseExtraArea(buffer, offset?, length?, source?)` — parses id/len/payload
  TLVs. Positions are never folded with 16-bit arithmetic, so a declared
  length cannot wrap and alias a later field. Any out-of-bounds field fails
  only that area (`error: truncated-header | truncated-payload`); no byte
  past the buffer is read, and the unparsed tail is retained verbatim.
- `mergeExtraAreas(local, central)` — merges by field-type policy:
  - `0x5455` extended timestamp and `0x7078` Info-ZIP Unicode path are
    singletons: central is preferred, local is kept as provenance, and
    disagreement is reported in `conflicts` (typed `timestamp-mtime` /
    `unicode-name` / `singleton-payload`).
  - All other (and unknown) fields use `collect`: duplicates from both
    sources are preserved in order with `source` tags.
- `serializeExtraArea` / `serializeMergedSource` — re-emit bytes. Untouched
  unknown fields and malformed tails round-trip byte-for-byte in original
  order; output is checked against the 65535-byte area limit unless
  `{ checkSize: false }`.
- Codecs: `encode/decodeUnicodePath` (with `crc32`),
  `encode/decodeExtendedTimestamp`.
- Editing: `replaceField` (same-position swap, sibling identity preserved)
  and `upsertField` (singleton replace or ordered append).
