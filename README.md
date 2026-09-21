# ZIP archive core

TypeScript library for archive records and entries, with bounds-checked
parsing and type-aware merging of ZIP extra fields (APPNOTE 4.5).

Run `npm install`, then `npm test` and `npm run build`.

## Extra fields

```ts
import {
  parseExtraArea,        // local-header or central-directory bytes -> ExtraArea
  serializeExtraArea,    // ExtraArea -> bytes (unknown fields round-trip exactly)
  mergeExtraAreas,       // (local, central) -> FieldGroup[]
  setFieldData,          // immutable payload edit by area index
  decodeUnicodePath,     // 0x7075
  decodeExtendedTimestamp, // 0x5455
} from './dist/index.js';
```

- **Bounded cursor.** The parser uses full-precision arithmetic (no 16-bit
  mask) and checks every header/payload read against the area's end. A
  declared size that overflows cannot wrap the cursor into the next field;
  the area ends as `truncated`, previously parsed fields stay valid, and the
  remaining partial bytes are preserved verbatim in `tail`. No byte beyond
  the given buffer is ever read, and local/central areas fail independently.
- **Type-aware merge.** `mergeExtraAreas` keeps every duplicate instance with
  its `source` (`local`/`central`) and area index, groups ids in first-seen
  order, and applies a per-id strategy (`keep-all`, `prefer-local`,
  `prefer-central`). Zip64 is `keep-all` because both locations carry
  legitimate, different members; timestamps and Unicode paths default to
  `prefer-central` with value-level `conflict` detection. Unknown ids are
  `keep-all`.
- **Lossless round-trip.** Payloads and unparseable tails are owned copies
  of the original bytes. Editing one field never reorders or rewrites any
  other field, and serialized output of an unedited area is byte-identical
  to its input.
