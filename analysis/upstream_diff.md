# Annotated Upstream Fix: google/brotli@0ed4268a

**Commit:** [0ed4268a](https://github.com/google/brotli/commit/0ed4268a) "Detect and report invalid stream earlier"
**Files changed:** 2 (`c/dec/decode.c`, `c/include/brotli/decode.h`)
**Stats:** +59 -32

## Change 1: New Error Code

```diff
--- a/c/include/brotli/decode.h
+++ b/c/include/brotli/decode.h
   BROTLI_ERROR_CODE(_ERROR_FORMAT_, DISTANCE, -16) SEPARATOR \
-  \
-  /* -17 code is reserved */ \
-  \
+  BROTLI_ERROR_CODE(_ERROR_FORMAT_, BLOCK_SWITCH, -17) SEPARATOR \
   BROTLI_ERROR_CODE(_ERROR_, COMPOUND_DICTIONARY, -18) SEPARATOR \
```

The previously reserved `-17` slot now holds `BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH`. This is the detection constant used for patch verification:

```js
require('zlib').constants.BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH // -17 or undefined
```

## Change 2: Return Type Upgrade

```diff
-static BROTLI_INLINE BROTLI_BOOL DecodeBlockTypeAndLength(
+static BROTLI_INLINE BrotliDecoderErrorCode DecodeBlockTypeAndLength(
```

The function now returns a rich error code instead of a boolean. The three conditions map to:

| Condition | Old Return | New Return |
|-----------|-----------|------------|
| `max_block_type ≤ 1` | `BROTLI_FALSE` | `BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH` |
| `SafeReadSymbol` fails | `BROTLI_FALSE` | `BROTLI_DECODER_NEEDS_MORE_INPUT` |
| `SafeReadBlockLength` fails | `BROTLI_FALSE` | `BROTLI_DECODER_NEEDS_MORE_INPUT` |
| Success | `BROTLI_TRUE` | `BROTLI_DECODER_SUCCESS` |

**Root cause of the bug:** The old `BROTLI_FALSE` was ambiguous — format error and "need more input" returned the same value. The safe path treated both as recoverable, and the unsafe path ignored both.

## Change 3: New Macro `BROTLI_SAFE_WITH_STATUS`

```diff
+  #define BROTLI_SAFE_WITH_STATUS(METHOD) \
+  { \
+    BrotliDecoderErrorCode status; \
+    if (safe) { \
+      status = Safe##METHOD; \
+    } else { \
+      status = METHOD; \
+    } \
+    if (status != BROTLI_DECODER_SUCCESS) { \
+      result = status; \
+      goto saveStateAndReturn; \
+    } \
+  }
```

Unlike `BROTLI_SAFE`, this macro checks the return on **both** the safe and unsafe paths. A non-success status (including `BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH`) immediately breaks processing.

## Change 4: Call Site Migration

All three block-switch sites are migrated from `BROTLI_SAFE` to `BROTLI_SAFE_WITH_STATUS`:

```diff
-    BROTLI_SAFE(DecodeCommandBlockSwitch(s));
+    BROTLI_SAFE_WITH_STATUS(DecodeCommandBlockSwitch(s));

-    BROTLI_SAFE(DecodeDistanceBlockSwitch(s));
+    BROTLI_SAFE_WITH_STATUS(DecodeDistanceBlockSwitch(s));

-  BROTLI_SAFE(DecodeLiteralBlockSwitch(s));
+  BROTLI_SAFE_WITH_STATUS(DecodeLiteralBlockSwitch(s));
```

The wrapper functions change from `void` to `BrotliDecoderErrorCode`:

```diff
-static void BROTLI_NOINLINE DecodeLiteralBlockSwitch(BrotliDecoderState* s) {
-  DecodeLiteralBlockSwitchInternal(0, s);
+static BROTLI_NOINLINE BrotliDecoderErrorCode
+DecodeLiteralBlockSwitch(BrotliDecoderState* s) {
+  return DecodeLiteralBlockSwitchInternal(0, s);
 }
```

## Change 5: Additional Assertion

```diff
+  BROTLI_DCHECK(s->meta_block_remaining_len <=
+      (int)BROTLI_BLOCK_SIZE_CAP);
```

This asserts `meta_block_remaining_len ≤ BLOCK_SIZE_CAP`, which is a secondary confirmation that MLEN never exceeds the block size cap. In debug builds, this would catch any violation of the structural constraint we identified.

## Assessment

The fix is correct and comprehensive. It addresses:
1. The ambiguous return type (bool → error code)
2. The dropped return value (void wrapper → typed wrapper)
3. The unchecked macro (BROTLI_SAFE → BROTLI_SAFE_WITH_STATUS)
4. A defensive assertion on the MLEN/BLOCK_SIZE_CAP invariant

The fix is defense-in-depth: even without it, the vulnerability is structurally unreachable. But the code was wrong, and the fix makes it correct.
