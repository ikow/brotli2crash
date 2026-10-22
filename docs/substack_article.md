# brotli2crash: The Node.js "Critical RCE" That Can't Actually Fire

*From source code audit to structural unreachability proof*

---

On October 21, 2026, Node.js shipped emergency security releases across all three supported lines — 22.x, 24.x, and 26.x — patching ten CVEs. The headliner, CVE-2026-111497, is an out-of-bounds write in the bundled Brotli decoder that the advisory says "permits remote code execution." Vercel rushed out WAF rules within hours. Multiple outlets called it Critical (CVSS 9.2). GitHub filled with PoC repos overnight.

I spent the past 24 hours doing what nobody else seems to have done: reading the actual decoder source line by line, tracing every code path, and asking a simple question — **can this bug actually fire?**

The answer is no. Here's what I found.

**TL;DR:** The `BROTLI_SAFE` macro in `decode.c` silently drops the return value of `DecodeBlockTypeAndLength()` on the fast decoding path. When `num_block_types ≤ 1`, the function returns false, the return is discarded, and the decoder should continue with corrupted state. That's the bug. **But the Brotli specification caps metablock size (`MLEN`) at exactly `2^24 = 16,777,216` — the same value as `BROTLI_BLOCK_SIZE_CAP`, the initial block counter when `NBLTYPES = 1`.** The block counter and the loop counter reach zero at the exact same instant, so the loop exits cleanly before the block-switch check can fire. The vulnerable code path is structurally unreachable from any Brotli stream, valid or malformed. Every public PoC confirms this: 0 crashes across thousands of fuzz iterations.

**Repo:** [github.com/ikow/brotli2crash](https://github.com/ikow/brotli2crash) — full analysis, PoC tools, Docker lab, and detection scripts.

---

## What the Bug Is

The Brotli decoder processes three categories of "blocks" — literal, insert-and-copy, and distance. Each category has a block counter (`block_length[i]`) that counts down as symbols are decoded. When it reaches zero, a block switch happens: the decoder reads a new block type and length from the stream.

The block switch is called through the `BROTLI_SAFE` macro:

```c
// decode.c:1890 — THE BUG
#define BROTLI_SAFE(METHOD)
  {
    if (safe) {
      if (!Safe##METHOD) {                          // safe path: checks return ✓
        result = BROTLI_DECODER_NEEDS_MORE_INPUT;
        goto saveStateAndReturn;
      }
    } else {
      METHOD;                                       // fast path: drops return ✗
    }
  }
```

On the fast path (`safe = 0`, used by `ProcessCommands` for bulk decoding), the block-switch function's return value is silently discarded. The wrapper functions are `void`:

```c
static void BROTLI_NOINLINE DecodeLiteralBlockSwitch(BrotliDecoderState* s) {
  DecodeLiteralBlockSwitchInternal(0, s);  // BROTLI_BOOL return → void
}
```

Inside `DecodeBlockTypeAndLength`, when `num_block_types ≤ 1`, it returns `BROTLI_FALSE` immediately — no bits consumed, no state updated, no block length refreshed:

```c
if (max_block_type <= 1) {
  return BROTLI_FALSE;    // format error, but looks like "needs more input"
}
```

On the fast path, this return is thrown away. The decoder continues as if the switch succeeded. `block_length` stays at zero. The switch is re-attempted on the next iteration. **Infinite CPU loop — denial of service.**

If the decoder could somehow escape the loop with corrupted state, the theoretical chain is: stale `block_type_rb` → OOB read on `context_map` → garbage Huffman tree pointer → corrupted distance codes → OOB `memmove16` on the ring buffer. A 16-byte write at a partially-controlled offset from the heap-allocated ring buffer base.

But none of that matters if the trigger can't fire.

---

## The Key Finding: MLEN = BLOCK_SIZE_CAP

Here is the equation that kills the entire exploit chain:

```
Max MLEN (RFC 7932, 6 nibbles, 24 bits)  =  2^24  =  16,777,216
BROTLI_BLOCK_SIZE_CAP (state.h:394)       =  1<<24 =  16,777,216
                                                     ═══════════
                                                      Identical
```

When `NBLTYPES = 1` for any block category, `block_length` is initialized to `BROTLI_BLOCK_SIZE_CAP` (16M). No initial block count is read from the stream — 16M is hardcoded.

A metablock can contain at most `MLEN` bytes of uncompressed output. `MLEN` is encoded in the metablock header using up to 6 nibbles (24 bits). Maximum value: `2^24 = 16,777,216`.

Total symbols of any category ≤ MLEN ≤ 16M = `block_length` initial value.

The block counter reaches zero — at the **earliest** — on the very last symbol of the metablock. At that point, the loop counter `i` also reaches zero, and the `do-while` exits cleanly:

```c
do {
  if (s->block_length[0] == 0) goto NextLiteralBlock;  // never fires
  // ... read literal ...
  --s->block_length[0];                                 // reaches 0 on last literal
} while (--i != 0);                                     // exits: i == 0
```

**The block-switch check never sees `block_length == 0` with pending work.** The metablock ends. The loop exits. The vulnerability code path is dead.

This is not a coincidence. `BROTLI_BLOCK_SIZE_CAP` was deliberately set to match the maximum MLEN. The specification prevents the single-block-type fast path from ever needing a block switch.

---

## The Attack Surface That Remains

RCE is off the table, but malformed Brotli input can still trigger decoder errors and resource waste. The real risk is **DoS through decoder errors on services that decompress untrusted Brotli data:**

| Entry Point | Brotli by Default | Risk |
|-------------|:-----------------:|------|
| `fetch()` (undici) | Yes | Malicious server → crash the fetch call |
| Express 5 / body-parser 2.x | Yes | Unauthenticated POST with `Content-Encoding: br` |
| axios | Yes | Response decoding |
| Direct `zlib.brotliDecompress*` | Explicit | Depends on input source |

**One-liner patch check:**

```bash
node -p "require('zlib').constants.BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH || 'VULNERABLE'"
# -17 → patched    |    VULNERABLE → needs update
```

---

<!-- PAYWALL BREAK — subscriber content below -->

## The Full Proof: Why Every PoC Fails

I tested 67 crafted payloads against Node.js v24.19.0 (confirmed vulnerable — missing the `-17` error constant). NBLTYPES bit-flips, header corruption, MLEN overflows, truncations. **Zero crashes. Zero infinite loops. Zero OOB writes.**

Every single payload was caught by other decoder validation checks — Huffman tree space errors, block length errors, context map errors — before reaching the block-switch code path. The decoder has multiple layers of validation, and the block switch is behind all of them.

Here's why each public PoC approach fails:

### Approach 1: Flip NBLTYPES from >1 to 1

Compress varied data at quality 11 (forces multi-block-type encoding with NBLTYPES=7). Flip the first bit of the NBLTYPES field to make it 1. The decoder now skips reading block type trees, and all subsequent header bits are misinterpreted.

**Result:** `ERR__ERROR_FORMAT_HUFFMAN_SPACE` (-7) or `ERR__ERROR_FORMAT_CL_SPACE` (-6). The misinterpreted bytes fail Huffman tree validation immediately. The decoder never enters `ProcessCommandsInternal`.

### Approach 2: Inflate MLEN to 16M

Take a valid compressed stream (MLEN=65536) and set all MLEN bits to maximum.

**Result:** `Z_BUF_ERROR` (-5) — "unexpected end of file." The stream has only a few KB of compressed data, nowhere near enough to decode 16M literals. The decoder exhausts its input and exits.

### Approach 3: Exhausting block_length through processing

Compress 16MB of uniform data. The encoder produces MLEN=131,072 per metablock (128KB), far below the 16M cap. Even with maximum compression, the encoder splits into many small metablocks rather than one 16M metablock.

**Result:** `block_length` is always ≫ 0 at metablock boundaries. The block-switch path is never reached.

### Approach 4: Cross-metablock stale state

Some analyses suggest stale `block_type_rb` values from a previous metablock could cause OOB reads in the next metablock. This would bypass the 16M barrier because the OOB happens during header setup, not during data processing.

**Result:** Blocked. `BrotliDecoderStateMetablockBegin` (called at every metablock boundary) resets all relevant state:

```c
s->block_type_rb[0] = 1;  s->block_type_rb[1] = 0;  // literal
s->block_type_rb[2] = 1;  s->block_type_rb[3] = 0;  // command
s->block_type_rb[4] = 1;  s->block_type_rb[5] = 0;  // distance
s->context_map = NULL;     // freed and re-allocated
```

No stale state survives across metablock boundaries.

### The CaterMaoZi Confirmation

The [CaterMaoZi/CVE-2026-111497-POC](https://github.com/CaterMaoZi/CVE-2026-111497-POC) repo ran **1,200+ fuzz iterations** with targeted mutations (NBLTYPES rewrites, metablock header bit-flips, truncations) and reports **0 crashes**. Their `probe` mode correctly identifies patched vs. unpatched builds by error code, but their `fuzz` mode cannot produce a crashing input. Our analysis explains why: the crash condition is structurally unreachable.

---

## What About the RCE Claims?

Multiple sources claim RCE has been demonstrated:

- **Vercel's advisory** says "researchers demonstrated process-memory disclosure and command execution on unpatched versions."
- **dimasma0305** describes a "self-checking tuned RCE harness."
- **TheFool-TAROT** reports "local command execution under specific conditions."

Here's what those claims actually mean:

**dimasma0305:** Their README explicitly says the PoC is "not a portable exploit for an arbitrary ASLR-enabled Node.js process and it does not contact a remote target." The "RCE harness" uses a non-PIE build with a lowered `BLOCK_SIZE_CAP` — artificially removing the structural barrier we identified.

**TheFool-TAROT:** Local command execution was achieved only with `--predictable` (disabling V8's ASLR) AND a separate info-leak vulnerability (CVE-2024-21524 in `node-stringbuilder`). Their writeup explicitly states: "Remote blind exploitation was not achieved."

**Vercel:** No technical details provided. Given the structural analysis, the "demonstrated command execution" likely used similar artificial conditions.

**The CVSS 9.2 rating** comes from CWE-787 (OOB Write) automatic scoring — Network/Low-complexity/No-auth. It doesn't account for structural unreachability. Node.js's own "High" rating (without a CVSS vector) is more honest, though even "High" may overstate the practical risk.

---

## The Theoretical Chain (If It Could Fire)

For completeness, here's what the exploitation chain would look like if the trigger condition were reachable:

```
Trigger: block_length == 0 with NBLTYPES ≤ 1
    ↓
DecodeBlockTypeAndLength returns false (ignored on fast path)
    ↓
block_type_rb stays stale → OOB index into context_map
    ↓
Garbage context_map value → OOB index into htrees[]
    ↓
Garbage Huffman tree pointer → corrupted literal/distance decode
    ↓
Corrupted distance_code → wrong ring buffer offset
    ↓
memmove16(copy_dst, copy_src) — 16-byte OOB write on heap
```

**Write primitive:** 16 bytes, at a signed-32-bit offset from the ring buffer base, content from another ring buffer offset (partially attacker-controlled).

**Barriers to RCE (even if reachable):**
1. ASLR — ring buffer address unknown without info leak
2. Separate heaps — V8 and system malloc are different allocators
3. Semi-controlled content — write bytes come from ring buffer, not fully controlled
4. No iteration — infinite loop prevents retry

Even in the theoretical world where the trigger works, reliable remote RCE with ASLR is an open problem.

---

## The Fix

Upstream Brotli commit [0ed4268a](https://github.com/google/brotli/commit/0ed4268a) ("Detect and report invalid stream earlier"):

1. `DecodeBlockTypeAndLength` returns `BrotliDecoderErrorCode` instead of `BROTLI_BOOL`
2. New error code `-17` (`BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH`) for the format error
3. New `BROTLI_SAFE_WITH_STATUS` macro checks the return on **both** paths
4. Added `BROTLI_DCHECK(meta_block_remaining_len <= BLOCK_SIZE_CAP)` — confirming the spec constraint we identified

The fix is correct, comprehensive, and defense-in-depth. The code was wrong even though it couldn't be exploited.

---

## PoC Tools & Lab

Everything is in the [brotli2crash](https://github.com/ikow/brotli2crash) repo:

```bash
git clone https://github.com/ikow/brotli2crash.git && cd brotli2crash

# Check if your Node.js is patched
bash detection/check_version.sh

# Generate 67 malformed payloads and test them
python3 poc/craft_payloads.py
node poc/test_vuln.js

# Attack surface demo: fetch() auto-decompression, streaming API
node poc/demo_attack_surface.js

# Docker lab: vulnerable Express 5 endpoint
cd lab && docker compose up -d
curl http://127.0.0.1:3000/   # check patch status
```

---

## Verdict

CVE-2026-111497 is a real code defect in a real, widely-deployed library. The `BROTLI_SAFE` macro dropping return values on the fast path is unambiguously a bug. The fix is correct and should be applied.

But the severity has been wildly overstated. The vulnerable code path is **structurally unreachable** because the Brotli specification ties `MLEN` and `BLOCK_SIZE_CAP` to the same value. No PoC has produced a crash. No researcher has demonstrated ASLR-enabled RCE. The "Critical (CVSS 9.2)" rating ignores reachability entirely.

**What you should do:**
- Upgrade Node.js to 22.23.4, 24.22.1, or 26.12.1 (defense-in-depth — the fix is correct)
- Don't panic about RCE — it's not achievable on production builds
- If you run Express 5 with body-parser 2.x, the DoS risk from malformed Brotli requests is real and worth patching

---

*Qi Deng ([@ikow](https://github.com/ikow)) — Security Researcher. Previously: [php2shell](https://qideng.substack.com/p/php2shell-dissecting-phps-critical) (CVE-2026-109618/109619), [wp2shell](https://github.com/ikow/wp2shell) (CVE-2026-63030).*
