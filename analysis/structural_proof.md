# Structural Unreachability Proof: CVE-2026-111497

## Claim

The vulnerable code path in the Brotli decoder — a block switch firing when `num_block_types ≤ 1` — is **unreachable from any Brotli stream** (valid or malformed), because the Brotli specification constrains `MLEN ≤ BROTLI_BLOCK_SIZE_CAP`.

## Definitions

- `MLEN`: metablock uncompressed length. Encoded in the metablock header using 4–6 nibbles (16–24 bits). Max value: `2^24 = 16,777,216`.
- `BROTLI_BLOCK_SIZE_CAP`: defined as `1U << 24 = 16,777,216` in `c/dec/state.h:394`.
- `block_length[i]`: initialized to `BROTLI_BLOCK_SIZE_CAP` when `num_block_types[i] = 1` (in `BrotliDecoderStateMetablockBegin`, `state.c:101–103`).
- `num_block_types[i]`: the number of block types for category `i` (0=literal, 1=command, 2=distance). When `= 1`, no block type trees are read and `block_length[i]` is not overwritten.

## Proof

### Lemma 1: MLEN ≤ BLOCK_SIZE_CAP

From RFC 7932, Section 9.2:

```
MNIBBLES = {raw_value} + 4, where raw_value ∈ {0, 1, 2}
MLEN is encoded as (MLEN - 1) in MNIBBLES nibbles
Max MNIBBLES = 2 + 4 = 6
Max MLEN - 1 = 2^(6*4) - 1 = 2^24 - 1 = 16,777,215
Max MLEN = 16,777,216 = BROTLI_BLOCK_SIZE_CAP  ∎
```

### Lemma 2: Total symbols ≤ MLEN

In `ProcessCommandsInternal`, each command produces `insert_length` literal symbols and `copy_length` copied bytes. The invariant is:

```
∑(insert_length[j] + copy_length[j]) = MLEN   (for all commands j in the metablock)
```

Therefore:

```
total_literals = ∑ insert_length[j] ≤ MLEN ≤ BLOCK_SIZE_CAP
total_commands = number of ReadCommand calls ≤ MLEN ≤ BLOCK_SIZE_CAP
total_distances = number of distance reads ≤ total_commands ≤ BLOCK_SIZE_CAP
```

### Lemma 3: block_length[i] never reaches 0 during active processing

For each category `i` with `num_block_types[i] = 1`:

```
initial:  block_length[i] = BLOCK_SIZE_CAP = 16,777,216
consumed: total_symbols_of_type_i ≤ MLEN ≤ 16,777,216
final:    block_length[i] = BLOCK_SIZE_CAP - total_symbols_of_type_i ≥ 0
```

**Case 1: total_symbols < BLOCK_SIZE_CAP**

`block_length[i] > 0` at metablock end. Block switch never fires. ∎

**Case 2: total_symbols = BLOCK_SIZE_CAP = MLEN**

This means all output bytes are of type `i` (e.g., all literals, no copies). `block_length[i]` reaches 0 at the exact last symbol. We must show the loop exits cleanly.

In the literal loop (`decode.c:1962–1990`):

```c
do {
  if (s->block_length[0] == 0) goto NextLiteralBlock;  // [A] block switch check
  // ... read literal ...
  --s->block_length[0];                                 // [B] decrement
  ++pos;
} while (--i != 0);                                     // [C] loop counter
```

At the last literal:
1. [A]: `block_length[0] = 1` (not 0) → continue
2. Read literal, [B]: `block_length[0] = 0`
3. [C]: `--i` becomes 0 → loop exits

On the next iteration (if there were one), [A] would trigger the block switch. But `i = 0` at [C] means the loop has already exited. ∎

### Theorem: The block switch with `num_block_types ≤ 1` is unreachable

Combining Lemmas 1–3:

1. `MLEN ≤ BLOCK_SIZE_CAP` (Lemma 1)
2. Total symbols per category ≤ MLEN (Lemma 2)
3. `block_length[i]` reaches 0 at earliest at the last symbol, where the loop counter also reaches 0 (Lemma 3)
4. The block-switch check at [A] never sees `block_length[i] == 0` with pending symbols
5. Therefore, `DecodeBlockTypeAndLength` is never called with `max_block_type ≤ 1` during `ProcessCommandsInternal`
6. The dropped return value in `BROTLI_SAFE` is never triggered ∎

### Corollary: Cross-metablock stale state is also blocked

`BrotliDecoderStateMetablockBegin` (called at the start of each metablock) resets:

```c
s->block_type_rb[0..5] = {1, 0, 1, 0, 1, 0};
s->block_length[0..2] = {BLOCK_SIZE_CAP, BLOCK_SIZE_CAP, BLOCK_SIZE_CAP};
s->context_map = NULL;  // freed and re-allocated
```

Stale `block_type_rb` values from a previous metablock cannot persist into the next. ∎

## Implications

- The vulnerability is a **latent code defect**, not an exploitable vulnerability
- `BLOCK_SIZE_CAP = MLEN_MAX` is a specification-level safety net that makes the code defect unexploitable
- The fix (upstream 0ed4268a) is **defense-in-depth**: correct engineering, not a security patch for an active threat
- CVSS 9.2 overstates the real-world severity; Node.js's "High" is also arguably too high for a structurally unreachable bug
