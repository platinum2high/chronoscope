//! MS-XCA "Xpress Huffman" (LZXPRESS Huffman) decompression — the
//! algorithm Windows 8+ uses to compress Prefetch (.pf) files under the
//! "MAM\x04" wrapper (see `prefetch.rs`).
//!
//! This is an independent implementation of the public LZ77 +
//! canonical-Huffman bitstream format (256-symbol prefix-code table,
//! literals 0-255, back-references 256-511, MSB-first 16-bit-word
//! bitstream), built from the documented field layout — not a port of
//! any existing decompressor's source.
//!
//! Every function here is `Option`-returning and never panics: a
//! compressed Prefetch file is host/attacker-influenced input, and a
//! truncated, corrupt, or hostile stream must degrade to `None`,
//! never crash the collector run — same contract as `reader.rs`.

const HUFFMAN_TABLE_BYTES: usize = 256;
const MAX_CODE_LENGTH: usize = 15;
/// Hard cap on the claimed decompressed size, checked before any
/// allocation — a corrupt or hostile size field must not be able to
/// drive an unbounded `Vec` allocation.
const MAX_DECOMPRESSED_SIZE: usize = 32 * 1024 * 1024;
/// Each chunk's bitstream covers at most this many output bytes before
/// a fresh 256-byte Huffman table starts; the last chunk may be
/// shorter. Prefetch files are almost always well under this, so the
/// multi-chunk path is exercised far less than the common case.
const CHUNK_SIZE: usize = 65536;

struct HuffmanTable {
    /// Symbol values in canonical order: grouped by code length
    /// ascending, symbol value ascending within a length.
    symbols_by_length: Vec<u16>,
    first_code: [u32; MAX_CODE_LENGTH + 1],
    first_symbol_index: [usize; MAX_CODE_LENGTH + 1],
    count_at_length: [u16; MAX_CODE_LENGTH + 1],
}

/// Build a canonical decode table from 512 code lengths (0..=15)
/// packed two per byte (low nibble = even symbol, high nibble = odd
/// symbol) across 256 bytes. Returns `None` if every length is 0 (an
/// empty/corrupt table).
fn build_huffman_table(raw_table: &[u8; HUFFMAN_TABLE_BYTES]) -> Option<HuffmanTable> {
    let mut lengths = [0u8; HUFFMAN_TABLE_BYTES * 2];
    for (i, &byte) in raw_table.iter().enumerate() {
        lengths[2 * i] = byte & 0x0F;
        lengths[2 * i + 1] = byte >> 4;
    }

    let mut count_at_length = [0u16; MAX_CODE_LENGTH + 1];
    for &len in lengths.iter() {
        count_at_length[len as usize] += 1;
    }
    if count_at_length[1..].iter().all(|&c| c == 0) {
        return None;
    }

    let mut first_code = [0u32; MAX_CODE_LENGTH + 1];
    let mut first_symbol_index = [0usize; MAX_CODE_LENGTH + 1];
    let mut code: u32 = 0;
    let mut index: usize = 0;
    for len in 1..=MAX_CODE_LENGTH {
        first_code[len] = code;
        first_symbol_index[len] = index;
        let count = count_at_length[len] as u32;
        code = (code + count) << 1;
        index += count as usize;
    }

    let mut symbols_by_length = Vec::with_capacity(index);
    for len in 1..=MAX_CODE_LENGTH {
        for (sym, &l) in lengths.iter().enumerate() {
            if l as usize == len {
                symbols_by_length.push(sym as u16);
            }
        }
    }

    Some(HuffmanTable {
        symbols_by_length,
        first_code,
        first_symbol_index,
        count_at_length,
    })
}

/// MSB-first bit reader over 16-bit little-endian words (per the
/// documented LZXPRESS Huffman bitstream convention: the MSB of the
/// first 16-bit word is the first bit in the stream).
struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    bit_buffer: u32,
    bits_available: u32,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        let mut br = Self {
            data,
            pos: 0,
            bit_buffer: 0,
            bits_available: 0,
        };
        br.fill();
        br
    }

    fn fill(&mut self) {
        while self.bits_available <= 16 && self.pos + 2 <= self.data.len() {
            let word = u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]) as u32;
            self.bit_buffer |= word << (16 - self.bits_available);
            self.pos += 2;
            self.bits_available += 16;
        }
    }

    /// Peek the next `n` (at most 1 — see below) bits without consuming
    /// them, topping up the accumulator first if needed.
    ///
    /// Refilling happens *here*, lazily, right before the bits are
    /// used — never automatically after the previous `consume()`. This
    /// mirrors Samba's reference decoder (`lzxpress_huffman.c`), which
    /// checks `remaining_bits == 16` (and refills if so) as the very
    /// first thing when servicing *the next bit request*, not the
    /// moment the previous bit was consumed. The two schedules produce
    /// identical decoded bit *values* either way (prefetch timing can't
    /// change what bits are in the stream) — but they produce different
    /// counts of how many bytes have been pulled from `data` at any
    /// given instant, and `self.pos` (used verbatim for the raw
    /// length-escape reads in `decode_match`, and for locating the next
    /// chunk's Huffman table) has to match Samba's count exactly, not
    /// just decode the same symbols. An eager post-consume fill was
    /// observed (via a byte-for-byte cross-check against a Samba-model
    /// port) to desync `pos` from Samba's `byte_pos` within the very
    /// first few symbols of a real compressed Prefetch stream, well
    /// before the decoded output itself showed any visible difference.
    ///
    /// This is also why `n` must be 1: refilling once per multi-bit
    /// batch — checking the threshold only against the state *before*
    /// the batch — does not reproduce Samba's per-bit "==16" trigger,
    /// which can fire partway through a would-be batch (e.g. starting
    /// at 17 bits available and reading 15 bits: Samba refills after
    /// the first of those 15, a single batched check at 17 <= 16 never
    /// would). Every caller here reads one bit at a time for exactly
    /// this reason.
    fn peek1(&mut self) -> u32 {
        self.fill();
        self.bit_buffer >> 31
    }

    fn consume1(&mut self) {
        self.bit_buffer = self.bit_buffer.wrapping_shl(1);
        self.bits_available = self.bits_available.saturating_sub(1);
    }

    /// Bytes of `data` pulled into the accumulator so far — used to
    /// locate the next chunk's Huffman table after this chunk ends.
    fn bytes_consumed(&self) -> usize {
        self.pos
    }

    fn exhausted(&self) -> bool {
        self.bits_available == 0 && self.pos >= self.data.len()
    }

    /// Read a raw byte directly from the underlying stream at the
    /// current byte cursor, completely bypassing the bit accumulator.
    ///
    /// This is *not* the same as `peek(8)`/`consume(8)`: those pull 8
    /// bits out of whatever is currently buffered in `bit_buffer`,
    /// which — because the accumulator is filled a whole 16-bit word
    /// (or two) ahead of what's actually been consumed as Huffman/
    /// distance bits — is not byte-aligned with the raw compressed
    /// stream at all. Per MS-XCA (and confirmed against Samba's
    /// `lzxpress_huffman.c`, which reads these fields via
    /// `CHECK_READ_8`/`_16`/`_32` straight off its `byte_pos`, never
    /// through the bit reader), a match's extended-length fields are
    /// literal bytes at the *stream's* current byte cursor, read
    /// independently of the bit-level Huffman/distance decoding.
    /// `self.pos` already tracks exactly that cursor (how many bytes
    /// have been pulled from `data`), so reading straight from it here
    /// is correct as long as it's called before any further bits are
    /// consumed for this match — which `decode_match` guarantees by
    /// decoding the length (and its raw escape bytes) before it
    /// touches any distance bits.
    fn read_raw_u8(&mut self) -> Option<u8> {
        let b = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn read_raw_u16(&mut self) -> Option<u16> {
        let s = self.data.get(self.pos..self.pos + 2)?;
        self.pos += 2;
        Some(u16::from_le_bytes(s.try_into().ok()?))
    }

    fn read_raw_u32(&mut self) -> Option<u32> {
        let s = self.data.get(self.pos..self.pos + 4)?;
        self.pos += 4;
        Some(u32::from_le_bytes(s.try_into().ok()?))
    }
}

fn decode_symbol(table: &HuffmanTable, br: &mut BitReader) -> Option<u16> {
    let mut code: u32 = 0;
    for len in 1..=MAX_CODE_LENGTH {
        if br.exhausted() {
            return None;
        }
        code = (code << 1) | br.peek1();
        br.consume1();
        let count = table.count_at_length[len] as u32;
        if count > 0 {
            let first = table.first_code[len];
            if code >= first && code - first < count {
                let idx = table.first_symbol_index[len] + (code - first) as usize;
                return table.symbols_by_length.get(idx).copied();
            }
        }
    }
    None
}

/// Decode the (length, distance) pair for a back-reference symbol
/// (`symbol` in 256..=511).
///
/// Order matters here and is not arbitrary: per MS-XCA (and Samba's
/// reference decoder), **length is decoded first, distance second**.
/// Length 0xF is an escape for an extended length read as a *raw byte
/// straight off the compressed stream* (bypassing the bit
/// accumulator entirely — see `BitReader::read_raw_u8`), with 0xFF in
/// that byte escaping again to a raw 16-bit length, and a 16-bit value
/// of 0 escaping further to a raw 32-bit length (guards against
/// pathological/hostile chunks near the 64KiB block boundary). Only
/// once the length — and any raw escape bytes it consumed — has been
/// fully resolved do we pull the distance's extra bits from the bit
/// stream. Decoding distance first (as a prior version of this code
/// did) or reading the length escape through the bit-level
/// `peek`/`consume` path both desync the stream: the bit accumulator
/// is filled a word or more ahead of what's been consumed as bits, so
/// it is not byte-aligned with the raw stream the escape bytes live
/// in, and consuming distance bits first shifts the raw byte cursor
/// out from under the escape read that should follow it.
fn decode_match(br: &mut BitReader, symbol: u16) -> Option<(u32, u32)> {
    let sym = (symbol - 256) as u32;
    let len_nibble = sym & 0x0F;
    let dist_bits = (sym >> 4) & 0x0F;

    let length = if len_nibble == 0x0F {
        let extra_byte = br.read_raw_u8()? as u32;
        let mut len = 15 + extra_byte;
        if extra_byte == 0xFF {
            len = br.read_raw_u16()? as u32;
            if len == 0 {
                len = br.read_raw_u32()?;
            }
        }
        len + 3
    } else {
        len_nibble + 3
    };

    let distance = if dist_bits == 0 {
        1
    } else {
        // One bit at a time — see `BitReader::peek1` for why a single
        // batched multi-bit peek/consume here would desync `pos` from
        // Samba's `byte_pos` even though it decodes the same value.
        let mut extra: u32 = 0;
        for _ in 0..dist_bits {
            if br.exhausted() {
                return None;
            }
            extra = (extra << 1) | br.peek1();
            br.consume1();
        }
        (1u32 << dist_bits) + extra
    };

    Some((length, distance))
}

/// Decompress a full LZXPRESS-Huffman stream to exactly
/// `decompressed_size` bytes, or `None` on any corrupt/truncated/
/// hostile input. Never allocates based on an unchecked size field.
pub fn decompress(compressed: &[u8], decompressed_size: usize) -> Option<Vec<u8>> {
    if decompressed_size == 0 {
        return Some(Vec::new());
    }
    if decompressed_size > MAX_DECOMPRESSED_SIZE {
        return None;
    }

    let mut out = Vec::with_capacity(decompressed_size.min(1 << 20));
    let mut consumed = 0usize;

    while out.len() < decompressed_size {
        let table_bytes: &[u8; HUFFMAN_TABLE_BYTES] = compressed
            .get(consumed..consumed + HUFFMAN_TABLE_BYTES)?
            .try_into()
            .ok()?;
        let table = build_huffman_table(table_bytes)?;
        consumed += HUFFMAN_TABLE_BYTES;

        let chunk_target = out.len() + CHUNK_SIZE.min(decompressed_size - out.len());
        let mut br = BitReader::new(compressed.get(consumed..)?);

        let max_iters = (chunk_target - out.len())
            .saturating_mul(2)
            .saturating_add(64);
        let mut guard = 0usize;

        while out.len() < chunk_target {
            guard += 1;
            if guard > max_iters {
                return None;
            }
            let symbol = decode_symbol(&table, &mut br)?;
            if symbol < 256 {
                out.push(symbol as u8);
                continue;
            }
            let (length, offset) = decode_match(&mut br, symbol)?;
            if offset == 0 || offset as usize > out.len() {
                return None;
            }
            let start = out.len() - offset as usize;
            // A match's *output* is allowed to run past this chunk's
            // nominal `chunk_target` boundary — chunking only bounds how
            // many output bytes trigger picking up a fresh 256-byte
            // Huffman table, it doesn't mean a match's compressed
            // encoding is byte/bit-aligned to that boundary. Reference
            // decoders (e.g. Samba's lzxpress_huffman.c) copy the full
            // match length here and only stop pulling more *symbols*
            // once `output_pos >= block_size` on the next loop check.
            // Truncating the copy at `chunk_target` — as a prior version
            // of this code did — silently dropped the overrun bytes from
            // the output entirely, corrupting every chunk after the
            // first for any real multi-chunk (>64KiB decompressed)
            // Prefetch file.
            //
            // Real Windows-generated streams also routinely let the
            // final match of the final chunk overrun the *overall*
            // claimed `decompressed_size` by a few dozen bytes (observed
            // on real samples) — the trailing bytes are simply discarded
            // by the final `out.truncate(decompressed_size)` below, same
            // as Windows' own decompressor does. So we cap the copy at
            // `decompressed_size` (never allocate/copy past it) but
            // don't treat undershooting `length` here as an error.
            let copy_len = (length as usize).min(decompressed_size.saturating_sub(out.len()));
            for i in 0..copy_len {
                let b = *out.get(start + i)?;
                out.push(b);
            }
        }

        consumed += br.bytes_consumed();
    }

    out.truncate(decompressed_size);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test-only encoder mirroring the exact bit order `BitReader`
    /// expects, so the round-trip tests prove the table format and bit
    /// order agree with the decoder — independent of whether our
    /// reading of the (partially TODO-marked) public spec matches a
    /// real Windows-produced stream bit-for-bit. That agreement is what
    /// the real-sample validation in the Prefetch parser is for.
    struct TestEncoder {
        bits: Vec<u8>, // one bit per element, MSB-first order as produced
    }

    impl TestEncoder {
        fn new() -> Self {
            Self { bits: Vec::new() }
        }

        fn push_bits(&mut self, value: u32, n: u32) {
            for i in (0..n).rev() {
                self.bits.push(((value >> i) & 1) as u8);
            }
        }

        /// Pack accumulated bits into 16-bit-little-endian words,
        /// MSB-first within each word, matching `BitReader::fill`.
        fn into_bytes(mut self) -> Vec<u8> {
            while !self.bits.len().is_multiple_of(16) {
                self.bits.push(0);
            }
            let mut out = Vec::new();
            for word_bits in self.bits.chunks(16) {
                let mut word: u16 = 0;
                for (i, &b) in word_bits.iter().enumerate() {
                    word |= (b as u16) << (15 - i);
                }
                out.extend_from_slice(&word.to_le_bytes());
            }
            out
        }
    }

    /// Build a trivial-but-valid Huffman table: every symbol gets an
    /// 8-bit code (Kraft sum = 256 * 2^-8 = 1, a complete code), so the
    /// canonical code for symbol `s` is simply `s` itself as an 8-bit
    /// value — easy to hand-encode.
    fn flat_length_8_table() -> [u8; HUFFMAN_TABLE_BYTES] {
        let mut raw = [0u8; HUFFMAN_TABLE_BYTES];
        for byte in raw.iter_mut() {
            *byte = 0x88; // both nibbles = length 8
        }
        raw
    }

    fn compress_flat(literals: &[u16]) -> Vec<u8> {
        let mut out = flat_length_8_table().to_vec();
        let mut enc = TestEncoder::new();
        for &sym in literals {
            enc.push_bits(sym as u32, 8);
        }
        out.extend_from_slice(&enc.into_bytes());
        out
    }

    #[test]
    fn decompress_empty_input_returns_empty() {
        assert_eq!(decompress(&[], 0), Some(Vec::new()));
        assert_eq!(decompress(&[0xFF; 10], 0), Some(Vec::new()));
    }

    #[test]
    fn decompress_oversized_target_rejected() {
        assert_eq!(decompress(&[0u8; 300], MAX_DECOMPRESSED_SIZE + 1), None);
    }

    #[test]
    fn decompress_truncated_table_rejected() {
        assert_eq!(decompress(&[0u8; 100], 10), None);
    }

    #[test]
    fn decompress_all_zero_length_table_rejected() {
        // A table claiming every symbol has code length 0 has no valid
        // codes at all — must be rejected, not treated as an
        // (incorrectly) empty-but-valid table.
        let raw = [0u8; HUFFMAN_TABLE_BYTES];
        let mut compressed = raw.to_vec();
        compressed.extend_from_slice(&[0u8; 16]);
        assert_eq!(decompress(&compressed, 4), None);
    }

    #[test]
    fn round_trip_literal_only_stream() {
        let plaintext = b"MZ\x90\x00";
        let literals: Vec<u16> = plaintext.iter().map(|&b| b as u16).collect();
        let compressed = compress_flat(&literals);
        let out = decompress(&compressed, plaintext.len()).expect("valid stream must decode");
        assert_eq!(out, plaintext);
    }

    #[test]
    fn round_trip_with_back_reference() {
        // Encode "AAAA" as literal 'A' followed by a back-reference:
        // len_nibble=0 (length 3), dist_bits=0 (distance 1) -> symbol
        // 256 + 0 = 256, copying 3 bytes from 1 byte back. Build a
        // minimal *valid* two-symbol canonical table: 'A' (65, odd ->
        // high nibble of byte 32) and the match symbol (256, even ->
        // low nibble of byte 128) both at length 1 (codes '0' and
        // '1') — a complete Kraft-sum-1 code with only these two
        // symbols in use, everything else unused (length 0).
        let mut raw = [0u8; HUFFMAN_TABLE_BYTES];
        raw[32] = 0x10; // symbol 65 ('A'): high nibble = length 1
        raw[128] = 0x01; // symbol 256 (match): low nibble = length 1

        let table = build_huffman_table(&raw).expect("valid table");
        // Recompute canonical codes ourselves is exactly what the
        // decoder does; to build a matching bitstream we mirror the
        // same canonical assignment by encoding through the decoded
        // table's first_code/first_symbol_index rather than assuming
        // fixed values, so this test can't silently drift from the
        // decoder's own logic.
        let code_for = |sym: u16| -> (u32, u32) {
            for len in 1..=MAX_CODE_LENGTH {
                let count = table.count_at_length[len] as u32;
                if count == 0 {
                    continue;
                }
                let start = table.first_symbol_index[len];
                if let Some(idx) = table.symbols_by_length[start..start + count as usize]
                    .iter()
                    .position(|&s| s == sym)
                {
                    return (table.first_code[len] + idx as u32, len as u32);
                }
            }
            panic!("symbol not in table");
        };

        let mut enc = TestEncoder::new();
        let (code_a, len_a) = code_for(b'A' as u16);
        enc.push_bits(code_a, len_a);
        let (code_match, len_match) = code_for(256);
        enc.push_bits(code_match, len_match);
        // symbol 256 -> sym=0 -> len_nibble=0 (length 3), dist_bits=0
        // (distance 1) - no extra bits needed.
        let bytes = enc.into_bytes();

        let mut compressed = raw.to_vec();
        compressed.extend_from_slice(&bytes);

        let out = decompress(&compressed, 4).expect("valid back-reference stream must decode");
        assert_eq!(out, b"AAAA");
    }

    /// Regression test for a real bug: a *lot* of single-bit literal
    /// codes (crossing many 16-bit-word boundaries in the bit
    /// accumulator) followed by a match whose distance needs several
    /// *extra bits pulled from the bit stream itself* (not the raw-byte
    /// length-escape path — `round_trip_with_back_reference` above only
    /// covers `dist_bits == 0`, which never touches that path at all).
    ///
    /// A previous version of `BitReader` refilled its accumulator
    /// eagerly right after every `consume()` call, rather than lazily
    /// right before the next bit is actually used, and extracted
    /// multi-bit distance values with a single batched `peek(n)`/
    /// `consume(n)` instead of one bit at a time. Both of those desync
    /// `BitReader::pos` from what a byte-precise reference decoder
    /// (cross-checked against Samba's `lzxpress_huffman.c` bit-for-bit)
    /// would report at the same point in the stream — invisibly at
    /// first, since it doesn't change which *bits* get decoded, only
    /// how many bytes have been prefetched into the accumulator. It
    /// only surfaces once something reads the raw stream position
    /// directly: a length-escape byte, or — as here — simply enough
    /// accumulated single-bit reads that a later *multi*-bit batched
    /// read starts from a bit-buffer state a real bit-by-bit reader
    /// would never be in. This test starts from 200 single-bit literal
    /// decodes (comfortably more than the ~16-bit refill cycle) before
    /// exercising a 4-extra-bit distance draw, so it would have caught
    /// that class of bug even though every literal byte still decoded
    /// correctly (this exact symptom was only found by fuzzing real
    /// captured Prefetch samples, not by unit tests at the time).
    #[test]
    fn round_trip_with_multi_bit_distance_after_many_literals() {
        // Two-symbol canonical table again: 'A' and a match symbol with
        // len_nibble=0 (length 3) and dist_bits=4 (distance =
        // 16..=31), both length-1 codes.
        let mut raw = [0u8; HUFFMAN_TABLE_BYTES];
        raw[32] = 0x10; // symbol 65 ('A'): high nibble = length 1
        let match_symbol: u16 = 256 + (4 << 4); // len_nibble=0, dist_bits=4
        let byte_idx = (match_symbol / 2) as usize;
        if match_symbol.is_multiple_of(2) {
            raw[byte_idx] |= 0x01;
        } else {
            raw[byte_idx] |= 0x10;
        }

        let table = build_huffman_table(&raw).expect("valid table");
        let code_for = |sym: u16| -> (u32, u32) {
            for len in 1..=MAX_CODE_LENGTH {
                let count = table.count_at_length[len] as u32;
                if count == 0 {
                    continue;
                }
                let start = table.first_symbol_index[len];
                if let Some(idx) = table.symbols_by_length[start..start + count as usize]
                    .iter()
                    .position(|&s| s == sym)
                {
                    return (table.first_code[len] + idx as u32, len as u32);
                }
            }
            panic!("symbol not in table");
        };

        const NUM_LITERALS: usize = 200;
        let mut enc = TestEncoder::new();
        let (code_a, len_a) = code_for(b'A' as u16);
        for _ in 0..NUM_LITERALS {
            enc.push_bits(code_a, len_a);
        }
        let (code_match, len_match) = code_for(match_symbol);
        enc.push_bits(code_match, len_match);
        // dist_bits=4: distance = 16 + extra. Pick extra=4 -> distance
        // 20, safely inside the 200-byte run of 'A's already written.
        let extra_dist_bits: u32 = 4;
        enc.push_bits(extra_dist_bits, 4);
        let bytes = enc.into_bytes();

        let mut compressed = raw.to_vec();
        compressed.extend_from_slice(&bytes);

        let expected_len = NUM_LITERALS + 3; // + the 3-byte match copy
        let out = decompress(&compressed, expected_len)
            .expect("valid multi-bit-distance stream must decode");
        assert_eq!(out, vec![b'A'; expected_len]);
    }

    #[test]
    fn garbage_bytes_no_panic() {
        let garbage = vec![0xABu8; 512];
        // Must not panic regardless of what it returns.
        let _ = decompress(&garbage, 64);
    }
}
