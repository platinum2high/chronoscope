//! Bounds-checked little-endian byte reader. Every artifact parser reads
//! from attacker-influenced or corrupt files, so out-of-range reads must
//! return `None` instead of panicking — a malformed/truncated sample
//! should degrade to partial results, never crash the collector run.

pub struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    pub fn u16(&self, offset: usize) -> Option<u16> {
        let s = self.buf.get(offset..offset + 2)?;
        Some(u16::from_le_bytes(s.try_into().ok()?))
    }

    pub fn u32(&self, offset: usize) -> Option<u32> {
        let s = self.buf.get(offset..offset + 4)?;
        Some(u32::from_le_bytes(s.try_into().ok()?))
    }

    pub fn u64(&self, offset: usize) -> Option<u64> {
        let s = self.buf.get(offset..offset + 8)?;
        Some(u64::from_le_bytes(s.try_into().ok()?))
    }

    pub fn slice(&self, offset: usize, len: usize) -> Option<&'a [u8]> {
        self.buf.get(offset..offset.checked_add(len)?)
    }

    /// NUL-terminated ANSI (cp1252-ish; we just use latin1/ASCII lossy)
    /// string, capped at `max_len` bytes so a corrupt length field can't
    /// walk off the end of the buffer.
    pub fn cstr(&self, offset: usize, max_len: usize) -> Option<String> {
        let end = (offset + max_len).min(self.buf.len());
        let raw = self.buf.get(offset..end)?;
        let nul = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        Some(String::from_utf8_lossy(&raw[..nul]).into_owned())
    }
}

/// Sequential, mutable-position cursor over an immutable byte slice.
/// Every read advances `pos` and returns `None` on an out-of-bounds
/// read rather than panicking — token-stream formats like EVTX's
/// BinXML need a walk-forward reader, not just random-access offsets.
pub struct Cursor<'a> {
    pub data: &'a [u8],
    pub pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    pub fn peek(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    pub fn u8(&mut self) -> Option<u8> {
        let v = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(v)
    }

    pub fn u16(&mut self) -> Option<u16> {
        let s = self.data.get(self.pos..self.pos + 2)?;
        self.pos += 2;
        Some(u16::from_le_bytes(s.try_into().ok()?))
    }

    pub fn u32(&mut self) -> Option<u32> {
        let s = self.data.get(self.pos..self.pos + 4)?;
        self.pos += 4;
        Some(u32::from_le_bytes(s.try_into().ok()?))
    }

    pub fn u64(&mut self) -> Option<u64> {
        let s = self.data.get(self.pos..self.pos + 8)?;
        self.pos += 8;
        Some(u64::from_le_bytes(s.try_into().ok()?))
    }

    pub fn read(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.data.get(self.pos..self.pos.checked_add(n)?)?;
        self.pos += n;
        Some(s)
    }

    pub fn skip(&mut self, n: usize) -> bool {
        match self.pos.checked_add(n) {
            Some(p) if p <= self.data.len() => {
                self.pos = p;
                true
            }
            _ => false,
        }
    }
}
