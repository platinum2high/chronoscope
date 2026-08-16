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
