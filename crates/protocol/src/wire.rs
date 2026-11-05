//! ssh-agent wire format (RFC 4251 §5): big-endian `uint32`, length-prefixed `string`, and the
//! `uint32 length` framing around every message.
//!
//! [`Reader`] checks every length against the bytes it has before using it, so a lying length is
//! an error and never an out-of-bounds read or a large allocation.

use std::fmt;
use std::io::{self, Read, Write};

/// Largest frame accepted, as OpenSSH's own agent (`AGENT_MAX_LEN`).
pub const MAX_FRAME: usize = 256 * 1024;

/// A message that does not parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Malformed {
    /// A field needs more bytes than are left.
    Truncated,
    /// Bytes are left after the last field.
    TrailingBytes,
}

impl fmt::Display for Malformed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Malformed::Truncated => "truncated message",
            Malformed::TrailingBytes => "trailing bytes after message",
        })
    }
}

impl std::error::Error for Malformed {}

/// Bounded reader over one message body.
pub struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    /// Takes the next `n` bytes.
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], Malformed> {
        if n > self.buf.len() {
            return Err(Malformed::Truncated);
        }
        let (head, rest) = self.buf.split_at(n);
        self.buf = rest;
        Ok(head)
    }

    pub fn u8(&mut self) -> Result<u8, Malformed> {
        Ok(self.bytes(1)?[0])
    }

    pub fn u32(&mut self) -> Result<u32, Malformed> {
        let b = self.bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// A `string`: `uint32 length` then that many bytes.
    pub fn string(&mut self) -> Result<&'a [u8], Malformed> {
        let len = self.u32()?;
        // A length that does not fit in usize cannot fit in the buffer either.
        let len = usize::try_from(len).map_err(|_| Malformed::Truncated)?;
        self.bytes(len)
    }

    /// Succeeds only if every byte was consumed.
    pub fn finish(self) -> Result<(), Malformed> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(Malformed::TrailingBytes)
        }
    }
}

/// Builder for one message body.
#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn string(&mut self, v: &[u8]) -> &mut Self {
        let len = u32::try_from(v.len()).expect("ssh strings are shorter than 4 GiB");
        self.u32(len);
        self.buf.extend_from_slice(v);
        self
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}

/// Reads one frame and returns its body. `Ok(None)` when the stream ends cleanly before a frame
/// starts. A length of 0 or above [`MAX_FRAME`] is an `InvalidData` error raised before any of the
/// body is read; a stream that ends inside a frame is `UnexpectedEof`.
pub fn read_frame(r: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut header = [0u8; 4];
    let mut filled = 0;
    while filled < header.len() {
        match r.read(&mut header[filled..]) {
            Ok(0) if filled == 0 => return Ok(None),
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    let len = u32::from_be_bytes(header) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame length {len} outside 1..={MAX_FRAME}"),
        ));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    Ok(Some(body))
}

/// Writes `body` as one frame and flushes.
pub fn write_frame(w: &mut impl Write, body: &[u8]) -> io::Result<()> {
    let len = u32::try_from(body.len()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(body)?;
    w.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_u32_and_string() {
        let mut r = Reader::new(&[0, 0, 0, 7, 0, 0, 0, 2, b'h', b'i', 9]);
        assert_eq!(r.u32(), Ok(7));
        assert_eq!(r.string(), Ok(&b"hi"[..]));
        assert_eq!(r.u8(), Ok(9));
        assert_eq!(r.finish(), Ok(()));
    }

    #[test]
    fn truncated_u32_is_an_error() {
        let mut r = Reader::new(&[0, 0, 1]);
        assert_eq!(r.u32(), Err(Malformed::Truncated));
    }

    #[test]
    fn string_length_past_the_end_is_an_error() {
        let mut r = Reader::new(&[0, 0, 0, 5, b'a', b'b']);
        assert_eq!(r.string(), Err(Malformed::Truncated));
    }

    #[test]
    fn huge_string_length_is_an_error_not_an_allocation() {
        let mut r = Reader::new(&[0xff, 0xff, 0xff, 0xff, 0]);
        assert_eq!(r.string(), Err(Malformed::Truncated));
    }

    #[test]
    fn empty_input_has_no_u8() {
        assert_eq!(Reader::new(&[]).u8(), Err(Malformed::Truncated));
    }

    #[test]
    fn trailing_bytes_are_an_error() {
        let mut r = Reader::new(&[1, 2]);
        r.u8().unwrap();
        assert_eq!(r.finish(), Err(Malformed::TrailingBytes));
    }

    #[test]
    fn writer_encodes_big_endian_and_strings() {
        let mut w = Writer::new();
        w.u8(12).u32(0x0102_0304).string(b"ab");
        assert_eq!(w.into_vec(), [12, 1, 2, 3, 4, 0, 0, 0, 2, b'a', b'b']);
    }

    fn frame(body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        write_frame(&mut out, body).unwrap();
        out
    }

    #[test]
    fn frame_round_trip() {
        let bytes = frame(&[11]);
        assert_eq!(bytes, [0, 0, 0, 1, 11]);
        assert_eq!(read_frame(&mut &bytes[..]).unwrap(), Some(vec![11]));
    }

    #[test]
    fn clean_eof_before_a_frame_is_none() {
        assert_eq!(read_frame(&mut &[][..]).unwrap(), None);
    }

    #[test]
    fn eof_inside_the_header_is_unexpected() {
        let err = read_frame(&mut &[0, 0][..]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn eof_inside_the_body_is_unexpected() {
        let err = read_frame(&mut &[0, 0, 0, 4, 1, 2][..]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn empty_frame_is_rejected() {
        let err = read_frame(&mut &[0, 0, 0, 0][..]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn frame_at_the_limit_is_accepted() {
        let body = vec![5u8; MAX_FRAME];
        assert_eq!(read_frame(&mut &frame(&body)[..]).unwrap(), Some(body));
    }

    #[test]
    fn oversized_frame_is_rejected_before_reading_the_body() {
        let mut input = io::Cursor::new([0x40, 0, 0, 0, 1, 2, 3]); // 1 GiB announced
        let err = read_frame(&mut input).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(input.position(), 4, "only the header may be read");

        let just_over = (MAX_FRAME as u32 + 1).to_be_bytes();
        assert!(read_frame(&mut &just_over[..]).is_err());
    }
}
