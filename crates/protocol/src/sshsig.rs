//! Namespace of an SSHSIG to-be-signed blob (OpenSSH PROTOCOL.sshsig, "Signed Data"), only for
//! the log line:
//!
//! ```text
//! byte[6] "SSHSIG"
//! string  namespace
//! string  reserved
//! string  hash_algorithm
//! string  H(message)
//! ```

use crate::wire::Reader;

const MAGIC: &[u8] = b"SSHSIG";

/// Longest namespace logged, in input bytes; longer ones are cut and end in `...`.
pub const MAX_LOGGED: usize = 64;

/// The namespace, made safe for a log line: printable ASCII is kept, any other byte becomes
/// `\xNN`. `None` if `data` is not a well-formed SSHSIG blob.
pub fn namespace(data: &[u8]) -> Option<String> {
    let mut r = Reader::new(data.strip_prefix(MAGIC)?);
    let ns = r.string().ok()?;
    for _ in 0..3 {
        r.string().ok()?; // reserved, hash_algorithm, H(message)
    }
    r.finish().ok()?;

    let mut out = String::new();
    for &b in ns.iter().take(MAX_LOGGED) {
        if b.is_ascii_graphic() || b == b' ' {
            out.push(b as char);
        } else {
            out.push_str(&format!("\\x{b:02x}"));
        }
    }
    if ns.len() > MAX_LOGGED {
        out.push_str("...");
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Writer;

    fn blob(ns: &[u8]) -> Vec<u8> {
        let mut w = Writer::new();
        w.string(ns)
            .string(b"")
            .string(b"sha512")
            .string(&[7; 64]);
        [MAGIC.to_vec(), w.into_vec()].concat()
    }

    #[test]
    fn extracts_the_namespace() {
        assert_eq!(namespace(&blob(b"git")), Some("git".into()));
    }

    #[test]
    fn other_data_has_no_namespace() {
        assert_eq!(namespace(b"session-id and userauth request"), None);
        assert_eq!(namespace(b""), None);
        assert_eq!(namespace(b"SSHSI"), None);
    }

    #[test]
    fn truncated_blob_has_no_namespace() {
        let b = blob(b"git");
        assert_eq!(namespace(&b[..b.len() - 1]), None);
        assert_eq!(namespace(&b[..8]), None);
    }

    #[test]
    fn escapes_unprintable_bytes() {
        assert_eq!(
            namespace(&blob(b"a\nb\x1b\xff")),
            Some("a\\x0ab\\x1b\\xff".into())
        );
    }

    #[test]
    fn caps_long_namespaces() {
        let long = vec![b'n'; 1000];
        let ns = namespace(&blob(&long)).unwrap();
        assert_eq!(ns, format!("{}...", "n".repeat(MAX_LOGGED)));
    }
}
