//! ECDSA P-256 in SSH form (RFC 5656 §3.1): public key blobs, OpenSSH public key lines, and the
//! conversion of NCrypt's P1363 signature (`r‖s`) into `mpint r`, `mpint s`.

use crate::base64;
use crate::wire::Writer;

pub const KEY_TYPE: &str = "ecdsa-sha2-nistp256";
pub const CURVE: &str = "nistp256";

/// Bytes of one P-256 coordinate or scalar.
pub const FIELD_LEN: usize = 32;

/// `BCRYPT_ECDSA_PUBLIC_P256_MAGIC` ("ECS1"), little endian in the blob header.
const ECDSA_PUBLIC_P256_MAGIC: u32 = 0x3153_4345;

/// Uncompressed public point, `X‖Y`.
pub type Point = [u8; 2 * FIELD_LEN];

/// Reads the point from a `BCRYPT_ECCPUBLIC_BLOB` (`BCRYPT_ECCKEY_BLOB { dwMagic, cbKey }`
/// followed by `X‖Y`). `None` unless it is a P-256 ECDSA public key.
pub fn point_from_eccpublic_blob(blob: &[u8]) -> Option<Point> {
    let (header, xy) = blob.split_at_checked(8)?;
    let magic = u32::from_le_bytes(header[..4].try_into().ok()?);
    let cb_key = u32::from_le_bytes(header[4..].try_into().ok()?);
    if magic != ECDSA_PUBLIC_P256_MAGIC || cb_key as usize != FIELD_LEN {
        return None;
    }
    xy.try_into().ok()
}

/// SSH public key blob: `string "ecdsa-sha2-nistp256"`, `string "nistp256"`, `string Q`,
/// with Q the uncompressed point `0x04‖X‖Y`.
pub fn public_blob(point: &Point) -> Vec<u8> {
    let mut q = Vec::with_capacity(1 + point.len());
    q.push(0x04);
    q.extend_from_slice(point);
    let mut w = Writer::new();
    w.string(KEY_TYPE.as_bytes())
        .string(CURVE.as_bytes())
        .string(&q);
    w.into_vec()
}

/// `ecdsa-sha2-nistp256 <base64 blob> <comment>`, as in an OpenSSH `.pub` file.
pub fn openssh_line(point: &Point, comment: &str) -> String {
    format!("{KEY_TYPE} {} {comment}", base64::encode(&public_blob(point)))
}

/// The contents of an SSH `mpint` holding the unsigned big-endian `n` (RFC 4251 §5): no leading
/// zero bytes, plus one `0x00` if the first byte left has its high bit set; zero is empty.
pub fn mpint(n: &[u8]) -> Vec<u8> {
    let start = n.iter().position(|&b| b != 0).unwrap_or(n.len());
    let n = &n[start..];
    let mut out = Vec::with_capacity(n.len() + 1);
    if n.first().is_some_and(|&b| b & 0x80 != 0) {
        out.push(0);
    }
    out.extend_from_slice(n);
    out
}

/// SSH signature blob from a P1363 signature (`r‖s`, 32 bytes each): `string
/// "ecdsa-sha2-nistp256"`, `string (mpint r ‖ mpint s)`. `None` if the input is not 64 bytes.
pub fn ssh_signature(p1363: &[u8]) -> Option<Vec<u8>> {
    if p1363.len() != 2 * FIELD_LEN {
        return None;
    }
    let (r, s) = p1363.split_at(FIELD_LEN);
    let mut inner = Writer::new();
    inner.string(&mpint(r)).string(&mpint(s));
    let mut outer = Writer::new();
    outer.string(KEY_TYPE.as_bytes()).string(&inner.into_vec());
    Some(outer.into_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Reader;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Generated with `ssh-keygen -t ecdsa -b 256 -C gfh-vector`; X‖Y taken from its blob.
    const VECTOR_LINE: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLsapc/7zOWAbxVKLqpp+g1hGfeGQhYdYOEgyy0DGQJcxfgXjF9MY9a/rGOLzvD+FyXafnRPLDqKYlDgVzFAsnM= gfh-vector";
    const VECTOR_XY: &str = "bb1aa5cffbcce5806f154a2eaa69fa0d6119f78642161d60e120cb2d0319025cc5f8178c5f4c63d6bfac638bcef0fe1725da7e744f2c3a8a6250e0573140b273";

    fn vector_point() -> Point {
        hex(VECTOR_XY).try_into().unwrap()
    }

    #[test]
    fn openssh_line_matches_ssh_keygen() {
        assert_eq!(openssh_line(&vector_point(), "gfh-vector"), VECTOR_LINE);
    }

    #[test]
    fn public_blob_layout() {
        let blob = public_blob(&vector_point());
        let mut r = Reader::new(&blob);
        assert_eq!(r.string().unwrap(), KEY_TYPE.as_bytes());
        assert_eq!(r.string().unwrap(), CURVE.as_bytes());
        let q = r.string().unwrap();
        assert_eq!(q.len(), 65);
        assert_eq!(q[0], 0x04);
        assert_eq!(&q[1..], &vector_point());
        r.finish().unwrap();
    }

    fn ecc_blob(magic: u32, cb_key: u32, xy: &[u8]) -> Vec<u8> {
        let mut b = magic.to_le_bytes().to_vec();
        b.extend_from_slice(&cb_key.to_le_bytes());
        b.extend_from_slice(xy);
        b
    }

    #[test]
    fn reads_p256_eccpublic_blob() {
        let blob = ecc_blob(0x3153_4345, 32, &vector_point());
        assert_eq!(point_from_eccpublic_blob(&blob), Some(vector_point()));
    }

    #[test]
    fn rejects_other_eccpublic_blobs() {
        let xy = vector_point();
        // P-384 public magic, ECDH P-256 public magic, private P-256 magic
        for magic in [0x3353_4345, 0x314b_4345, 0x3253_4345] {
            assert_eq!(point_from_eccpublic_blob(&ecc_blob(magic, 32, &xy)), None);
        }
        assert_eq!(
            point_from_eccpublic_blob(&ecc_blob(0x3153_4345, 48, &xy)),
            None
        );
        assert_eq!(
            point_from_eccpublic_blob(&ecc_blob(0x3153_4345, 32, &xy[..63])),
            None
        );
        let mut long = ecc_blob(0x3153_4345, 32, &xy);
        long.push(0);
        assert_eq!(point_from_eccpublic_blob(&long), None);
        assert_eq!(point_from_eccpublic_blob(&[0x45, 0x43]), None);
    }

    #[test]
    fn mpint_keeps_a_scalar_without_high_bit() {
        let n = hex("7f00000000000000000000000000000000000000000000000000000000000001");
        assert_eq!(mpint(&n), n);
    }

    #[test]
    fn mpint_prefixes_zero_when_high_bit_set() {
        let n = hex("8000000000000000000000000000000000000000000000000000000000000001");
        let mut expected = vec![0];
        expected.extend_from_slice(&n);
        assert_eq!(mpint(&n), expected);
    }

    #[test]
    fn mpint_strips_leading_zeros() {
        let n = hex("00007f0000000000000000000000000000000000000000000000000000000001");
        assert_eq!(mpint(&n), n[2..]);
    }

    #[test]
    fn mpint_strips_zeros_then_prefixes_for_high_bit() {
        let n = hex("0000ff0000000000000000000000000000000000000000000000000000000001");
        let mut expected = vec![0];
        expected.extend_from_slice(&n[2..]);
        assert_eq!(mpint(&n), expected);
    }

    #[test]
    fn mpint_of_zero_is_empty() {
        assert_eq!(mpint(&[0; 32]), Vec::<u8>::new());
        assert_eq!(mpint(&[]), Vec::<u8>::new());
    }

    #[test]
    fn ssh_signature_layout() {
        let r = hex("8000000000000000000000000000000000000000000000000000000000000001");
        let s = hex("0000000000000000000000000000000000000000000000000000000000000102");
        let p1363 = [r.clone(), s].concat();
        let sig = ssh_signature(&p1363).unwrap();

        let mut outer = Reader::new(&sig);
        assert_eq!(outer.string().unwrap(), KEY_TYPE.as_bytes());
        let inner = outer.string().unwrap();
        outer.finish().unwrap();

        let mut inner = Reader::new(inner);
        let mut r_mpint = vec![0];
        r_mpint.extend_from_slice(&r);
        assert_eq!(inner.string().unwrap(), r_mpint);
        assert_eq!(inner.string().unwrap(), [1, 2]);
        inner.finish().unwrap();
    }

    #[test]
    fn ssh_signature_needs_64_bytes() {
        assert_eq!(ssh_signature(&[1; 63]), None);
        assert_eq!(ssh_signature(&[1; 65]), None);
        assert_eq!(ssh_signature(&[]), None);
    }
}
