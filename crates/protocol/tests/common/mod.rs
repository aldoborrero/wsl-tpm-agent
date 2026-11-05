//! A software stand-in for the TPM: P-256 keys held in memory, signing prehashed digests and
//! returning P1363 signatures exactly as `NCryptSignHash` does.

#![allow(dead_code)] // each test binary uses a different part

use std::io;

use p256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use wta_protocol::agent::{Backend, Key};
use wta_protocol::ecdsa::{self, Point};
use wta_protocol::wire::Reader;

pub struct FakeTpm {
    pub keys: Vec<(String, SigningKey)>,
    /// When set, every `sign` call fails, as when the TPM refuses (e.g. a key that needs UI).
    pub refuse: bool,
    /// Digests passed to `sign`, to check that the agent hashes what it should.
    pub signed: Vec<[u8; 32]>,
}

impl FakeTpm {
    /// Keys from fixed secret scalars, so failures reproduce.
    pub fn new(names: &[&str]) -> Self {
        let keys = names
            .iter()
            .enumerate()
            .map(|(i, name)| {
                let mut secret = [0x11u8; 32];
                secret[31] = i as u8 + 1;
                (name.to_string(), SigningKey::from_slice(&secret).unwrap())
            })
            .collect();
        Self {
            keys,
            refuse: false,
            signed: Vec::new(),
        }
    }

    pub fn point(&self, name: &str) -> Point {
        let key = &self.keys.iter().find(|(n, _)| n == name).unwrap().1;
        point_of(key.verifying_key())
    }

    pub fn blob(&self, name: &str) -> Vec<u8> {
        ecdsa::public_blob(&self.point(name))
    }

    pub fn verifying_key(&self, name: &str) -> VerifyingKey {
        *self
            .keys
            .iter()
            .find(|(n, _)| n == name)
            .unwrap()
            .1
            .verifying_key()
    }
}

pub fn point_of(vk: &VerifyingKey) -> Point {
    let encoded = vk.to_encoded_point(false);
    encoded.as_bytes()[1..].try_into().unwrap()
}

impl Backend for FakeTpm {
    fn keys(&mut self) -> io::Result<Vec<Key>> {
        Ok(self
            .keys
            .iter()
            .map(|(name, sk)| Key {
                name: name.clone(),
                point: point_of(sk.verifying_key()),
            })
            .collect())
    }

    fn sign(&mut self, name: &str, digest: &[u8; 32]) -> io::Result<Vec<u8>> {
        if self.refuse {
            return Err(io::Error::other("NTE_SILENT_CONTEXT"));
        }
        self.signed.push(*digest);
        let (_, sk) = self
            .keys
            .iter()
            .find(|(n, _)| n == name)
            .ok_or_else(|| io::Error::other("no such key"))?;
        let sig: Signature = sk.sign_prehash(digest).map_err(io::Error::other)?;
        Ok(sig.to_bytes().to_vec())
    }
}

/// Parses an SSH `ecdsa-sha2-nistp256` signature blob back into `(r, s)` mpint contents,
/// checking the outer layout.
pub fn ssh_signature_parts(sig: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut outer = Reader::new(sig);
    assert_eq!(outer.string().unwrap(), ecdsa::KEY_TYPE.as_bytes());
    let inner = outer.string().unwrap();
    outer.finish().unwrap();
    let mut inner = Reader::new(inner);
    let r = inner.string().unwrap().to_vec();
    let s = inner.string().unwrap().to_vec();
    inner.finish().unwrap();
    (r, s)
}

/// Checks that an mpint is canonical and returns the scalar left-padded to 32 bytes.
pub fn scalar_from_mpint(m: &[u8]) -> [u8; 32] {
    if let Some(&first) = m.first() {
        if first == 0 {
            assert!(m.len() > 1 && m[1] & 0x80 != 0, "superfluous leading zero");
        } else {
            assert_eq!(first & 0x80, 0, "negative mpint");
        }
    }
    let m = m.strip_prefix(&[0]).unwrap_or(m);
    assert!(m.len() <= 32);
    let mut out = [0u8; 32];
    out[32 - m.len()..].copy_from_slice(m);
    out
}

/// Verifies an SSH signature blob over `digest` with `vk`.
pub fn verify(vk: &VerifyingKey, digest: &[u8; 32], sig: &[u8]) -> bool {
    let (r, s) = ssh_signature_parts(sig);
    let Ok(sig) = Signature::from_scalars(scalar_from_mpint(&r), scalar_from_mpint(&s)) else {
        return false;
    };
    vk.verify_prehash(digest, &sig).is_ok()
}
