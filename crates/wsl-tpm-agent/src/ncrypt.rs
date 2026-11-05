//! Windows only: P-256 keys in the Microsoft Platform Crypto Provider through `ncrypt.dll`.
//!
//! This is the only module with `unsafe`. Every call passes `NCRYPT_SILENT_FLAG` where the API
//! takes it, so a key that would need a dialog fails instead of showing one. Handles and buffers
//! NCrypt returns are owned by [`Handle`] and [`Buffer`], which free them on drop.

use std::ffi::c_void;
use std::io;
use std::ptr;

use windows_sys::Win32::Foundation::{
    NTE_BAD_KEYSET, NTE_BUFFER_TOO_SMALL, NTE_EXISTS, NTE_NO_MORE_ITEMS, NTE_PERM,
    NTE_SILENT_CONTEXT, NTE_USER_CANCELLED,
};
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_P256_ALGORITHM, MS_PLATFORM_CRYPTO_PROVIDER, NCRYPT_HANDLE,
    NCRYPT_SILENT_FLAG, NCryptCreatePersistedKey, NCryptEnumKeys, NCryptExportKey,
    NCryptFinalizeKey, NCryptFreeBuffer, NCryptFreeObject, NCryptKeyName, NCryptOpenKey,
    NCryptOpenStorageProvider, NCryptSignHash,
};
use windows_sys::core::HRESULT;
use wta_protocol::agent::{Backend, Key};
use wta_protocol::ecdsa::{self, FIELD_LEN, Point};
use wta_protocol::warn;

use crate::cli::PREFIX;

/// Turns an NCrypt status into an `io::Error` that names the call and, for the codes this
/// program meets, says what happened.
fn check(status: HRESULT, call: &str) -> io::Result<()> {
    if status == 0 {
        return Ok(());
    }
    let (kind, meaning) = match status {
        NTE_EXISTS => (io::ErrorKind::AlreadyExists, "a key with this name exists"),
        NTE_BAD_KEYSET => (io::ErrorKind::NotFound, "no key with this name"),
        NTE_SILENT_CONTEXT => (
            io::ErrorKind::PermissionDenied,
            "the key needs user interaction, refused because of NCRYPT_SILENT_FLAG",
        ),
        NTE_PERM | NTE_USER_CANCELLED => (io::ErrorKind::PermissionDenied, "access denied"),
        NTE_BUFFER_TOO_SMALL => (io::ErrorKind::InvalidData, "not a P-256 key"),
        _ => (io::ErrorKind::Other, "NCrypt error"),
    };
    Err(io::Error::new(
        kind,
        format!("{call}: {meaning} (0x{:08x})", status as u32),
    ))
}

/// A NUL-terminated UTF-16 copy of `s`.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

/// A provider or key handle, released with `NCryptFreeObject`.
struct Handle(NCRYPT_HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        if self.0 != 0 {
            // SAFETY: the handle came from a successful NCryptOpenStorageProvider, NCryptOpenKey
            // or NCryptCreatePersistedKey, is owned only by this value, and is freed once.
            unsafe { NCryptFreeObject(self.0) };
        }
    }
}

/// Memory NCrypt allocated for us, released with `NCryptFreeBuffer`.
struct Buffer(*mut c_void);

impl Drop for Buffer {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer was returned by NCryptEnumKeys (key name or enumeration state),
            // is owned only by this value, and is freed once.
            unsafe { NCryptFreeBuffer(self.0) };
        }
    }
}

/// The Platform Crypto Provider (the TPM).
pub struct Provider(Handle);

impl Provider {
    pub fn open() -> io::Result<Self> {
        let mut h = 0;
        // SAFETY: `h` is a valid out-pointer; the provider name is a static NUL-terminated wide
        // string; flags must be 0.
        let status = unsafe { NCryptOpenStorageProvider(&mut h, MS_PLATFORM_CRYPTO_PROVIDER, 0) };
        check(status, "NCryptOpenStorageProvider")?;
        Ok(Self(Handle(h)))
    }

    fn open_key(&self, name: &str) -> io::Result<Handle> {
        let name = wide(name);
        let mut h = 0;
        // SAFETY: the provider handle is open; `h` is a valid out-pointer; `name` is
        // NUL-terminated and outlives the call; legacy key spec 0 means a CNG key.
        let status =
            unsafe { NCryptOpenKey(self.0.0, &mut h, name.as_ptr(), 0, NCRYPT_SILENT_FLAG) };
        check(status, "NCryptOpenKey")?;
        Ok(Handle(h))
    }

    /// Creates and persists a P-256 key named `name` (not exportable, no UI policy: the
    /// provider defaults) and returns its public point. Fails if the name is taken.
    pub fn create_key(&self, name: &str) -> io::Result<Point> {
        match self.open_key(name) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("key {name} already exists; not overwriting it"),
                ));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let wname = wide(name);
        let mut h = 0;
        // SAFETY: the provider handle is open; `h` is a valid out-pointer; the algorithm id is a
        // static NUL-terminated wide string and `wname` is NUL-terminated and outlives the call.
        // Flags 0: no NCRYPT_OVERWRITE_KEY_FLAG, so an existing key is never replaced.
        let status = unsafe {
            NCryptCreatePersistedKey(
                self.0.0,
                &mut h,
                BCRYPT_ECDSA_P256_ALGORITHM,
                wname.as_ptr(),
                0,
                0,
            )
        };
        check(status, "NCryptCreatePersistedKey")?;
        let key = Handle(h);
        // SAFETY: `key` holds the handle just created and not yet finalized.
        let status = unsafe { NCryptFinalizeKey(key.0, NCRYPT_SILENT_FLAG) };
        check(status, "NCryptFinalizeKey")?;
        public_point(&key)
    }

    /// The public point of key `name`; an error if it is missing or not P-256.
    pub fn point(&self, name: &str) -> io::Result<Point> {
        public_point(&self.open_key(name)?)
    }

    /// Names of every key in the provider for the current user.
    pub fn key_names(&self) -> io::Result<Vec<String>> {
        let mut names = Vec::new();
        let mut state = Buffer(ptr::null_mut());
        loop {
            let mut item: *mut NCryptKeyName = ptr::null_mut();
            // SAFETY: the provider handle is open; `item` and `state.0` are valid out-pointers;
            // a NULL scope lists the current user's keys; `state.0` is NULL on the first call
            // and afterwards whatever the previous call stored there.
            let status = unsafe {
                NCryptEnumKeys(
                    self.0.0,
                    ptr::null(),
                    &mut item,
                    &mut state.0,
                    NCRYPT_SILENT_FLAG,
                )
            };
            if status == NTE_NO_MORE_ITEMS {
                return Ok(names);
            }
            check(status, "NCryptEnumKeys")?;
            let item = Buffer(item.cast());
            // SAFETY: on success `item` points to an NCryptKeyName owned by NCrypt (freed when
            // `item` drops); its `pszName` is a NUL-terminated wide string valid until then.
            let name = unsafe { from_wide((*item.0.cast::<NCryptKeyName>()).pszName) };
            names.push(name);
        }
    }

    /// Signs a SHA-256 digest with key `name`, through the same handle whose public point was
    /// checked against `expected`; returns P1363 `r‖s`.
    pub fn sign(&self, name: &str, expected: &Point, digest: &[u8; 32]) -> io::Result<Vec<u8>> {
        let key = self.open_key(name)?;
        if public_point(&key)? != *expected {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("key {name} was replaced after it was listed"),
            ));
        }
        let mut sig = [0u8; 2 * FIELD_LEN];
        let mut len = 0u32;
        // SAFETY: `key` is open; no padding info for ECDSA; `digest` is 32 readable bytes and
        // `sig` 64 writable bytes, the lengths passed match; `len` is a valid out-pointer.
        let status = unsafe {
            NCryptSignHash(
                key.0,
                ptr::null(),
                digest.as_ptr(),
                digest.len() as u32,
                sig.as_mut_ptr(),
                sig.len() as u32,
                &mut len,
                NCRYPT_SILENT_FLAG,
            )
        };
        check(status, "NCryptSignHash")?;
        Ok(sig[..(len as usize).min(sig.len())].to_vec())
    }
}

/// Exports `BCRYPT_ECCPUBLIC_BLOB` and reads the P-256 point from it.
fn public_point(key: &Handle) -> io::Result<Point> {
    // Header (magic, cbKey) plus X‖Y: exactly the size of a P-256 public blob. Larger curves do
    // not fit and fail with NTE_BUFFER_TOO_SMALL.
    let mut blob = [0u8; 8 + 2 * FIELD_LEN];
    let mut len = 0u32;
    // SAFETY: `key` is open; no export key or parameters; `blob` is writable for the length
    // passed; `len` is a valid out-pointer.
    let status = unsafe {
        NCryptExportKey(
            key.0,
            0,
            BCRYPT_ECCPUBLIC_BLOB,
            ptr::null(),
            blob.as_mut_ptr(),
            blob.len() as u32,
            &mut len,
            NCRYPT_SILENT_FLAG,
        )
    };
    check(status, "NCryptExportKey")?;
    let blob = &blob[..(len as usize).min(blob.len())];
    ecdsa::point_from_eccpublic_blob(blob)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "not an ECDSA P-256 key"))
}

/// Copies a NUL-terminated UTF-16 string, replacing invalid sequences.
///
/// # Safety
///
/// `p` must be NULL or point to a NUL-terminated UTF-16 string that stays valid for the call.
unsafe fn from_wide(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0;
    // SAFETY: per the contract, every unit up to and including the terminator is readable.
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: the `len` units before the terminator were just read and are initialized.
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len) })
}

/// The agent's backend: the key given with `--name`, or every `gfh-*` P-256 key.
pub struct Tpm {
    provider: Provider,
    only: Option<String>,
}

impl Tpm {
    pub fn open(only: Option<String>) -> io::Result<Self> {
        Ok(Self {
            provider: Provider::open()?,
            only,
        })
    }
}

impl Backend for Tpm {
    fn keys(&mut self) -> io::Result<Vec<Key>> {
        let names = match &self.only {
            Some(name) => vec![name.clone()],
            None => {
                let mut names = self.provider.key_names()?;
                names.retain(|n| n.starts_with(PREFIX));
                names
            }
        };
        let mut keys = Vec::new();
        for name in names {
            match self.provider.point(&name) {
                Ok(point) => keys.push(Key { name, point }),
                Err(e) => warn!("skipping key {name}: {e}"),
            }
        }
        Ok(keys)
    }

    fn sign(&mut self, key: &Key, digest: &[u8; 32]) -> io::Result<Vec<u8>> {
        self.provider.sign(&key.name, &key.point, digest)
    }
}
