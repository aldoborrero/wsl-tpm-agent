//! The serve loop: one connection, framed requests in, framed responses out, signatures made by
//! a [`Backend`] (the TPM on Windows, a software key in tests).

use std::io::{self, Read, Write};

use sha2::{Digest as _, Sha256};

use crate::ecdsa::{self, Point};
use crate::message::{Identity, Request, Response};
use crate::{debug, error, info, sshsig, wire};

/// A P-256 key the backend can sign with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    /// Name in the key store; also the identity comment.
    pub name: String,
    pub point: Point,
}

/// Where the private keys live.
pub trait Backend {
    /// The keys to offer. Called for every request, so a key removed from the store stops being
    /// offered or used without restarting anything.
    fn keys(&mut self) -> io::Result<Vec<Key>>;

    /// Signs a SHA-256 digest with the key named `key.name`; returns the P1363 signature (`r‖s`,
    /// 64 bytes). Fails if that key's public point is no longer `key.point`, so a key replaced
    /// after [`Backend::keys`] listed it never signs in its place.
    fn sign(&mut self, key: &Key, digest: &[u8; 32]) -> io::Result<Vec<u8>>;
}

/// Serves requests until `input` ends. A framing error (length 0 or above
/// [`wire::MAX_FRAME`], or a stream cut inside a frame) ends the connection with that error;
/// every other problem is answered with `FAILURE` and the loop goes on.
pub fn serve(
    input: &mut impl Read,
    output: &mut impl Write,
    backend: &mut impl Backend,
) -> io::Result<()> {
    while let Some(body) = wire::read_frame(input)? {
        wire::write_frame(output, &handle(&body, backend))?;
    }
    Ok(())
}

/// The response body for one request body.
pub fn handle(body: &[u8], backend: &mut impl Backend) -> Vec<u8> {
    let request = match Request::parse(body) {
        Ok(request) => request,
        Err(e) => {
            debug!("refused type={}: {e}", body.first().copied().unwrap_or(0));
            return Response::Failure.encode();
        }
    };
    match request {
        Request::Identities => match identities(backend) {
            Ok(ids) => Response::Identities(&ids).encode(),
            Err(e) => {
                error!("listing keys failed: {e}");
                Response::Failure.encode()
            }
        },
        Request::Sign { key_blob, data, .. } => match sign(backend, key_blob, data) {
            Ok(sig) => Response::Signature(&sig).encode(),
            Err(e) => {
                error!("signing failed: {e}");
                Response::Failure.encode()
            }
        },
        Request::Other(t) => {
            debug!("refused type={t}");
            Response::Failure.encode()
        }
    }
}

fn identities(backend: &mut impl Backend) -> io::Result<Vec<Identity>> {
    Ok(backend
        .keys()?
        .into_iter()
        .map(|k| Identity {
            blob: ecdsa::public_blob(&k.point),
            comment: k.name,
        })
        .collect())
}

fn sign(backend: &mut impl Backend, key_blob: &[u8], data: &[u8]) -> io::Result<Vec<u8>> {
    let key = backend
        .keys()?
        .into_iter()
        .find(|k| ecdsa::public_blob(&k.point) == key_blob)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "key not held by this agent"))?;
    let digest: [u8; 32] = Sha256::digest(data).into();
    let p1363 = backend.sign(&key, &digest)?;
    let sig = ecdsa::ssh_signature(&p1363).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("backend returned a {}-byte signature", p1363.len()),
        )
    })?;
    let namespace = sshsig::namespace(data);
    info!(
        "signed key={} bytes={} namespace={}",
        key.name,
        data.len(),
        namespace.as_deref().unwrap_or("-")
    );
    Ok(sig)
}
