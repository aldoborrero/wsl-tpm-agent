//! The ssh-agent messages this agent understands (draft-ietf-sshm-ssh-agent, OpenSSH
//! PROTOCOL.agent). Everything else parses as [`Request::Other`] and is answered with
//! [`Response::Failure`].

use crate::wire::{Malformed, Reader, Writer};

pub const SSH_AGENT_FAILURE: u8 = 5;
pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
pub const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

/// A request, borrowing from the frame body it was parsed from.
#[derive(Debug, PartialEq, Eq)]
pub enum Request<'a> {
    Identities,
    Sign {
        key_blob: &'a [u8],
        data: &'a [u8],
        /// Only selects RSA hashes; ignored for ECDSA.
        flags: u32,
    },
    /// Any other message type, never acted on.
    Other(u8),
}

impl<'a> Request<'a> {
    /// Parses one frame body. Known types must be well formed and fully consumed.
    pub fn parse(body: &'a [u8]) -> Result<Self, Malformed> {
        let mut r = Reader::new(body);
        let request = match r.u8()? {
            SSH_AGENTC_REQUEST_IDENTITIES => Request::Identities,
            SSH_AGENTC_SIGN_REQUEST => Request::Sign {
                key_blob: r.string()?,
                data: r.string()?,
                flags: r.u32()?,
            },
            other => return Ok(Request::Other(other)),
        };
        r.finish()?;
        Ok(request)
    }
}

/// A public key the agent offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// SSH public key blob.
    pub blob: Vec<u8>,
    /// Shown by `ssh-add -L`; the TPM key name.
    pub comment: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Response<'a> {
    Failure,
    Identities(&'a [Identity]),
    /// An encoded SSH signature blob.
    Signature(&'a [u8]),
}

impl Response<'_> {
    /// The frame body for this response.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            Response::Failure => {
                w.u8(SSH_AGENT_FAILURE);
            }
            Response::Identities(ids) => {
                let count = u32::try_from(ids.len()).expect("fewer than 4G identities");
                w.u8(SSH_AGENT_IDENTITIES_ANSWER).u32(count);
                for id in ids.iter() {
                    w.string(&id.blob).string(id.comment.as_bytes());
                }
            }
            Response::Signature(sig) => {
                w.u8(SSH_AGENT_SIGN_RESPONSE).string(sig);
            }
        }
        w.into_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sign_body(key: &[u8], data: &[u8], flags: u32) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(SSH_AGENTC_SIGN_REQUEST)
            .string(key)
            .string(data)
            .u32(flags);
        w.into_vec()
    }

    #[test]
    fn parses_request_identities() {
        assert_eq!(Request::parse(&[11]), Ok(Request::Identities));
    }

    #[test]
    fn request_identities_with_payload_is_malformed() {
        assert_eq!(Request::parse(&[11, 0]), Err(Malformed::TrailingBytes));
    }

    #[test]
    fn parses_sign_request() {
        let body = sign_body(b"key", b"data", 2);
        assert_eq!(
            Request::parse(&body),
            Ok(Request::Sign {
                key_blob: b"key",
                data: b"data",
                flags: 2
            })
        );
    }

    #[test]
    fn sign_request_missing_flags_is_truncated() {
        let body = sign_body(b"key", b"data", 0);
        assert_eq!(
            Request::parse(&body[..body.len() - 1]),
            Err(Malformed::Truncated)
        );
    }

    #[test]
    fn sign_request_with_key_length_past_the_end_is_truncated() {
        let mut body = sign_body(b"key", b"data", 0);
        body[1..5].copy_from_slice(&1000u32.to_be_bytes());
        assert_eq!(Request::parse(&body), Err(Malformed::Truncated));
    }

    #[test]
    fn sign_request_with_data_length_past_the_end_is_truncated() {
        let mut body = sign_body(b"key", b"data", 0);
        // type(1) + key string(4+3), then the data length
        body[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(Request::parse(&body), Err(Malformed::Truncated));
    }

    #[test]
    fn sign_request_with_trailing_bytes_is_malformed() {
        let mut body = sign_body(b"key", b"data", 0);
        body.push(0);
        assert_eq!(Request::parse(&body), Err(Malformed::TrailingBytes));
    }

    #[test]
    fn other_types_are_not_parsed() {
        for t in [0u8, 5, 12, 17, 18, 19, 22, 23, 25, 27, 255] {
            assert_eq!(Request::parse(&[t, 1, 2, 3]), Ok(Request::Other(t)));
        }
    }

    #[test]
    fn empty_body_is_truncated() {
        assert_eq!(Request::parse(&[]), Err(Malformed::Truncated));
    }

    #[test]
    fn encodes_failure() {
        assert_eq!(Response::Failure.encode(), [SSH_AGENT_FAILURE]);
    }

    #[test]
    fn encodes_identities_answer() {
        let ids = [
            Identity {
                blob: b"k1".to_vec(),
                comment: "gfh-a".into(),
            },
            Identity {
                blob: b"k2".to_vec(),
                comment: "gfh-b".into(),
            },
        ];
        let body = Response::Identities(&ids).encode();
        let mut r = Reader::new(&body);
        assert_eq!(r.u8(), Ok(SSH_AGENT_IDENTITIES_ANSWER));
        assert_eq!(r.u32(), Ok(2));
        assert_eq!(r.string(), Ok(&b"k1"[..]));
        assert_eq!(r.string(), Ok(&b"gfh-a"[..]));
        assert_eq!(r.string(), Ok(&b"k2"[..]));
        assert_eq!(r.string(), Ok(&b"gfh-b"[..]));
        assert_eq!(r.finish(), Ok(()));
    }

    #[test]
    fn encodes_empty_identities_answer() {
        assert_eq!(Response::Identities(&[]).encode(), [12, 0, 0, 0, 0]);
    }

    #[test]
    fn encodes_sign_response() {
        assert_eq!(
            Response::Signature(b"sig").encode(),
            [14, 0, 0, 0, 3, b's', b'i', b'g']
        );
    }
}
