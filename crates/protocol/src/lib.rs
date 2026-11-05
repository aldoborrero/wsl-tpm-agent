//! Everything in wsl-tpm-agent that does not need Windows: the ssh-agent wire format, the
//! message subset the agent answers, ECDSA P-256 encodings, SSHSIG parsing for the log line and
//! the serve loop over a [`agent::Backend`]. Tested on Linux.

#![forbid(unsafe_code)]

pub mod base64;
pub mod ecdsa;
pub mod log;
pub mod message;
pub mod wire;
