//! Properties over generated input: whatever a client sends, the agent answers only with
//! FAILURE, IDENTITIES_ANSWER or SIGN_RESPONSE, never panics, never reads a frame body with a bad
//! length, and every r‖s becomes canonical mpints.

mod common;

use std::io::Cursor;

use common::{FakeTpm, scalar_from_mpint, ssh_signature_parts};
use proptest::prelude::*;
use wta_protocol::agent::serve;
use wta_protocol::ecdsa::ssh_signature;
use wta_protocol::message::*;
use wta_protocol::wire::{MAX_FRAME, read_frame, write_frame};

/// Runs `input` through `serve` and returns its result and the reply bodies.
fn run(input: &[u8]) -> (std::io::Result<()>, Vec<Vec<u8>>, FakeTpm) {
    let mut tpm = FakeTpm::new(&["gfh-a"]);
    let mut output = Vec::new();
    let result = serve(&mut &input[..], &mut output, &mut tpm);
    let mut replies = Vec::new();
    let mut out = &output[..];
    while let Some(r) = read_frame(&mut out).unwrap() {
        replies.push(r);
    }
    (result, replies, tpm)
}

fn allowed(reply: &[u8]) -> bool {
    reply == [SSH_AGENT_FAILURE]
        || reply.first() == Some(&SSH_AGENT_IDENTITIES_ANSWER)
        || reply.first() == Some(&SSH_AGENT_SIGN_RESPONSE)
}

/// Message bodies whose type byte is often 11 or 13, so the parsers see more than the type.
fn body() -> impl Strategy<Value = Vec<u8>> {
    let kind = prop_oneof![
        Just(SSH_AGENTC_REQUEST_IDENTITIES),
        Just(SSH_AGENTC_SIGN_REQUEST),
        any::<u8>()
    ];
    (kind, prop::collection::vec(any::<u8>(), 0..300)).prop_map(|(k, rest)| {
        let mut b = vec![k];
        b.extend(rest);
        b
    })
}

/// 32 bytes, often with a run of leading zeros, the case a raw copy into an mpint gets wrong.
fn scalar() -> impl Strategy<Value = [u8; 32]> {
    (any::<[u8; 32]>(), 0..=32usize).prop_map(|(mut s, zeros)| {
        s[..zeros].fill(0);
        s
    })
}

proptest! {
    #[test]
    fn well_framed_bodies_get_one_allowed_reply_each(bodies in prop::collection::vec(body(), 0..8)) {
        let mut input = Vec::new();
        for b in &bodies {
            write_frame(&mut input, b).unwrap();
        }
        let (result, replies, tpm) = run(&input);
        prop_assert!(result.is_ok());
        prop_assert_eq!(replies.len(), bodies.len());
        prop_assert!(replies.iter().all(|r| allowed(r)));
        prop_assert_eq!(tpm.keys.len(), 1);
    }

    /// Frames whose length may not match what follows, so streams end mid-frame or run on.
    #[test]
    fn lying_frame_lengths_get_only_allowed_replies(
        frames in prop::collection::vec((0u32..400, body()), 0..8),
    ) {
        let mut input = Vec::new();
        for (len, b) in &frames {
            input.extend_from_slice(&len.to_be_bytes());
            input.extend_from_slice(b);
        }
        let (_, replies, tpm) = run(&input);
        prop_assert!(replies.iter().all(|r| allowed(r)));
        prop_assert_eq!(tpm.keys.len(), 1);
    }

    #[test]
    fn bad_frame_lengths_close_before_the_body(
        len in prop_oneof![Just(0u32), (MAX_FRAME as u32 + 1)..=u32::MAX],
        rest in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let mut input = Cursor::new([&len.to_be_bytes()[..], &rest].concat());
        let mut output = Vec::new();
        let result = serve(&mut input, &mut output, &mut FakeTpm::new(&["gfh-a"]));
        prop_assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
        prop_assert_eq!(input.position(), 4);
        prop_assert!(output.is_empty());
    }

    #[test]
    fn every_p1363_signature_becomes_canonical_mpints(r in scalar(), s in scalar()) {
        let sig = ssh_signature(&[r, s].concat()).unwrap();
        let (mr, ms) = ssh_signature_parts(&sig);
        prop_assert_eq!(scalar_from_mpint(&mr), r);
        prop_assert_eq!(scalar_from_mpint(&ms), s);
    }
}
