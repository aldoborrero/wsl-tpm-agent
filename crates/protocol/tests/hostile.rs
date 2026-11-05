//! What a hostile or broken client can send: none of it may panic, add keys or read past a
//! buffer. Malformed messages get FAILURE and the connection goes on; framing errors close it.

mod common;

use std::io::{self, Read};

use common::FakeTpm;
use wta_protocol::agent::serve;
use wta_protocol::message::*;
use wta_protocol::wire::{Writer, read_frame, write_frame};

fn run(input: &[u8]) -> (io::Result<()>, Vec<Vec<u8>>, FakeTpm) {
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

fn frames(bodies: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for b in bodies {
        write_frame(&mut out, b).unwrap();
    }
    out
}

#[test]
fn key_management_requests_get_failure_and_change_nothing() {
    let mut add = Writer::new();
    add.u8(17)
        .string(b"ecdsa-sha2-nistp256")
        .string(b"nistp256")
        .string(&[4; 65])
        .string(&[1; 32])
        .string(b"evil");
    let add = add.into_vec();
    // add, remove, remove all, add smartcard key, lock, add constrained, extension
    let bodies: Vec<&[u8]> = vec![
        &add,
        &[18, 0, 0, 0, 0],
        &[19],
        &[20],
        &[22, 0, 0, 0, 0],
        &[25],
        &[27],
    ];
    let (result, replies, tpm) = run(&frames(&bodies));
    result.unwrap();
    assert_eq!(replies.len(), bodies.len());
    assert!(replies.iter().all(|r| r == &[SSH_AGENT_FAILURE]));
    assert_eq!(tpm.keys.len(), 1);

    let (_, replies, _) = run(&frames(&[&[SSH_AGENTC_REQUEST_IDENTITIES]]));
    assert_eq!(
        &replies[0][1..5],
        &1u32.to_be_bytes(),
        "still exactly one identity"
    );
}

#[test]
fn every_single_byte_message_is_answered() {
    let bodies: Vec<[u8; 1]> = (0..=255u8).map(|t| [t]).collect();
    let refs: Vec<&[u8]> = bodies.iter().map(|b| &b[..]).collect();
    let (result, replies, tpm) = run(&frames(&refs));
    result.unwrap();
    assert_eq!(replies.len(), 256);
    for (t, reply) in replies.iter().enumerate() {
        if t == SSH_AGENTC_REQUEST_IDENTITIES as usize {
            assert_eq!(reply[0], SSH_AGENT_IDENTITIES_ANSWER);
        } else {
            assert_eq!(reply, &[SSH_AGENT_FAILURE], "type {t}");
        }
    }
    assert!(tpm.signed.is_empty());
}

#[test]
fn malformed_sign_request_gets_failure_then_a_valid_one_is_served() {
    let tpm = FakeTpm::new(&["gfh-a"]);
    let mut lying = Writer::new();
    lying.u8(SSH_AGENTC_SIGN_REQUEST).u32(0xffff_fff0).u32(0);
    let mut valid = Writer::new();
    valid
        .u8(SSH_AGENTC_SIGN_REQUEST)
        .string(&tpm.blob("gfh-a"))
        .string(b"x")
        .u32(0);
    let (lying, valid) = (lying.into_vec(), valid.into_vec());
    let mut trailing = valid.clone();
    trailing.push(0);
    let truncated = &valid[..valid.len() - 2];

    let (result, replies, _) = run(&frames(&[&lying, &trailing, truncated, &valid]));
    result.unwrap();
    assert_eq!(replies[0], [SSH_AGENT_FAILURE]);
    assert_eq!(replies[1], [SSH_AGENT_FAILURE]);
    assert_eq!(replies[2], [SSH_AGENT_FAILURE]);
    assert_eq!(replies[3][0], SSH_AGENT_SIGN_RESPONSE);
}

#[test]
fn garbage_bytes_never_panic() {
    // Deterministic pseudo-random frames of every size up to 300 bytes.
    let mut x: u32 = 0x1234_5678;
    let mut bodies = Vec::new();
    for len in 1..300 {
        let body: Vec<u8> = (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect();
        bodies.push(body);
    }
    let refs: Vec<&[u8]> = bodies.iter().map(|b| &b[..]).collect();
    let (result, replies, _) = run(&frames(&refs));
    result.unwrap();
    assert_eq!(replies.len(), bodies.len());
}

/// Fails the test if more than `limit` bytes are read.
struct Limited<'a> {
    data: &'a [u8],
    read: usize,
    limit: usize,
}

impl Read for Limited<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = buf.len().min(self.data.len());
        buf[..n].copy_from_slice(&self.data[..n]);
        self.data = &self.data[n..];
        self.read += n;
        assert!(self.read <= self.limit, "read past the frame header");
        Ok(n)
    }
}

#[test]
fn huge_frame_closes_the_connection_without_reading_it() {
    let mut input = vec![0x40, 0, 0, 0]; // 1 GiB
    input.extend_from_slice(&[0; 1024]);
    let mut tpm = FakeTpm::new(&["gfh-a"]);
    let mut output = Vec::new();
    let mut reader = Limited {
        data: &input,
        read: 0,
        limit: 4,
    };
    let err = serve(&mut reader, &mut output, &mut tpm).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(output.is_empty());
}

#[test]
fn empty_frame_closes_the_connection() {
    let (result, replies, _) = run(&[0, 0, 0, 0]);
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    assert!(replies.is_empty());
}

#[test]
fn eof_mid_frame_ends_the_connection_after_earlier_answers() {
    let mut input = frames(&[&[SSH_AGENTC_REQUEST_IDENTITIES]]);
    input.extend_from_slice(&[0, 0, 0, 9, 13, 0]);
    let (result, replies, _) = run(&input);
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    assert_eq!(replies.len(), 1);
}
