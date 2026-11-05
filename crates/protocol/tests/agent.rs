//! The serve loop against the fake TPM: identities, signatures that verify, and refusals.

mod common;

use common::FakeTpm;
use sha2::{Digest as _, Sha256};
use wta_protocol::agent::{handle, serve};
use wta_protocol::message::*;
use wta_protocol::wire::{Reader, Writer, read_frame, write_frame};

fn sign_request(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(SSH_AGENTC_SIGN_REQUEST).string(key).string(data).u32(0);
    w.into_vec()
}

fn signature_from(reply: &[u8]) -> Vec<u8> {
    let mut r = Reader::new(reply);
    assert_eq!(r.u8().unwrap(), SSH_AGENT_SIGN_RESPONSE, "reply: {reply:?}");
    let sig = r.string().unwrap().to_vec();
    r.finish().unwrap();
    sig
}

#[test]
fn lists_every_key_with_its_name_as_comment() {
    let mut tpm = FakeTpm::new(&["gfh-a", "gfh-b"]);
    let reply = handle(&[SSH_AGENTC_REQUEST_IDENTITIES], &mut tpm);
    let mut r = Reader::new(&reply);
    assert_eq!(r.u8().unwrap(), SSH_AGENT_IDENTITIES_ANSWER);
    assert_eq!(r.u32().unwrap(), 2);
    assert_eq!(r.string().unwrap(), tpm.blob("gfh-a"));
    assert_eq!(r.string().unwrap(), b"gfh-a");
    assert_eq!(r.string().unwrap(), tpm.blob("gfh-b"));
    assert_eq!(r.string().unwrap(), b"gfh-b");
    r.finish().unwrap();
}

#[test]
fn signs_sha256_of_the_data_with_the_requested_key() {
    let mut tpm = FakeTpm::new(&["gfh-a", "gfh-b"]);
    let data = b"SSHSIG and some data";
    let reply = handle(&sign_request(&tpm.blob("gfh-b"), data), &mut tpm);
    let digest: [u8; 32] = Sha256::digest(data).into();
    assert_eq!(tpm.signed, [digest]);
    let sig = signature_from(&reply);
    assert!(common::verify(&tpm.verifying_key("gfh-b"), &digest, &sig));
    assert!(!common::verify(&tpm.verifying_key("gfh-a"), &digest, &sig));
}

/// NCrypt returns fixed-width r‖s; scalars with the high bit set or with leading zero bytes are
/// the cases a raw copy gets wrong. Sign until both have been seen in r and in s, and check that
/// every signature verifies and every mpint is canonical.
#[test]
fn signatures_verify_for_high_bit_and_leading_zero_scalars() {
    let mut tpm = FakeTpm::new(&["gfh-a"]);
    let blob = tpm.blob("gfh-a");
    let vk = tpm.verifying_key("gfh-a");
    let (mut high_bit, mut leading_zero) = (0, 0);
    for i in 0u32..20_000 {
        let data = i.to_be_bytes();
        let sig = signature_from(&handle(&sign_request(&blob, &data), &mut tpm));
        let digest: [u8; 32] = Sha256::digest(data).into();
        assert!(common::verify(&vk, &digest, &sig), "signature {i}");
        let (r, s) = common::ssh_signature_parts(&sig);
        for m in [r, s] {
            match m.len() {
                33 => high_bit += 1,
                n if n < 32 => leading_zero += 1,
                _ => {}
            }
        }
        if high_bit > 0 && leading_zero > 0 && i > 100 {
            return;
        }
    }
    panic!("not enough coverage: {high_bit} high-bit, {leading_zero} leading-zero scalars");
}

#[test]
fn unknown_key_gets_failure() {
    let mut tpm = FakeTpm::new(&["gfh-a"]);
    let other = FakeTpm::new(&["x", "gfh-other"]).blob("gfh-other");
    assert_eq!(handle(&sign_request(&other, b"d"), &mut tpm), [SSH_AGENT_FAILURE]);
    assert!(tpm.signed.is_empty());
}

#[test]
fn backend_refusal_gets_failure() {
    let mut tpm = FakeTpm::new(&["gfh-a"]);
    tpm.refuse = true;
    let blob = tpm.blob("gfh-a");
    assert_eq!(handle(&sign_request(&blob, b"d"), &mut tpm), [SSH_AGENT_FAILURE]);
}

#[test]
fn serve_answers_each_frame_until_eof() {
    let mut tpm = FakeTpm::new(&["gfh-a"]);
    let mut input = Vec::new();
    write_frame(&mut input, &[SSH_AGENTC_REQUEST_IDENTITIES]).unwrap();
    write_frame(&mut input, &sign_request(&tpm.blob("gfh-a"), b"hola")).unwrap();
    write_frame(&mut input, &[17]).unwrap();
    let mut output = Vec::new();
    serve(&mut &input[..], &mut output, &mut tpm).unwrap();

    let mut out = &output[..];
    assert_eq!(read_frame(&mut out).unwrap().unwrap()[0], SSH_AGENT_IDENTITIES_ANSWER);
    assert_eq!(read_frame(&mut out).unwrap().unwrap()[0], SSH_AGENT_SIGN_RESPONSE);
    assert_eq!(read_frame(&mut out).unwrap().unwrap(), [SSH_AGENT_FAILURE]);
    assert_eq!(read_frame(&mut out).unwrap(), None);
}
