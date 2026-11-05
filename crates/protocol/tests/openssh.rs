//! End to end on Linux: the serve loop behind a Unix socket, the fake TPM as backend, and stock
//! OpenSSH as the client: `ssh-add -L`, `ssh-keygen -Y sign` and `ssh-keygen -Y verify`.
//! Needs `ssh-add` and `ssh-keygen` on PATH (the devshell and `checks.tests` provide them).

mod common;

use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::{fs, thread};

use common::FakeTpm;
use wta_protocol::agent::serve;
use wta_protocol::ecdsa;

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("wta-{tag}-{}", std::process::id()));
        _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        _ = fs::remove_dir_all(&self.0);
    }
}

/// Binds the socket and serves each connection, like systemd with `Accept=yes` starting one
/// agent per connection.
fn start_agent(socket: &Path) {
    let listener = UnixListener::bind(socket).unwrap();
    thread::spawn(move || {
        for conn in listener.incoming() {
            let conn = conn.unwrap();
            thread::spawn(move || {
                let mut tpm = FakeTpm::new(&["gfh-test"]);
                let mut input = &conn;
                let mut output = &conn;
                _ = serve(&mut input, &mut output, &mut tpm);
            });
        }
    });
}

fn run(dir: &Path, socket: &Path, program: &str, args: &[&str], stdin: Option<&Path>) -> Output {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .current_dir(dir)
        .env("SSH_AUTH_SOCK", socket)
        .env("HOME", dir)
        .stdin(match stdin {
            Some(p) => Stdio::from(fs::File::open(p).unwrap()),
            None => Stdio::null(),
        });
    let out = cmd
        .output()
        .unwrap_or_else(|e| panic!("{program} must be on PATH: {e}"));
    assert!(
        out.status.success(),
        "{program} {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

#[test]
fn ssh_add_lists_and_ssh_keygen_signs_and_verifies() {
    let tmp = TempDir::new("openssh");
    let dir = tmp.0.as_path();
    let socket = dir.join("tpm-agent.sock");
    start_agent(&socket);

    let line = ecdsa::openssh_line(&FakeTpm::new(&["gfh-test"]).point("gfh-test"), "gfh-test");
    fs::write(dir.join("gfh-test.pub"), format!("{line}\n")).unwrap();

    let listed = run(dir, &socket, "ssh-add", &["-L"], None);
    assert_eq!(String::from_utf8(listed.stdout).unwrap().trim_end(), line);

    fs::write(dir.join("msg"), "hola\n").unwrap();
    run(
        dir,
        &socket,
        "ssh-keygen",
        &["-Y", "sign", "-n", "git", "-f", "gfh-test.pub", "msg"],
        None,
    );
    assert!(dir.join("msg.sig").exists());

    fs::write(dir.join("allowed_signers"), format!("test {line}\n")).unwrap();
    let verified = run(
        dir,
        &socket,
        "ssh-keygen",
        &[
            "-Y",
            "verify",
            "-f",
            "allowed_signers",
            "-I",
            "test",
            "-n",
            "git",
            "-s",
            "msg.sig",
        ],
        Some(&dir.join("msg")),
    );
    let said = String::from_utf8_lossy(&verified.stdout);
    assert!(said.contains("Good \"git\" signature for test"), "{said}");
}
