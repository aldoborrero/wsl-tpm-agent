# wsl-tpm-agent Constitution

## Core Principles

### I. Secure by Default

- The agent MUST refuse every request it does not need: only `REQUEST_IDENTITIES` (11) and
  `SIGN_REQUEST` (13) get an answer other than `FAILURE` (5). Adding, removing or locking keys is
  never possible from a client.
- Every length read from the wire MUST be checked against the bytes actually available and against
  the message limit (256 KiB) before anything is allocated or read. Malformed input ends in
  `FAILURE` or a closed connection, never in a panic or an out-of-bounds read.
- Signing MUST pass `NCRYPT_SILENT_FLAG`, so a key whose policy would need a dialog fails instead of
  blocking the agent behind a window nobody sees.
- ECDSA signatures MUST be returned in the SSH wire format (`mpint r`, `mpint s`), never as the raw
  P1363 `r‖s` that NCrypt produces.
- Keys are created non-exportable, without UI policy, and are never overwritten: `keygen` fails if
  the name already exists.
- Logs record that a signature happened (time, size, SSHSIG namespace when present), never the
  signed data.

Rationale: both existing Windows agents we reviewed failed on exactly these points (invalid ECDSA
signatures, unchecked lengths, dialogs that block, clients that can add keys).

### II. No Network Surface

- The agent MUST NOT open a listening socket of any kind: no TCP, no Hyper-V socket, no named pipe.
  It serves exactly one connection, on its own stdin/stdout, and exits at end of input.
- The only way to reach it is a Unix socket in `$XDG_RUNTIME_DIR` owned by systemd
  (`tpm-agent.socket`, `Accept=yes`, mode `0600`), which starts one `.exe` per connection through
  WSL interop.

Rationale: a process that never listens cannot be reached from another distro, VM or host. File
permissions on the user's runtime directory are the whole access control, and they are already
there.

### III. Minimal, Justified Unsafe

- `unsafe` code MUST appear only in the Windows NCrypt adapter, where Rust calls `ncrypt.dll`.
  Every other module carries `#![forbid(unsafe_code)]` or lives in a crate that does.
- Every `unsafe` block MUST carry a `// SAFETY:` comment stating the invariant it relies on
  (enforced by `clippy::undocumented_unsafe_blocks = "deny"`).
- Handles and buffers returned by NCrypt MUST be released by RAII wrappers (`NCryptFreeObject`,
  `NCryptFreeBuffer`), not by hand on each path.

Rationale: the value of writing this in Rust is lost if unsafe spreads past the FFI boundary.

### IV. Platform-Independent, Tested Core

- Everything that can run on Linux (wire codec, message parsing, P1363 to SSH conversion, SSHSIG
  namespace extraction, the agent loop) MUST compile and be tested on `x86_64-unknown-linux-gnu`,
  behind a backend trait that a fake TPM implements in tests.
- Parser and conversion code is written test-first: truncated messages, lying lengths, oversized
  frames, high-bit and leading-zero scalars each have a test before the code that handles them.
- An end-to-end test on Linux drives the agent with a fake backend through the real `ssh-add` and
  `ssh-keygen -Y sign`/`verify`.
- Changes that touch signing are done only after the manual check on sirius (`keygen`, `ssh-add
  -L`, `ssh-keygen -Y sign` without a dialog, `ssh-keygen -Y verify`).

Rationale: Windows binaries cannot run in the Nix build sandbox, so correctness has to be provable
where tests can run.

### V. Reproducible with Nix

- `nix flake check` (crane build, tests, clippy with `--deny warnings` for Linux and Windows,
  module evaluation, treefmt check) MUST pass on every change.
- The Rust toolchain comes only from `rust-toolchain.toml`; the executable is cross-compiled to
  `x86_64-pc-windows-gnu` with nixpkgs' mingw-w64. `Cargo.lock` is committed and builds use
  `--locked`.
- Deployment is the home-manager module this flake exports; nothing is installed on Windows by hand
  except the key itself.

Rationale: one command reproduces the build and every check, here and in CI.

## Technical Constraints

- Language: Rust (edition 2024), standard library first. A crate is added only when it replaces
  substantial code that is easy to get wrong: `windows-sys` for the NCrypt bindings, `sha2` for
  SHA-256. Test-only crates (a software P-256 for the fake TPM) are dev-dependencies.
- Key type: ECDSA P-256 (`ecdsa-sha2-nistp256`) in the Microsoft Platform Crypto Provider, opened
  by name. No X.509 certificate, no RSA.
- Out of scope: Hyper-V sockets, TCP, a Windows service, remote key management, RSA.

## Development Workflow

- Features are specified with Spec Kit (`specs/<NNN-feature>/`): spec, clarifications, plan,
  tasks, then implementation.
- Commits are small and describe only the change. They are signed when the signing key is
  available.
- Prose (README, specs, commit messages) is written plainly, without filler or AI attribution.

## Governance

This constitution overrides other practices in this repository. Amendments are made by editing
this file in a commit that states what changed and why, with the version bumped by semantic
versioning (MAJOR for removed or redefined principles, MINOR for new ones, PATCH for wording).
Every plan (`/speckit-plan`) checks its design against these principles, and any deviation is
written into the plan's Complexity Tracking with its reason. Runtime guidance for agents lives in
`AGENTS.md`.

**Version**: 1.0.0 | **Ratified**: 2026-11-05 | **Last Amended**: 2026-11-05
