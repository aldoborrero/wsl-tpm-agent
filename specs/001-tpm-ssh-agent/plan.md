# Implementation Plan: TPM-backed ssh-agent for WSL

**Branch**: `main` | **Date**: 2026-11-05 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `specs/001-tpm-ssh-agent/spec.md`

## Summary

A Windows executable, `wsl-tpm-agent.exe`, with two subcommands: `keygen` creates a P-256 key in
the Microsoft Platform Crypto Provider and prints it in OpenSSH format; `agent` serves the
ssh-agent protocol for one connection on stdin/stdout and signs with `NCryptSignHash` and
`NCRYPT_SILENT_FLAG`. A home-manager module adds a systemd user socket with `Accept=yes` that
starts one `.exe` per connection through WSL interop. Everything except the NCrypt adapter
compiles and is tested on Linux, behind a `Backend` trait that a software P-256 key implements in
tests.

## Technical Context

**Language/Version**: Rust 1.99.1 (edition 2024), pinned in `rust-toolchain.toml`
**Primary Dependencies**: `windows-sys` 0.61 (NCrypt, Windows only), `sha2` (SHA-256);
dev-only: `p256` (software key for the fake TPM)
**Storage**: the TPM, through the Platform Crypto Provider (keys persisted by name)
**Testing**: `cargo test` on Linux (unit tests for codec and conversion, agent loop with a fake
backend, end-to-end through real `ssh-add`/`ssh-keygen` over a Unix socket); manual hardware test
on sirius
**Target Platform**: `x86_64-pc-windows-gnu` executable, started from NixOS-WSL (`x86_64-linux`)
**Project Type**: CLI executable plus a Nix flake with a home-manager module
**Performance Goals**: one signature in under 1 s end to end (process start dominates)
**Constraints**: no network listener; 256 KiB frame limit; no UI ever; unsafe only in the NCrypt
adapter
**Scale/Scope**: one user, one or a few keys, a handful of signatures per minute

## Constitution Check

| Principle | How the design meets it |
|---|---|
| I. Secure by default | Only types 11 and 13 answered; lengths checked by a bounded reader before use; `NCRYPT_SILENT_FLAG` on open, sign and finalize; P1363 converted to two mpints; `keygen` never passes `NCRYPT_OVERWRITE_KEY_FLAG`; logs carry key name, size and namespace only. |
| II. No network surface | The executable only reads stdin and writes stdout/stderr. The socket belongs to systemd (`ListenStream=%t/tpm-agent.sock`, `SocketMode=0600`). |
| III. Minimal, justified unsafe | `wta-protocol` and the CLI parser carry `#![forbid(unsafe_code)]`; `unsafe` lives in `ncrypt.rs` only, each block with `// SAFETY:`, handles and buffers in RAII wrappers. |
| IV. Tested core | Codec, messages, mpint conversion, SSHSIG parsing and the serve loop are in `wta-protocol`, tested on Linux; the e2e test runs stock OpenSSH against the fake backend. |
| V. Reproducible with Nix | crane builds, `checks.{tests,clippy,clippy-windows,home-module}`, treefmt check; `--locked`. |

Gate result: pass, no deviations. Re-checked after Phase 1: pass.

## Project Structure

### Documentation (this feature)

```text
specs/001-tpm-ssh-agent/
├── spec.md
├── plan.md              # this file
├── research.md          # Phase 0
├── data-model.md        # Phase 1
├── quickstart.md        # Phase 1
├── contracts/
│   ├── cli.md           # subcommands, output, exit codes
│   └── agent-protocol.md# accepted messages, answers, limits
├── checklists/requirements.md
└── tasks.md             # /speckit-tasks
```

### Source Code (repository root)

```text
crates/
├── protocol/                 # lib wta-protocol, #![forbid(unsafe_code)], all tested on Linux
│   ├── src/lib.rs
│   ├── src/wire.rs           # bounded Reader, Writer, frame read/write (256 KiB limit)
│   ├── src/message.rs        # Request parse / Response encode, message numbers
│   ├── src/ecdsa.rs          # P-256 public blob, OpenSSH line, P1363 → SSH signature
│   ├── src/base64.rs         # encoder for the OpenSSH public key line
│   ├── src/sshsig.rs         # namespace extraction from an SSHSIG to-be-signed blob
│   ├── src/agent.rs          # Backend trait, serve loop
│   ├── src/log.rs            # stderr logger
│   └── tests/
│       ├── fake.rs           # software P-256 Backend (shared by the tests)
│       ├── hostile.rs        # garbage, lying lengths, oversized, add-key
│       └── openssh.rs        # ssh-add -L, ssh-keygen -Y sign/verify over a Unix socket
└── wsl-tpm-agent/            # bin wsl-tpm-agent(.exe)
    ├── src/main.rs           # entry point, dispatch
    ├── src/cli.rs            # argument parsing and key name rules (tested on Linux)
    └── src/ncrypt.rs         # Windows only: NCrypt calls, Backend impl, keygen
nix/
├── lib/default.nix           # toolchain, crane args, Windows cross env
├── packages/wsl-tpm-agent/   # the .exe in $out/bin
├── checks/                   # tests (with openssh), clippy, clippy-windows, home-module
├── modules/home/wsl-tpm-agent.nix
├── devshell.nix
└── formatter.nix
```

**Structure Decision**: two crates, following the reference project (wsl-fido-bridge): a
platform-independent library that holds all logic that can be tested on Linux, and a thin binary
whose Windows-only module talks to `ncrypt.dll`.

## Complexity Tracking

No constitution violations to justify.
