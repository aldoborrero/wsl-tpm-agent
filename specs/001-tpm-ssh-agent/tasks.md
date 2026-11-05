# Tasks: TPM-backed ssh-agent for WSL

**Input**: design documents in `specs/001-tpm-ssh-agent/`
**Tests**: required by the constitution (principle IV) and GOAL.md: written before the code they
cover, and seen to fail first.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: can run in parallel (different files, no dependencies)
- **[Story]**: US1 sign, US2 keygen, US3 list, US4 hostile clients

## Phase 1: Setup

- [x] T001 Scaffold the blueprint flake, `nix/lib`, devshell, formatter, package and checks
  (`flake.nix`, `nix/`)
- [x] T002 Initialise Spec Kit and write the constitution (`.specify/`)
- [ ] T003 Create crate `crates/protocol` (`wta-protocol`, `#![forbid(unsafe_code)]`) and add
  `sha2` and dev-dependency `p256` (`crates/protocol/Cargo.toml`)

## Phase 2: Foundational (blocks every story)

- [ ] T004 [P] Tests for the bounded reader and writer: `u32`, `string`, truncated input, a
  length past the end, trailing bytes (`crates/protocol/src/wire.rs`)
- [ ] T005 Implement `wire::Reader`/`Writer` to pass T004 (`crates/protocol/src/wire.rs`)
- [ ] T006 [P] Tests for frame reading: length 0, length above 256 KiB (body never read),
  EOF in header, EOF in body, exact frame (`crates/protocol/src/wire.rs`)
- [ ] T007 Implement `wire::read_frame`/`write_frame` to pass T006
- [ ] T008 [P] Tests for request parsing and response encoding: 11, 13 (valid, truncated, lying
  inner lengths, trailing bytes), unknown types (`crates/protocol/src/message.rs`)
- [ ] T009 Implement `message::Request::parse` and `Response::encode` to pass T008
- [ ] T010 [P] Stderr logger with debug switch `WSL_TPM_AGENT_DEBUG` (`crates/protocol/src/log.rs`)

## Phase 3: US1 - Sign with the TPM key (P1) 🎯 MVP

- [ ] T011 [P] [US1] Tests for mpint and P1363 → SSH signature: high bit set, leading zeros, both,
  zero scalar, wrong input length (`crates/protocol/src/ecdsa.rs`)
- [ ] T012 [US1] Implement `ecdsa::mpint` and `ecdsa::ssh_signature` to pass T011
- [ ] T013 [P] [US1] Tests for SSHSIG namespace extraction: valid blob, not SSHSIG, truncated,
  control characters, long namespace (`crates/protocol/src/sshsig.rs`)
- [ ] T014 [US1] Implement `sshsig::namespace` to pass T013
- [ ] T015 [US1] Fake P-256 backend for tests (`crates/protocol/tests/common/mod.rs`)
- [ ] T016 [US1] Tests for the serve loop: sign with a listed key verifies with `p256`; unknown key
  → FAILURE; backend error → FAILURE (`crates/protocol/src/agent.rs`, `tests/agent.rs`)
- [ ] T017 [US1] Implement `agent::Backend` and `agent::serve` with the signature log line
- [ ] T018 [US1] End-to-end test: Unix socket + fake backend + `ssh-add -L`,
  `ssh-keygen -Y sign`, `ssh-keygen -Y verify` (`crates/protocol/tests/openssh.rs`)
- [ ] T019 [US1] NCrypt adapter: provider/key handles (RAII), open by name, export public, sign
  with `NCRYPT_SILENT_FLAG` (`crates/wsl-tpm-agent/src/ncrypt.rs`)
- [ ] T020 [US1] `agent [--name]` subcommand wiring stdin/stdout to `serve`
  (`crates/wsl-tpm-agent/src/main.rs`)

## Phase 4: US2 - Create the key (P1)

- [ ] T021 [P] [US2] Tests for the public blob, base64 and the OpenSSH line against a known
  `ssh-keygen` output (`crates/protocol/src/ecdsa.rs`, `crates/protocol/src/base64.rs`)
- [ ] T022 [US2] Implement `ecdsa::public_blob`, `base64::encode`, `ecdsa::openssh_line`
- [ ] T023 [P] [US2] Tests for argument parsing and key name rules (`crates/wsl-tpm-agent/src/cli.rs`)
- [ ] T024 [US2] Implement `cli::parse` to pass T023
- [ ] T025 [US2] `keygen`: refuse an existing name, create, finalize silently, print the line
  (`crates/wsl-tpm-agent/src/ncrypt.rs`, `main.rs`)

## Phase 5: US3 - List through the socket (P2)

- [ ] T026 [US3] Enumerate `gfh-*` P-256 keys when `--name` is absent (`ncrypt.rs`)
- [ ] T027 [US3] home-manager module: `tpm-agent.socket` (`Accept=yes`, `%t/tpm-agent.sock`,
  `0600`) and `tpm-agent@.service` (socket stdin/stdout, `StandardError=journal`)
  (`nix/modules/home/wsl-tpm-agent.nix`)
- [ ] T028 [US3] Module evaluation check (`nix/checks/home-module.nix`)

## Phase 6: US4 - Hostile clients (P2)

- [ ] T029 [US4] Tests over the serve loop: garbage, 1 GiB header, add/remove/lock/extension
  requests, malformed sign request then a valid one on the same connection, EOF mid-frame
  (`crates/protocol/tests/hostile.rs`)

## Phase 7: Polish

- [ ] T030 `just try-sign` recipe for the hardware test (`justfile`)
- [ ] T031 README written with crafting-effective-readmes, passed through humanizer (`README.md`)
- [ ] T032 `AGENTS.md` (+ `CLAUDE.md` symlink)
- [ ] T033 Run every acceptance command: `cargo test`, `cargo clippy -D warnings`, `nix fmt`,
  `nix flake check`, `nix build .#wsl-tpm-agent`
- [ ] T034 Hardware test on sirius (quickstart.md), then delete `gfh-test`
- [ ] T035 `HANDOFF.md`: state, hardware results, decisions, unsigned commits, nix-system steps

## Dependencies

- T003 → Phase 2 → stories. T005 before T009; T009 and T012 before T017; T017 before T018 and
  T029. T019 before T020, T025, T026. T024 before T020 and T025.
- US1 and US2 share the Windows adapter; US3 needs the package; US4 only needs T017.
