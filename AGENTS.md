# AGENTS.md

wsl-tpm-agent: an ssh-agent for WSL that signs with an ECDSA P-256 key in the Windows TPM
(Microsoft Platform Crypto Provider, NCrypt). `wsl-tpm-agent.exe` serves one connection on
stdin/stdout; a systemd user socket with `Accept=yes` starts it through WSL interop.

## Layout

| Path | What |
| --- | --- |
| `crates/protocol/` | lib `wta-protocol`, `#![forbid(unsafe_code)]`: `wire.rs` (bounded reader, 256 KiB frames), `message.rs` (requests 11/13, responses 5/12/14), `ecdsa.rs` (P-256 blob, OpenSSH line, P1363 → mpint signature, `BCRYPT_ECCPUBLIC_BLOB` parsing), `base64.rs`, `sshsig.rs` (namespace for the log), `agent.rs` (`Backend` trait, serve loop), `log.rs`; `tests/` = fake TPM (`common/`), serve loop, hostile clients, OpenSSH end to end |
| `crates/wsl-tpm-agent/` | bin `wsl-tpm-agent(.exe)`: `cli.rs` (arguments, key name rules, tested on Linux), `ncrypt.rs` (Windows only, the only `unsafe`), `main.rs` |
| `nix/` | blueprint prefix: `lib/` (toolchain, crane args, Windows cross env), `packages/wsl-tpm-agent/`, `checks/` (`tests` with openssh, `clippy`, `clippy-windows`, `home-module`), `modules/home/wsl-tpm-agent.nix` (`services.wsl-tpm-agent`), `devshell.nix`, `formatter.nix` |
| `specs/001-tpm-ssh-agent/`, `.specify/` | Spec Kit: spec (with clarifications), plan, research, contracts, tasks; constitution in `.specify/memory/` |
| `HANDOFF.md` | state of the work, hardware results, decisions, what is left |

## Commands

| Task | Command |
| --- | --- |
| list recipes | `just` |
| tests | `just test` |
| lint | `just lint` |
| format | `just fmt` |
| everything CI runs | `just check` (`nix flake check`) |
| build the `.exe` | `just build` → `result/bin/` |
| transient socket units from this checkout | `just try-units` / `just stop-units` |
| hardware test (Windows TPM) | `just try-sign [name]` |

## Invariants

- Only `REQUEST_IDENTITIES` (11) and `SIGN_REQUEST` (13) are answered; everything else gets
  `FAILURE` (5). Never add a way to add, remove or lock keys through the protocol.
- Every length from the wire goes through `wire::Reader`; frames of length 0 or above 256 KiB
  close the connection before the body is read.
- NCrypt calls pass `NCRYPT_SILENT_FLAG` wherever the API accepts it. `keygen` never passes
  `NCRYPT_OVERWRITE_KEY_FLAG`.
- Signatures leave as `string "ecdsa-sha2-nistp256"`, `string (mpint r ‖ mpint s)`; the tests
  cover high-bit and leading-zero scalars and verify with OpenSSH.
- The executable never opens a listener. In the unit, `StandardError=journal` is required:
  the default would send stderr into the socket.
- `unsafe` only in `ncrypt.rs`, each block with `// SAFETY:`; handles and buffers in RAII
  wrappers.
- Windows binaries cannot run in the build sandbox: keep testable logic in `wta-protocol` or
  `cli.rs`.
- `windows-sys` links via raw-dylib, so the Windows build needs mingw's `dlltool` (in
  `nativeBuildInputs` and the devshell).
- Flakes see only tracked files: `git add` new files before any `nix` command.
- In this user's shell `ssh-add` is an alias that forces `SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/ssh-agent`;
  call `command ssh-add` (or anything not starting with `ssh-add`) to talk to the TPM socket.
