# Feature Specification: TPM-backed ssh-agent for WSL

**Feature Branch**: `main` (no feature branch; the repository starts here)
**Created**: 2026-11-05
**Status**: Draft
**Input**: `GOAL.md` and the "Agente TPM", "Detalles de implementación" and "Alternativas
descartadas" sections of `nix-system/docs/plans/2026-11-03-firma-sin-yubikey-design.md`.

## Context

The user signs Git commits with YubiKeys. Coding agents running unattended on sirius (a Windows
machine running NixOS-WSL) also need to sign, with a key that is clearly marked as unattended and
that cannot be copied off the machine. WSL has no TPM device of its own, so the key has to live in
the Windows TPM and be reached from WSL. Two existing Windows agents were reviewed and rejected
(see `README.md`, "Why not an existing agent").

## Clarifications

### Session 2026-11-05

Answered from the design document without waiting for the user, as GOAL.md asks; each decision is
also listed in `HANDOFF.md`.

- Q: Without `--name`, which keys does `agent` list? → A: every P-256 key in the Platform Crypto
  Provider whose name starts with `gfh-` (design doc: "con las claves `gfh-*` del provider").
  With `--name <n>` it lists only `<n>`. `keygen` accepts any name made of letters, digits, `.`,
  `_` and `-` (1 to 64 characters, the first a letter or digit) and warns when it lacks the `gfh-` prefix.
- Q: The design doc says "Módulo NixOS", GOAL.md says home-manager. Which one? → A: home-manager
  (`homeModules.wsl-tpm-agent`, option `services.wsl-tpm-agent`). The units are per-user and
  GOAL.md is the newer, explicit instruction.
- Q: What does the agent do with `SSH_AGENTC_EXTENSION` (27), e.g. the `query` extension? → A:
  `FAILURE`, like every type other than 11 and 13. OpenSSH treats that as "extension not
  supported".
- Q: What about the `flags` field of `SIGN_REQUEST`? → A: it is read and ignored. Its defined bits
  only select RSA hashes; `ecdsa-sha2-nistp256` always uses SHA-256.
- Q: Oversized or empty frame: `FAILURE` or close? → A: close the connection without reading the
  body. Answering `FAILURE` would leave the stream out of sync; OpenSSH's own agent also drops the
  connection here. Messages that fit but are malformed get `FAILURE` and the connection stays open.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Sign with the TPM key from WSL (Priority: P1)

An agent session on sirius-wsl runs `ssh-keygen -Y sign` (directly or through Git and gfh) with
`SSH_AUTH_SOCK` pointing at the TPM agent socket. The signature is made by the key in the Windows
TPM, with no dialog and no touch, and verifies against an `allowed_signers` file.

**Why this priority**: unattended signing is the reason the project exists.

**Independent Test**: with a key created by `keygen`, run `ssh-keygen -Y sign` through the socket
and check the result with `ssh-keygen -Y verify`.

**Acceptance Scenarios**:

1. **Given** a key named `gfh-test` in the TPM and the socket unit running, **When** the user runs
   `ssh-keygen -Y sign -n git -f gfh-test.pub msg`, **Then** a signature file is written without any
   window appearing on Windows.
2. **Given** that signature and an `allowed_signers` line with the public key, **When** the user runs
   `ssh-keygen -Y verify`, **Then** verification succeeds.
3. **Given** a request to sign with a key the agent does not hold, **When** the agent receives it,
   **Then** it answers `FAILURE`.

### User Story 2 - Create the TPM key once (Priority: P1)

The user runs `wsl-tpm-agent.exe keygen --name gfh-sirius` once. A P-256 key is created in the
TPM and its public key is printed in OpenSSH format, ready to add to `allowed_signers` and to
GitHub as a signing key.

**Why this priority**: there is nothing to sign with until the key exists.

**Independent Test**: run `keygen` with a fresh name and check that the printed line parses with
`ssh-keygen -l -f`; run it again with the same name and check that it fails.

**Acceptance Scenarios**:

1. **Given** no key named `gfh-test`, **When** `keygen --name gfh-test` runs, **Then** it prints one
   `ecdsa-sha2-nistp256 AAAA… gfh-test` line and exits 0.
2. **Given** a key named `gfh-test` already exists, **When** `keygen --name gfh-test` runs again,
   **Then** it exits non-zero, says the key exists, and the existing key is unchanged.

### User Story 3 - List the key through the socket (Priority: P2)

`ssh-add -L` with `SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/tpm-agent.sock` prints the TPM public key, so
gfh and ssh-agent-mux can see that the signer is available.

**Why this priority**: gfh decides whether the `sirius-tpm` signer is available from this list.

**Independent Test**: `ssh-add -L` against the socket prints the same line `keygen` printed.

**Acceptance Scenarios**:

1. **Given** the key exists and the home-manager module is enabled, **When** `ssh-add -L` runs
   against the socket, **Then** it prints the key.
2. **Given** interop is broken or the key is gone, **When** `ssh-add -L` runs, **Then** it prints no
   TPM key (or fails), and nothing hangs.

### User Story 4 - Hostile clients cannot do harm (Priority: P2)

Any process that can open the socket may send anything. Garbage, oversized messages and requests
to add or remove keys get `FAILURE` or a closed connection. The agent never panics, never reads
outside its buffers and never changes the set of keys.

**Why this priority**: both rejected alternatives failed here.

**Independent Test**: send crafted messages to the agent (in tests, through the same code path the
executable uses) and check each answer.

**Acceptance Scenarios**:

1. **Given** a frame announcing 1 GiB, **When** the agent reads its header, **Then** it closes the
   connection without allocating or reading the body.
2. **Given** a `SIGN_REQUEST` whose inner key length points past the end of the message, **When** the
   agent parses it, **Then** it answers `FAILURE` and keeps serving.
3. **Given** `SSH_AGENTC_ADD_IDENTITY` (17), `REMOVE_IDENTITY` (18), `REMOVE_ALL_IDENTITIES` (19),
   `LOCK` (22) or an unknown type, **When** the agent receives it, **Then** it answers `FAILURE`.

### Edge Cases

- A frame of length 0 (no message type) is malformed: the connection is closed.
- The connection closes in the middle of a frame header or body: the agent exits quietly.
- A `SIGN_REQUEST` with trailing bytes after the flags is rejected with `FAILURE`.
- The TPM refuses to sign (policy changed so a dialog would be needed, TPM locked out): the agent
  answers `FAILURE` and logs the reason; no window appears.
- `keygen` with an empty name or characters outside `[A-Za-z0-9._-]` fails before touching the
  TPM. A name without the `gfh-` prefix is created with a warning, and `agent` lists it only when
  started with `--name`.
- P-256 signature scalars with the high bit set or with leading zero bytes must still produce
  valid SSH signatures.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: `keygen --name <n>` MUST create a persisted ECDSA P-256 key named `<n>` in the
  Microsoft Platform Crypto Provider, non-exportable and without UI policy, and print its public
  key as one OpenSSH line (`ecdsa-sha2-nistp256 <base64> <n>`).
- **FR-002**: `keygen` MUST fail, without changing anything, when a key with that name exists.
- **FR-003**: `agent` MUST speak the ssh-agent protocol on stdin/stdout for one connection and exit
  when stdin ends.
- **FR-004**: `REQUEST_IDENTITIES` MUST be answered with `IDENTITIES_ANSWER` listing the key named
  by `--name`, or, without `--name`, every P-256 key in the provider whose name starts with
  `gfh-`. The comment of each identity is the key name.
- **FR-005**: `SIGN_REQUEST` for a listed key MUST be answered with `SIGN_RESPONSE` holding an
  `ecdsa-sha2-nistp256` signature over SHA-256 of the data, with `r` and `s` encoded as SSH
  `mpint`s. The request's `flags` are ignored.
- **FR-006**: Signing MUST NOT show any UI; if the key would need UI, signing fails.
- **FR-007**: Every other message type MUST be answered with `FAILURE`. Keys can never be added,
  removed or locked through the agent.
- **FR-008**: Frames longer than 256 KiB, or of length 0, MUST close the connection before the body
  is read. Every length inside a message MUST be checked against the remaining bytes before use;
  a malformed message is answered with `FAILURE`.
- **FR-009**: Each signature MUST log one line to stderr (and so to the journal) with the key name,
  the data size and, when the data is an SSHSIG blob, its namespace. Signed data MUST NOT be
  logged.
- **FR-010**: The flake MUST export a home-manager module (`homeModules.wsl-tpm-agent`) that
  installs a user socket unit
  `tpm-agent.socket` listening on `$XDG_RUNTIME_DIR/tpm-agent.sock` with `Accept=yes`, starting
  `wsl-tpm-agent.exe agent` through WSL interop for each connection, with stderr going to the
  journal.
- **FR-011**: The executable MUST NOT open any network listener, Hyper-V socket or named pipe.

### Key Entities

- **TPM key**: a named, persisted P-256 key in the Platform Crypto Provider. Attributes: name,
  public point. The private part never leaves the TPM.
- **Identity**: what the agent lists: public key blob in SSH format plus a comment (the key name).
- **Frame**: a 4-byte big-endian length followed by that many bytes, the first of which is the
  message type.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: On sirius, `keygen`, `ssh-add -L`, `ssh-keygen -Y sign` and `ssh-keygen -Y verify`
  succeed in sequence with no window shown at any step.
- **SC-002**: Signatures made through the agent verify with stock OpenSSH in 100% of test runs,
  including scalars with the high bit set and with leading zeros.
- **SC-003**: Every malformed-input test (truncated, lying lengths, oversized, add-key, unknown
  type) ends in `FAILURE` or a closed connection with no panic.
- **SC-004**: One signature through the socket completes in under one second on sirius.
- **SC-005**: `nix flake check` and `nix build .#wsl-tpm-agent` pass from a clean checkout.

## Assumptions

- Only sirius-wsl uses this; the Windows user running WSL is the only one who needs the key.
- WSL interop is enabled, so a systemd user service can start a Windows `.exe`.
- Any process of the Windows user can also use the key: the TPM prevents copying it, not using it.
  That is accepted (design doc) and is why the key is registered as unattended.
- Removing the key is done with Windows tools (`certutil -csp "Microsoft Platform Crypto Provider"
  -delkey <name>`); the executable has no `delete` command.
- Out of scope: Hyper-V sockets, TCP, a Windows service, adding keys remotely, RSA.
