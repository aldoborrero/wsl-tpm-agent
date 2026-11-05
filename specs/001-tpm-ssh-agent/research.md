# Research: TPM-backed ssh-agent for WSL

## R1. Key creation in the Platform Crypto Provider

- **Decision**: `NCryptOpenStorageProvider(MS_PLATFORM_CRYPTO_PROVIDER)`, then
  `NCryptCreatePersistedKey(BCRYPT_ECDSA_P256_ALGORITHM, name, 0, flags = 0)` and
  `NCryptFinalizeKey(NCRYPT_SILENT_FLAG)`. No properties are set: the PCP default export policy is
  "not exportable" and no UI policy means no PIN or consent dialog.
- **Existing key**: before creating, `NCryptOpenKey` with the same name. If it opens, `keygen`
  stops with "key exists". Without `NCRYPT_OVERWRITE_KEY_FLAG`, create/finalize also fail with
  `NTE_EXISTS`, so a race between the check and the create cannot overwrite anything.
- **Alternatives**: setting `NCRYPT_EXPORT_POLICY_PROPERTY = 0` explicitly (redundant, and some
  providers reject properties they do not support); a self-signed certificate in `CurrentUser\My`
  as both reviewed agents need (rejected: the design asks to open the key by name).

## R2. Public key export and SSH encoding

- **Decision**: `NCryptExportKey(BCRYPT_ECCPUBLIC_BLOB)` gives `BCRYPT_ECCKEY_BLOB { dwMagic,
  cbKey }` followed by `X‖Y`. Accept it only when `dwMagic == BCRYPT_ECDSA_PUBLIC_P256_MAGIC`
  (`ECS1`) and `cbKey == 32`. The SSH blob is `string "ecdsa-sha2-nistp256"`, `string "nistp256"`,
  `string (0x04‖X‖Y)` (RFC 5656 §3.1).
- **Why the magic and not the algorithm property**: the PKCS11SSHAgent review notes that the PCP
  may report the algorithm property as the group (`ECDSA`) rather than `ECDSA_P256`, and the key
  length as 0. The exported blob is unambiguous.

## R3. Listing keys

- **Decision**: `NCryptEnumKeys(provider, scope = NULL, NCRYPT_SILENT_FLAG)` until
  `NTE_NO_MORE_ITEMS`; keep names starting with `gfh-`, open each and export its public blob (R2);
  skip keys that are not P-256. Free each `NCryptKeyName` and the enum state with
  `NCryptFreeBuffer`.
- With `--name`, skip enumeration and open that name only.

## R4. Signing

- **Decision**: SHA-256 of the data in Rust (`sha2`), then `NCryptSignHash(key, padding = NULL,
  digest, 32, sig, 64, NCRYPT_SILENT_FLAG)`. The result is P1363 `r‖s`, 32 bytes each.
- Keys are opened with `NCryptOpenKey(..., NCRYPT_SILENT_FLAG)` too.
- **Encoding**: SSH wants `string "ecdsa-sha2-nistp256"`, `string (mpint r ‖ mpint s)` (RFC 5656
  §3.1.2). An mpint drops leading zero bytes and prepends `0x00` when the first remaining byte has
  its high bit set; zero is the empty string (RFC 4251 §5).
- **Why not BCrypt for hashing**: it would add a second set of unsafe calls for no benefit.

## R5. Transport and process model

- **Decision**: systemd user socket `tpm-agent.socket` with `ListenStream=%t/tpm-agent.sock`,
  `Accept=yes`, `SocketMode=0600`; template `tpm-agent@.service` with `StandardInput=socket`,
  `StandardOutput=socket` and `StandardError=journal`.
- **Why `StandardError=journal` explicitly**: with `StandardOutput=socket`, the default
  `StandardError=inherit` would send stderr into the socket and corrupt the protocol stream.
- **Interop**: the unit runs the `.exe` from the Nix store; WSL's binfmt handler starts it as a
  Windows process of the logged-in user. Cost: a process start per connection (tens of ms).

## R6. Frame limits and parsing

- **Decision**: read the 4-byte length; if it is 0 or above 256 KiB, close without reading more.
  Otherwise read exactly that many bytes into a buffer and parse with a bounded reader whose every
  `u32`/`string` read checks the remaining length first and returns an error, never panics.
  `SIGN_REQUEST` must be consumed exactly (no trailing bytes).
- OpenSSH's own `ssh-agent` uses the same 256 KiB limit (`AGENT_MAX_LEN`).

## R7. SSHSIG namespace for the log line

- **Decision**: if the data starts with the 6-byte magic `SSHSIG`, parse `uint32 version`,
  `string namespace` and log the namespace with non-printable characters escaped and the length
  capped at 64. Otherwise log `namespace=-`. (PROTOCOL.sshsig, "Signed Data".)

## R8. Testing without a TPM

- **Decision**: a `Backend` trait (`identities()`, `sign(name, digest)`), implemented by the
  NCrypt adapter on Windows and by a `p256` software key in tests. The end-to-end test binds a
  Unix socket in a temp dir, serves each connection with the fake backend in a thread, and runs
  `ssh-add -L`, `ssh-keygen -Y sign` and `ssh-keygen -Y verify`. Nix's `checks.tests` adds
  `openssh` to `nativeCheckInputs`.
- Known vectors for mpint: hand-written scalars with high bit set, with leading zeros, both, and
  zero, plus signatures from the fake key checked by `p256` verification and by OpenSSH.

## R9. Spec Kit invocation

- GOAL.md says `specify init . --ai claude`. Spec Kit 1.1.0 (nixpkgs) renamed the flag:
  `specify init --here --integration claude --script sh --non-interactive` was used instead.
