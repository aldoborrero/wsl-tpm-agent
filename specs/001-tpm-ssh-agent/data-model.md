# Data Model: TPM-backed ssh-agent for WSL

## Key name

- 1 to 64 characters from `[A-Za-z0-9._-]`, the first a letter or digit, so a name is never
  taken for an option. Validated by `keygen` and `agent --name` before any
  NCrypt call.
- `agent` without `--name` lists only names starting with `gfh-`.

## TPM key (Windows, Platform Crypto Provider)

| Field | Value |
|---|---|
| Algorithm | `ECDSA_P256` |
| Name | key name above |
| Export policy | provider default (not exportable) |
| UI policy | none |
| Public point | `X‖Y`, 32 bytes each, from `BCRYPT_ECCPUBLIC_BLOB` |

Lifecycle: created once by `keygen`; never modified or deleted by the executable; deleted by the
user with `certutil -csp "Microsoft Platform Crypto Provider" -delkey <name>`.

## Identity (agent side)

| Field | Encoding |
|---|---|
| key blob | `string "ecdsa-sha2-nistp256"`, `string "nistp256"`, `string (0x04‖X‖Y)` |
| comment | key name, UTF-8 |

A `SIGN_REQUEST` is matched to an identity by byte-for-byte equality of the key blob.

## Frame

`uint32 length` (big endian, 1..=262144) followed by `length` bytes; byte 0 is the message type.

## Signature

P1363 `r‖s` (64 bytes) → `string "ecdsa-sha2-nistp256"`, `string (mpint r ‖ mpint s)`.
