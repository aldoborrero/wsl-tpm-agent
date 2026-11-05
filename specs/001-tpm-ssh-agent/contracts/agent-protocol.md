# Contract: ssh-agent protocol subset

Reference: draft-ietf-sshm-ssh-agent; OpenSSH PROTOCOL.agent.

| Request | Answer |
|---|---|
| `SSH_AGENTC_REQUEST_IDENTITIES` (11), no payload | `SSH_AGENT_IDENTITIES_ANSWER` (12): `uint32 nkeys`, then per key `string key_blob`, `string comment` |
| `SSH_AGENTC_SIGN_REQUEST` (13): `string key_blob`, `string data`, `uint32 flags` | `SSH_AGENT_SIGN_RESPONSE` (14): `string signature` for a listed key; `SSH_AGENT_FAILURE` (5) for an unknown key or a signing error |
| any other type, including 17, 18, 19, 22, 23, 25, 27 | `SSH_AGENT_FAILURE` (5) |

## Limits and malformed input

- Frame length 0 or above 262144: the connection is closed; the body is not read.
- Connection ends mid-frame: the agent exits.
- Message 11 with payload, or 13 with truncated fields, lengths past the end, or trailing bytes:
  `FAILURE`, and the connection stays open.
- `flags` in 13 is ignored.

## Logging (stderr)

- Per signature: `signed key=<name> bytes=<len(data)> namespace=<ns|->`.
- Per refused request: `refused type=<n>` at debug level only (`WSL_TPM_AGENT_DEBUG` set).
- Signing errors with the NCrypt status code, at error level.
