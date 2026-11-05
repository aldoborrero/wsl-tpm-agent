# Contract: command line

```text
wsl-tpm-agent.exe keygen --name <name>
wsl-tpm-agent.exe agent [--name <name>]
wsl-tpm-agent.exe --help | -h
wsl-tpm-agent.exe --version | -V
```

## keygen

- Creates the key (see data-model.md) and writes one line to stdout:
  `ecdsa-sha2-nistp256 <base64 blob> <name>`, then exits 0.
- Name without the `gfh-` prefix: key is created; a warning on stderr says `agent` will list it
  only with `--name`.
- Exit 1 with a message on stderr when the name is invalid, the key already exists, or NCrypt
  fails. Nothing is written to stdout in that case.
- Does not read stdin.

## agent

- Serves the protocol in [agent-protocol.md](agent-protocol.md) on stdin/stdout until stdin ends,
  then exits 0. Exits 1 after closing a connection because of a framing error.
- stderr carries log lines only: `wsl-tpm-agent: <level>: <message>`.

## Errors

- Unknown subcommand or option, missing value: usage on stderr, exit 2.
- On Linux, the binary prints "only runs on Windows" and exits 1 (it is built there only for
  tests and clippy).
