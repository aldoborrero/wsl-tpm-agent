# Quickstart: validate the TPM-backed ssh-agent

## On any Linux machine

```bash
nix flake check          # build, tests (incl. ssh-add/ssh-keygen e2e with a fake TPM), clippy, fmt
nix build .#wsl-tpm-agent
```

## On sirius (hardware)

Prerequisites: the home-manager module enabled (or the units from
`nix/modules/home/wsl-tpm-agent.nix` started by hand), WSL interop working.

```bash
exe=$(nix build .#wsl-tpm-agent --print-out-paths)/bin/wsl-tpm-agent.exe
"$exe" keygen --name gfh-test | tr -d '\r' > target/gfh-test.pub
SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/tpm-agent.sock ssh-add -L          # lists gfh-test
echo hola > target/msg
SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/tpm-agent.sock \
  ssh-keygen -Y sign -n git -f target/gfh-test.pub target/msg     # no window appears
echo "test $(cat target/gfh-test.pub)" > target/allowed_signers
ssh-keygen -Y verify -f target/allowed_signers -I test -n git -s target/msg.sig < target/msg
certutil.exe -csp "Microsoft Platform Crypto Provider" -delkey gfh-test
```

Expected: `ssh-add -L` prints the same key `keygen` printed; verify prints `Good "git" signature
for test`; no window at any step. `just try-sign` runs the same sequence.
