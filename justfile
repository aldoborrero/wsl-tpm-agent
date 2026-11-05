# wsl-tpm-agent

default:
    @just --list

# Run the test suite
test *args:
    cargo test --workspace {{ args }}

# Lint (Linux, then the Windows-only NCrypt adapter)
lint:
    cargo clippy --workspace --all-targets -- --deny warnings
    cargo clippy --package wsl-tpm-agent --target x86_64-pc-windows-gnu --all-targets -- --deny warnings

# Format everything (nix, rust, yaml, toml, markdown, shell)
fmt:
    nix fmt

# Every check CI runs
check:
    nix flake check --log-format bar-with-logs

# Build the Windows executable into ./result/bin
build:
    nix build .#wsl-tpm-agent --log-format bar-with-logs

# Build the Windows executable with cargo (devshell provides the mingw linker)
build-exe:
    cargo build --package wsl-tpm-agent --target x86_64-pc-windows-gnu

# Create a worktree for a feature branch under .worktrees/
worktree branch:
    git worktree add .worktrees/{{ branch }} -b {{ branch }}

# Start tpm-agent.socket from this checkout's module, as transient units in $XDG_RUNTIME_DIR (gone on reboot)
try-units:
    #!/usr/bin/env bash
    set -euo pipefail
    nix build --impure --out-link target/hm --log-format bar-with-logs --expr '
      let f = builtins.getFlake (toString ./.); in
      (f.inputs.home-manager.lib.homeManagerConfiguration {
        pkgs = f.inputs.nixpkgs.legacyPackages.x86_64-linux;
        modules = [ f.homeModules.wsl-tpm-agent {
          home.username = "'"$USER"'"; home.homeDirectory = "'"$HOME"'"; home.stateVersion = "26.05";
          services.wsl-tpm-agent.enable = true;
        } ];
      }).config.home-files'
    units="$XDG_RUNTIME_DIR/systemd/user"
    mkdir -p "$units"
    cp -fL target/hm/.config/systemd/user/tpm-agent.socket target/hm/.config/systemd/user/tpm-agent@.service "$units/"
    systemctl --user daemon-reload
    systemctl --user restart tpm-agent.socket
    echo "listening on $XDG_RUNTIME_DIR/tpm-agent.sock (remove with: just stop-units)"

# Stop and remove the transient units started by try-units
stop-units:
    systemctl --user stop tpm-agent.socket || true
    rm -f "$XDG_RUNTIME_DIR/systemd/user/tpm-agent.socket" "$XDG_RUNTIME_DIR/systemd/user/tpm-agent@.service"
    systemctl --user daemon-reload
    systemctl --user reset-failed 'tpm-agent@*' || true

# Hardware test on the Windows host: create a TPM key, list, sign, verify, delete it again
try-sign name="gfh-test": build
    #!/usr/bin/env bash
    set -euo pipefail
    export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/tpm-agent.sock"
    test -S "$SSH_AUTH_SOCK" || { echo "no socket at $SSH_AUTH_SOCK: enable the module or run just try-units" >&2; exit 1; }
    dir=target/try-sign && rm -rf "$dir" && mkdir -p "$dir"
    delete() { certutil.exe -user -csp "Microsoft Platform Crypto Provider" -delkey {{ name }} | tr -d '\r'; }
    ./result/bin/wsl-tpm-agent.exe keygen --name {{ name }} | tr -d '\r' > "$dir/key.pub"
    trap delete EXIT
    ssh-add -L | grep -qxF "$(cat "$dir/key.pub")"
    echo "ssh-add -L lists {{ name }}"
    echo hola > "$dir/msg"
    time ssh-keygen -Y sign -n git -f "$dir/key.pub" "$dir/msg"
    echo "test $(cat "$dir/key.pub")" > "$dir/allowed_signers"
    ssh-keygen -Y verify -f "$dir/allowed_signers" -I test -n git -s "$dir/msg.sig" < "$dir/msg"
