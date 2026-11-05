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
    # $XDG_RUNTIME_DIR/systemd/user comes after ~/.config/systemd/user in the unit search path, so
    # with the module installed the old units would keep running and this would test nothing.
    units="$XDG_RUNTIME_DIR/systemd/user"
    installed=$(systemctl --user show -P FragmentPath tpm-agent.socket)
    if [ -n "$installed" ] && [ "$installed" != "$units/tpm-agent.socket" ]; then
      echo "tpm-agent.socket is already installed at $installed, which takes precedence; disable services.wsl-tpm-agent first" >&2
      exit 1
    fi
    nix build --impure --out-link target/hm --log-format bar-with-logs --expr '
      let f = builtins.getFlake (toString ./.); in
      (f.inputs.home-manager.lib.homeManagerConfiguration {
        pkgs = f.inputs.nixpkgs.legacyPackages.x86_64-linux;
        modules = [ f.homeModules.wsl-tpm-agent {
          home.username = "'"$USER"'"; home.homeDirectory = "'"$HOME"'"; home.stateVersion = "26.05";
          services.wsl-tpm-agent.enable = true;
        } ];
      }).config.home-files'
    mkdir -p "$units"
    cp -fL target/hm/.config/systemd/user/tpm-agent.socket target/hm/.config/systemd/user/tpm-agent@.service "$units/"
    systemctl --user daemon-reload
    systemctl --user restart tpm-agent.socket
    echo "listening on $XDG_RUNTIME_DIR/tpm-agent.sock (remove with: just stop-units)"

# Stop and remove the transient units started by try-units
stop-units:
    #!/usr/bin/env bash
    set -euo pipefail
    units="$XDG_RUNTIME_DIR/systemd/user"
    # Leave a socket installed by home-manager alone.
    [ -e "$units/tpm-agent.socket" ] || { echo "no transient units in $units" >&2; exit 0; }
    systemctl --user stop tpm-agent.socket || true
    rm -f "$units/tpm-agent.socket" "$units/tpm-agent@.service" "$XDG_RUNTIME_DIR/tpm-agent.sock"
    systemctl --user daemon-reload

# Hardware test on the Windows host: create a TPM key, list, sign, verify, delete it again
try-sign name="gfh-test": build
    #!/usr/bin/env bash
    set -euo pipefail
    export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/tpm-agent.sock"
    test -S "$SSH_AUTH_SOCK" || { echo "no socket at $SSH_AUTH_SOCK: enable the module or run just try-units" >&2; exit 1; }
    dir=target/try-sign && rm -rf "$dir" && mkdir -p "$dir"
    delete() { certutil.exe -user -csp "Microsoft Platform Crypto Provider" -delkey "{{ name }}" | tr -d '\r'; }
    ./result/bin/wsl-tpm-agent.exe keygen --name "{{ name }}" | tr -d '\r' > "$dir/key.pub"
    trap delete EXIT
    ssh-add -L | grep -qxF "$(cat "$dir/key.pub")"
    echo "ssh-add -L lists {{ name }}"
    echo hola > "$dir/msg"
    time ssh-keygen -Y sign -n git -f "$dir/key.pub" "$dir/msg"
    echo "test $(cat "$dir/key.pub")" > "$dir/allowed_signers"
    ssh-keygen -Y verify -f "$dir/allowed_signers" -I test -n git -s "$dir/msg.sig" < "$dir/msg"
