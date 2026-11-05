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
