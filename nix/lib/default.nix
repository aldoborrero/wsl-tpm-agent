{ inputs, ... }:
rec {
  # The toolchain pinned by rust-toolchain.toml, including the Windows target the agent is
  # cross-compiled for.
  rustToolchain =
    pkgs:
    (inputs.rust-overlay.lib.mkRustBin { } pkgs).fromRustupToolchainFile ../../rust-toolchain.toml;

  craneLib = pkgs: (inputs.crane.mkLib pkgs).overrideToolchain rustToolchain;

  # Arguments shared by every crane derivation, so they agree on one dependency build.
  commonArgs = pkgs: {
    src = (craneLib pkgs).cleanCargoSource inputs.self;
    strictDeps = true;
  };

  # Workspace dependencies for Linux, compiled once and reused by the tests and clippy.
  cargoArtifacts = pkgs: (craneLib pkgs).buildDepsOnly (commonArgs pkgs);

  # The Windows executable, cross-compiled with nixpkgs' mingw-w64.
  windowsArgs =
    pkgs:
    commonArgs pkgs
    // windowsTargetEnv pkgs
    // {
      pname = "wsl-tpm-agent-exe";
      cargoExtraArgs = "--locked --package wsl-tpm-agent";
      CARGO_BUILD_TARGET = "x86_64-pc-windows-gnu";
      # dlltool for windows-sys raw-dylib imports (ncrypt.dll).
      nativeBuildInputs = [ pkgs.pkgsCross.mingwW64.stdenv.cc ];
      doCheck = false; # Windows binaries cannot run in the Linux build sandbox
    };

  # Dependencies of the Windows executable, shared by its build and its clippy check.
  windowsArtifacts = pkgs: (craneLib pkgs).buildDepsOnly (windowsArgs pkgs);

  # Environment that makes cargo link x86_64-pc-windows-gnu with nixpkgs' mingw-w64.
  windowsTargetEnv =
    pkgs:
    let
      mingw = pkgs.pkgsCross.mingwW64;
      cc = "${mingw.stdenv.cc}/bin/${mingw.stdenv.cc.targetPrefix}cc";
    in
    {
      CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER = cc;
      CC_x86_64_pc_windows_gnu = cc;
      CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUSTFLAGS = "-L native=${mingw.windows.pthreads}/lib";
    };
}
