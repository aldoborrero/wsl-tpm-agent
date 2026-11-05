{ flake, pkgs, ... }:
# Runs every test on Linux, including the end-to-end test that drives the agent (with a fake TPM)
# through ssh-add and ssh-keygen.
(flake.lib.craneLib pkgs).cargoTest (
  flake.lib.commonArgs pkgs
  // {
    cargoArtifacts = flake.lib.cargoArtifacts pkgs;
    cargoTestExtraArgs = "--workspace";
    nativeCheckInputs = [ pkgs.openssh ];
  }
)
