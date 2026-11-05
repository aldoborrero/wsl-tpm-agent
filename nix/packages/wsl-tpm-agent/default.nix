{ flake, pkgs, ... }:
pkgs.callPackage ./package.nix {
  craneLib = flake.lib.craneLib pkgs;
  windowsArgs = flake.lib.windowsArgs pkgs;
  windowsArtifacts = flake.lib.windowsArtifacts pkgs;
}
