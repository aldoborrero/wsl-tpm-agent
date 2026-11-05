{
  lib,
  craneLib,
  windowsArgs,
  windowsArtifacts,
}:
# wsl-tpm-agent.exe: talks to ncrypt.dll; launched through WSL interop, one process per connection.
craneLib.buildPackage (
  windowsArgs
  // {
    pname = "wsl-tpm-agent";
    cargoArtifacts = windowsArtifacts;

    meta = {
      description = "ssh-agent for WSL that signs with an ECDSA P-256 key kept in the Windows TPM";
      homepage = "https://github.com/aldoborrero/wsl-tpm-agent";
      license = lib.licenses.asl20;
      sourceProvenance = with lib.sourceTypes; [ fromSource ];
      maintainers = with lib.maintainers; [ aldoborrero ];
      mainProgram = "wsl-tpm-agent.exe";
      platforms = [ "x86_64-linux" ];
    };
  }
)
