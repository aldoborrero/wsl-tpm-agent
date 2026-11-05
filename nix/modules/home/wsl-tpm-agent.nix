{ flake, ... }:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.wsl-tpm-agent;
in
{
  options.services.wsl-tpm-agent = {
    enable = lib.mkEnableOption "an ssh-agent socket that signs with a P-256 key in the Windows TPM, through WSL interop";

    package = lib.mkOption {
      type = lib.types.package;
      default = flake.packages.${pkgs.stdenv.hostPlatform.system}.wsl-tpm-agent;
      defaultText = lib.literalExpression "wsl-tpm-agent.packages.\${system}.wsl-tpm-agent";
      description = "Package providing `bin/wsl-tpm-agent.exe`.";
    };

    keyName = lib.mkOption {
      type = lib.types.nullOr (lib.types.strMatching "[A-Za-z0-9._-]{1,64}");
      default = null;
      example = "gfh-sirius";
      description = "Offer only this TPM key. When null, every `gfh-*` P-256 key is offered.";
    };

    debug = lib.mkEnableOption "debug lines in the journal (`WSL_TPM_AGENT_DEBUG`)";
  };

  config = lib.mkIf cfg.enable {
    # One agent process per connection: systemd owns the socket, the .exe only ever sees its
    # stdin/stdout. Clients use SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/tpm-agent.sock (or ssh-agent-mux).
    systemd.user.sockets.tpm-agent = {
      Unit.Description = "ssh-agent backed by the Windows TPM (wsl-tpm-agent)";
      Socket = {
        ListenStream = "%t/tpm-agent.sock";
        Accept = true;
        SocketMode = "0600";
        DirectoryMode = "0700";
      };
      Install.WantedBy = [ "sockets.target" ];
    };

    systemd.user.services."tpm-agent@" = {
      Unit.Description = "wsl-tpm-agent connection";
      Service = {
        ExecStart = lib.escapeShellArgs (
          [
            "${cfg.package}/bin/wsl-tpm-agent.exe"
            "agent"
          ]
          ++ lib.optionals (cfg.keyName != null) [
            "--name"
            cfg.keyName
          ]
        );
        StandardInput = "socket";
        StandardOutput = "socket";
        # Not the default (inherit), which would follow stdout into the socket and corrupt the
        # protocol stream.
        StandardError = "journal";
        # WSLENV forwards the variable to the Windows process.
        Environment = lib.optionals cfg.debug [
          "WSL_TPM_AGENT_DEBUG=1"
          "WSLENV=WSL_TPM_AGENT_DEBUG"
        ];
      };
    };
  };
}
