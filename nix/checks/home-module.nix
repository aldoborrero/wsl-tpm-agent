# Evaluates the home-manager module and checks the units it generates, without activating them.
{
  flake,
  inputs,
  pkgs,
  system,
  ...
}:
let
  eval =
    extra:
    (inputs.home-manager.lib.homeManagerConfiguration {
      inherit pkgs;
      modules = [
        flake.homeModules.wsl-tpm-agent
        {
          home.username = "check";
          home.homeDirectory = "/home/check";
          home.stateVersion = "26.05";
          services.wsl-tpm-agent.enable = true;
        }
        extra
      ];
    }).config;
  cfg = eval { };
  named = eval { services.wsl-tpm-agent.keyName = "gfh-sirius"; };
  exe = "${flake.packages.${system}.wsl-tpm-agent}/bin/wsl-tpm-agent.exe";
  socket = cfg.systemd.user.sockets.tpm-agent;
  service = cfg.systemd.user.services."tpm-agent@".Service;
  # Compare the strings without their store-path context.
  plain = builtins.unsafeDiscardStringContext;
in
assert socket.Socket.ListenStream == "%t/tpm-agent.sock";
assert socket.Socket.Accept;
assert socket.Socket.SocketMode == "0600";
assert socket.Install.WantedBy == [ "sockets.target" ];
assert plain (toString service.ExecStart) == plain "${exe} agent";
assert service.StandardInput == "socket";
assert service.StandardOutput == "socket";
assert service.StandardError == "journal";
assert
  plain (toString named.systemd.user.services."tpm-agent@".Service.ExecStart)
  == plain "${exe} agent --name gfh-sirius";
pkgs.runCommand "home-module-check" { } "touch $out"
