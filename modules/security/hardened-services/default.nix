{ config, lib, ... }:

  /*
    Hardened services
    Based on: https://github.com/wallago/nix-system-services-hardened
  */

{
  imports = [
    ./accounts-daemon.nix
    ./display-manager.nix
    ./iwd.nix
    ./NetworkManager.nix
    ./NetworkManager-dispatcher.nix
    ./sshd.nix
    ./user-session.nix
  ];
}
