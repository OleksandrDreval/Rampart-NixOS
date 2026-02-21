{ config, lib, ... }:

{
  /*
    Coordinator module for centralized service hardening.
    Imports specialized security profiles for various system services.

    Mostly based on templates from: https://github.com/wallago/nix-system-services-hardened
  */

  imports = [
    ./accounts-daemon.nix
    ./display-manager.nix
    ./iwd.nix
    ./NetworkManager.nix
    ./NetworkManager-dispatcher.nix
    ./systemd-rfkill.nix
    ./systemd-udevd.nix
    ./sshd.nix
    ./user-session.nix
  ];
}
