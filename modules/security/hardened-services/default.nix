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

    # User service hardening (seccomp-based)
    ./user-services/pipewire-user.nix
    ./user-services/plasma-desktop-user.nix
    ./user-services/wireplumber-user.nix
    ./user-services/xdg-desktop-portal-user.nix
  ];
}
