{ config, pkgs, ... }:

let
  vars = import ./includes/variables.nix;
in

{
  # LXQt Desktop Environment Module
  # Lightweight Qt-based desktop environment

  # Enable X11 windowing system (required for LXQt)
  services.xserver.enable = true;

  # Enable LXQt Desktop Environment
  services.xserver.desktopManager.lxqt = {
    enable = true;
  };
}
