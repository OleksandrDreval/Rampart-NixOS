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

  # Display Manager: SDDM (recommended for LXQt)
  services.displayManager.sddm = {
    enable = true;
    
    # Wayland support (experimental for LXQt)
    wayland.enable = true;
  };

  # Enable Xwayland for compatibility
  programs.xwayland.enable = true;
}
