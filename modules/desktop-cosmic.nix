{ config, pkgs, ... }:

let
  vars = import ./includes/variables.nix;
in

{
  # COSMIC Desktop Environment
  # Note: COSMIC runs natively on Wayland only
  services.desktopManager.cosmic = {
    enable = true;
  };

  # Enable GDM as display manager (recommended for COSMIC)
  services.displayManager.gdm = {
    enable = true;
    wayland = true;  # COSMIC requires Wayland
  };
}
