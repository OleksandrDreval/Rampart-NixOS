{ config, pkgs, ... }:

let
  vars = import ./includes/variables.nix;
in

{
  # COSMIC Desktop Environment Module
  # Next-generation desktop environment by System76
  #
  # Features:
  # - Modern Rust-based desktop (memory safe)
  # - Native Wayland compositor
  # - Tiling window management
  # - Customizable and fast
  # - Developed by System76 (Pop!_OS)
  # - Focus on productivity
  # - GTK 4 and iced-based applications
  # - No X11 dependency (Wayland-only)
  #
  # Official Documentation:
  # - https://github.com/pop-os/cosmic-epoch
  # - https://system76.com/cosmic
  #
  # NixOS Manual:
  # - https://nixos.org/manual/nixos/stable/options.html#opt-services.desktopManager.cosmic.enable

  # COSMIC Desktop Environment
  # Note: COSMIC runs natively on Wayland only
  services.desktopManager.cosmic = {
    enable = true;
    
    # Enable Xwayland for legacy X11 applications
    xwayland.enable = true;
  };

  # Enable GDM as display manager (recommended for COSMIC)
  services.displayManager.gdm = {
    enable = true;
    wayland = true;  # COSMIC requires Wayland
  };
}
