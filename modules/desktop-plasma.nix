{ config, pkgs, ... }:

let
  vars = import ./includes/variables.nix;
in

{
  # KDE Plasma 6 Desktop Environment Module
  # Modern, feature-rich desktop environment with Wayland support
  #
  # Features:
  # - Full Wayland support (native)
  # - Xwayland for legacy X11 applications
  # - Qt 6 based (modern toolkit)
  # - Highly customizable
  # - Integrated applications ecosystem
  # - Advanced power management
  # - KDE Connect integration
  #
  # Official Documentation:
  # - https://userbase.kde.org/Plasma
  # - https://develop.kde.org/docs/plasma/
  #
  # NixOS Manual:
  # - https://nixos.org/manual/nixos/stable/options.html#opt-services.desktopManager.plasma6.enable

  # Enable KDE Plasma 6 Desktop Environment
  # Plasma 6 runs natively on Wayland by default
  services.desktopManager.plasma6 = {
    enable = true;
    
    # Enable Qt 5 integration for backward compatibility
    # Set to false for a pure Qt 6 system
    enableQt5Integration = true;
  };
}
