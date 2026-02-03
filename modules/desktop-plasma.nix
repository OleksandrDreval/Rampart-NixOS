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

  # Enable SDDM (Simple Desktop Display Manager)
  # SDDM is the recommended display manager for KDE Plasma
  services.displayManager.sddm = {
    enable = true;
    
    # Enable Wayland support for SDDM
    # This allows SDDM to run on Wayland instead of X11
    wayland.enable = true;
  };

  # Enable Xwayland for backward compatibility with X11 applications
  # This allows running legacy X11 apps on Wayland
  programs.xwayland.enable = true;

  # Configure keyboard layout (applies to both Wayland and Xwayland)
  services.xserver.xkb = {
    layout = vars.keyboardLayout;
    variant = "";
  };

  # Environment variables for Wayland
  environment.sessionVariables = {
    # Force Qt applications to use Wayland
    QT_QPA_PLATFORM = "wayland;xcb";  # Wayland first, X11 fallback
    
    # Enable Wayland for Qt 5 applications
    QT_WAYLAND_DISABLE_WINDOWDECORATION = "1";
    
    # Firefox Wayland support
    MOZ_ENABLE_WAYLAND = "1";
    
    # Electron apps Wayland support
    NIXOS_OZONE_WL = "1";
  };

  # Additional KDE packages (optional)
  environment.systemPackages = with pkgs; [
    # KDE applications
    # kdePackages.kate           # Advanced text editor
    # kdePackages.konsole        # Terminal emulator
    # kdePackages.dolphin        # File manager
    # kdePackages.gwenview       # Image viewer
    # kdePackages.okular         # Document viewer
    # kdePackages.spectacle      # Screenshot utility
    # kdePackages.kdenlive       # Video editor
    # kdePackages.krita          # Digital painting
    # kdePackages.ark            # Archive manager
    # kdePackages.kcalc          # Calculator
    
    # System tools
    # libsForQt5.kio-admin       # Admin file access (Qt5)
    # kdePackages.kio-admin      # Admin file access (Qt6)
    # kdePackages.plasma-browser-integration  # Browser integration
  ];
}
