{ config, pkgs, ... }:

let
  vars = import ./includes/variables.nix;
in

{
  # LXQt Desktop Environment Module
  # Lightweight Qt-based desktop environment
  #
  # Features:
  # - Lightweight and fast
  # - Qt 6 based (modern toolkit)
  # - Modular architecture
  # - Low resource usage
  # - Highly customizable
  # - Modern and clean interface
  # - Good for older hardware
  # - Wayland support via labwc or wayfire
  #
  # Official Documentation:
  # - https://lxqt-project.org/
  # - https://github.com/lxqt/lxqt
  #
  # NixOS Manual:
  # - https://nixos.org/manual/nixos/stable/options.html#opt-services.xserver.desktopManager.lxqt.enable

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

  # Configure keyboard layout
  services.xserver.xkb = {
    layout = vars.keyboardLayout;
    variant = "";
  };

  # Configure Qt theming for LXQt
  qt = {
    enable = true;
    platformTheme = "lxqt";  # Use LXQt platform theme
  # style = "kvantum";       # Alternative: use Kvantum for theming
  };

  # XDG Portal for sandboxed applications
  xdg.portal = {
    enable = true;
    
    # Enable LXQt portal
    lxqt = {
      enable = true;
      # Additional Qt styles (optional)
      styles = with pkgs; [
        # libsForQt5.qtstyleplugins
        # kvantum
      ];
    };
    
    extraPortals = [ 
      pkgs.xdg-desktop-portal-gtk  # For GTK apps
    ];
    config.common.default = "*";
  };

  # Environment variables
  environment.sessionVariables = {
    # Qt Wayland support
    QT_QPA_PLATFORM = "wayland;xcb";  # Wayland first, X11 fallback
    
    # Firefox Wayland support
    MOZ_ENABLE_WAYLAND = "1";
    
    # Electron apps Wayland support
    NIXOS_OZONE_WL = "1";
  };

  # Power management
  services.upower.enable = true;
}
