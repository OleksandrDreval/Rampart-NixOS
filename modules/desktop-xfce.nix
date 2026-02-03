{ config, pkgs, ... }:

let
  vars = import ./includes/variables.nix;
in

{
  # XFCE Desktop Environment Module
  # Lightweight, fast, and traditional desktop environment
  #
  # Features:
  # - Lightweight and fast
  # - Traditional desktop layout
  # - Highly customizable
  # - GTK 3 based
  # - Modular architecture
  # - Low resource usage
  # - Experimental Wayland support (via labwc compositor)
  #
  # Official Documentation:
  # - https://docs.xfce.org/
  # - https://wiki.xfce.org/
  #
  # NixOS Manual:
  # - https://nixos.org/manual/nixos/stable/options.html#opt-services.xserver.desktopManager.xfce.enable

  # Enable X11 windowing system (required for XFCE)
  services.xserver.enable = true;

  # Enable XFCE Desktop Environment
  services.xserver.desktopManager.xfce = {
    enable = true;
    
    # Enable experimental Wayland session (uses labwc compositor)
    # Note: Wayland support is still experimental in XFCE
    # Set to false if you experience issues
    enableWaylandSession = true;
    
    # Don't install desktop components (set to true for minimal setup)
    noDesktop = false;
    
    # Enable XFCE screensaver
    enableScreensaver = true;
  };

  # Display Manager: LightDM (lightweight, traditional)
  services.xserver.displayManager.lightdm = {
    enable = true;
    
    # LightDM greeters (choose one)
    greeters.gtk = {
      enable = true;
      # Theme configuration
      # theme.name = "Adwaita-dark";
      # iconTheme.name = "Adwaita";
    };
  };

  # Enable Xwayland for Wayland session (if enableWaylandSession = true)
  programs.xwayland.enable = true;
}
