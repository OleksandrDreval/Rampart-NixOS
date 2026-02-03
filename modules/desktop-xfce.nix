{ config, pkgs, ... }:

let
  vars = import ./includes/variables.nix;
in

{
  # XFCE Desktop Environment Module
  # Lightweight, fast, and traditional desktop environment

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
