{ config, pkgs, ... }:

let
  vars = import ./includes/variables.nix;
in

{
  # MATE Desktop Environment Module
  # Traditional desktop environment, continuation of GNOME 2
  #
  # Features:
  # - Traditional GNOME 2 interface
  # - Lightweight and fast
  # - GTK 3 based
  # - Familiar and intuitive
  # - Low resource usage
  # - Stable and reliable
  # - Experimental Wayland support
  #
  # Official Documentation:
  # - https://mate-desktop.org/
  # - https://wiki.mate-desktop.org/
  #
  # NixOS Manual:
  # - https://nixos.org/manual/nixos/stable/options.html#opt-services.xserver.desktopManager.mate.enable

  # Enable X11 windowing system (required for MATE)
  services.xserver.enable = true;

  # Enable MATE Desktop Environment
  services.xserver.desktopManager.mate = {
    enable = true;
    
    # Enable experimental Wayland session
    # Note: Wayland support is experimental
    enableWaylandSession = true;
    
    # Enable debug messages (set to true for troubleshooting)
    debug = false;
  };

  # Display Manager: LightDM (recommended for MATE)
  services.xserver.displayManager.lightdm = {
    enable = true;
    
    # LightDM GTK Greeter
    greeters.gtk = {
      enable = true;
      # Theme configuration
      # theme.name = "Arc-Dark";
      # iconTheme.name = "Papirus-Dark";
    };
  };

  # Enable Xwayland for Wayland session support
  programs.xwayland.enable = true;
}
