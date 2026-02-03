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

  # Configure keyboard layout
  services.xserver.xkb = {
    layout = vars.keyboardLayout;
    variant = "";
  };

  # Enable touchpad support
  services.xserver.libinput.enable = true;

  # Enable printing support
  services.printing.enable = true;

  # Sound configuration with PipeWire
  services.pulseaudio.enable = false;
  security.rtkit.enable = true;
  services.pipewire = {
    enable = true;
    alsa.enable = true;
    alsa.support32Bit = true;
    pulse.enable = true;
    # JACK support (optional)
    # jack.enable = true;
  };

  # MATE-specific packages
  environment.systemPackages = with pkgs; [
    # MATE applications (many are already included)
    # mate.caja                    # File manager
    # mate.pluma                   # Text editor
    # mate.atril                   # Document viewer
    # mate.eom                     # Image viewer
    # mate.mate-terminal           # Terminal emulator
    # mate.mate-calc               # Calculator
    # mate.mate-screenshot         # Screenshot tool
    # mate.mate-system-monitor     # System monitor
    # mate.mate-power-manager      # Power management
    # mate.mate-control-center     # Control center
    
    # Additional panel applets (optional)
    # mate.mate-applets            # Collection of applets
    # mate.mate-sensors-applet     # Hardware sensors
    # mate.mate-netbook            # Netbook enhancements
    
    # Archive manager
    # mate.engrampa                # Archive manager (MATE)
    # gnome.file-roller            # Alternative archive manager
    
    # Additional useful applications
    # vlc                          # Media player
    # gparted                      # Partition editor
    # gnome.gnome-disk-utility     # Disk utility
  ];

  # Add extra panel applets (optional)
  # services.xserver.desktopManager.mate.extraPanelApplets = with pkgs.mate; [
  #   mate-applets
  #   mate-sensors-applet
  # ];

  # Exclude unwanted MATE packages (optional)
  # environment.mate.excludePackages = with pkgs.mate; [
  #   mate-terminal  # If you prefer another terminal
  # ];

  # Enable MATE-specific services
  services.gnome.gnome-keyring.enable = true;  # Keyring for password management

  # XDG Portal for sandboxed applications
  xdg.portal = {
    enable = true;
    extraPortals = [ 
      pkgs.xdg-desktop-portal-gtk
      pkgs.xdg-desktop-portal-xapp  # Better integration for MATE
    ];
    config.common.default = "*";
  };

  # GTK theme configuration
  # programs.dconf.enable = true;  # Required for GTK settings

  # Environment variables
  environment.sessionVariables = {
    # Firefox Wayland support (if using Wayland session)
    MOZ_ENABLE_WAYLAND = "1";
    
    # Electron apps Wayland support
    NIXOS_OZONE_WL = "1";
    
    # GTK backend
    GDK_BACKEND = "wayland,x11";  # Wayland first, X11 fallback
  };

  # Power management
  services.upower.enable = true;
}
