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

  # Configure keyboard layout
  services.xserver.xkb = {
    layout = vars.keyboardLayout;
    variant = "";
  };

  # Enable Thunar file manager with additional features
  programs.thunar = {
    enable = true;
    plugins = with pkgs.xfce; [
      thunar-archive-plugin    # Archive support
      thunar-volman           # Volume management
      thunar-media-tags-plugin # Media tags
    ];
  };

  # Enable Xfconf (XFCE configuration storage)
  programs.xfconf.enable = true;

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

  # XFCE-specific packages
  environment.systemPackages = with pkgs; [
    # XFCE applications (already included by default)
    # xfce.xfce4-taskmanager      # Task manager
    # xfce.xfce4-terminal         # Terminal emulator
    # xfce.xfce4-screenshooter    # Screenshot tool
    # xfce.xfce4-panel            # Panel
    # xfce.xfdesktop              # Desktop manager
    # xfce.thunar                 # File manager
    # xfce.ristretto              # Image viewer
    # xfce.mousepad               # Text editor
    
    # Additional XFCE plugins (optional)
    # xfce.xfce4-pulseaudio-plugin    # PulseAudio plugin
    # xfce.xfce4-weather-plugin       # Weather plugin
    # xfce.xfce4-systemload-plugin    # System load plugin
    # xfce.xfce4-netload-plugin       # Network load plugin
    # xfce.xfce4-cpugraph-plugin      # CPU graph plugin
    # xfce.xfce4-diskperf-plugin      # Disk performance plugin
    # xfce.xfce4-fsguard-plugin       # File system guard plugin
    # xfce.xfce4-genmon-plugin        # Generic monitor plugin
    # xfce.xfce4-timer-plugin         # Timer plugin
    # xfce.xfce4-clipman-plugin       # Clipboard manager
    # xfce.xfce4-whiskermenu-plugin   # Application menu
    
    # Useful applications for XFCE
    # mate.engrampa         # Archive manager (GTK 3)
    # gnome.file-roller     # Archive manager (GNOME)
    # gnome.evince          # Document viewer
    # vlc                   # Media player
    # gimp                  # Image editor
  ];

  # Exclude unwanted XFCE packages (optional)
  # environment.xfce.excludePackages = with pkgs.xfce; [
  #   xfce4-screensaver
  #   xfburn  # CD/DVD burning application
  #   parole  # Media player
  # ];

  # Environment variables for Wayland (if using Wayland session)
  environment.sessionVariables = {
    # Firefox Wayland support
    MOZ_ENABLE_WAYLAND = "1";
    
    # Electron apps Wayland support
    NIXOS_OZONE_WL = "1";
    
    # GTK Wayland backend
    GDK_BACKEND = "wayland,x11";  # Wayland first, X11 fallback
  };
}
