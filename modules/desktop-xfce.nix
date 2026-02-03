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

  # Printing support (DISABLED for hardened systems)
  # CUPS has history of CVEs: CVE-2024-47076, CVE-2024-47175, CVE-2023-32360
  # Increases attack surface (network ports 631/tcp, 631/udp)
  services.printing.enable = false;

  # Sound configuration is handled by modules/audio.nix
  # See that module for PipeWire configuration and security details

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

  # GTK theme configuration
  # programs.dconf.enable = true;  # Required for GTK settings

  # XDG Portal for sandboxed applications
  xdg.portal = {
    enable = true;
    extraPortals = [ 
      pkgs.xdg-desktop-portal-gtk 
      # pkgs.xdg-desktop-portal-xapp  # For better Cinnamon/MATE/XFCE integration
    ];
    config.common.default = "*";
  };

  # Environment variables for Wayland (if using Wayland session)
  environment.sessionVariables = {
    # Firefox Wayland support
    MOZ_ENABLE_WAYLAND = "1";
    
    # Electron apps Wayland support
    NIXOS_OZONE_WL = "1";
    
    # GTK Wayland backend
    GDK_BACKEND = "wayland,x11";  # Wayland first, X11 fallback
  };

  # Power management (xfce4-power-manager)
  # Already included in XFCE, but you can configure it here
  # services.xserver.displayManager.lightdm.greeters.gtk.indicators = [
  #   "~host" "~spacer" "~clock" "~spacer" "~session" "~power"
  # ];

  # Notes:
  # - XFCE is a traditional X11 desktop environment
  # - Wayland support is experimental via labwc compositor
  # - If Wayland causes issues, set enableWaylandSession = false
  # - XFCE is known for being lightweight and fast
  # - Great for older hardware or users who prefer traditional UI
  # - Highly customizable through its settings manager
  #
  # Troubleshooting:
  # - If Wayland session doesn't work, use X11 session
  # - Check logs: journalctl -xe
  # - XFCE logs: ~/.xsession-errors
  # - For display issues, try: services.xserver.videoDrivers = [ "modesetting" ];
}
