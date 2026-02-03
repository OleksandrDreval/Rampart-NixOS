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

  # Configure keyboard layout
  services.xserver.xkb = {
    layout = vars.keyboardLayout;
    variant = "";
  };

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
    jack.enable = true;
  };

  # COSMIC-specific packages
  environment.systemPackages = with pkgs; [
    # COSMIC applications (many are already included)
    # cosmic-term            # Terminal emulator
    # cosmic-edit            # Text editor
    # cosmic-files           # File manager
    # cosmic-store           # App store
    # cosmic-settings        # Settings application
    # cosmic-comp            # Compositor
    # cosmic-panel           # Panel
    # cosmic-launcher        # Application launcher
    # cosmic-applets         # System applets
    # cosmic-workspaces      # Workspace management
    
    # Additional useful applications
    # firefox                # Web browser
    # gnome.nautilus         # Alternative file manager
    # vlc                    # Media player
    # gimp                   # Image editor
  ];

  # Environment variables for Wayland
  environment.sessionVariables = {
    # Force Wayland for Qt applications
    QT_QPA_PLATFORM = "wayland";
    
    # GTK Wayland backend
    GDK_BACKEND = "wayland";
    
    # Firefox Wayland support
    MOZ_ENABLE_WAYLAND = "1";
    
    # Electron apps Wayland support
    NIXOS_OZONE_WL = "1";
    
    # COSMIC-specific environment variables
    COSMIC_DATA_CONTROL_ENABLED = "1";
  };

  # XDG Portal for sandboxed applications
  xdg.portal = {
    enable = true;
    extraPortals = [ 
      pkgs.xdg-desktop-portal-cosmic  # COSMIC portal
      pkgs.xdg-desktop-portal-gtk     # For GTK apps
    ];
    config.common.default = "*";
  };

  # Power management
  services.upower.enable = true;
}
