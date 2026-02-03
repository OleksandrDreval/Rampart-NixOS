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

  # Printing support (DISABLED for hardened systems)
  # CUPS has history of CVEs: CVE-2024-47076, CVE-2024-47175, CVE-2023-32360
  # Increases attack surface (network ports 631/tcp, 631/udp)
  services.printing.enable = false;

  # Sound configuration is handled by modules/audio.nix
  # See that module for PipeWire configuration and security details

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

  # Enable NetworkManager (recommended)
  # networking.networkmanager.enable = true;

  # Bluetooth support (optional)
  # hardware.bluetooth.enable = true;

  # Notes:
  # - COSMIC is the next-generation desktop by System76
  # - Written in Rust for memory safety and performance
  # - Wayland-native (no X11 support, only Xwayland for legacy apps)
  # - Inspired by Pop!_OS but more modular and customizable
  # - Focus on productivity with tiling window management
  # - Still in active development (some features may be incomplete)
  # - Uses its own compositor (cosmic-comp) based on Smithay
  #
  # Key Features:
  # - Tiling window management: Automatic window organization
  # - Workspaces: Multiple virtual desktops
  # - COSMIC Launcher: Quick application and command launcher
  # - COSMIC Panel: Customizable top panel
  # - COSMIC Applets: System tray, notifications, etc.
  # - COSMIC Settings: Comprehensive settings application
  # - Keyboard-first workflow: Many keyboard shortcuts
  #
  # Window Management:
  # - Automatic tiling with smart placement
  # - Manual tiling with keyboard shortcuts
  # - Floating windows support
  # - Multiple monitor support
  # - Workspace-per-monitor or global workspaces
  #
  # Keyboard Shortcuts (default):
  # - Super: Open launcher
  # - Super+T: Open terminal
  # - Super+F: Toggle fullscreen
  # - Super+Arrow: Move focus between windows
  # - Super+Shift+Arrow: Move windows
  # - Super+Number: Switch workspace
  # - Super+Shift+Number: Move window to workspace
  #
  # Customization:
  # - COSMIC Settings for all configuration
  # - Theme customization: Light/Dark themes
  # - Panel configuration: Position, size, applets
  # - Keyboard shortcuts: Fully customizable
  # - Window management: Tiling behavior, gaps, etc.
  #
  # Development Status:
  # - Alpha/Beta stage (as of 2024-2026)
  # - Rapidly evolving with frequent updates
  # - Some features may not be complete
  # - Check GitHub for latest development status
  #
  # Troubleshooting:
  # - Check logs: journalctl -xe
  # - COSMIC logs: ~/.local/share/cosmic/
  # - For compositor issues: cosmic-comp --replace
  # - For panel issues: cosmic-panel --replace
  # - NVIDIA users: Ensure latest drivers and Wayland support
  #   hardware.nvidia.modesetting.enable = true;
  #   hardware.nvidia.open = true;  # For newer GPUs
  #
  # System Requirements:
  # - Modern GPU with Wayland support
  # - Vulkan support recommended
  # - At least 4GB RAM (8GB+ recommended)
  # - Works best on AMD and Intel GPUs
  # - NVIDIA requires proprietary drivers with Wayland support
  #
  # Comparison with other DEs:
  # - More modern than GNOME (Wayland-native)
  # - More productive than traditional DEs (tiling)
  # - Lighter than KDE Plasma
  # - More polished than other tiling compositors
  # - Rust-based (memory safe, unlike C/C++ DEs)
  #
  # Migration Notes:
  # - Coming from GNOME: Similar workflow but with tiling
  # - Coming from Pop!_OS: COSMIC is the evolution of Pop Shell
  # - Coming from i3/sway: More user-friendly with GUI configuration
  # - Coming from Windows: Launcher similar to Windows Search
}
