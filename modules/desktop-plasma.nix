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

  # Printing support (DISABLED for hardened systems)
  # CUPS has history of CVEs: CVE-2024-47076, CVE-2024-47175, CVE-2023-32360
  # Increases attack surface (network ports 631/tcp, 631/udp)
  services.printing.enable = false;

  # Sound configuration with PipeWire
  # PipeWire provides modern audio/video routing and processing
  services.pulseaudio.enable = false;
  security.rtkit.enable = true;
  services.pipewire = {
    enable = true;
    alsa.enable = true;
    alsa.support32Bit = true;
    pulse.enable = true;
    # JACK support for professional audio applications
    jack.enable = true;
  };

  # KDE-specific configurations
  
  # Enable KDE Partition Manager (useful for disk management)
  # programs.partition-manager.enable = true;
  
  # Enable KDE Connect (phone integration)
  # programs.kdeconnect.enable = true;
  
  # Enable KDE PIM (Personal Information Management)
  # Includes KMail, KOrganizer, KAddressBook, etc.
  # programs.kde-pim.enable = true;
  
  # Configure Qt theming
  qt = {
    enable = true;
    platformTheme = "kde";  # Use KDE platform theme
    style = "breeze";       # Use Breeze style (KDE default)
  };

  # KWallet PAM integration (auto-unlock wallet on login)
  security.pam.services.sddm.kwallet.enable = true;

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

  # XDG Portal for sandboxed applications (Flatpak, etc.)
  xdg.portal = {
    enable = true;
    # KDE portal is automatically added by plasma6
    extraPortals = [ pkgs.xdg-desktop-portal-gtk ];
  };

  # Enable touchpad support (usually enabled by default)
  # services.xserver.libinput.enable = true;
  
  # Wayland-specific tweaks
  
  # Disable screen tearing for Wayland
  # (Usually not needed on Wayland, but can be enabled if issues occur)
  # services.xserver.videoDrivers = [ "modesetting" ];
  
  # Performance optimizations for Wayland
  # services.xserver.displayManager.sddm.settings = {
  #   General = {
  #     DisplayServer = "wayland";
  #     GreeterEnvironment = "QT_WAYLAND_SHELL_INTEGRATION=layer-shell";
  #   };
  # };

  # Notes:
  # - Plasma 6 is the latest version and is Qt 6 based
  # - Wayland is the default and recommended session
  # - X11 session is still available via Xwayland if needed
  # - To switch to X11 session, select "Plasma (X11)" in SDDM
  # - SDDM can also run on Wayland for a full Wayland stack
  #
  # Troubleshooting:
  # - If you experience issues with Wayland, you can temporarily use X11
  # - Check logs: journalctl -xe
  # - Check Plasma logs: ~/.local/share/sddm/
  # - For NVIDIA users, ensure you have the latest drivers and enable:
  #   services.xserver.videoDrivers = [ "nvidia" ];
  #   hardware.nvidia.modesetting.enable = true;
}
