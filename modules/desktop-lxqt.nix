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

  # LXQt-specific packages
  environment.systemPackages = with pkgs; [
    # LXQt core applications (many are already included)
    # lxqt.lxqt-config          # Configuration center
    # lxqt.pcmanfm-qt           # File manager
    # lxqt.qterminal            # Terminal emulator
    # lxqt.lximage-qt           # Image viewer
    # lxqt.lxqt-archiver        # Archive manager
    # lxqt.lxqt-runner          # Application launcher
    # lxqt.lxqt-notificationd   # Notification daemon
    # lxqt.lxqt-policykit       # PolicyKit agent
    # lxqt.lxqt-powermanagement # Power management
    # lxqt.lxqt-qtplugin        # Qt platform integration
    # lxqt.lxqt-session         # Session manager
    # lxqt.lxqt-sudo            # Graphical sudo
    # lxqt.pavucontrol-qt       # PulseAudio volume control
    # lxqt.qps                  # Process manager
    # lxqt.screengrab           # Screenshot tool
    
    # Additional useful applications
    # featherpad                # Lightweight text editor
    # qpdfview                  # PDF viewer
    # nomacs                    # Image viewer
    # vlc                       # Media player
    # kde-partitionmanager      # Partition manager (Qt-based)
  ];

  # Exclude unwanted LXQt packages (optional)
  # environment.lxqt.excludePackages = with pkgs.lxqt; [
  #   # Example: exclude packages you don't need
  # ];

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

  # Enable NetworkManager (usually preferred)
  # networking.networkmanager.enable = true;

  # Bluetooth support (optional)
  # hardware.bluetooth.enable = true;
  # services.blueman.enable = true;

  # Compositor (for visual effects)
  # LXQt uses Openbox or KWin by default
  # You can configure compositor in LXQt Session Settings

  # PCManFM-Qt file manager configuration
  programs.thunar = {
    # Enable if you prefer Thunar over PCManFM-Qt
    enable = false;
  };

  # Notes:
  # - LXQt is the Qt port of LXDE (Lightweight X11 Desktop Environment)
  # - One of the lightest full-featured desktop environments
  # - Great for older hardware or users who want minimal resource usage
  # - Uses Openbox window manager by default (can be changed)
  # - Qt 6 based (modern and actively maintained)
  # - Modular design allows customization
  # - Wayland support is experimental (via wayfire or labwc)
  #
  # Customization:
  # - LXQt Configuration Center for all settings
  # - Themes: Use LXQt Appearance settings
  # - Can use Kvantum for advanced Qt theming
  # - Qt5ct/Qt6ct for additional Qt styling
  #
  # Window Managers:
  # - Default: Openbox (lightweight, configurable)
  # - Alternative: KWin (more features, effects)
  # - Can be changed in LXQt Session Settings
  #
  # Wayland Compositors (experimental):
  # - labwc (Openbox-like Wayland compositor)
  # - wayfire (3D Wayland compositor)
  # Enable with: programs.labwc.enable or programs.wayfire.enable
  #
  # Troubleshooting:
  # - Check logs: journalctl -xe
  # - Session logs: ~/.xsession-errors
  # - LXQt settings: ~/.config/lxqt/
  # - For graphics issues: services.xserver.videoDrivers = [ "modesetting" ];
  # - If panel crashes: lxqt-panel --replace &
  #
  # Comparison with other DEs:
  # - Lighter than KDE Plasma, GNOME, Cinnamon, MATE
  # - Similar weight to XFCE but Qt-based
  # - More modern than LXDE (its predecessor)
  # - More customizable than most lightweight DEs
}
