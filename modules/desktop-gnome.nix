{ config, pkgs, ... }:

let
  vars = import ./includes/variables.nix;
in

{
  # Import X11 auto-isolation module (automatic for all X11 apps)
  imports = [
    ./x11-auto-isolation.nix  # Automatic X11 isolation for legacy applications
  # ./sandbox-x11.nix         # Optional: for manual detailed configuration
  ];

  #############################################################################
  # GNOME Desktop Environment with Wayland and Security Hardening
  #############################################################################
  # Architecture:
  # - Wayland-native compositor (secure display protocol)
  # - XDG Desktop Portals for sandboxed application access
  # - Automatic X11 isolation via nix-bwrapper + xwayland-satellite
  # - Bubblewrap for low-level sandboxing (user namespaces)
  # - NO shared Xwayland (each X11 app has isolated X server)
  #############################################################################

  # Enable GNOME Desktop Environment (Wayland-native)
  services.desktopManager.gnome.enable = true;

  # Enable GDM (GNOME Display Manager) with Wayland support
  services.displayManager.gdm = {
    enable = true;
    wayland = true;  # Native Wayland session (default: true)
  };

  # Configure keyboard layout (applies to Wayland and Xwayland)
  services.xserver.xkb = {
    layout = vars.keyboardLayout;
    variant = "";
  };

  #############################################################################
  # XDG Desktop Portals - Sandboxed Application Interface
  #############################################################################
  # GNOME automatically enables xdg-desktop-portal-gnome
  # Provides secure APIs: FileChooser, Screenshot, ScreenCast, etc.
  # Used by sandboxed applications (nix-bwrapper, etc.)
  # See: https://flatpak.github.io/xdg-desktop-portal/
  xdg.portal.enable = true;

  #############################################################################
  # X11 Auto-Isolation - Automatic Legacy Application Sandboxing
  #############################################################################
  # Module x11-auto-isolation.nix provides:
  # - Automatic isolation of ALL X11 applications (without manual configuration)
  # - Nixpkgs overlay: automatically wraps X11-only packages (build-time)
  # - Runtime wrapper: x11-launch for any X11 programs
  # - xwayland-satellite: each X11 application gets a separate X server
  # - Filesystem, D-Bus, network sandboxing via bubblewrap
  # - Data stored in $HOME/.bwrapper/auto/{app-id}/

  security.x11AutoIsolation = {
    enable = true;
    mode = "both";  # overlay (nixpkgs) + wrapper (runtime)
    disableCompositorXwayland = false;  # true after verifying everything works
    
    # Default isolation settings
    isolationSettings = {
      allowAudio = true;
      allowWayland = false;  # Pure X11 mode
      privateTmp = true;
      dbusAccess = [ "org.freedesktop.portal.*" ];
    };
    
    # X11-only packages for automatic wrapping (overlay mode)
    # Add packages here that need to be isolated
    overlayPackages = [
      "xterm" "xeyes" "xcalc"
      # Add other X11-only programs
    ];
  };
  
  # For detailed manual configuration of specific applications:
  # Uncomment ./sandbox-x11.nix in imports and use
  # security.x11Isolation.isolatedApps for specific settings
  
  # Security tip: After testing, set:
  # security.x11AutoIsolation.disableCompositorXwayland = true;

  # Required for GDM and input configuration (does NOT enable standalone Xorg)
  services.xserver.enable = true;

  # Printing support (DISABLED for hardened systems)
  # CUPS has a history of critical vulnerabilities:
  # - CVE-2024-47076 (Remote Code Execution via PPD)
  # - CVE-2024-47175 (libcupsfilters flaw)
  # - CVE-2023-32360 (Privilege escalation)
  # Attack surface: network ports 631/tcp, 631/udp
  # Recommendation: Use PDF export and external printing services
  services.printing.enable = false;

  # Sound configuration is handled by modules/audio.nix
  # See that module for PipeWire configuration with portal integration
  # PipeWire is designed for containerized apps (Flatpak primary use case)
}
