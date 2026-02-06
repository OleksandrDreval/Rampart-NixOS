{ config, pkgs, ... }:

let
  vars = import ./includes/variables.nix;
in
{
  # Enable GNOME Desktop Environment with Wayland
  # services.xserver is required for display management and some X11 compatibility
  services.xserver.enable = true;

  # Enable GNOME Desktop Environment (runs on Wayland by default)
  services.desktopManager.gnome.enable = true;

  # Enable GDM (GNOME Display Manager) with Wayland support
  services.displayManager.gdm = {
    enable = true;
    wayland = true;  # Enable Wayland session (default: true)
  };

  # Enable Xwayland for backward compatibility with X11 applications
  # This allows running legacy X11 apps on Wayland
  programs.xwayland.enable = true;

  # Configure keyboard layout (applies to both Wayland and X11/Xwayland)
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
