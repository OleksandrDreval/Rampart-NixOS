{ config, pkgs, ... }:

let
  vars = import ../../security/secrets/vars-compat.nix { inherit config lib; };
in

{
  #############################################################################
  # GNOME Desktop Environment
  #############################################################################
  # Wayland-native desktop environment with modern security features
  # Documentation: https://nixos.org/manual/nixos/stable/#sec-gnome
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
  # Used by sandboxed applications (Flatpak, bubblewrap-based, etc.)
  # Documentation: https://flatpak.github.io/xdg-desktop-portal/
  xdg.portal.enable = true;

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
