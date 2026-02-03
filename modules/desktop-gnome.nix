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

  # Enable touchpad support (enabled by default in most desktop managers)
  # services.xserver.libinput.enable = true;

  # Printing support (DISABLED for hardened systems)
  # CUPS has history of CVEs: CVE-2024-47076, CVE-2024-47175, CVE-2023-32360
  # Increases attack surface (network ports 631/tcp, 631/udp)
  services.printing.enable = false;

  # Sound configuration with PipeWire
  services.pulseaudio.enable = false;
  security.rtkit.enable = true;
  services.pipewire = {
    enable = true;
    alsa.enable = true;
    alsa.support32Bit = true;
    pulse.enable = true;
    # If you want to use JACK applications, uncomment this
    # jack.enable = true;

    # Use the example session manager (no others are packaged yet so this is enabled by default,
    # no need to redefine it in your config for now)
    # media-session.enable = true;
  };
}
