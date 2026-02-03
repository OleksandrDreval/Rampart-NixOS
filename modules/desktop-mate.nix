{ config, pkgs, ... }:

let
  vars = import ./includes/variables.nix;
in

{
  # MATE Desktop Environment Module
  # Traditional desktop environment, continuation of GNOME 2
  #
  # Features:
  # - Traditional GNOME 2 interface
  # - Lightweight and fast
  # - GTK 3 based
  # - Familiar and intuitive
  # - Low resource usage
  # - Stable and reliable
  # - Experimental Wayland support
  #
  # Official Documentation:
  # - https://mate-desktop.org/
  # - https://wiki.mate-desktop.org/
  #
  # NixOS Manual:
  # - https://nixos.org/manual/nixos/stable/options.html#opt-services.xserver.desktopManager.mate.enable
}
