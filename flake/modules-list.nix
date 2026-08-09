# Centralized module list for imports
# All modules loaded into the system are defined here
# This simplifies management of large module sets

{ config, lib, ... }:

{
  # Optional: add options to enable/disable module groups
  options.rampart = {
    # enableDesktop = lib.mkEnableOption "Enable desktop environment modules";
    # enableHardening = lib.mkEnableOption "Enable hardening modules";
  };

  config = {
    imports = [
      # Core System
      # Boot (choose one):
      ../modules/core/boot.nix           # Standard systemd-boot
      # ../modules/core/boot-secure.nix  # Secure Boot with Lanzaboote (requires flakes)
      
      ../modules/core/kernel.nix
      ../modules/core/kernel-finalize.nix
      ../modules/core/hardware-configuration.nix
      
      # Networking
      ../modules/networking/networking.nix
      
      # DNS (choose one):
      ../modules/networking/dns/resolved.nix
      # ../modules/networking/dns/dnsmasq.nix
      # ../modules/networking/dns/classic.nix
      
      # Security
      ../modules/security/mandatory-access-control/apparmor.nix
      ../modules/security/device-control/usbguard.nix
      ../modules/services/ssh.nix
      ../modules/core/entropy.nix
      ../modules/security/nixos-permissions.nix
      
      # Desktop Environment
      ../modules/desktop/environments/gnome.nix
      ../modules/common/localization.nix
      
      # X11 Isolation (nix-bwrapper)
      ../modules/desktop/x11-isolation/config.nix
      # Modules inside auto-load via coordinator
      
      # Applications
      ../modules/apps/browsers/chromium.nix
      ../modules/common/packages.nix
      
      # Filesystems & Storage
      ../modules/core/filesystems.nix
      ../modules/apps/encryption/veracrypt.nix
      ../modules/core/memory.nix
      
      # Virtualization
      ../modules/services/virtualisation.nix
      
      # Users
      ../modules/common/users.nix
      
      # Custom Options
      ../modules/options/rampart.nix
    ];
  };
}
