# Alternative Configuration using Category Coordinators
# This is a simplified version using default.nix coordinators for each category
# Copy this to configuration.nix if you prefer coordinator-based imports

{ config, pkgs, ... }:

let
  # DNS and Boot guards
  checkDns = 
    let
      dnsCount = 
        (if config.rampart.networking.dnsProvider == "classic" then 1 else 0) +
        (if config.rampart.networking.dnsProvider == "resolved" then 1 else 0) +
        (if config.rampart.networking.dnsProvider == "dnsmasq" then 1 else 0);
    in
    if dnsCount <= 1 then true 
    else builtins.error "Only one DNS provider can be enabled";

  checkBoot =
    let
      usingSystemdBoot = config.boot.loader.systemd-boot.enable or false;
      usingLanzaboote = config.boot.lanzaboote.enable or false;
    in
    if !(usingSystemdBoot && usingLanzaboote) then true 
    else builtins.error "Enable either systemd-boot or lanzaboote, not both";
in

{
  imports = [
    # Category Coordinators (simplified approach)
    ./modules/core           # Core system (boot, kernel, memory, entropy, filesystems)
    ./modules/common         # Common modules (audio, localization, users, packages)
    ./modules/networking     # Networking + DNS
    ./modules/security       # Security hardening
    ./modules/desktop        # Desktop environment + X11 isolation
    ./modules/apps           # Applications
    ./modules/services       # System services
    
    # Options and finalizer
    ./modules/options/rampart.nix
    ./modules/core/kernel-finalize.nix
  ];

  # Configure via options instead of manual module selection
  rampart = {
    # Networking
    networking = {
      enable = true;
      dnsProvider = "classic";  # Options: "classic" | "resolved" | "dnsmasq"
    };

    # Security
    security = {
      enable = false;  # Set to true to enable security coordinator
      level = "standard";  # Options: "minimal" | "standard" | "paranoid"
      apparmor = false;
      usbguard = false;
      privilegeEscalation = "sudo";  # Options: "sudo" | "doas" | "run0"
    };

    # Desktop
    desktop = {
      enable = true;
      de = "gnome";  # Options: "gnome" | "kde" | "cosmic" | "none"
      x11Isolation = {
        enable = true;
        autoIsolation = true;
      };
    };

    # Applications
    apps = {
      browsers.chromium = "firejail";  # Options: "none" | "standard" | "firejail"
      encryption.veracrypt = true;
    };

    # Services
    services = {
      ssh = false;
      virtualization = false;
    };
  };

  system.stateVersion = "25.11";
}
