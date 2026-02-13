# Edit this configuration file to define what should be installed on
# your system.  Help is available in the configuration.nix(5) man page
# and in the NixOS manual (accessible by running ‘nixos-help’).

{ config, pkgs, lib, ... }:

# Guards to prevent enabling mutually-exclusive modules simultaneously.
# `checkDns` and `checkBoot` are evaluated in the `let` below and will
# abort evaluation with a clear error message if violated.

let
  # Load centralized variables from SOPS secrets
  vars = import ./modules/security/secrets/vars-compat.nix { inherit config lib; };

  # DNS configuration guards
  usingResolved = config.services.resolved.enable or false;
  usingDnsmasq  = config.services.dnsmasq.enable or false;
  usingClassic  = ((config.networking.nameservers or []) != []) && !(usingResolved || usingDnsmasq);

  # Bootloader configuration guards
  usingSystemdBoot = config.boot.loader.systemd-boot.enable or false;
  usingLanzaboote  = config.boot.lanzaboote.enable or false;

  # Guard evaluations
  checkDns  = if (!(usingResolved && usingDnsmasq) && !(usingResolved && usingClassic) && !(usingDnsmasq && usingClassic)) then true else builtins.error "Only one of dns-resolved, dns-dnsmasq or dns-classic may be enabled";
  checkBoot = if (!(usingSystemdBoot && usingLanzaboote)) then true else builtins.error "Enable either systemd-boot or boot-secure (lanzaboote), not both";
in

{
  imports =
    [
      # Core System
      ./modules/core/hardware-configuration.nix    # Hardware configuration
      ./modules/options/rampart.nix                # Custom Rampart options declarations

      # Secrets Management
      ./modules/security/secrets/sops.nix          # SOPS secrets configuration

      # Boot (choose ONE)
      ./modules/core/boot.nix                      # Standard systemd-boot
    # ./modules/core/boot-secure.nix               # Secure Boot with Lanzaboote

      # System Core
    # ./modules/core/kernel.nix                    # Kernel parameters, modules and sysctl
      ./modules/core/memory.nix                    # Memory management (RAM, swap, hardened malloc)
      ./modules/core/entropy.nix                   # RNG/Entropy configuration
      ./modules/core/filesystems.nix               # Filesystem-related sysctl and NTFS support

      # Security
    # ./modules/security/mandatory-access-control/apparmor.nix     # AppArmor MAC
    # ./modules/security/device-control/usbguard.nix               # USB device authorization
      ./modules/security/nixos-permissions.nix                     # Secure /etc/nixos/ permissions

      # Privilege Escalation (choose ONE)
      ./modules/security/privilege-escalation/sudo.nix             # Sudo (traditional)
    # ./modules/security/privilege-escalation/doas.nix             # Doas (OpenBSD alternative)
    # ./modules/security/privilege-escalation/run0.nix             # Run0 (systemd-native)

      # Networking
      ./modules/networking/networking.nix                          # General networking

      # DNS (choose ONE)
      ./modules/networking/dns/classic.nix                         # Classic static DNS
    # ./modules/networking/dns/resolved.nix                        # systemd-resolved + DNSSEC
    # ./modules/networking/dns/dnsmasq.nix                         # dnsmasq + DNSSEC

      # Common
      ./modules/common/localization.nix            # Localization settings
      ./modules/common/audio.nix                   # PipeWire audio system
      ./modules/common/users.nix                   # User accounts and permissions
      ./modules/common/packages.nix                # System packages

      # Desktop Environment (choose ONE)
      ./modules/desktop/environments/gnome.nix     # GNOME Desktop (Wayland-native)
    # ./modules/desktop/environments/plasma.nix    # KDE Plasma 6 (Wayland-native)
    # ./modules/desktop/environments/cosmic.nix    # COSMIC Desktop (Wayland-only)

      # X11 Isolation
      ./modules/desktop/x11-isolation/config.nix   # X11 sandboxing via nix-bwrapper

      # Applications
    # ./modules/apps/browsers/chromium.nix         # Chromium browser
      ./modules/apps/browsers/chromium-firejail.nix               # Chromium + Firejail
      ./modules/apps/encryption/veracrypt.nix                     # VeraCrypt disk encryption

      # Services
    # ./modules/services/ssh.nix                   # SSH server/client
    # ./modules/services/virtualisation.nix        # Virtualization

      # Finalizer (MUST BE LAST)
      ./modules/core/kernel-finalize.nix           # Kernel arrays/sysctl finalizer
    ];

  # This value determines the NixOS release from which the default
  # settings for stateful data, like file locations and database versions
  # on your system were taken. It‘s perfectly fine and recommended to leave
  # this value at the release version of the first install of this system.
  # Before changing this value read the documentation for this option
  # (e.g. man configuration.nix or on https://nixos.org/nixos/options.html).
  system.stateVersion = vars.stateVersion; # Did you read the comment?
}
