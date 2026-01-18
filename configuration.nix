# Edit this configuration file to define what should be installed on
# your system.  Help is available in the configuration.nix(5) man page
# and in the NixOS manual (accessible by running ‘nixos-help’).

{ config, pkgs, ... }:

{
  imports =
    [
      # Hardware configuration
      ./modules/hardware-configuration.nix
      
      # Boot modules
      ./modules/boot.nix               # Standard boot configuration
    # ./modules/boot-secure.nix        # Secure Boot with Lanzaboote

      # System modules
      ./modules/kernel.nix             # Kernel parameters, modules and sysctl settings
      ./modules/memory.nix             # Anything related to system memory (RAM)
      ./modules/entropy.nix            # Entropy / RNG configuration
    # ./modules/apparmor.nix           # AppArmor MAC configuration
    # ./modules/usbguard.nix           # USB device authorization

      # Networking modules
      ./modules/networking.nix         # General networking configuration

      # DNS configuration modules
      ./modules/dns-classic.nix        # Classic static DNS configuration (conflicts with resolved and dnsmasq)
    # ./modules/dns-resolved.nix       # DNSSEC DNS with systemd-resolved (conflicts with classic and dnsmasq)
    # ./modules/dns-dnsmasq.nix        # Alternative: DNSSEC DNS with dnsmasq (conflicts with classic and resolved)

      ./modules/localization.nix       # Localization settings
      ./modules/desktop.nix            # Desktop environment settings
      ./modules/users.nix              # User accounts and permissions
      ./modules/packages.nix           # Additional system packages
      ./modules/veracrypt.nix          # VeraCrypt disk encryption
      ./modules/nixos-permissions.nix  # Secure /etc/nixos/ permissions
    # ./modules/ssh.nix                # SSH server/client configuration 
    # ./modules/virtualisation.nix     # Virtualization settings
    ];

  # This value determines the NixOS release from which the default
  # settings for stateful data, like file locations and database versions
  # on your system were taken. It‘s perfectly fine and recommended to leave
  # this value at the release version of the first install of this system.
  # Before changing this value read the documentation for this option
  # (e.g. man configuration.nix or on https://nixos.org/nixos/options.html).
  system.stateVersion = "25.11"; # Did you read the comment?

}
