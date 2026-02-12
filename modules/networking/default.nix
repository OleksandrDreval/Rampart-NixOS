# Networking Modules Coordinator
# Manages networking and DNS configuration

{ config, lib, ... }:

{
  imports = [
    ./networking.nix
  ];

  options.rampart.networking = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Enable networking modules";
    };

    dnsProvider = lib.mkOption {
      type = lib.types.enum [ "classic" "resolved" "dnsmasq" ];
      default = "classic";
      description = ''
        DNS provider configuration (mutually exclusive):
        - classic: Static DNS configuration
        - resolved: systemd-resolved with DNSSEC
        - dnsmasq: dnsmasq with DNSSEC
      '';
    };
  };

  config = {
    imports = lib.mkMerge [
      (lib.mkIf (config.rampart.networking.dnsProvider == "classic") [
        ./dns/classic.nix
      ])
      (lib.mkIf (config.rampart.networking.dnsProvider == "resolved") [
        ./dns/resolved.nix
      ])
      (lib.mkIf (config.rampart.networking.dnsProvider == "dnsmasq") [
        ./dns/dnsmasq.nix
      ])
    ];
  };
}
