{ config, pkgs, ... }:

let
  vars = import ./variables.nix;
in
{
  # Network configuration
  networking.hostName = vars.hostname;
  networking.networkmanager.enable = true;

  # Wireless support via wpa_supplicant (disabled by default)
  # networking.wireless.enable = true;

  # Configure network proxy if necessary
  # networking.proxy.default = "http://user:password@proxy:port/";
  # networking.proxy.noProxy = "127.0.0.1,localhost,internal.domain";

  # Firewall configuration
  # networking.firewall.allowedTCPPorts = [ ... ];
  # networking.firewall.allowedUDPPorts = [ ... ];
  # networking.firewall.enable = false;
}
