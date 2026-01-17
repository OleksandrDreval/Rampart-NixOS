{ config, pkgs, lib, ... }:

{
  # systemd-resolved DNS configuration with DNSSEC
  # Provides secure DNS resolution with cryptographic validation
  
  services.resolved = {
    enable = lib.mkForce true;
    
    # DNSSEC configuration
    # "allow-downgrade" = use DNSSEC when available, fallback if domain doesn't support it
    # This prevents breaking sites without DNSSEC while maintaining security for supported domains
    dnssec = lib.mkForce "allow-downgrade";
    
    # Alternative DNSSEC modes:
    # "true"  - Strict DNSSEC validation (fails for domains without DNSSEC) - NOT recommended
    # "false" - Disabled (least secure) - NOT recommended
    
    # Fallback DNS servers (used when NetworkManager doesn't provide DNS)
    fallbackDns = lib.mkForce [
      "1.1.1.1"     # Cloudflare (supports DNSSEC)
      "9.9.9.9"     # Quad9 (supports DNSSEC, privacy-focused)
    ];
    
    # Disable LLMNR (Link-Local Multicast Name Resolution)
    # Security: LLMNR can be spoofed and used for credential theft
    llmnr = lib.mkForce "false";
    
    # Disable mDNS (Multicast DNS)
    # Security: mDNS exposes hostnames on local network
    multicastDns = lib.mkForce "false";
    
    # DNS over TLS configuration
    # "opportunistic" = try DNS-over-TLS, fallback to plain DNS if unavailable
    # "true" = require DNS-over-TLS (strict, may break some networks)
    # "false" = disabled
    dnsovertls = lib.mkForce "opportunistic";
    
    # Enable DNS caching
    cache = lib.mkForce true;
    
    # Additional security settings
    extraConfig = ''
      [Resolve]
      # Cache DNS results for faster lookups
      CacheFromLocalhost=no
      
      # Read /etc/hosts for local resolution
      ReadEtcHosts=yes
      
      # Prefer IPv4 over IPv6 (some networks have broken IPv6)
      # DNSDefaultRoute=no
    '';
  };
  
  # Let systemd-resolved manage /etc/resolv.conf
  # systemd-resolved creates a stub resolver at 127.0.0.53
  # Comment out static nameservers in networking.nix to avoid conflicts
  
  # Verification commands:
  # Check DNSSEC status:
  #   resolvectl status
  #
  # Test DNS resolution:
  #   resolvectl query github.com
  #
  # Test DNSSEC validation (should succeed):
  #   resolvectl query dnssec-deployment.org
  #
  # Test DNSSEC failure (should fail):
  #   resolvectl query dnssec-failed.org
  #
  # View logs:
  #   journalctl -u systemd-resolved -f
  #
  # Flush DNS cache:
  #   resolvectl flush-caches
}
