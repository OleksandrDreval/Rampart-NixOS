{ config, pkgs, lib, ... }:

{
  # systemd-resolved DNS configuration with DNSSEC
  # Provides secure DNS resolution with cryptographic validation
  
  services.resolved = {
    enable = lib.mkForce true;
    
    # DNSSEC configuration
    # "true" = require DNSSEC validation for all DNS responses. If DNSSEC
    # validation fails or is unavailable for a zone, resolution will fail.
    # This enforces cryptographic integrity of DNS replies.
    dnssec = lib.mkForce "true";

    # Alternative DNSSEC modes:
    # "allow-downgrade" - use DNSSEC when available, fall back to plain DNS when not
    # "false" - Disabled (least secure)
    
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
    # "true" = require DNS-over-TLS (DoT) for upstream connections; if TLS is
    # unavailable resolution will fail. This enforces encryption of DNS queries
    # to upstream servers and prevents downgrade to plaintext DNS.
    # "opportunistic" - try DoT and fall back to plain DNS if unavailable
    # "false" - disabled
    dnsovertls = lib.mkForce "true";
    
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
