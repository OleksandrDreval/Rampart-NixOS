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
    # Forward to local dnscrypt-proxy instance (listening on 127.0.0.1:53)
    fallbackDns = lib.mkForce [ "127.0.0.1" ];
    
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

  # dnscrypt-proxy instance for systemd-resolved (listen on 127.0.0.1:53)
  environment.systemPackages = with pkgs; [ dnscrypt-proxy ] ++ (config.environment.systemPackages or []);

  services.systemd.services.dnscrypt-proxy-resolved = {
    description = "dnscrypt-proxy for systemd-resolved (DoH/DoT/DNSCrypt forwarder)";
    wantedBy = [ "network-online.target" ];
    serviceConfig = {
      ExecStart = "${pkgs.dnscrypt-proxy}/bin/dnscrypt-proxy -config /etc/dnscrypt-proxy/dnscrypt-proxy-resolved.toml";
      Restart = "on-failure";
      RestartSec = 5;
      NoNewPrivileges = "true";
      ProtectSystem = "full";
      ProtectHome = "read-only";
      PrivateTmp = "true";
      PrivateDevices = "true";
      ProtectControlGroups = "true";
      ProtectKernelTunables = "true";
      ProtectKernelModules = "true";
      CapabilityBoundingSet = "CAP_NET_BIND_SERVICE";
    };
    install.wantedBy = [ "multi-user.target" ];
    enable = true;
  };

  # Provide external TOML to avoid formatting issues inside Nix modules.
  environment.etc."dnscrypt-proxy/dnscrypt-proxy-resolved.toml".source = ./includes/dnscrypt-configs/dnscrypt-proxy-resolved.toml;
  
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
