{ config, pkgs, lib, ... }:

{
  # dnsmasq DNS configuration with DNSSEC
  # Lightweight DNS caching server with DNSSEC validation
  # Note: This module conflicts with systemd-resolved - enable only one
  
  services.dnsmasq = {
    enable = lib.mkForce true;
    
    settings = {
      # Listen only on localhost (don't expose DNS to local network)
      listen-address = "127.0.0.1";
      bind-interfaces = true;
      
      # Upstream DNS servers with DNSSEC support
      server = lib.mkForce [
        "1.1.1.1"  # Cloudflare (supports DNSSEC)
        "9.9.9.9"  # Quad9 (supports DNSSEC, privacy-focused)
        "8.8.8.8"  # Google Public DNS (supports DNSSEC)
      ];
      
      # DNSSEC configuration
      dnssec = true;
      dnssec-check-unsigned = true;  # Reject unsigned responses for signed domains
      
      # DNSSEC trust anchors (root KSKs)
      # Source: https://data.iana.org/root-anchors/root-anchors.xml
      # Keep both old and new anchors during key rollovers
      trust-anchor = [
        ".,20326,8,2,E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"  # 2017 KSK
        ".,38696,8,2,683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"  # 2024 KSK (new)
      ];
      
      # Security settings
      bogus-priv = true;             # Don't forward private IP ranges (192.168.x.x, 10.x.x.x) upstream
      domain-needed = true;          # Don't forward queries without dots (prevents info leakage)
      no-resolv = lib.mkForce true;  # Don't read /etc/resolv.conf for upstream servers
      
      # Cache settings
      cache-size = 1000;     # DNS cache size (number of entries)
      no-negcache = false;   # Cache negative responses (NXDOMAIN) - improves performance
      
      # Local network settings
      local-service = true;  # Accept DNS queries only from local machine
      
      # Logging (disable for privacy)
      log-queries = false;   # Don't log all DNS queries
      log-dhcp = false;      # We don't use DHCP feature
      
      # Optional: Block advertising/tracking domains
      # addn-hosts = "/etc/dnsmasq-blocklist.txt";
      
      # Optional: Local DNS entries for custom domains
      # address = [
      #   "/monitoring.local/127.0.0.1"
      # ];
    };
  };
  
  # Point system DNS to dnsmasq
  networking.nameservers = lib.mkForce [ "127.0.0.1" ];
  
  # Prevent NetworkManager from overriding DNS
  # This ensures dnsmasq always handles DNS resolution
  networking.networkmanager.dns = lib.mkForce "none";
  
  # Verification commands:
  # Test DNS resolution through dnsmasq:
  #   dig @127.0.0.1 github.com
  #
  # Test DNSSEC validation (should succeed):
  #   dig @127.0.0.1 +dnssec dnssec-deployment.org
  #
  # Test DNSSEC failure (should fail with SERVFAIL):
  #   dig @127.0.0.1 dnssec-failed.org
  #
  # View dnsmasq statistics:
  #   sudo killall -USR1 dnsmasq
  #   journalctl -u dnsmasq | tail -20
  #
  # View logs:
  #   journalctl -u dnsmasq -f
  #
  # Flush DNS cache:
  #   sudo systemctl restart dnsmasq
  #
  # Test DNS leaks (should show only your DNS server):
  #   curl https://www.dnsleaktest.com/
}
