{ config, pkgs, lib, ... }:

let
  vars = import ../security/secrets/vars-compat.nix { inherit config lib; };

  # Rampart exposure for networking-related kernel settings so the finalizer
  # can aggregate and enforce authoritative defaults.
  rampartNetworkingSysctl = {
    # IPv4 Critical Security

    # Source routing and redirects protection (prevents route hijacking and MitM)
    "net.ipv4.conf.all.accept_source_route"       = 0;  # Block source-routed packets (IP spoofing)
    "net.ipv4.conf.default.accept_source_route"   = 0;
    "net.ipv4.conf.all.accept_redirects"          = 0;  # Block ICMP redirects (route hijacking)
    "net.ipv4.conf.default.accept_redirects"      = 0;
    "net.ipv4.conf.all.secure_redirects"          = 0;  # Block even "secure" redirects
    "net.ipv4.conf.default.secure_redirects"      = 0;
    "net.ipv4.conf.all.send_redirects"            = 0;  # Don't send redirects (info disclosure)
    "net.ipv4.conf.default.send_redirects"        = 0;
    # Shared media redirects - keep disabled for untrusted networks
    "net.ipv4.conf.all.shared_media"              = 0;  # Disable shared-media redirects
    "net.ipv4.conf.default.shared_media"          = 0;

    # IP forwarding (explicitly disable - we're not a router)
    "net.ipv4.conf.all.forwarding"                = 0;  # No packet forwarding
    "net.ipv4.conf.default.forwarding"            = 0;
    "net.ipv4.ip_forward"                         = 0;  # Global forwarding disable

    # ARP protection (critical in public WiFi - prevents ARP spoofing/poisoning)
    "net.ipv4.conf.all.arp_announce"              = 2;  # Best mode - reply only for local IPs
    "net.ipv4.conf.default.arp_announce"          = 2;
    "net.ipv4.conf.all.arp_ignore"                = 1;  # Reply to ARP only for local addresses
    "net.ipv4.conf.default.arp_ignore"            = 1;
    "net.ipv4.conf.all.drop_gratuitous_arp"       = 1;  # Drop gratuitous ARP (prevents ARP cache poisoning)
    "net.ipv4.conf.default.drop_gratuitous_arp"   = 1;
    "net.ipv4.conf.all.arp_filter"                = 1;  # Enable ARP filtering (prevents global ARP table handling)
    "net.ipv4.conf.default.arp_filter"            = 1;

    # Reverse path filtering (anti-spoofing)
    "net.ipv4.conf.all.rp_filter"                 = 1;  # Loose mode (safe for WiFi, asymmetric routing)
    "net.ipv4.conf.default.rp_filter"             = 1;

    # ICMP protection
    "net.ipv4.icmp_echo_ignore_all"               = 1;  # Ignore all IPv4 ping requests (stealth mode)
    "net.ipv4.icmp_echo_ignore_broadcasts"        = 1;  # Ignore broadcast pings (smurf attack prevention)
    "net.ipv4.icmp_ignore_bogus_error_responses"  = 1;  # Ignore malformed ICMP errors
    "net.ipv6.icmp.echo_ignore_all"               = 1;  # Ignore all IPv6 ping requests (stealth mode)
    "net.ipv6.icmp.echo_ignore_anycast"           = 1;  # Ignore IPv6 anycast pings (prevents enumeration)
    "net.ipv6.icmp.echo_ignore_multicast"         = 1;  # Ignore IPv6 multicast pings (prevents enumeration)

    # Logging (for security monitoring)
    "net.ipv4.conf.all.log_martians"              = 1;  # Log packets with impossible source addresses
    "net.ipv4.conf.default.log_martians"          = 1;

    # TCP security (protection against attacks)
    "net.ipv4.tcp_syncookies"                     = 1;  # SYN flood protection (critical!)
    "net.ipv4.tcp_rfc1337"                        = 1;  # TIME-WAIT assassination protection
    # Keep TCP timestamps enabled: protects against wrapped sequence numbers
    # and improves performance (do not disable by default for laptop)
    "net.ipv4.tcp_timestamps"                     = 1;
  # "net.ipv4.tcp_timestamps"                     = 0;
  # "net.ipv4.tcp_tw_reuse"                       = 0;
    # Optional hardening: disable TCP SACK/FACK/DSACK to reduce past DoS exploit surface
    # Note: may reduce performance in lossy/high-latency networks. Kept as strict hardening.
    "net.ipv4.tcp_dsack"                          = 0;  # disable Duplicate SACK processing
    "net.ipv4.tcp_fack"                           = 0;  # disable FACK (forward acknowledgement)
    "net.ipv4.tcp_sack"                           = 0;  # disable Selective Acknowledgement (SACK)

    # IPv6 Critical Security

    # Source routing and redirects protection
    "net.ipv6.conf.all.accept_source_route"       = 0;  # Block IPv6 source routing
    "net.ipv6.conf.default.accept_source_route"   = 0;
    "net.ipv6.conf.all.accept_redirects"          = 0;  # Block ICMPv6 redirects
    "net.ipv6.conf.default.accept_redirects"      = 0;
    # IPv6 Privacy Extensions (RFC3041) - prefer temporary addresses to avoid tracking
    "net.ipv6.conf.all.use_tempaddr"              = 2;  # prefer temporary addresses
    "net.ipv6.conf.default.use_tempaddr"          = 2;

    # Router Advertisement protection (prevents rogue RA attacks in public WiFi)
    "net.ipv6.conf.all.accept_ra"                 = 0;  # Don't accept Router Advertisements
    "net.ipv6.conf.default.accept_ra"             = 0;
    "net.ipv6.conf.all.accept_ra_defrtr"          = 0;  # Don't accept default router from RA
    "net.ipv6.conf.default.accept_ra_defrtr"      = 0;
    "net.ipv6.conf.all.accept_ra_pinfo"           = 0;  # Don't accept prefix info from RA
    "net.ipv6.conf.default.accept_ra_pinfo"       = 0;
    "net.ipv6.conf.all.accept_ra_rtr_pref"        = 0;  # Ignore router preference from RA
    "net.ipv6.conf.default.accept_ra_rtr_pref"    = 0;

    # SLAAC autoconfiguration protection (prevents address auto-assignment attacks)
    "net.ipv6.conf.all.autoconf"                  = 0;  # Disable SLAAC autoconfiguration
    "net.ipv6.conf.default.autoconf"              = 0;
    "net.ipv6.conf.all.dad_transmits"             = 0;  # Disable DAD (reduces network reconnaissance)
    "net.ipv6.conf.default.dad_transmits"         = 0;
    "net.ipv6.conf.all.max_addresses"             = 1;  # Limit IPv6 addresses per interface (DoS prevention)
    "net.ipv6.conf.default.max_addresses"         = 1;

    # Router Solicitation protection (reduces information disclosure)
    "net.ipv6.conf.all.router_solicitations"      = 0;  # Don't send RS messages (reduces fingerprinting)
    "net.ipv6.conf.default.router_solicitations"  = 0;

    # IPv6 forwarding (explicitly disable)
    "net.ipv6.conf.all.forwarding"                = 0;  # Not a router
    "net.ipv6.conf.default.forwarding"            = 0;

    # TCP Performance Optimization (modern stack)
    "net.ipv4.tcp_fastopen"                       = 3;       # Enable TCP Fast Open (client + server)
    "net.ipv4.tcp_congestion_control"             = "bbr";   # Google BBR congestion control (better throughput)
    "net.core.default_qdisc"                      = "cake";  # CAKE queue discipline (bufferbloat mitigation)
  };
in

{
  # Network configuration
  networking.hostName = vars.hostName;
  networking.networkmanager.enable = true;

  # Use iwd (Intel Wireless Daemon) instead of wpa_supplicant
  # iwd benefits: modern codebase, better WPA3 support, faster connections, lower battery usage
  # Note: If enterprise WiFi (EAP-TTLS) fails, revert to wpa_supplicant:
  #   networking.networkmanager.wifi.backend = "wpa_supplicant";
  networking.networkmanager.wifi.backend = "iwd";

  # Integrate IPv6 privacy extensions with NetworkManager (prefer temporary addresses)
  networking.networkmanager.connectionConfig."ipv6.ip6-privacy" = 2;  # prefer temporary IPv6 addresses (RFC3041)

  # iwd privacy settings for MAC address randomization
  networking.wireless.iwd = {
    enable = true;
    settings = {
      General = {
        # Randomize MAC per-network (different MAC for each SSID)
        AddressRandomization = "network";
      };
      Settings = {
        # Always randomize address for maximum privacy
        AlwaysRandomizeAddress = true;
      };
    };
  };

  # Ensure systemd-networkd follows kernel IPv6 privacy settings
  systemd.network.config.networkConfig.IPv6PrivacyExtensions = "kernel";  # follow kernel use_tempaddr setting

  # MAC address randomization for privacy
  # Enable MAC randomization during WiFi network scanning to prevent tracking
  # WiFi routers and trackers can monitor probe requests to track physical location
  networking.networkmanager.wifi.scanRandMacAddress = true;

  # MAC address randomization: Generate new MAC on each connection/reboot for maximum privacy
  networking.networkmanager.wifi.macAddress = "random";
  networking.networkmanager.ethernet.macAddress = "random";

  # DNS servers - moved to modules/dns-classic.nix for static/classic setups.
  # Use dns-resolved.nix or dns-dnsmasq.nix for managed resolver configurations.

  # Wireless support via wpa_supplicant (disabled by default)
  # networking.wireless.enable = true;

  # Configure network proxy if necessary
  # networking.proxy.default = "http://user:password@proxy:port/";
  # networking.proxy.noProxy = "127.0.0.1,localhost,internal.domain";

  # Firewall configuration
  # "Zero Trust" approach - block all incoming, allow all outgoing
  # Safe for laptops that connect to untrusted networks (public WiFi, hotels, airports)
  networking.firewall = {
    enable = true;  # Enable firewall protection

    # Connection tracking helpers (FTP, SIP, IRC, etc.)
    # Explicitly disable to prevent security vulnerabilities in old protocol helpers
    autoLoadConntrackHelpers = false;  # Don't auto-load conntrack helpers (security)

    # Block all incoming connections by default (not a server)
    allowedTCPPorts = [ ];  # No open TCP ports
    allowedUDPPorts = [ ];  # No open UDP ports

    # ICMP (ping) configuration
    # Note: allowPing controls firewall rules, but kernel sysctl blocks all ICMP echo at kernel level
    allowPing = false;  # Block ping at firewall (also blocked at kernel via icmp_echo_ignore_all)

    # Connection tracking and logging
    logRefusedConnections = true;  # Log blocked connections for security monitoring
    logRefusedPackets = false;     # Don't log individual packets (reduces noise)

    # Packet rejection method
    rejectPackets = true;  # Send REJECT instead of DROP (faster feedback for legitimate traffic)

    # Outgoing connections - allow all (laptops need to connect to various services)
    # This is the default behavior, no restriction on outgoing traffic
  };

  # Additional firewall rules can be added here if needed:
  # networking.firewall.extraCommands for custom iptables/nftables rules
  # networking.firewall.allowedTCPPortRanges for port ranges
  # networking.firewall.interfaces for per-interface rules

  # Hardening NetworkManager services
  # Based on: https://github.com/wallago/nix-system-services-hardened
  systemd.services.NetworkManager.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Disallow gaining new privileges
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits
    RestrictRealtime = true;  # Disable realtime scheduling
  };

  # Export rampart networking sysctl values for finalizer
  rampart = {
    networkingSysctl = rampartNetworkingSysctl;
  };
}
