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

  # Network security sysctl parameters
  boot.kernel.sysctl = {
    # Network security - BPF
    "net.core.bpf_jit_enable"                     = "false";  # Disable BPF JIT compilation to prevent JIT spraying attacks
    "net.core.bpf_jit_harden"                     = "2";      # Maximum BPF JIT hardening with additional checks
    
    # IPv4 security - All interfaces
    "net.ipv4.conf.all.accept_redirects"          = "false";  # Ignore ICMP redirect messages to prevent route hijacking
    "net.ipv4.conf.all.accept_source_route"       = "0";      # Disable source-routed packets to prevent route spoofing
    "net.ipv4.conf.all.arp_announce"              = "2";      # Best mode for ARP announce to reduce information leakage
    "net.ipv4.conf.all.drop_gratuitous_arp"       = "1";      # Drop gratuitous ARP to prevent ARP spoofing
    "net.ipv4.conf.all.forwarding"                = "0";      # Disable IP forwarding - not a router
    "net.ipv4.conf.all.log_martians"              = "true";   # Log packets with impossible addresses
    "net.ipv4.conf.all.rp_filter"                 = "1";      # Enable reverse path filtering to prevent IP spoofing
    "net.ipv4.conf.all.secure_redirects"          = "false";  # Ignore secure ICMP redirects
    "net.ipv4.conf.all.send_redirects"            = "false";  # Don't send ICMP redirects to prevent topology disclosure
    "net.ipv4.conf.all.shared_media"              = "0";      # Disable shared media for security
    
    # IPv4 security - Default interface
    "net.ipv4.conf.default.accept_redirects"      = "false";  # Ignore ICMP redirect messages on new interfaces
    "net.ipv4.conf.default.accept_source_route"   = "0";      # Disable source routing on new interfaces
    "net.ipv4.conf.default.arp_announce"          = "2";      # Best ARP announce mode for new interfaces
    "net.ipv4.conf.default.arp_ignore"            = "1";      # Reply to ARP only for local addresses
    "net.ipv4.conf.default.drop_gratuitous_arp"   = "1";      # Drop gratuitous ARP on new interfaces
    "net.ipv4.conf.default.forwarding"            = "0";      # Disable forwarding on new interfaces
    "net.ipv4.conf.default.log_martians"          = "true";   # Log martian packets on new interfaces
    "net.ipv4.conf.default.rp_filter"             = "1";      # Enable reverse path filtering on new interfaces
    "net.ipv4.conf.default.secure_redirects"      = "false";  # Ignore secure redirects on new interfaces
    "net.ipv4.conf.default.send_redirects"        = "false";  # Don't send redirects on new interfaces
    "net.ipv4.conf.default.shared_media"          = "0";      # Disable shared media on new interfaces
    
    # IPv4 ICMP security
    "net.ipv4.icmp_echo_ignore_all"               = "1";      # Ignore all ping requests to make system stealthy
    "net.ipv4.icmp_echo_ignore_broadcasts"        = "1";      # Ignore broadcast pings to prevent smurf attacks
    "net.ipv4.icmp_ignore_bogus_error_responses"  = "1";      # Ignore malformed ICMP error messages
    "net.ipv4.ip_forward"                         = "0";      # Disable IP forwarding globally
    
    # IPv4 TCP security
    "net.ipv4.tcp_dsack"                          = "0";      # Disable D-SACK to reduce information leakage
    "net.ipv4.tcp_fack"                           = "0";      # Disable Forward Acknowledgment to reduce info leakage
    "net.ipv4.tcp_rfc1337"                        = "1";      # Protect against TIME-WAIT assassination attacks
    "net.ipv4.tcp_sack"                           = "0";      # Disable SACK to reduce information leakage
    "net.ipv4.tcp_syncookies"                     = "1";      # Enable SYN cookies to protect against SYN flood attacks
    "net.ipv4.tcp_timestamps"                     = "1";      # Enable TCP timestamps for better performance
    
    # IPv6 security - All interfaces
    "net.ipv6.conf.all.accept_ra"                 = "0";      # Ignore Router Advertisements to prevent autoconfiguration
    "net.ipv6.conf.all.accept_ra_defrtr"          = "0";      # Don't accept default router from RA
    "net.ipv6.conf.all.accept_ra_pinfo"           = "0";      # Don't accept prefix info from RA
    "net.ipv6.conf.all.accept_ra_rtr_pref"        = "0";      # Ignore router preference from RA
    "net.ipv6.conf.all.accept_redirects"          = "false";  # Ignore ICMPv6 redirects
    "net.ipv6.conf.all.accept_source_route"       = "0";      # Disable IPv6 source routing
    "net.ipv6.conf.all.autoconf"                  = "0";      # Disable SLAAC autoconfiguration
    "net.ipv6.conf.all.dad_transmits"             = "0";      # Disable Duplicate Address Detection
    "net.ipv6.conf.all.forwarding"                = "0";      # Disable IPv6 forwarding - not a router
    "net.ipv6.conf.all.max_addresses"             = "1";      # Limit IPv6 addresses per interface
    "net.ipv6.conf.all.router_solicitations"      = "0";      # Don't send Router Solicitation messages
    
    # IPv6 security - Default interface
    "net.ipv6.conf.default.accept_ra_defrtr"      = "0";      # Don't accept default router on new interfaces
    "net.ipv6.conf.default.accept_ra_pinfo"       = "0";      # Don't accept prefix info on new interfaces
    "net.ipv6.conf.default.accept_ra_rtr_pref"    = "0";      # Ignore router preference on new interfaces
    "net.ipv6.conf.default.accept_redirects"      = "false";  # Ignore redirects on new interfaces
    "net.ipv6.conf.default.accept_source_route"   = "0";      # Disable source routing on new interfaces
    "net.ipv6.conf.default.autoconf"              = "0";      # Disable autoconfiguration on new interfaces
    "net.ipv6.conf.default.dad_transmits"         = "0";      # Disable DAD on new interfaces
    "net.ipv6.conf.default.forwarding"            = "0";      # Disable forwarding on new interfaces
    "net.ipv6.conf.default.max_addresses"         = "1";      # Limit addresses on new interfaces
    "net.ipv6.conf.default.router_solicitations"  = "0";      # Don't send RS on new interfaces
  };
}
