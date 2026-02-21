{ config, pkgs, lib, ... }:

{
  # systemd-resolved DNS configuration with DNSSEC
  # This module enables and configures systemd-resolved for secure DNS
  # resolution. We expose the most commonly used resolved.conf keys here.
  #
  # Notes on priorities:
  # - We use `lib.mkDefault` so users and higher-priority modules may
  #   override these defaults. If you need to force a value, wrap with
  #   `lib.mkForce` at the calling site.
  # - Some distributions expose a `services.resolved.settings` submodule
  #   that maps directly to resolved.conf(5). NixOS exposes that as
  #   `services.resolved` options on channel 25.11; we set them here.

  services.resolved = {
    # Enable the resolver daemon (systemd-resolved)
    enable = lib.mkDefault true;

    # DNSSEC: validate DNSSEC signatures locally.
    # - "true": require validation (may break on non-compliant servers)
    # - "allow-downgrade": attempt validation, but fall back if server
    #   doesn't support it (vulnerable to downgrade attacks)
    # - "false": do not perform DNSSEC validation
    # Upstream note: in some systemd versions DNSSEC is known to cause
    # issues with non-compliant servers; choose "allow-downgrade" if
    # you need robustness over strict validation.
    dnssec = lib.mkDefault "true";

    # DNS-over-TLS (DoT) mode for upstream connections
    # - "true": require DoT (fail if unavailable)
    # - "opportunistic": try DoT, but fall back to plaintext
    # - "false": do not use DoT
    dnsovertls = lib.mkDefault "true";

    # LLMNR support (RFC 4795)
    # - "true": enable full responder + resolver (less secure)
    # - "resolve": only resolve, do not respond
    # - "false": disable LLMNR (recommended for security)
    llmnr = lib.mkDefault "false";

    # Fallback DNS servers used when no resolver is provided by network
    # managers. Useful to point to a local forwarder such as a
    # `dnscrypt-proxy` instance running on 127.0.0.1.
    fallbackDns = lib.mkDefault [ "127.0.0.1" ];

    # Additional raw configuration appended to resolved.conf. Use this to
    # set more esoteric keys from resolved.conf(5) when necessary.
    extraConfig = lib.mkDefault ''
      [Resolve]
      # Avoid using localhost-only cache sources
      CacheFromLocalhost=no
      # Respect /etc/hosts for local name resolution
      ReadEtcHosts=yes
      # Prefer IPv4 over IPv6 (some networks have broken IPv6)
      # DNSDefaultRoute=no
    '';
  };

  # Also ensure the systemd unit exists; keep it a default so other modules can override if necessary.
  systemd.services.systemd-resolved.enable = lib.mkDefault true;

  # dnscrypt-proxy instance for systemd-resolved (listen on 127.0.0.1:53)
  # Provided as a default package so the local forwarder is available
  # when `services.resolved.fallbackDns` points to 127.0.0.1.
  environment.systemPackages = lib.mkDefault (with pkgs; [ dnscrypt-proxy ] ++ (config.environment.systemPackages or []));

  # Run dnscrypt-proxy as a systemd service dedicated for forwarding to
  # systemd-resolved. Hardening is applied centrally via
  # modules/security/hardened-services/dnscrypt-proxy-resolved.nix.
  systemd.services.dnscrypt-proxy-resolved = {
    description = "dnscrypt-proxy for systemd-resolved (DoH/DoT/DNSCrypt forwarder)";
    wantedBy = [ "network-online.target" "multi-user.target" ];
    serviceConfig = {
      ExecStart = "${pkgs.dnscrypt-proxy}/bin/dnscrypt-proxy -config /etc/dnscrypt-proxy/dnscrypt-proxy-resolved.toml";
      Restart = "on-failure";
      RestartSec = 5;
    };
  };

  # Provide external TOML to avoid escaping/formatting issues inside Nix
  # modules. The file is kept in `includes/dnscrypt-configs`.
  environment.etc."dnscrypt-proxy/dnscrypt-proxy-resolved.toml".source = ./includes/dnscrypt-configs/dnscrypt-proxy-resolved.toml;

  # Let systemd-resolved integrate with NetworkManager. This makes
  # NetworkManager push per-connection DNS settings to resolved rather
  # than writing /etc/resolv.conf directly.
  networking.networkmanager.dns = lib.mkForce "systemd-resolved";

  # Verification commands (useful after rebuild):
  # Check DNS resolver and DNSSEC status:
  #   resolvectl status
  #
  # Test DNS resolution:
  #   resolvectl query github.com
  #
  # Test DNSSEC validation (should succeed when dnssec = "true"):
  #   resolvectl query dnssec-deployment.org
  #
  # Test DNSSEC failure (should fail):
  #   resolvectl query dnssec-failed.org
  #
  # View logs for systemd-resolved:
  #   journalctl -u systemd-resolved -f
  #
  # Flush DNS cache:
  #   resolvectl flush-caches
}
