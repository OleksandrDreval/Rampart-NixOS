{ config, lib, ... }:

{
  # Classic/static DNS settings module
  # Move basic/static DNS server entries here so DNS config is separated
  # from general networking policies (e.g., NetworkManager). This module
  # is intended for setups that prefer static upstream servers (dnsmasq
  # or resolved should be disabled or configured accordingly).

  # Static DNS servers for classic setups. This module is exclusive —
  # enable only one of the DNS modules (dns-classic, dns-resolved, dns-dnsmasq).
  # Force values so other modules won't silently overwrite this policy.
  networking.networkmanager.dns = lib.mkForce "none";
  networking.nameservers = lib.mkForce [
    "1.1.1.1"  # Cloudflare
    "9.9.9.9"  # Quad9
  ];

  # Note: If you use `modules/dns-resolved.nix` or `modules/dns-dnsmasq.nix`,
  # disable this module or comment out `networking.nameservers` here to
  # avoid conflicts and ensure the desired resolver manages DNS.
}
