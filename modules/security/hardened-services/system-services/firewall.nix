{ config, lib, ... }:

{
  /*
    Rampart Firewall (iptables/nftables) Hardening Module

    Based on upstream NixOS firewall.service configuration.
    The firewall service is a one-shot script that applies network rules.
    It requires network administration capabilities but can be strictly
    isolated from the filesystem and other processes.
  */

  systemd.services.firewall.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;
    CapabilityBoundingSet = [
      "CAP_NET_ADMIN"
      "CAP_NET_RAW"
      "CAP_SYS_MODULE" # iptables often needs to load netfilter modules (xt_conntrack, etc.)
    ];

    RestrictSUIDSGID = true;
    RestrictRealtime = true;

    # Filesystem Isolation
    ProtectSystem = "strict";
    ProtectHome = true;
    PrivateTmp = true;
    UMask = "0077";

    # Kernel & Hardware Protection
    ProtectKernelTunables = true;
    ProtectKernelModules = false; # Must be false to allow iptables to modprobe netfilter modules
    ProtectKernelLogs = true;
    ProtectControlGroups = true;
    ProtectClock = true;
    ProtectHostname = true;
    LockPersonality = true;
    KeyringMode = "private";
    DevicePolicy = "closed";

    # Network & Process Isolation
    # Note: RestrictNamespaces is NOT set to true as some container networking
    # setups rely on the firewall service interacting with network namespaces.
    RestrictAddressFamilies = [
       "AF_INET"
       "AF_INET6"
       "AF_NETLINK"
       "AF_UNIX"
    ];

    # System Call Filtering
    # MDWE is explicitly NOT set, as the firewall relies on bash/nft/iptables
    # which may fail under strict memory execution constraints depending on the backend.
    SystemCallArchitectures = "native";
    SystemCallErrorNumber = "EPERM";
    SystemCallFilter = [
      "~@mount"
      "~@reboot"
      "~@swap"
      "~@clock"
      "~@resources"
      "~@obsolete"
      "~@cpu-emulation"
      "~@debug"
      "~@raw-io"
    ];
  };
}
