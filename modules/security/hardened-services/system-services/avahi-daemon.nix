{ config, lib, ... }:

{
  /*
    Rampart Avahi Daemon (mDNS) Hardening Module

    Based on upstream avahi-daemon.service.
    Avahi requires chroot and network capabilities to function correctly,
    but it drops privileges extensively.
  */

  systemd.services.avahi-daemon.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;
    # CapabilityBoundingSet is omitted: avahi-daemon internally drops capabilities
    # and might need CAP_SETPCAP or others temporarily during startup.
    # Upstream explicitly does not restrict this at the systemd level.
    RestrictSUIDSGID = true;
    RestrictRealtime = true;

    # Filesystem Isolation
    ProtectSystem = "full"; # Upstream uses full
    ProtectHome = true;
    PrivateTmp = true;
    PrivateMounts = true;
    PrivateDevices = true; # Upstream explicitly enables PrivateDevices

    # Kernel & Hardware Protection
    ProtectKernelTunables = true;
    ProtectKernelModules = true;
    ProtectKernelLogs = true;
    ProtectControlGroups = true;
    ProtectClock = true;
    ProtectHostname = true;
    LockPersonality = true;
    KeyringMode = "private";

    # Process & Network Isolation
    RestrictNamespaces = true;
    ProtectProc = "invisible";
    RestrictAddressFamilies = [
       "AF_UNIX"
       "AF_INET"
       "AF_INET6"
       "AF_NETLINK"
    ];

    # System Call Filtering
    MemoryDenyWriteExecute = true;
    SystemCallArchitectures = "native";
    SystemCallErrorNumber = "EPERM";
    # Exact upstream system call filter whitelist
    SystemCallFilter = [
      "chroot"
      "@system-service"
    ];
  };
}
