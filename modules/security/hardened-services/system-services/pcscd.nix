{ config, lib, ... }:

{
  /*
    Rampart pcscd (Smart Card Daemon) Hardening Module

    Based on upstream pcscd.service.
    pcscd needs direct access to USB devices but no network access.
  */

  systemd.services.pcscd.serviceConfig = {
    # Privilege Restrictions
    NoNewPrivileges = true;
    CapabilityBoundingSet = ""; # Upstream explicitly drops ALL capabilities!
    RestrictSUIDSGID = true;
    RestrictRealtime = true;

    # Filesystem Isolation
    ProtectSystem = "strict";
    ProtectHome = true;
    PrivateTmp = true;
    PrivateUsers = "identity"; # Upstream explicitly sets this

    # Kernel & Hardware Protection
    ProtectKernelTunables = true;
    ProtectKernelModules = true;
    ProtectKernelLogs = true;
    ProtectControlGroups = true;
    ProtectClock = true;
    ProtectHostname = true;
    LockPersonality = true;

    # Process & Network Isolation
    RestrictNamespaces = true;
    ProtectProc = "invisible";
    UMask = "0077";

    # System Call Filtering
    MemoryDenyWriteExecute = true;
    SystemCallArchitectures = "native";
    SystemCallErrorNumber = "EPERM";
    # Exact upstream system call filter
    SystemCallFilter = [
      "@system-service"
      "~@resources"
      "~@privileged"
    ];
  };
}
