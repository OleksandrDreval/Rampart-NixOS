{ config, lib, ... }:

{
  /*
    Rampart Chrony (NTP Daemon) Hardening Module

    Based on upstream chronyd.service.
    chronyd needs CAP_SYS_TIME to adjust the system clock and
    CAP_NET_BIND_SERVICE to listen on port 123.
  */

  systemd.services.chronyd.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;
    CapabilityBoundingSet = [
      "CAP_CHOWN"
      "CAP_DAC_OVERRIDE"
      "CAP_NET_BIND_SERVICE"
      "CAP_SETGID"
      "CAP_SETUID"
      "CAP_SYS_RESOURCE"
      "CAP_SYS_TIME"
    ];

    RestrictSUIDSGID = true;
    RestrictRealtime = true;

    # Filesystem Isolation
    ProtectSystem = "full";
    ProtectHome = true;
    PrivateTmp = true;
    PrivateMounts = true;

    # Kernel & Hardware Protection
    ProtectKernelTunables = true;
    ProtectKernelModules = true;
    ProtectKernelLogs = true;
    ProtectControlGroups = true;
    ProtectHostname = true;
    LockPersonality = true;
    KeyringMode = "private";
    DevicePolicy = "closed";
    DeviceAllow = [
      "char-pps rw"
      "char-ptp rw"
      "char-rtc rw"
    ];

    # Process & Network Isolation
    RestrictNamespaces = true;
    ProtectProc = "invisible";
    ProcSubset = "pid";
    RestrictAddressFamilies = [
       "AF_UNIX"
       "AF_INET"
       "AF_INET6"
    ];

    # System Call Filtering & IPC
    MemoryDenyWriteExecute = true;
    RemoveIPC = true;
    SystemCallArchitectures = "native";
    SystemCallErrorNumber = "EPERM";
    SystemCallFilter = [
      "~@cpu-emulation @debug @keyring @mount @obsolete @privileged @resources"
      "@clock"
      "@setuid"
      "capset"
      "@chown"
    ];
  };
}
