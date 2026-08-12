{ config, lib, ... }:

{
  /*
    Rampart save-hwclock Hardening Module

    Based on NixOS defaults. This service is a one-shot that saves the 
    current system time to the hardware clock (RTC). It needs CAP_SYS_TIME.
  */

  systemd.services.save-hwclock.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;
    CapabilityBoundingSet = [
      "CAP_SYS_TIME"
    ];

    RestrictSUIDSGID = true;
    RestrictRealtime = true;

    # Filesystem Isolation
    ProtectSystem = "strict";
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
    DeviceAllow = "/dev/rtc0 rw";

    # Network & Process Isolation
    PrivateNetwork = true;
    PrivateIPC = true;
    RestrictNamespaces = true;
    ProtectProc = "invisible";
    ProcSubset = "pid";
    RestrictAddressFamilies = [ "AF_UNIX" ];

    # System Call Filtering
    MemoryDenyWriteExecute = true;
    SystemCallArchitectures = "native";
    SystemCallErrorNumber = "EPERM";
    SystemCallFilter = [
      "~@mount"
      "~@module"
      "~@reboot"
      "~@swap"
      "~@resources"
      "~@obsolete"
      "~@cpu-emulation"
      "~@debug"
      "~@raw-io"
    ];
  };
}
