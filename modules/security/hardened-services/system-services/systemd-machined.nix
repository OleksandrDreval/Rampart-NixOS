{ config, lib, ... }:

{
  /*
    Rampart systemd-machined Hardening Module

    This module adds extra hardening on top of upstream systemd-machined.
    Upstream already provides comprehensive sandboxing including:
    CapabilityBoundingSet (allowlist), IPAddressDeny=any, LockPersonality,
    MemoryDenyWriteExecute, NoNewPrivileges, ProtectHostname,
    RestrictAddressFamilies (AF_UNIX AF_NETLINK AF_INET AF_INET6),
    RestrictRealtime, SystemCallArchitectures=native, SystemCallErrorNumber,
    SystemCallFilter=@system-service @mount.

    IMPORTANT — mount-namespace directives (ProtectSystem, ProtectHome,
    PrivateTmp, PrivateMounts, PrivateNetwork, PrivateUsers, ProtectProc,
    ProtectControlGroups, ProtectKernelTunables) MUST NOT be set.
    Upstream comment: "machined cannot be placed in a mount namespace,
    since it needs access to the host's mount namespace in order to
    implement the 'machinectl bind' operation."
    RestrictNamespaces MUST NOT be set — machined creates mount namespaces.
  */

  systemd.services.systemd-machined.serviceConfig = {
    # Extra hardening beyond upstream (seccomp-based only — no mount namespaces)
    ProtectClock = true;       # Does not modify system clock
    ProtectKernelLogs = true;  # Does not read kernel logs (dmesg)
  };
}
