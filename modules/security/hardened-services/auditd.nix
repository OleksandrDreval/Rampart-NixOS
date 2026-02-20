{ config, lib, ... }:

{
  /*
    Rampart Audit Daemon Hardening Module

    This module hardens auditd, which is responsible for system security
    auditing. Since it collects sensitive logs, it is isolated from the
    network and restricted from modifying kernel internals. We use a
    balanced filesystem protection to ensure it can continuously write its
    audit trails while remaining protected from subversion.
  */

  systemd.services.auditd.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Disallow gaining new privileges
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits
    RestrictRealtime = true;  # Prevent abuse of real-time scheduling
    # Block specific capabilities while keeping those needed for auditing
    CapabilityBoundingSet = [
      "~CAP_CHOWN"
      "~CAP_FSETID"
      "~CAP_SETFCAP"
    ];

    # Filesystem Isolation
    ProtectSystem = "strict";     # Mount entire filesystem hierarchy read-only
    LogsDirectory = "audit";      # Writable /var/log/audit for audit trails
    ProtectHome = true;           # Make /home and /root completely inaccessible
    PrivateTmp = true;            # Use a private and isolated /tmp directory
    PrivateMounts = true;         # Use a private file system namespace
    PrivateDevices = true;        # Make /dev inaccessible (except standard ones)
    ProtectControlGroups = true;  # Mount cgroups hierarchy as read-only

    # Kernel & Hardware Protection
    ProtectKernelTunables = true;  # Make kernel variables (/proc/sys) read-only
    ProtectKernelModules = true;   # Prevent loading/unloading kernel modules
    ProtectHostname = true;        # Prevent changing system hostname
    ProtectClock = true;           # Prevent changing system clock
    LockPersonality = true;        # Prevent execution domain changes

    # Network & Process Isolation
    PrivateNetwork = true;      # Completely isolate the service from the network
    ProtectProc = "invisible";  # Hidden processes of other users in /proc
    RestrictNamespaces = true;  # Prohibit creation of any new namespaces
    # Disable network address families
    RestrictAddressFamilies = [
      "~AF_INET6"
      "~AF_INET"
      "~AF_PACKET"
    ];
  };
}
