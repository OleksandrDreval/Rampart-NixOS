{ config, lib, ... }:

{
  /*
    Rampart ACPI Daemon (acpid) Hardening Module

    This module hardens acpid, which handles hardware events like power
    buttons and laptop lids. It isolates the service from the network,
    hides other processes, and applies strict system call filtering to
    ensure that power management events are processed securely without
    exposing a large attack surface.
  */

  systemd.services.acpid.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Disallow gaining new privileges
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits
    RestrictRealtime = true;  # Prevent abuse of real-time scheduling
    # Block specific capabilities that are not needed for ACPI events
    CapabilityBoundingSet = [
      "~CAP_CHOWN"
      "~CAP_FSETID"
      "~CAP_SETFCAP"
    ];

    # Filesystem & Process Isolation
    ProtectSystem = "full";     # Protect /usr, /boot, and /etc from writes
    ProtectHome = true;         # Make /home and /root completely inaccessible
    ProtectProc = "invisible";  # Hidden processes of other users in /proc
    PrivateTmp = true;          # Use a private and isolated /tmp directory
    PrivateMounts = true;       # Use a private file system namespace
  };
}
