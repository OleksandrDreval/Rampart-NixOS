{ config, lib, ... }:

{
  /*
    Rampart Virtual Terminal (AutoVT) Hardening Module

    This module hardens the virtual terminal services (getty/autovt). It
    applies strict filesystem isolation, network blocking, and restricts
    system calls to prevent virtual consoles from being used to escalate
    privileges or leak system state information.
  */

  systemd.services."autovt@".serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Disallow gaining new privileges
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits
    RestrictRealtime = true;  # Prevent abuse of real-time scheduling

    # Filesystem Isolation
    ProtectSystem = "strict";     # Mount the entire filesystem read-only
    ProtectHome = true;           # Make /home and /root completely inaccessible
  };
}
