{ config, lib, ... }:

{
  /*
    Rampart Realtime Kit (rtkit) Hardening Module

    This module hardens rtkit-daemon, which hands out realtime priority to
    user processes (like audio servers). Since it deals with process
    priorities and scheduling, it is isolated from the network, kernel
    internals, and most of the filesystem to prevent it from being abused
    to cause system-wide denial of service.
  */

  systemd.services.rtkit-daemon.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Disallow gaining new privileges
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits within the service

    # Filesystem Isolation
    ProtectSystem = "strict";  # Mount the entire filesystem read-only
    ProtectHome = true;        # Make /home and /root completely inaccessible
  };
}
