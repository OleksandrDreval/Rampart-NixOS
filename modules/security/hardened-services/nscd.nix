{ config, lib, ... }:

{
  /*
    Rampart Name Service Cache Daemon (nscd) Hardening Module

    This module hardens nscd, which caches lookups for hosts, passwords,
    groups, and other databases. It hides processes, restricts system
    modifications, and blocks unnecessary root capabilities while allowing
    it to reliably provide character-to-ID lookups for the system.
  */

  systemd.services.nscd.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Disallow gaining new privileges

    PrivateTmp = true;          # Use a private and isolated /tmp directory

    LockPersonality = true;        # Prevent execution domain changes

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;       # Prevent W^X memory regions
    SystemCallArchitectures = "native";  # Use only native system calls
  };
}
