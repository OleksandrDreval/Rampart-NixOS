{ config, lib, ... }:

{
  /*
    Rampart systemd-journald Hardening Module

    This module hardens the systemd logging service (journald). It restricts
    the visibility of other processes, protects the system hostname, and
    isolates the service mount namespace. These settings ensure that the
    logging system is tamper-resistant while reliably collecting system
    and service logs.
  */

  systemd.services.systemd-journald.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;  # Disallow gaining new privileges

    # Process & Identity Isolation
    ProtectProc = "invisible";  # Hidden processes of other users in /proc
    ProtectHostname = true;     # Prevent changing system hostname
    PrivateMounts = true;       # Use a private file system namespace

    # Filesystem & Storage
    ProtectSystem = "strict";   # Mount entire filesystem hierarchy read-only
    LogsDirectory = "journal";  # Writable /var/log/journal for persistent logs
    ReadWritePaths = [
      "/run/log/journal"      # Writable volatile journal storage
      "/run/systemd/journal"  # Writable journal communication sockets
    ];
  };
}
