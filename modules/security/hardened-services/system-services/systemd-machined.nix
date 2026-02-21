{ config, lib, ... }:

{
  /*
    Rampart systemd-machined Hardening Module

    This module hardens the systemd machine registration manager. It
    implements strict filesystem isolation, network blocking, and uses
    private user namespaces to ensure that the management of local
    containers and virtual machines is performed in a highly secure,
    untrusted environment.
  */

  systemd.services.systemd-machined.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Disallow gaining new privileges
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits
    RestrictRealtime = true;  # Prevent abuse of real-time scheduling

    # Filesystem Isolation
    ProtectSystem = "strict";     # Mount the entire filesystem read-only
    ProtectHome = true;           # Make /home and /root completely inaccessible
    PrivateTmp = true;            # Use a private and isolated /tmp directory
    PrivateMounts = true;         # Use a private file system namespace
    ProtectControlGroups = true;  # Mount cgroups hierarchy as read-only

    # Kernel & Hardware Protection
    ProtectClock = true;           # Prevent modification of system clock
    ProtectHostname = true;        # Prevent changing system hostname
    ProtectKernelTunables = true;  # Make kernel variables (/proc/sys) read-only
    ProtectKernelModules = true;   # Prevent loading/unloading kernel modules
    ProtectKernelLogs = true;      # Prevent reading kernel logs (dmesg)
    LockPersonality = true;        # Prevent execution domain changes

    # Network & Process Isolation
    PrivateNetwork = true;      # Completely isolate the service from the network
    PrivateUsers = true;        # Map service UID/GID to a private user namespace
    ProtectProc = "invisible";  # Hidden processes of other users in /proc
    RestrictNamespaces = true;  # Prohibit creation of any new namespaces
    # Limit allowed network address families (local IPC only)
    RestrictAddressFamilies = [ "AF_UNIX" ];

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;       # Prevent W^X memory regions
    SystemCallArchitectures = "native";  # Use only native system calls
  };
}
