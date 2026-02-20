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
    PrivateTmp = true;            # Use a private and isolated /tmp directory
    PrivateMounts = true;         # Use a private file system namespace
    ProtectControlGroups = true;  # Mount cgroups hierarchy as read-only

    # Kernel & Hardware Protection
    ProtectKernelTunables = true;  # Make kernel variables (/proc/sys) read-only
    ProtectKernelModules = true;   # Prevent loading/unloading kernel modules
    ProtectKernelLogs = true;      # Prevent reading kernel logs (dmesg)
    ProtectClock = true;           # Prevent modification of system clock
    ProtectHostname = true;        # Prevent changing system hostname
    LockPersonality = true;        # Prevent execution domain changes

    # Network & Process Isolation
    IPAddressDeny = [ "0.0.0.0/0" "::/0" ];  # Zero trust network isolation
    RestrictNamespaces = true;               # Prohibit creation of any new namespaces
    # Limit allowed network address families (terminal does not need network)
    RestrictAddressFamilies = [
      "AF_UNIX"
      "AF_NETLINK"
    ];

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;       # Prevent W^X memory regions
  };
}
