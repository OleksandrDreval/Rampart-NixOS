{ config, lib, ... }:

{
  /*
    Rampart Getty Terminal Hardening Module

    This module hardens the Getty service, which provides login terminals on
    virtual consoles. It implements strict filesystem isolation, blocks
    all network access, and restricts system calls to ensure that the
    console login interface is protected from exploitation.
  */

  systemd.services."getty@".serviceConfig = {
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
    # Limit allowed network address families
    RestrictAddressFamilies = [
      "AF_UNIX"
      "AF_NETLINK"
    ];

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;       # Prevent W^X memory regions
    SystemCallArchitectures = "native";  # Use only native system calls
    SystemCallErrorNumber = "EPERM";     # Return EPERM for blocked calls
    SystemCallFilter = [
      "~@obsolete"       # Block deprecated system calls
      "~@debug"          # Block debugging system calls
      "~@reboot"         # Block system reboot
      "~@swap"           # Block swap management
      "~@clock"          # Block clock configuration
      "~@cpu-emulation"  # Block non-native CPU emulation
    ];

    # Other Security Settings
    UMask = 0077;  # Ensure console related files stay private
  };
}
