{ config, lib, ... }:

{
  /*
    Rampart D-Bus Hardening Module

    This module hardens the D-Bus system bus daemon, which is the central
    nervous system of a Linux desktop. It implements strict filesystem
    sandboxing, network isolation (D-Bus system bus should not need the internet),
    and restricted system calls to prevent it from being used as an escape
    vector while maintaining full system messaging functionality.
  */

  systemd.services.dbus.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Disallow gaining new privileges via setuid/setgid
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits within the service
    RestrictRealtime = true;  # Prevent abuse of real-time scheduling

    # Filesystem Isolation
    # Using "strict" combined with systemd internal handling for dbus sockets
    ProtectSystem = "strict";     # Mount the entire filesystem read-only
    ProtectHome = true;           # Make /home and /root completely inaccessible
    PrivateTmp = true;            # Use a private and isolated /tmp directory
    PrivateDevices = true;        # Make /dev inaccessible (except standard pseudo-devices)
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
    PrivateNetwork = true;      # Completely isolate the service from the network
    IPAddressDeny = "any";      # Zero trust network isolation
    ProtectProc = "invisible";  # Hidden processes of other users in /proc
    ProcSubset = "pid";         # Only show the daemon's own PID
    RestrictNamespaces = true;  # Prohibit creation of any new namespaces
    # Limit allowed network address families (local IPC only)
    RestrictAddressFamilies = [ "AF_UNIX" ];

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;       # Prevent W^X memory regions
    SystemCallArchitectures = "native";  # Use only native system calls
    SystemCallErrorNumber = "EPERM";     # Return EPERM for blocked calls
    SystemCallFilter = [
      "~@obsolete"       # Block deprecated system calls
      "~@resources"      # Block resource limit changes
      "~@debug"          # Block debugging system calls
      "~@mount"          # Block filesystem mounting
      "~@reboot"         # Block system reboot
      "~@swap"           # Block swap management
      "~@cpu-emulation"  # Block non-native CPU emulation
      "~@raw-io"         # Block raw I/O access
    ];

    # Other Security Settings
    DevicePolicy = "closed";  # Allow access only to /dev/null, /dev/zero, etc.
    KeyringMode = "private";  # Isolated kernel keyring
    PrivateIPC = true;        # Private IPC namespace
    RemoveIPC = true;         # Clean up IPC objects on service stop
    UMask = "0077";           # Ensure files created are private
  };
}
