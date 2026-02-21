{ config, lib, ... }:

{
  /*
    Rampart WirePlumber User Service Hardening Module

    This module hardens the WirePlumber session manager for PipeWire.
    WirePlumber uses PUC-Rio Lua (NOT LuaJIT) for scripting, so
    MemoryDenyWriteExecute is safe. Unlike PipeWire itself, WirePlumber
    does not require real-time scheduling.
  */

  systemd.user.services.wireplumber.serviceConfig = {
    # Privilege Restrictions
    NoNewPrivileges = true;   # Disallow privilege escalation
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits
    RestrictRealtime = true;  # WirePlumber does not need RT scheduling

    # Kernel Protection (seccomp-based)
    ProtectHostname = true;  # Prevent changing system hostname
    ProtectClock = true;     # Prevent modification of system clock
    LockPersonality = true;  # Prevent execution domain changes

    # Namespace Restrictions
    RestrictNamespaces = true;  # Prohibit creation of any new namespaces

    # Network Restrictions (seccomp-based)
    RestrictAddressFamilies = [
      "AF_UNIX"     # D-Bus, PipeWire socket
      "AF_NETLINK"  # Device discovery via udev
    ];

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;       # PUC-Rio Lua does not use JIT
    SystemCallArchitectures = "native";  # Allow only native system calls
    SystemCallErrorNumber = "EPERM";     # Return EPERM for blocked syscalls
    SystemCallFilter = [
      "~@mount"          # Block filesystem mounting
      "~@reboot"         # Block system reboot
      "~@swap"           # Block swap management
      "~@obsolete"       # Block deprecated system calls
      "~@cpu-emulation"  # Block non-native CPU emulation
      "~@module"         # Block kernel module operations
      "~@debug"          # Block debugging syscalls
      "~@raw-io"         # Block raw I/O operations
    ];

    UMask = "0077";  # Restrictive file creation mask
  };
}
