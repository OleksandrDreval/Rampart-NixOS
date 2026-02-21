{ config, lib, ... }:

{
  /*
    Rampart PipeWire User Service Hardening Module

    This module hardens the PipeWire audio/video server and its companions
    (pipewire-pulse PulseAudio compatibility layer). These are user services
    running as the logged-in user, so most mount-namespace-based directives
    (ProtectSystem, ProtectHome, PrivateDevices, etc.) are silently ignored
    by systemd. We focus on seccomp-based restrictions that work reliably
    in user service context.

    IMPORTANT — do NOT set:
    - RestrictRealtime: PipeWire REQUIRES real-time scheduling for
      low-latency audio processing (SCHED_FIFO/SCHED_RR)
  */

  systemd.user.services.pipewire.serviceConfig = {
    # Privilege Restrictions
    NoNewPrivileges = true;   # Disallow privilege escalation
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits
    # RestrictRealtime intentionally NOT set — PipeWire needs RT scheduling

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
    MemoryDenyWriteExecute = true;       # PipeWire uses no JIT engine
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
    ];

    UMask = "0077";  # Restrictive file creation mask
  };

  # PulseAudio compatibility layer — same restrictions as PipeWire
  systemd.user.services.pipewire-pulse.serviceConfig = {
    # Privilege Restrictions
    NoNewPrivileges = true;   # Disallow privilege escalation
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits

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
    MemoryDenyWriteExecute = true;       # No JIT engine in PulseAudio bridge
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
    ];

    UMask = "0077";  # Restrictive file creation mask
  };
}
