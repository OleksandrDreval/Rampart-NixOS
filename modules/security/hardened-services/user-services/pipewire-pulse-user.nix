{ config, lib, ... }:

{
  /*
    Rampart PipeWire PulseAudio Compatibility Layer Hardening Module

    This module hardens pipewire-pulse, the PulseAudio compatibility layer.
    As a user service running as the logged-in user, most mount-namespace-based 
    directives are silently ignored by systemd. We focus on seccomp-based 
    restrictions that work reliably in user service context.
  */

  systemd.user.services.pipewire-pulse.serviceConfig = {
    # Privilege Restrictions
    NoNewPrivileges = true;   # Disallow privilege escalation
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits
    # RestrictRealtime intentionally NOT set — Pulse bridge needs RT scheduling for low latency

    # Kernel Protection (seccomp-based)
    ProtectHostname = true;   # Prevent changing system hostname
    ProtectClock = true;      # Prevent modification of system clock
    LockPersonality = true;   # Prevent execution domain changes
    KeyringMode = "private";  # Allow isolated kernel keyring for audio session components

    # Namespace Restrictions
    RestrictNamespaces = true;  # Prohibit creation of any new namespaces

    # Network Restrictions (seccomp-based)
    RestrictAddressFamilies = [
      "AF_UNIX"       # D-Bus, PipeWire socket
      "AF_NETLINK"    # Device discovery via udev
      "AF_INET"       # Network audio (ROC, Pulse TCP, AirPlay)
      "AF_INET6"      # IPv6 network audio
      "AF_BLUETOOTH"  # Bluetooth audio devices
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
      "~@clock"          # Block clock configuration
      "~@raw-io"         # Block raw I/O access
      # allow use of an isolated kernel keyring for session secrets
    ];

    UMask = "0077";  # Restrictive file creation mask
  };
}
