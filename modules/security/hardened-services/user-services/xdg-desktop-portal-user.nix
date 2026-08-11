{ config, lib, ... }:

{
  /*
    Rampart XDG Desktop Portal User Service Hardening Module

    This module hardens the XDG Desktop Portal services that provide a
    D-Bus interface for sandboxed applications (Flatpak, Snap, etc.) to
    access desktop resources like file choosers, screenshots, screen
    sharing, and notifications.

    NOTE: xdg-desktop-portal-kde may use QtWebEngine internally for
    certain portal implementations; MemoryDenyWriteExecute is set to false
    for the KDE backend as a precaution.
  */

  # Main portal multiplexer
  systemd.user.services.xdg-desktop-portal.serviceConfig = {
    # Privilege Restrictions
    NoNewPrivileges = true;   # Disallow privilege escalation
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits
    RestrictRealtime = true;  # Does not need real-time scheduling

    # Kernel Protection (seccomp-based)
    ProtectHostname = true;   # Prevent changing system hostname
    ProtectClock = true;      # Prevent modification of system clock
    LockPersonality = true;   # Prevent execution domain changes
    KeyringMode = "private";  # Allow isolated kernel keyring for portal processes

    # Namespace Restrictions
    RestrictNamespaces = true;  # Prohibit creation of any new namespaces

    # Network Restrictions (seccomp-based)
    RestrictAddressFamilies = [
      "AF_UNIX"     # D-Bus communication
      "AF_INET"     # Network portal may proxy connections
      "AF_INET6"    # Network portal may proxy connections
      "AF_NETLINK"  # Device and network information
    ];

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;       # No JIT engine in the multiplexer
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
      "~@clock"          # Block clock configuration
      # allow use of an isolated kernel keyring for session secrets
    ];

    UMask = "0077";  # Restrictive file creation mask
  };

  # KDE Plasma portal backend
  systemd.user.services.xdg-desktop-portal-kde.serviceConfig = {
    # Privilege Restrictions
    NoNewPrivileges = true;   # Disallow privilege escalation
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits
    RestrictRealtime = true;  # Does not need real-time scheduling

    # Kernel Protection (seccomp-based)
    ProtectHostname = true;   # Prevent changing system hostname
    ProtectClock = true;      # Prevent modification of system clock
    LockPersonality = true;   # Prevent execution domain changes
    KeyringMode = "private";  # Allow isolated kernel keyring for portal processes

    # Namespace Restrictions
    RestrictNamespaces = true;  # Prohibit creation of any new namespaces

    # Network Restrictions (seccomp-based)
    RestrictAddressFamilies = [
      "AF_UNIX"     # D-Bus communication
      "AF_INET"     # Network portal may proxy connections
      "AF_INET6"    # Network portal may proxy connections
      "AF_NETLINK"  # Device and network information
    ];

    # Memory & System Call Filtering
    # MDWE disabled — KDE portal may use QtWebEngine (V8 JIT)
    MemoryDenyWriteExecute = false;
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
      "~@clock"          # Block clock configuration
      # allow use of an isolated kernel keyring for session secrets
    ];

    UMask = "0077";  # Restrictive file creation mask
  };

  # GTK portal backend (used by some applications even in KDE)
  systemd.user.services.xdg-desktop-portal-gtk.serviceConfig = {
    # Privilege Restrictions
    NoNewPrivileges = true;   # Disallow privilege escalation
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits
    RestrictRealtime = true;  # Does not need real-time scheduling

    # Kernel Protection (seccomp-based)
    ProtectHostname = true;   # Prevent changing system hostname
    ProtectClock = true;      # Prevent modification of system clock
    LockPersonality = true;   # Prevent execution domain changes
    KeyringMode = "private";  # Allow isolated kernel keyring for portal processes

    # Namespace Restrictions
    RestrictNamespaces = true;  # Prohibit creation of any new namespaces

    # Network Restrictions (seccomp-based)
    RestrictAddressFamilies = [
      "AF_UNIX"     # D-Bus communication
      "AF_INET"     # Network portal may proxy connections
      "AF_INET6"    # Network portal may proxy connections
      "AF_NETLINK"  # Device and network information
    ];

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;       # GTK portal does not use JIT
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
      "~@clock"          # Block clock configuration
      # allow use of an isolated kernel keyring for session secrets
    ];

    UMask = "0077";  # Restrictive file creation mask
  };
}
