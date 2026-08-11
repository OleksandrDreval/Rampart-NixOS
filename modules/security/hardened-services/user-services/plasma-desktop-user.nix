{ config, lib, ... }:

{
  /*
    Rampart KDE Plasma Desktop User Service Hardening Module

    This module hardens KDE Plasma 6 desktop user services. Plasma services
    are tightly integrated with the desktop environment and require broad
    access to hardware, network, and D-Bus. Hardening is CONSERVATIVE —
    we only apply seccomp-based restrictions that are proven safe.

    KEY CONSTRAINTS:
    - kwin (Wayland compositor): minimal hardening only — needs GPU, input
      devices, RT scheduling, and broad system access
    - plasmashell: minimal hardening — uses QtWebEngine (V8 JIT) for widgets
    - kded6: plugin host — conservative due to unknown plugin requirements
    - baloo (file indexer): best hardening candidate — pure C++ indexer

    NOTE: MemoryDenyWriteExecute CANNOT be set for services that may use
    QtWebEngine (plasmashell, kded6, kwin) because V8 uses JIT compilation.
  */

  # kwin_wayland — Wayland compositor (MINIMAL hardening)
  systemd.user.services.plasma-kwin_wayland.serviceConfig = {
    # Only the safest, most conservative restrictions
    SystemCallArchitectures = "native";  # Block non-native syscall ABIs
    RestrictSUIDSGID = true;             # Disable SUID/SGID bits
    LockPersonality = true;              # Prevent execution domain changes
    ProtectHostname = true;              # Prevent changing system hostname
    ProtectClock = true;                 # Prevent modification of system clock
    SystemCallErrorNumber = "EPERM";     # Return EPERM for blocked syscalls
    SystemCallFilter = [
      "~@obsolete"       # Block deprecated system calls
      "~@cpu-emulation"  # Block non-native CPU emulation
      "~@module"         # Block kernel module operations
    ];
    # Do NOT set: NoNewPrivileges, RestrictRealtime, MDWE, RestrictNamespaces,
    # RestrictAddressFamilies — kwin needs broad access as Wayland compositor
  };

  # kded6 — KDE daemon module host (conservative)
  systemd.user.services.plasma-kded6.serviceConfig = {
    # Privilege Restrictions
    NoNewPrivileges = true;   # Disallow privilege escalation
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits

    # Kernel Protection (seccomp-based)
    ProtectHostname = true;              # Prevent changing system hostname
    ProtectClock = true;                 # Prevent modification of system clock
    LockPersonality = true;              # Prevent execution domain changes
    SystemCallArchitectures = "native";  # Allow only native system calls

    # Namespace Restrictions
    RestrictNamespaces = true;  # Prohibit creation of any new namespaces

    # Network Restrictions (seccomp-based)
    RestrictAddressFamilies = [
      "AF_UNIX"       # D-Bus communication
      "AF_INET"       # Network-dependent plugins
      "AF_INET6"      # Network-dependent plugins
      "AF_NETLINK"    # Device and network information
      "AF_BLUETOOTH"  # KDE bluedevil Bluetooth integration
    ];

    # Memory & System Call Filtering
    # MDWE disabled — kded6 plugins may use QtWebEngine (V8 JIT)
    MemoryDenyWriteExecute = false;
    SystemCallErrorNumber = "EPERM";  # Return EPERM for blocked syscalls
    SystemCallFilter = [
      "~@obsolete"       # Block deprecated system calls
      "~@cpu-emulation"  # Block non-native CPU emulation
      "~@module"         # Block kernel module operations
      "~@swap"           # Block swap management
      "~@reboot"         # Block system reboot
    ];

    UMask = "0077";  # Restrictive file creation mask
  };

  # plasmashell — Desktop shell (MINIMAL hardening)
  systemd.user.services.plasma-plasmashell.serviceConfig = {
    # Kernel Protection (seccomp-based)
    # Plasmashell uses QtWebEngine for widgets — very restricted hardening
    ProtectHostname = true;              # Prevent changing system hostname
    ProtectClock = true;                 # Prevent modification of system clock
    LockPersonality = true;              # Prevent execution domain changes
    RestrictSUIDSGID = true;             # Disable SUID/SGID bits
    SystemCallArchitectures = "native";  # Allow only native system calls

    # Memory & System Call Filtering
    # MDWE disabled — plasmashell uses QtWebEngine (V8 JIT)
    # RestrictAddressFamilies not set — needs full network for widgets
    # RestrictNamespaces not set — may create namespaces for sandboxing
    SystemCallErrorNumber = "EPERM";  # Return EPERM for blocked syscalls
    SystemCallFilter = [
      "~@obsolete"       # Block deprecated system calls
      "~@cpu-emulation"  # Block non-native CPU emulation
      "~@module"         # Block kernel module operations
    ];
  };

  # kglobalaccel — Global keyboard shortcut daemon
  systemd.user.services.plasma-kglobalaccel.serviceConfig = {
    # Privilege Restrictions
    NoNewPrivileges = true;   # Disallow privilege escalation
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits
    RestrictRealtime = true;  # Does not need real-time scheduling

    # Kernel Protection (seccomp-based)
    ProtectHostname = true;              # Prevent changing system hostname
    ProtectClock = true;                 # Prevent modification of system clock
    LockPersonality = true;              # Prevent execution domain changes
    SystemCallArchitectures = "native";  # Allow only native system calls

    # Namespace Restrictions
    RestrictNamespaces = true;  # Prohibit creation of any new namespaces

    # Network Restrictions (seccomp-based)
    RestrictAddressFamilies = [ "AF_UNIX" ];  # D-Bus only

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;  # Simple daemon, no JIT
    SystemCallErrorNumber = "EPERM";  # Return EPERM for blocked syscalls
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
      "~@keyring"        # Block kernel keyring access
    ];

    UMask = "0077";  # Restrictive file creation mask
  };

  # kactivitymanagerd — Activity tracking daemon
  systemd.user.services.plasma-kactivitymanagerd.serviceConfig = {
    # Privilege Restrictions
    NoNewPrivileges = true;   # Disallow privilege escalation
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits
    RestrictRealtime = true;  # Does not need real-time scheduling

    # Kernel Protection (seccomp-based)
    ProtectHostname = true;              # Prevent changing system hostname
    ProtectClock = true;                 # Prevent modification of system clock
    LockPersonality = true;              # Prevent execution domain changes
    SystemCallArchitectures = "native";  # Allow only native system calls

    # Namespace Restrictions
    RestrictNamespaces = true;  # Prohibit creation of any new namespaces

    # Network Restrictions (seccomp-based)
    RestrictAddressFamilies = [ "AF_UNIX" ];  # D-Bus only

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;  # SQLite-based daemon, no JIT
    SystemCallErrorNumber = "EPERM";  # Return EPERM for blocked syscalls
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
      "~@keyring"        # Block kernel keyring access
    ];

    UMask = "0077";  # Restrictive file creation mask
  };

  # ksmserver — Session manager
  systemd.user.services.plasma-ksmserver.serviceConfig = {
    # Privilege Restrictions
    NoNewPrivileges = true;   # Disallow privilege escalation
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits

    # Kernel Protection (seccomp-based)
    ProtectHostname = true;              # Prevent changing system hostname
    ProtectClock = true;                 # Prevent modification of system clock
    LockPersonality = true;              # Prevent execution domain changes
    SystemCallArchitectures = "native";  # Allow only native system calls

    # Namespace Restrictions
    RestrictNamespaces = true;  # Prohibit creation of any new namespaces

    # Network Restrictions (seccomp-based)
    RestrictAddressFamilies = [
      "AF_UNIX"   # D-Bus, X11 socket
      "AF_INET"   # XSMP protocol
      "AF_INET6"  # XSMP protocol (IPv6)
    ];

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = false;  # May use Qt components with JIT
    SystemCallErrorNumber = "EPERM";  # Return EPERM for blocked syscalls
    SystemCallFilter = [
      "~@obsolete"       # Block deprecated system calls
      "~@cpu-emulation"  # Block non-native CPU emulation
      "~@module"         # Block kernel module operations
      "~@swap"           # Block swap management
      "~@reboot"         # Block system reboot
      "~@debug"          # Block debugging syscalls
      "~@raw-io"         # Block raw I/O operations
      "~@clock"          # Block clock configuration
      "~@keyring"        # Block kernel keyring access
    ];

    UMask = "0077";  # Restrictive file creation mask
  };

  # xembedsniproxy — X11 system tray proxy
  systemd.user.services.plasma-xembedsniproxy.serviceConfig = {
    # Privilege Restrictions
    NoNewPrivileges = true;   # Disallow privilege escalation
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits
    RestrictRealtime = true;  # Does not need real-time scheduling

    # Kernel Protection (seccomp-based)
    ProtectHostname = true;              # Prevent changing system hostname
    ProtectClock = true;                 # Prevent modification of system clock
    LockPersonality = true;              # Prevent execution domain changes
    SystemCallArchitectures = "native";  # Allow only native system calls

    # Namespace Restrictions
    RestrictNamespaces = true;  # Prohibit creation of any new namespaces

    # Network Restrictions (seccomp-based)
    RestrictAddressFamilies = [ "AF_UNIX" ];  # X11 socket only

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;  # Simple proxy, no JIT
    SystemCallErrorNumber = "EPERM";  # Return EPERM for blocked syscalls
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
      "~@keyring"        # Block kernel keyring access
    ];

    UMask = "0077";  # Restrictive file creation mask
  };

  # polkit-kde-authentication-agent-1 — PolicyKit UI agent
  systemd.user.services.plasma-polkit-agent.serviceConfig = {
    # Privilege Restrictions
    NoNewPrivileges = true;   # Disallow privilege escalation
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits
    RestrictRealtime = true;  # Does not need real-time scheduling

    # Kernel Protection (seccomp-based)
    ProtectHostname = true;              # Prevent changing system hostname
    ProtectClock = true;                 # Prevent modification of system clock
    LockPersonality = true;              # Prevent execution domain changes
    SystemCallArchitectures = "native";  # Allow only native system calls

    # Namespace Restrictions
    RestrictNamespaces = true;  # Prohibit creation of any new namespaces

    # Network Restrictions (seccomp-based)
    RestrictAddressFamilies = [ "AF_UNIX" ];  # D-Bus only

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = false;   # Qt UI — may load Qt components with JIT
    KeyringMode = "private";          # Allow isolated kernel keyring for auth UI agent
    SystemCallErrorNumber = "EPERM";  # Return EPERM for blocked syscalls
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
      # allow use of an isolated kernel keyring for policy/auth interactions
    ];

    UMask = "0077";  # Restrictive file creation mask
  };

  # kde-baloo — File indexer
  systemd.user.services.kde-baloo.serviceConfig = {
    # Privilege Restrictions
    NoNewPrivileges = true;   # Disallow privilege escalation
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits
    RestrictRealtime = true;  # Indexer does not need real-time scheduling

    # Kernel Protection (seccomp-based)
    ProtectHostname = true;              # Prevent changing system hostname
    ProtectClock = true;                 # Prevent modification of system clock
    LockPersonality = true;              # Prevent execution domain changes
    SystemCallArchitectures = "native";  # Allow only native system calls

    # Namespace Restrictions
    RestrictNamespaces = true;  # Prohibit creation of any new namespaces

    # Network Restrictions (seccomp-based)
    RestrictAddressFamilies = [ "AF_UNIX" ];  # D-Bus communication only

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;    # Pure C++ indexer, no JIT required
    SystemCallErrorNumber = "EPERM";  # Return EPERM for blocked syscalls
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
      "~@keyring"        # Block kernel keyring access
    ];

    UMask = "0077";  # Restrictive file creation mask
  };
}
