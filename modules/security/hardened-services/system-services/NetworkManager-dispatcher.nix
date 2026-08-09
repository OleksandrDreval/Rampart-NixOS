{ config, lib, ... }:

{
  /*
    Rampart NetworkManager Dispatcher Hardening Module

    This module applies conservative hardening to the NM dispatcher service,
    which executes custom scripts on network events (connect, disconnect, etc.).
    Upstream NM-dispatcher has zero hardening (only KillMode=process).

    IMPORTANT — dispatcher runs ARBITRARY user scripts from
    /etc/NetworkManager/dispatcher.d/. Scripts may restart services, update
    DNS, flush routes, set hostname, or use SUID helpers. Therefore:
    - NoNewPrivileges MUST NOT be true — scripts may use SUID helpers
    - CapabilityBoundingSet MUST NOT restrict — scripts may need broad caps
    - ~@privileged MUST NOT be in SystemCallFilter — scripts may call
      sethostname, chroot, and other privileged operations
    - ProtectHostname MUST NOT be set — scripts often set hostname on events
    - RestrictNamespaces MUST NOT be set — scripts may create namespaces
  */

  systemd.services.NetworkManager-dispatcher.serviceConfig = {
    # Privilege & Capability Restrictions
    # NoNewPrivileges and CapabilityBoundingSet are intentionally omitted
    # because dispatcher scripts often execute external utilities that require
    # broad privileges (like systemctl to restart services, or SUID helpers).
    RestrictSUIDSGID = false; # Allow SUID/SGID bits for scripts to use helpers if needed
    RestrictRealtime = true;  # Dispatcher scripts do not need RT scheduling

    # Filesystem Isolation
    ProtectSystem = "full";  # Protect /usr, /boot, /efi read-only (on NixOS, /etc is immutable anyway)
    ProtectHome = true;      # Scripts do not need access to home directories
    PrivateTmp = true;       # Isolated /tmp directory
    PrivateMounts = true;    # Private mount namespace

    # Kernel & Hardware Protection
    # Many protections are intentionally omitted to allow scripts to function:
    # - ProtectKernelModules: Scripts may load modules.
    # - ProtectHostname: Scripts often set hostname on events.
    ProtectKernelLogs = true;     # Scripts do not read dmesg
    ProtectControlGroups = true;  # Scripts do not modify cgroups
    ProtectClock = true;          # Scripts do not modify system clock
    LockPersonality = true;       # Prevent personality changes

    # Network & Process Isolation
    # RestrictAddressFamilies is intentionally omitted because scripts often
    # need IPv4/IPv6 access (e.g., dynamic DNS updates, cloud metadata APIs).
    # ProtectProc and ProcSubset omitted: dispatcher scripts frequently use
    # `pgrep`, `pidof`, or `ps` to check if other services (like VPNs or SSH)
    # are running. Hiding other processes breaks these scripts.

    # Memory & System Call Filtering
    # SystemCallFilter is minimal because scripts might call privileged
    # operations (chroot, sethostname, mount).
    MemoryDenyWriteExecute = true;       # Shell scripts do not use JIT
    SystemCallArchitectures = "native";  # Allow only native syscalls
    SystemCallErrorNumber = "EPERM";     # Return EPERM for blocked syscalls
    SystemCallFilter = [
      "~@obsolete"       # Block deprecated calls
      "~@cpu-emulation"  # Block CPU emulation
      "~@debug"          # Block debugging calls
    ];

    # Other Security Settings
    KeyringMode = "private";  # Isolated kernel keyring
    PrivateIPC = true;        # Private IPC namespace
    # UMask = "0077" omitted: If a dispatcher script updates /etc/resolv.conf or
    # other shared config files, it will make them unreadable by normal users.
  };
}
