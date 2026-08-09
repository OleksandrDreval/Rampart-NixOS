{ config, lib, ... }:

{
  /*
    Rampart AppArmor Service Hardening Module

    This module hardens the AppArmor profile loader service. AppArmor is a
    oneshot service that compiles MAC profiles and loads them into the kernel
    via securityfs (/sys/kernel/security/apparmor/). After loading, the
    service remains in active state (RemainAfterExit).

    NOTE: ProtectSystem is "full" for safety. "strict" with ReadWritePaths
    would also work, but "full" is the more conservative choice.
    ProtectKernelTunables MUST NOT be set — it makes /sys/ read-only,
    which prevents profile loading into the kernel security module via
    /sys/kernel/security/apparmor/.
  */

  systemd.services.apparmor.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Disallow gaining new privileges
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits
    RestrictRealtime = true;  # Prevent abuse of real-time scheduling
    CapabilityBoundingSet = [
      "CAP_SYS_ADMIN"      # securityfs access for loading profiles
      "CAP_MAC_ADMIN"      # MAC policy management
      "CAP_DAC_OVERRIDE"   # Read profiles from restricted paths
      "CAP_DAC_READ_SEARCH" # Traverse directories
    ];

    # Filesystem Isolation
    ProtectSystem = "strict";      # Mount entire filesystem hierarchy read-only
    CacheDirectory = [ "apparmor" "apparmor/logprof" ]; # Writable /var/cache/apparmor (NixOS default)
    ProtectHome = true;            # Make /home and /root completely inaccessible
    PrivateTmp = true;             # Use a private and isolated /tmp directory
    PrivateDevices = true;         # No device access needed

    # Access to securityfs for loading profiles into kernel
    ReadWritePaths = [ "/sys/kernel/security/apparmor" ];

    # Kernel & Hardware Protection
    ProtectKernelTunables = true;  # Protect /proc/sys, /sys/class, /sys/module, etc.
    ProtectKernelModules = true;   # Does not load kernel modules
    ProtectKernelLogs = true;      # Does not read kernel logs
    ProtectControlGroups = true;   # Mount cgroups hierarchy as read-only
    ProtectClock = true;           # Prevent modification of system clock
    ProtectHostname = true;        # Prevent changing system hostname
    LockPersonality = true;        # Prevent execution domain changes

    # Network & Process Isolation
    PrivateNetwork = true;      # Zero network access needed
    IPAddressDeny = "any";      # Defense-in-depth: deny all IP traffic
    ProtectProc = "invisible";  # Hide processes of other users in /proc
    ProcSubset = "pid";         # Only show the daemon's own PID
    RestrictNamespaces = true;  # Prohibit creation of any new namespaces
    RestrictAddressFamilies = [ "AF_UNIX" ];  # Only local communication

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;       # Prevent W^X memory regions
    SystemCallArchitectures = "native";  # Allow only native system calls
    SystemCallErrorNumber = "EPERM";     # Return EPERM for blocked syscalls
    SystemCallFilter = [
      "~@clock"          # Block clock configuration
      "~@cpu-emulation"  # Block non-native CPU emulation
      "~@debug"          # Block debugging syscalls
      "~@obsolete"       # Block deprecated system calls
      "~@reboot"         # Block system reboot
      "~@swap"           # Block swap management
      "~@raw-io"         # Block raw I/O operations
      "~@keyring"        # Block kernel keyring access
      "~@mount"          # Block filesystem mounting
      "~@module"         # Block kernel module operations
    ];

    # Other Security Settings
    DevicePolicy = "closed";  # Allow access only to pseudo-devices
    KeyringMode = "private";  # Isolated kernel keyring
    PrivateIPC = true;        # Private IPC namespace
    RemoveIPC = true;         # Clean up IPC objects on service stop (oneshot defense-in-depth)
    UMask = "0077";           # Restrictive file creation mask
  };
}
