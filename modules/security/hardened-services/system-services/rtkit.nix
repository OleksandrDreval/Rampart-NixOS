{ config, lib, ... }:

{
  /*
    Rampart Realtime Kit (rtkit) Hardening Module

    This module hardens rtkit-daemon, which hands out realtime priority to
    user processes (like audio servers). Since it deals with process
    priorities and scheduling, it is isolated from the network, kernel
    internals, and most of the filesystem to prevent it from being abused
    to cause system-wide denial of service.
  */

  systemd.services.rtkit-daemon.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Disallow gaining new privileges
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits within the service
    # rtkit needs CAP_SYS_NICE to grant realtime priority to audio clients
    # and CAP_DAC_READ_SEARCH so it can read /proc/*/limits and verify resource limits
    RestrictRealtime = false;  # NixOS upstream: rtkit MUST manage realtime scheduling for clients
    CapabilityBoundingSet = [ "CAP_SYS_NICE" "CAP_DAC_READ_SEARCH" ];  # Minimal required capabilities

    # Filesystem Isolation
    ProtectSystem = "strict";     # Mount the entire filesystem read-only
    ProtectHome = true;           # Make /home and /root completely inaccessible
    PrivateTmp = "disconnected";  # NixOS upstream: enhanced isolation without mount propagation
    PrivateMounts = true;         # Use a private file system namespace
    PrivateDevices = true;        # Make /dev inaccessible (except standard ones)

    # Kernel & Hardware Protection
    ProtectClock = true;              # Prevent modification of system clock
    ProtectHostname = true;           # Prevent changing system hostname
    ProtectKernelTunables = true;     # Make kernel variables (/proc/sys) read-only
    ProtectKernelModules = true;      # Prevent loading/unloading kernel modules
    ProtectKernelLogs = true;         # Prevent reading kernel logs (dmesg)
    ProtectControlGroups = "strict";  # NixOS upstream: stricter than bool true
    LockPersonality = true;           # Prevent execution domain changes

    # Network & Process Isolation
    # rtkit does not need network access at all
    PrivateNetwork = true;      # Disable all network access
    IPAddressDeny = "any";      # Explicitly deny all IP traffic
    ProtectProc = "default";    # NixOS upstream: rtkit MUST see /proc of other processes to adjust scheduling
    ProcSubset = "all";         # NixOS upstream: rtkit MUST see all PIDs to manage their realtime priority
    RestrictNamespaces = true;  # Prohibit creation of any new namespaces
    RestrictAddressFamilies = [
      "AF_UNIX"  # D-Bus communication
    ];

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;  # Prevent W^X memory regions
    DevicePolicy = "closed";        # Allow access only to /dev/null, /dev/zero, etc.
    SystemCallFilter = [
      "~@keyring"        # Block kernel keyring access
      "~@swap"           # Block swap management
      "~@clock"          # Block clock configuration
      "~@module"         # Block kernel module operations
      "~@obsolete"       # Block deprecated system calls
      "~@cpu-emulation"  # Block non-native CPU emulation
      # ~@mount intentionally NOT blocked — NixOS upstream: rtkit uses chroot(1) which requires @mount
      "~@reboot"         # Block system reboot
      "~@debug"          # Block debugging syscalls
      "~@raw-io"         # Block raw I/O operations
    ];

    # Other Security Settings
    PrivateIPC = true;        # Private IPC namespace
    RemoveIPC = true;         # Clean up IPC objects on service stop
    UMask = "0777";           # NixOS upstream: maximally restrictive — rtkit creates no files
  };
}
