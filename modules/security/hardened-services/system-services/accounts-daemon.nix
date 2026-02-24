{ config, lib, ... }:

{
  /*
    Rampart Accounts Daemon Hardening Module

    This module hardens the accounts-daemon service, which manages user account
    information. It implements a strict read-only sandbox for the daemon,
    granting write access only to its state directory to ensure maximum
    tamper-resistance with zero network exposure.
  */

  systemd.services.accounts-daemon.serviceConfig = {
    # Environment restrictions (disabling remote VFS and FUSE)
    Environment = [
      "GVFS_DISABLE_FUSE=1"                  # Disable GVFS FUSE support
      "GIO_USE_VFS=local"                    # Force local VFS for GIO
      "GVFS_REMOTE_VOLUME_MONITOR_IGNORE=1"  # Ignore remote volume monitoring
    ];

    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Disallow gaining new privileges
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits
    RestrictRealtime = true;  # Prevent abuse of real-time scheduling

    # Filesystem Isolation
    ProtectSystem = "strict";            # Mount entire filesystem read-only
    StateDirectory = "AccountsService";  # Allow write access to /var/lib/AccountsService
    ProtectHome = "read-only";           # Allow reading avatars from home, but no writes
    PrivateTmp = true;                   # Use isolated /tmp directory
    PrivateDevices = true;               # Make /dev inaccessible
    ProtectControlGroups = true;         # Make cgroups read-only

    # Kernel & Hardware Protection
    ProtectKernelTunables = true;  # Make kernel variables (/proc/sys) read-only
    ProtectKernelModules = true;   # Prevent loading/unloading kernel modules
    ProtectKernelLogs = true;      # Prevent reading kernel logs
    ProtectClock = true;           # Prevent changing system clock
    ProtectHostname = true;        # Prevent changing hostname
    LockPersonality = true;        # Prevent personality changes (emulation)

    # Network & Process Isolation
    PrivateNetwork = true;      # Completely disable network access
    ProtectProc = "invisible";  # Hide processes of other users
    RestrictNamespaces = true;  # Disable creation of new namespaces
    RemoveIPC = true;           # Clean up Inter-Process Communication objects on exit
    RestrictAddressFamilies = [
      "AF_UNIX"  # Allow only local communication (D-Bus)
    ];

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;       # Prevent W^X memory regions
    SystemCallArchitectures = "native";  # Allow only native syscalls
    SystemCallFilter = [
      "~@swap"           # Block swap management
      "~@resources"      # Block resource limit changes
      "~@raw-io"         # Block raw I/O access
      "~@mount"          # Block filesystem mounting
      "~@module"         # Block kernel module calls
      "~@reboot"         # Block system reboot
      "~@debug"          # Block debugging calls
      "~@cpu-emulation"  # Block non-native CPU emulation
      "~@clock"          # Block clock configuration
      "~@keyring"        # Block kernel keyring access
    ];

    # Other Security Settings
    DevicePolicy = "closed";  # Deny all device access by default
    KeyringMode = "private";  # Isolated kernel keyring
  };
}
