{ config, lib, ... }:

{
  /*
    Rampart Nix Daemon Hardening Module

    This module hardens the Nix daemon, which performs builds and manages the
    Nix store. Hardening the nix-daemon is complex because it must be able
    to create build sandboxes. This configuration limits its kernel
    capabilities, restricts memory execution, and applies system call
    filtering to protect the host system from malicious build scripts.
  */

  systemd.services.nix-daemon.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Disallow gaining new privileges
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits within the service
    RestrictRealtime = true;  # Prevent abuse of real-time scheduling

    # Strip unnecessary root capabilities while keeping those needed for builds
    CapabilityBoundingSet = [
      "~CAP_SYS_CHROOT"       # Builds use chroot, but daemon itself can be restricted
      "~CAP_BPF"              # Prevent BPF program loading
      "~CAP_AUDIT_WRITE"      # Prevent audit log manipulation
      "~CAP_AUDIT_CONTROL"    # Prevent audit system control
      "~CAP_AUDIT_READ"       # Prevent audit log reading
      "~CAP_SYS_PTRACE"       # Prevent process tracing
      "~CAP_SYS_NICE"         # Prevent priority changes
      "~CAP_SYS_RESOURCE"     # Prevent resource limit changes
      "~CAP_SYS_RAWIO"        # Prevent raw I/O access
      "~CAP_SYS_TIME"         # Prevent changing system time
      "~CAP_SYS_PACCT"        # Prevent process accounting changes
      "~CAP_LINUX_IMMUTABLE"  # Prevent modifying immutable files
      "~CAP_IPC_LOCK"         # Prevent locking memory
      "~CAP_WAKE_ALARM"       # Prevent wake alarms
      "~CAP_SYS_TTY_CONFIG"   # Prevent TTY configuration
      "~CAP_SYS_BOOT"         # Prevent system reboot
      "~CAP_LEASE"            # Prevent file leases
      "~CAP_BLOCK_SUSPEND"    # Prevent stay-awake
      "~CAP_MAC_ADMIN"        # Prevent MAC policy changes
      "~CAP_MAC_OVERRIDE"     # Prevent MAC policy override
    ];

    # Filesystem Isolation
    # nix-daemon manages its own store, but we protect the rest of the system
    ProtectControlGroups = true;  # Mount cgroups hierarchy as read-only
    ProtectKernelModules = true;  # Prevent loading/unloading kernel modules
    PrivateMounts = true;         # Use a private file system namespace
    PrivateTmp = true;            # Use a private and isolated /tmp directory
    PrivateDevices = true;        # Make /dev inaccessible (except standard ones)

    # Network & Process Isolation
    # nix-daemon needs network to download substitutes/sources
    RestrictNamespaces = [ "~cgroup" ];  # Allow most namespaces for build sandboxing
    RestrictAddressFamilies = [
      "AF_UNIX"     # Local communication
      "AF_NETLINK"  # Kernel communication
      "AF_INET6"    # IPv6 for downloads
      "AF_INET"     # IPv4 for downloads
    ];

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;       # Prevent W^X memory regions
    SystemCallArchitectures = "native";  # Use only native system calls
    SystemCallErrorNumber = "EPERM";     # Return EPERM for blocked calls
    SystemCallFilter = [
      "~@resources"      # Block resource limit changes
      "~@module"         # Block kernel module operations
      "~@obsolete"       # Block deprecated system calls
      "~@debug"          # Block debugging system calls
      "~@reboot"         # Block system reboot
      "~@swap"           # Block swap management
      "~@cpu-emulation"  # Block non-native CPU emulation
      "~@clock"          # Block clock configuration
      "~@raw-io"         # Block raw I/O access
    ];

    # Other Security Settings
    DevicePolicy = "closed";  # Allow access only to /dev/null, /dev/zero, etc.
    LockPersonality = true;   # Prevent execution domain changes
    UMask = 0077;             # Ensure store paths are managed by Nix permissions
  };
}
