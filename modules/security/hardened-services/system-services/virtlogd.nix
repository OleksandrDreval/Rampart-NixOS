{ config, lib, ... }:

{
  /*
    Rampart virtlogd Service Hardening Module

    This module hardens the virtual machine log daemon, a companion to
    libvirtd that manages VM console logs. Unlike libvirtd itself,
    virtlogd is a simple log-writing service with minimal privilege
    requirements, allowing aggressive sandboxing.
  */

  systemd.services.virtlogd.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Disallow gaining new privileges
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits
    RestrictRealtime = true;  # Prevent abuse of real-time scheduling
    CapabilityBoundingSet = [
      "CAP_DAC_OVERRIDE"     # Read/write VM logs owned by different users
      "CAP_DAC_READ_SEARCH"  # Search directories with restricted permissions
    ];

    # Filesystem Isolation
    ProtectSystem = "strict";        # Mount entire filesystem hierarchy read-only
    LogsDirectory = "libvirt/qemu";  # Writable /var/log/libvirt/qemu for VM logs
    RuntimeDirectory = "libvirt/virtlogd";  # Writable /run/libvirt/virtlogd
    ProtectHome = true;              # Make /home and /root completely inaccessible
    PrivateTmp = true;               # Use a private and isolated /tmp directory
    PrivateDevices = true;           # No device access needed
    PrivateMounts = true;            # Private mount namespace

    # Kernel & Hardware Protection
    ProtectKernelTunables = true;  # Make kernel variables (/proc/sys) read-only
    ProtectKernelModules = true;   # Prevent loading/unloading kernel modules
    ProtectKernelLogs = true;      # Prevent reading kernel logs (dmesg)
    ProtectControlGroups = true;   # Mount cgroups hierarchy as read-only
    ProtectClock = true;           # Prevent modification of system clock
    ProtectHostname = true;        # Prevent changing system hostname
    LockPersonality = true;        # Prevent execution domain changes

    # Network & Process Isolation
    PrivateNetwork = true;      # Zero network access needed
    ProtectProc = "invisible";  # Hide processes of other users in /proc
    RestrictNamespaces = true;  # Prohibit creation of any new namespaces
    RestrictAddressFamilies = [ "AF_UNIX" ];  # Only local socket communication

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;       # Prevent W^X memory regions
    SystemCallArchitectures = "native";  # Allow only native system calls
    SystemCallErrorNumber = "EPERM";     # Return EPERM for blocked syscalls
    SystemCallFilter = [
      "~@clock"          # Block clock configuration
      "~@cpu-emulation"  # Block non-native CPU emulation
      "~@debug"          # Block debugging syscalls
      "~@module"         # Block kernel module operations
      "~@mount"          # Block filesystem mounting
      "~@obsolete"       # Block deprecated system calls
      "~@raw-io"         # Block raw I/O operations
      "~@reboot"         # Block system reboot
      "~@swap"           # Block swap management
      "~@privileged"     # Block privilege escalation syscalls
      # NOTE: ~@resources intentionally NOT blocked — libnuma constructor
      # calls set_mempolicy() at startup which is in @resources group
    ];

    DevicePolicy = "closed";  # Allow access only to pseudo-devices
    UMask = "0077";           # Restrictive file creation mask
  };
}
