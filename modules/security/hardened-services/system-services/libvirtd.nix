{ config, lib, ... }:

{
  /*
    Rampart libvirtd Service Hardening Module

    This module applies CONSERVATIVE hardening to the libvirt virtualisation
    daemon. libvirtd is one of the most privileged services on the system:
    it manages VMs, creates network bridges, manipulates cgroups, accesses
    block and character devices, and spawns QEMU processes with varied
    privilege levels. Aggressive hardening WILL break virtualisation.

    We only block capabilities and syscalls that libvirtd genuinely never
    needs, while leaving the rest unrestricted. The real security for VMs
    comes from libvirt's own security drivers (sVirt/AppArmor/SELinux)
    and QEMU's sandboxing, not from restricting the management daemon.

    IMPORTANT — do NOT set any of these:
    - ProtectSystem = "strict" (needs broad filesystem access)
    - ProtectKernelTunables (needs sysfs for passthrough, hugepages)
    - ProtectControlGroups (creates cgroups for each VM)
    - PrivateDevices (needs /dev/kvm, /dev/net/tun, /dev/vhost-*)
    - PrivateNetwork (creates bridges, TAP interfaces)
    - PrivateTmp (VMs may use shared /tmp)
    - NoNewPrivileges (QEMU processes need different privilege levels)
    - RestrictNamespaces (creates namespaces for VM isolation)
    - MemoryDenyWriteExecute (may interfere with QEMU JIT backend)
  */

  systemd.services.libvirtd.serviceConfig = {
    # Privilege & Capability Restrictions
    # Block only capabilities that libvirtd genuinely never needs
    CapabilityBoundingSet = [
      "~CAP_SYS_RAWIO"        # No raw I/O port access
      "~CAP_SYS_BOOT"         # Cannot reboot the host
      "~CAP_SYS_PTRACE"       # No process tracing
      "~CAP_SYS_PACCT"        # No process accounting
      "~CAP_LINUX_IMMUTABLE"  # No immutable file flags
      "~CAP_WAKE_ALARM"       # No wake alarms
      "~CAP_BLOCK_SUSPEND"    # No block suspend
      "~CAP_SYS_TTY_CONFIG"   # No TTY configuration
      "~CAP_MAC_ADMIN"        # No MAC policy management
      "~CAP_MAC_OVERRIDE"     # No MAC override
      "~CAP_BPF"              # No BPF program loading
    ];

    # Filesystem Isolation
    ProtectSystem = "full";        # Protect /usr, /boot, /etc (not strict)
    StateDirectory = "libvirt";    # Writable /var/lib/libvirt for VM state
    LogsDirectory = "libvirt";     # Writable /var/log/libvirt for VM logs
    RuntimeDirectory = "libvirt";  # Writable /run/libvirt for runtime data
    CacheDirectory = "libvirt";    # Writable /var/cache/libvirt for cache
    ProtectHome = true;            # VMs should not access user home directories

    # Kernel & Hardware Protection
    ProtectKernelModules = true;  # Does not load kernel modules
    ProtectKernelLogs = true;     # Does not read kernel logs (dmesg)
    ProtectClock = true;          # Does not modify system clock
    ProtectHostname = true;       # Does not change system hostname
    LockPersonality = true;       # Prevent execution domain changes

    # Network & Process Isolation
    ProtectProc = "invisible";  # Hide processes of other users in /proc
    RestrictAddressFamilies = [
      "AF_UNIX"     # Local communication, D-Bus
      "AF_NETLINK"  # Kernel-user network communication
      "AF_INET"     # IPv4 (VM networking, DHCP)
      "AF_INET6"    # IPv6 (VM networking)
      "AF_PACKET"   # Raw packet access (VM bridge networking)
    ];

    # System Call Filtering — minimal, only truly irrelevant syscalls
    SystemCallArchitectures = "native";
    SystemCallFilter = [
      "~@obsolete"       # Block deprecated system calls
      "~@cpu-emulation"  # Block non-native CPU emulation
      "~@reboot"         # Block host reboot
    ];
  };
}
