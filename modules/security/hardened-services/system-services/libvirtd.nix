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
      # MAC and BPF intentionally NOT blocked: libvirtd requires CAP_MAC_ADMIN/OVERRIDE
      # for sVirt (AppArmor/SELinux) VM labeling, and CAP_BPF for cgroup device access control.
    ];

    # Filesystem Isolation
    ProtectSystem = "full";        # Protect /usr, /boot, /etc (not strict)
    StateDirectory = "libvirt";    # Writable /var/lib/libvirt for VM state
    LogsDirectory = "libvirt";     # Writable /var/log/libvirt for VM logs
    RuntimeDirectory = "libvirt";  # Writable /run/libvirt for runtime data
    CacheDirectory = "libvirt";    # Writable /var/cache/libvirt for cache
    # ProtectHome intentionally NOT set — users frequently store ISOs and
    # QEMU disk images in their home directories (e.g. ~/Downloads or ~/VMs).

    # Kernel & Hardware Protection
    # ProtectKernelModules omitted: libvirtd often invokes modprobe for vhost_net, macvlan, kvm, etc.
    ProtectKernelLogs = true;     # Does not read kernel logs (dmesg)
    ProtectClock = true;          # Does not modify system clock
    ProtectHostname = true;       # Does not change system hostname
    # LockPersonality omitted: Breaks QEMU user-mode emulation (e.g., qemu-arm running 32-bit payloads)

    # Network & Process Isolation
    ProtectProc = "invisible";  # Hide processes of other users in /proc
    # ProcSubset intentionally NOT set — libvirtd reads /proc/meminfo,
    # /proc/cpuinfo, /proc/stat for VM resource calculations
    # RestrictAddressFamilies omitted: QEMU requires highly dynamic socket access (e.g., AF_VSOCK for virtio-fs,
    # AF_ALG for hardware-accelerated crypto, AF_PACKET for macvtap). Restricting this breaks VMs.

    # System Call Filtering
    # SystemCallFilter and SystemCallArchitectures omitted: QEMU is a CPU emulator and hypervisor. It has its
    # own highly tuned seccomp sandbox (`sandbox on` in libvirt). Systemd's filters unconditionally cascade to QEMU,
    # blocking legitimate virtualization syscalls (like emulation quirks) and breaking the VM.

    # Other Security Settings
    # UMask = "0077" omitted: Creates libvirt-sock and VM directories with root-only access,
    # completely breaking `virsh` for non-root users and QEMU's ability to access its own files.
  };
}
