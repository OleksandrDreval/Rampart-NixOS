{ config, lib, ... }:

{
  /*
    Rampart Bluetooth Service Hardening Module

    This module hardens the Bluetooth daemon (bluetoothd). It isolates the
    service from kernel internals, hides other system processes, and
    restricts system calls. Given that Bluetooth is a historically frequent
    attack vector, this configuration minimizes the potential impact of
    remote exploits.
  */

  systemd.services.bluetooth.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Disallow gaining new privileges
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits
    RestrictRealtime = true;  # Prevent abuse of real-time scheduling

    # Kernel & Hardware Protection
    ProtectKernelTunables = false;  # NixOS upstream: bluetoothd needs kernel tunables for hardware
    ProtectKernelModules = false;   # NixOS upstream: bluetoothd needs to load BT hardware modules
    ProtectKernelLogs = true;      # Prevent reading kernel logs (dmesg)
    ProtectHostname = true;        # Prevent changing system hostname
    ProtectControlGroups = true;   # Mount cgroups hierarchy as read-only
    ProtectClock = true;           # Prevent changing system clock
    LockPersonality = true;        # Prevent execution domain changes

    # Process & File System Isolation
    ProtectProc = "invisible";     # Hidden processes of other users in /proc
    ProcSubset = "pid";            # Only show the daemon's own PID
    ProtectSystem = "strict";      # Mount entire filesystem hierarchy read-only
    StateDirectory = "bluetooth";  # Writable /var/lib/bluetooth for device pairings
    ProtectHome = true;            # Make /home and /root completely inaccessible
    PrivateTmp = true;             # Use a private and isolated /tmp directory
    PrivateMounts = true;          # Private mount namespace
    # PrivateNetwork intentionally NOT set — bluetoothd needs AF_NETLINK for
    # udev device hotplug events (detecting new Bluetooth adapters)

    # Network & Process Isolation
    IPAddressDeny = "any";      # Block all IP traffic (BT uses HCI, not IP)
    RestrictNamespaces = true;  # Prohibit creation of any new namespaces
    RestrictAddressFamilies = [
      "AF_UNIX"       # D-Bus communication and local IPC
      "AF_BLUETOOTH"  # Core Bluetooth protocol (HCI, L2CAP, SCO, RFCOMM)
      "AF_NETLINK"    # Udev device events for BT adapter hotplug
    ];

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;       # Prevent W^X memory regions (C daemon, no JIT)
    SystemCallArchitectures = "native";  # Use only native system calls
    SystemCallErrorNumber = "EPERM";     # Return EPERM for blocked syscalls
    # lib.mkForce required: NixOS upstream uses string "@system-service" — type mismatch with list
    SystemCallFilter = lib.mkForce [
      "@system-service"  # Base allow-list (NixOS upstream for bluetooth)
      "~@mount"          # Block filesystem mounting
      "~@reboot"         # Block system reboot
      "~@swap"           # Block swap management
      "~@obsolete"       # Block deprecated system calls
      "~@cpu-emulation"  # Block non-native CPU emulation
      "~@debug"          # Block debugging/tracing syscalls
      "~@clock"          # Block clock configuration
      "~@raw-io"         # Block raw I/O port access (BT uses HCI sockets, not iopl)
      "~@keyring"        # Block kernel keyring access
    ];

    DevicePolicy = "auto";  # Allow HCI device access for Bluetooth operations

    # Other Security Settings
    KeyringMode = "private";  # Isolated kernel keyring
    PrivateIPC = true;         # Private IPC namespace
    RemoveIPC = true;         # Clean up IPC objects on service stop
    UMask = "0077";           # Restrictive file creation mask
  };
}
