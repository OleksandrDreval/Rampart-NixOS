{ config, lib, ... }:

{
  /*
    Rampart User Session Manager Hardening Module

    This module applies a balanced security profile to the user's systemd session
    manager (user@.service). It isolates session processes from the system core,
    restricts kernel access, and protects other users' data while ensuring
    seamless desktop integration and application compatibility.
  */

  systemd.services."user@".serviceConfig = {
    # Kernel & Hardware Protection
    ProtectClock = true;           # Prevent user from changing system clock
    ProtectHostname = true;        # Prevent user from changing hostname
    ProtectKernelTunables = true;  # Make kernel variables (/proc/sys) read-only
    ProtectKernelModules = true;   # Prevent loading/unloading kernel modules
    ProtectKernelLogs = true;      # Prevent reading kernel logs (dmesg)

    # Process & File System Isolation
    ProtectSystem = "full";     # Mount /usr, /boot, and /etc read-only
    ProtectProc = "invisible";  # Hide processes of other users
    PrivateTmp = true;          # Use isolated /tmp for each user session

    # Network & IPC isolation
    RestrictAddressFamilies = [
      "AF_UNIX"     # Local IPC (Wayland/X11/DBus)
      "AF_NETLINK"  # Network status updates
      "AF_INET"     # IPv4 access
      "AF_INET6"    # IPv6 access
    ];

    # Privilege & Capability Restrictions
    RestrictRealtime = true;  # Prevent abuse of real-time scheduling
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits in the session

    # Memory & System Call Filtering
    SystemCallArchitectures = "native";  # Allow only native syscalls (prevents 32-bit exploitation)
    SystemCallFilter = [
      "~@swap"           # Block swap management
      "~@module"         # Block kernel module calls
      "~@obsolete"       # Block deprecated/legacy syscalls
      "~@cpu-emulation"  # Block non-native CPU emulation
    ];
  };
}
