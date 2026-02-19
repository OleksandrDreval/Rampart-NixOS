{ config, lib, ... }:

{
  /*
    Rampart systemd-rfkill Hardening Module

    This module hardens the systemd-rfkill service, which is responsible for
    storing and restoring the radio transmitter (WiFi, Bluetooth, etc.)
    state across reboots. It applies extreme sandboxing, including network
    isolation, private user namespaces, and restricted system call filters,
    while ensuring state persistence using a dedicated StateDirectory.
  */

  systemd.services.systemd-rfkill.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Disallow gaining new privileges via setuid/setgid
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits within the service
    RestrictRealtime = true;  # Prevent abuse of real-time scheduling
    # Restrict root capabilities to the bare minimum
    CapabilityBoundingSet = [
      "~CAP_SYS_PTRACE"
      "~CAP_SYS_PACCT"
    ];

    # Filesystem Isolation
    ProtectSystem = "full";  # Protect core system directories (/usr, /boot, /etc)
    ProtectHome = true;      # Make /home and /root completely inaccessible
    StateDirectory = "systemd/rfkill";  # Allow persistent storage in /var/lib/systemd/rfkill
    PrivateTmp = true;       # Use a private and isolated /tmp directory

    # Kernel & Hardware Protection
    ProtectKernelLogs = true;     # Prevent reading kernel messages from dmesg
    ProtectControlGroups = true;  # Mount cgroups hierarchy as read-only
    ProtectClock = true;          # Prevent modification of system clock or RTC
    ProtectHostname = true;       # Prevent changing system hostname
    LockPersonality = true;       # Prevent execution domain changes (personalities)

    # Network & Process Isolation
    PrivateNetwork = true;      # Completely isolate the service from the network
    PrivateUsers = true;        # Map service UID/GID to a private user namespace
    ProtectProc = "invisible";  # Hide processes of other users in /proc
    RestrictNamespaces = true;  # Prohibit creation of any new namespaces
    # Limit allowed network address families (local IPC only)
    RestrictAddressFamilies = [ "AF_UNIX" ];

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;       # Prevent W^X memory regions
    SystemCallArchitectures = "native";  # Use only native system calls
    SystemCallFilter = [
      "~@swap"           # Block swap management
      "~@obsolete"       # Block deprecated system calls
      "~@cpu-emulation"  # Block non-native CPU emulation
      "~@privileged"     # Block general privileged system calls
    ];
  };
}
