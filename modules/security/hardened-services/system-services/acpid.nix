{ config, lib, ... }:

{
  /*
    Rampart ACPI Daemon (acpid) Hardening Module

    This module hardens acpid, which handles hardware events like power
    buttons and laptop lids. It isolates the service from the network,
    hides other processes, and applies strict system call filtering to
    ensure that power management events are processed securely without
    exposing a large attack surface.
  */

  systemd.services.acpid.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Disallow gaining new privileges
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits
    RestrictRealtime = true;  # Prevent abuse of real-time scheduling
    # Block specific capabilities that are not needed for ACPI events
    CapabilityBoundingSet = [
      "~CAP_CHOWN"
      "~CAP_FSETID"
      "~CAP_SETFCAP"
    ];

    # Filesystem & Process Isolation
    ProtectSystem = "yes";      # Protect /usr and /boot, but allow scripts to write to /var or /etc
    ProtectHome = "read-only";  # Scripts often need to read ~/.Xauthority to interact with X11 sessions
    # ProtectProc/ProcSubset omitted: scripts often use pgrep/pidof to find user sessions
    # PrivateTmp omitted: scripts often need access to /tmp/.X11-unix to run xrandr/xbacklight
    # PrivateDevices omitted: scripts may need /dev/dri for backlight control or audio devices
    PrivateMounts = true;       # Use a private file system namespace

    # Kernel & Hardware Protection
    # acpid executes arbitrary user-defined bash scripts in response to ACPI
    # events (e.g. pressing a custom hotkey). We must intentionally omit
    # ProtectKernelModules, ProtectClock, ProtectHostname, and RestrictNamespaces
    # so these scripts can function (e.g. loading a driver or syncing time).
    ProtectKernelLogs = true;      # Prevent reading kernel logs (dmesg)
    ProtectControlGroups = true;   # Mount cgroups hierarchy as read-only
    LockPersonality = true;        # Prevent execution domain changes

    # Network Isolation
    PrivateNetwork = true;      # Completely isolate the service from the network
    IPAddressDeny = "any";      # Explicitly block all IP traffic
    # Limit allowed network address families
    RestrictAddressFamilies = [
      "AF_UNIX"     # Local IPC and communication
      "AF_NETLINK"  # Required for ACPI events via netlink
    ];

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;       # Prevent W^X memory regions
    SystemCallArchitectures = "native";  # Use only native system calls
    SystemCallErrorNumber = "EPERM";     # Return EPERM for blocked syscalls
    SystemCallFilter = [
      "~@swap"           # Block swap management
      "~@obsolete"       # Block deprecated system calls
      "~@cpu-emulation"  # Block non-native CPU emulation
      "~@reboot"         # Block system reboot (acpid dispatches events to scripts, not direct reboot)
      "~@raw-io"         # Block raw I/O access
      "~@debug"          # Block debugging/tracing syscalls
      "~@keyring"        # Block kernel keyring access
    ];

    # Other Security Settings
    DevicePolicy = "closed";  # Restrict device access to pseudo-devices
    KeyringMode = "private";  # Isolated kernel keyring
    PrivateIPC = true;         # Private IPC namespace
    RemoveIPC = true;         # Clean up IPC objects on service stop
    UMask = "0077";           # Restrictive file creation mask
  };
}
