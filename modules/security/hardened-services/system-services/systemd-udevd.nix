{ config, lib, ... }:

{
  /*
    Rampart systemd-udevd Hardening Module

    This module adds extra hardening on top of upstream systemd-udevd.
    Upstream already provides comprehensive sandboxing including:
    CapabilityBoundingSet=~CAP_SYS_TIME CAP_WAKE_ALARM, PrivateMounts,
    ProtectHostname, MemoryDenyWriteExecute, RestrictAddressFamilies
    (AF_UNIX AF_NETLINK AF_INET AF_INET6), RestrictRealtime,
    RestrictSUIDSGID, SystemCallFilter=@system-service @module @raw-io bpf
    ~@clock, SystemCallErrorNumber=EPERM, SystemCallArchitectures=native,
    LockPersonality, IPAddressDeny=any.

    IMPORTANT — do NOT set any of these:
    - ProtectSystem: udev rules execute via RUN+= and may write anywhere
    - ProtectHome: creates mount namespace (see above)
    - NoNewPrivileges: udev rules may execute SUID helpers
    - RestrictNamespaces: upstream intentionally omits this
    - ProtectProc: udev rules may need to inspect processes
    - ProtectKernelTunables: udev rules may write to sysfs tunables
    - ProtectKernelModules: upstream allows @module syscall group for udevd
    - ProtectControlGroups: upstream uses Delegate=pids + DelegateSubgroup
  */

  systemd.services.systemd-udevd.serviceConfig = {
    # Extra hardening beyond upstream
    ProtectKernelLogs = true;  # Does not need to read kernel logs (dmesg)
    ProtectClock = true;       # Prevent clock modification (defense-in-depth over upstream cap restriction)
    KeyringMode = "private";   # Isolated kernel keyring
    PrivateTmp = true;         # Prevent access to global /tmp to thwart symlink attacks
  };
}
