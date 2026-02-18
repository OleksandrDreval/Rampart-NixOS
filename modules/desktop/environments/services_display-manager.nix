{ config, lib, ... }:

{
  /*
    Rampart Display Manager Hardening Module

    This module implements comprehensive security hardening for the display-manager service.
    It applies systemd sandboxing techniques to isolate the graphical login manager from
    the rest of the system. It restricts network access (Zero Trust), limits hardware
    interaction, and strips unnecessary kernel capabilities to minimize the attack
    surface of the root-privileged display manager (GDM/SDDM/LightDM) without breaking
    GPU acceleration or session switching.
  */

  systemd.services.display-manager.serviceConfig = {
    # File System Isolation
    ProtectSystem = "full";       # Protect /usr, /boot, and /etc from writes
    ProtectControlGroups = true;  # Restrict access to cgroup configuration
    PrivateMounts = true;         # Use a private mount namespace
    UMask = 0077;                 # Ensure files created by DM are private

    # Network Isolation (Zero Trust)
    # Display managers should never need network access.
    IPAddressDeny = [ "0.0.0.0/0" "::/0" ];
    RestrictAddressFamilies = [
      "AF_UNIX"     # Local IPC (Wayland/X11/DBus)
      "AF_NETLINK"  # Network status monitoring
      "AF_INET"     # IPv4 (required for some seat/session logic)
      "AF_INET6"    # IPv6 (required for some seat/session logic)
    ];

    # Kernel & Hardware Protection
    ProtectClock = true;          # Prevent changing system clock
    ProtectKernelModules = true;  # Prevent loading/unloading kernel modules
    LockPersonality = true;       # Prevent personality changes (emulation)
    KeyringMode = "private";      # Isolated kernel keyring for the service
    PrivateIPC = true;            # Isolated Inter-Process Communication

    # Privilege & Capability Restrictions
    # We strip all capabilities except those strictly necessary for a DM to function.
    CapabilityBoundingSet = [
      "CAP_SYS_ADMIN"        # Seat and session management
      "CAP_SETUID"           # Switching to user sessions
      "CAP_SETGID"           # Switching to user session groups
      "CAP_SETPCAP"          # Capability management
      "CAP_KILL"             # Terminating sessions
      "CAP_SYS_TTY_CONFIG"   # TTY/VT switching
      "CAP_DAC_OVERRIDE"     # Resource access (required for various DM tasks)
      "CAP_DAC_READ_SEARCH"  # Resource reading
      "CAP_FOWNER"           # File ownership management
      "CAP_IPC_OWNER"        # IPC ownership
      "CAP_FSETID"           # Set ID on execution
      "CAP_SETFCAP"          # Forced capabilities
      "CAP_CHOWN"            # Changing file ownership
    ];

    RestrictSUIDSGID = true;  # Disable SUID/SGID bits within the service
    RestrictRealtime = true;  # Prevent abuse of real-time scheduling

    # System Call Filtering
    SystemCallArchitectures = "native";  # Block non-native syscalls (e.g., 32-bit on 64-bit)
    SystemCallErrorNumber = "EPERM";     # Return 'Permission Denied' instead of SIGSYS
    SystemCallFilter = [
      "~@obsolete"       # Block deprecated syscalls
      "~@cpu-emulation"  # Block non-native CPU emulation
      "~@clock"          # Block clock configuration
      "~@swap"           # Block swap management
      "~@module"         # Block kernel module operations
      "~@reboot"         # Block system reboot
      "~@raw-io"         # Block raw I/O access
      "~@debug"          # Block debugging/tracing syscalls
    ];
  };
}
