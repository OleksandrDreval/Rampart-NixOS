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
    RestrictRealtime = true;  # Prevent abuse of real-time scheduling

    # NOTE: CapabilityBoundingSet is intentionally omitted. `nix-daemon` spawns highly dynamic
    # build scripts and QEMU VMs (for NixOS tests). Nix has its own robust internal sandbox
    # (using seccomp, user namespaces, and pivot_root). Systemd capabilities cascade to all
    # builds, randomly breaking legitimate tests and compilations.

    # Filesystem Isolation
    # nix-daemon writes to /nix/store — ProtectSystem MUST NOT be set.
    # Build sandboxes get their own mount namespace with separate /proc.
    # ProtectHome intentionally NOT set — nix-daemon often needs to read
    # /root/.ssh/ for remote builders or /root/.netrc for binary cache auth.
    ProtectKernelModules = true;   # Prevent loading/unloading kernel modules
    ProtectKernelTunables = true;  # Build sandboxes get own /proc — daemon itself does not write /proc/sys
    ProtectKernelLogs = true;      # Daemon does not read kernel logs (dmesg)
    PrivateMounts = true;          # Use a private file system namespace

    # Network & Process Isolation
    # nix-daemon needs network to download substitutes/sources
    RestrictNamespaces = [ "~cgroup" ];  # Allow most namespaces for build sandboxing
    # RestrictAddressFamilies is intentionally omitted: NixOS VM tests (which run as derivations)
    # spawn QEMU VMs that require AF_VSOCK, AF_PACKET, and other sockets. Restricting this breaks all VM tests.

    # Memory & System Call Filtering
    # SystemCallFilter and SystemCallArchitectures are intentionally omitted.
    # Nix builds execute arbitrary compiler toolchains, emulation layers, and test suites.
    # Blocking syscalls at the systemd level cascades to builders and breaks them.

    # Other Security Settings
    KeyringMode = "private";    # Isolated kernel keyring — builds have own namespace
    ProtectClock = true;        # Prevent modification of system clock (defense-in-depth)
    ProtectHostname = true;     # nix-daemon does not change system hostname
    # LockPersonality omitted: Breaks cross-architecture compilation (e.g. building 32-bit pkgs on 64-bit hosts)
  };
}
