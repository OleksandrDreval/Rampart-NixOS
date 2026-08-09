{ config, lib, ... }:

{
  /*
    Rampart Docker Daemon Hardening Module

    This module hardens the Docker daemon. Hardening Docker is challenging
    because it requires extensive privileges to manage containers,
    networking, and filesystems. This configuration strips unnecessary
    capabilities, isolates it from kernel logs/tunables, and restricts
    system calls while preserving the ability to run and manage containers.

    IMPORTANT — NoNewPrivileges MUST NOT be true. Docker/runc uses
    execve() with file capabilities and SUID binaries for container setup.
    NoNewPrivileges=true prevents privilege transitions via execve(),
    breaking container creation. Docker's own docs: "Before using
    no-new-privileges, ensure containers don't use SUID binaries or
    file capabilities."
  */

  systemd.services.docker.serviceConfig = {
    # Privilege & Capability Restrictions
    # NoNewPrivileges = false omitted: This is the systemd default. It MUST NOT be set to true,
    # as containers need privilege transitions via execve() (e.g. for SUID binaries like sudo inside containers).
    # RestrictRealtime omitted: Breaks real-time scheduling inside containers
    # CapabilityBoundingSet omitted: Breaks Docker's own granular capability management (--cap-add)

    # Filesystem & Process Isolation
    # ProtectSystem omitted: Can interfere with complex host bind-mounts
    # ProtectHome intentionally NOT set — users frequently bind-mount their
    # home directories into containers (e.g. `docker run -v ~/project:/project`)
    # ProtectProc = "invisible" omitted: Can hide host processes from privileged monitoring containers
    # PrivateTmp intentionally NOT set — breaks mounting host /tmp into containers
    # PrivateMounts omitted: Prevents dockerd from seeing new host mounts (e.g., USB drives) for bind-mounting

    # Kernel & Hardware Protection
    # ProtectKernelTunables intentionally NOT set — Docker writes to
    # /proc/sys/net/ (ip_forward, bridge-nf-call-iptables, etc.) for
    # container networking setup
    # ProtectControlGroups intentionally NOT set — Docker creates cgroups
    # for each container's resource isolation; read-only cgroupfs breaks
    # container creation entirely
    # ProtectKernelModules/Logs/Clock/Hostname omitted: These cascade to containers and
    # permanently neuter `--privileged` containers from performing administrative tasks.
    # LockPersonality omitted: Breaks 32-bit execution domains inside containers

    # Network & Process Isolation
    # RestrictAddressFamilies omitted: Breaks raw sockets (AF_PACKET) inside containers
    # RestrictNamespaces omitted: Interferes with Docker's internal namespace management

    # Memory & System Call Filtering
    # MemoryDenyWriteExecute omitted: Instantly crashes Java/Node.js (V8) JIT compilers inside containers
    # SystemCallArchitectures omitted: Breaks 32-bit container images (e.g., i386/ubuntu)
    # SystemCallFilter omitted: Overrides Docker's own seccomp profiles and breaks `--privileged` containers

    # Other Security Settings
    # UMask = "0077" omitted: If dockerd runs with 0077, it creates volume directories (like /var/lib/docker/volumes/)
    # with 700 permissions (root-only). This instantly breaks any non-root container (e.g., Postgres, Node)
    # attempting to write to its volume with a "Permission denied" error. Systemd default (0022) is required.
  };
}
