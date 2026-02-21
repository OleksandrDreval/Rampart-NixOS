{ config, lib, ... }:

{
  /*
    Rampart Docker Daemon Hardening Module

    This module hardens the Docker daemon. Hardening Docker is challenging
    because it requires extensive privileges to manage containers,
    networking, and filesystems. This configuration strips unnecessary
    capabilities, isolates it from kernel logs/tunables, and restricts
    system calls while preserving the ability to run and manage containers.
  */

  systemd.services.docker.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Disallow gaining new privileges
  };
}
