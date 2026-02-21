{ config, lib, ... }:

{
  /*
    Rampart Blocky Hardening Module

    This module hardens Blocky, a modern DNS proxy and ad-blocker.
    Since DNS is critical for network security and privacy, we isolate
    the service, restrict its networking capabilities to only binding
    ports, and sandbox its execution environment to prevent it from
    accessing sensitive system data.
  */

  systemd.services.blocky.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Disallow gaining new privileges
  };
}
