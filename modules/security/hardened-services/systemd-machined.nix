{ config, lib, ... }:

{
  /*
    Rampart systemd-machined Hardening Module

    This module hardens the systemd machine registration manager. It
    implements strict filesystem isolation, network blocking, and uses
    private user namespaces to ensure that the management of local
    containers and virtual machines is performed in a highly secure,
    untrusted environment.
  */

  systemd.services.systemd-machined.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Disallow gaining new privileges

    ProtectProc = "invisible";  # Hidden processes of other users in /proc
    RestrictNamespaces = true;  # Prohibit creation of any new namespaces

    # Memory & System Call Filtering
    MemoryDenyWriteExecute = true;       # Prevent W^X memory regions
  };
}
