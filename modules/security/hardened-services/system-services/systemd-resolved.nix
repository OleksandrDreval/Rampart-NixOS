{ config, lib, ... }:

{
  /*
    Rampart systemd-resolved Hardening Module

    This module reinforces hardening for the DNS resolver daemon. Upstream
    systemd-resolved already ships with comprehensive sandboxing (strict
    ProtectSystem, MemoryDenyWriteExecute, capability bounding, syscall
    filtering, etc.). This overlay adds a few extra restrictions that
    upstream omits, ensuring they persist across NixOS/systemd updates.
  */

  systemd.services.systemd-resolved.serviceConfig = {
    # Network & Process Isolation — upstream omits ProtectProc
    ProtectProc = "invisible";  # Hide processes of other users in /proc
  };
}
