{ config, lib, ... }:

{
  /*
    Rampart systemd-networkd Hardening Module

    This module reinforces hardening for the network configuration daemon.
    systemd-networkd manages network interfaces, DHCP, IPv6 SLAAC, and
    routing. Upstream already provides strong sandboxing (ProtectSystem=strict,
    ProtectHome, ProtectClock, ProtectProc=invisible, MemoryDenyWriteExecute,
    capability bounding, etc.).

    This overlay adds only settings that upstream genuinely omits.

    IMPORTANT — do NOT set:
    - ProtectKernelTunables: networkd writes to /proc/sys/net/* for IP
      forwarding, accept_ra, and other network tunables
    - ProtectHostname: networkd sets hostname via DHCP (UseHostname=yes
      is the default in [DHCPv4]/[DHCPv6] sections)
  */

  systemd.services.systemd-networkd.serviceConfig = {
    # Filesystem Isolation — upstream omits PrivateMounts
    PrivateMounts = true;  # Private mount namespace

    # Kernel & Hardware Protection — document upstream settings for persistence
    ProtectKernelLogs = true;     # Does not read kernel logs (dmesg)
    ProtectKernelModules = true;  # Does not load kernel modules
  };
}
