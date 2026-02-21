{ config, lib, ... }:

{
  /*
    Coordinator module for centralized service hardening.
    Imports specialized security profiles for various system services.

    Mostly based on templates from: https://github.com/wallago/nix-system-services-hardened
  */

  imports = [
    # System service hardening
    ./system-services/accounts-daemon.nix
    ./system-services/acpid.nix
    ./system-services/apparmor.nix
    ./system-services/auditd.nix
    ./system-services/autovt.nix
    ./system-services/blocky.nix
    ./system-services/bluetooth.nix
    ./system-services/colord.nix
    ./system-services/cups.nix
    ./system-services/dbus.nix
    ./system-services/display-manager.nix
    ./system-services/dnscrypt-proxy-dnsmasq.nix
    ./system-services/dnscrypt-proxy-resolved.nix
    ./system-services/dnsmasq.nix
    ./system-services/docker.nix
    ./system-services/emergency.nix
    ./system-services/getty.nix
    ./system-services/iwd.nix
    ./system-services/libvirtd.nix
    ./system-services/NetworkManager.nix
    ./system-services/NetworkManager-dispatcher.nix
    ./system-services/nix-daemon.nix
    ./system-services/nscd.nix
    ./system-services/polkit.nix
    ./system-services/power-profiles-daemon.nix
    ./system-services/reload-systemd-vconsole-setup.nix
    ./system-services/rescue.nix
    ./system-services/rtkit.nix
    ./system-services/sshd.nix
    ./system-services/systemd-ask-password-console.nix
    ./system-services/systemd-ask-password-wall.nix
    ./system-services/systemd-journald.nix
    ./system-services/systemd-logind.nix
    ./system-services/systemd-machined.nix
    ./system-services/systemd-networkd.nix
    ./system-services/systemd-oomd.nix
    ./system-services/systemd-resolved.nix
    ./system-services/systemd-rfkill.nix
    ./system-services/systemd-timesyncd.nix
    ./system-services/systemd-udevd.nix
    ./system-services/udisks2.nix
    ./system-services/upower.nix
    ./system-services/usbguard.nix
    ./system-services/user-session.nix
    ./system-services/virtlogd.nix
    ./system-services/wpa_supplicant.nix

    # User service hardening (seccomp-based)
    ./user-services/pipewire-user.nix
    ./user-services/plasma-desktop-user.nix
    ./user-services/wireplumber-user.nix
    ./user-services/xdg-desktop-portal-user.nix
  ];
}
