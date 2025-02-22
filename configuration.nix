# Edit this configuration file to define what should be installed on
# your system.  Help is available in the configuration.nix(5) man page
# and in the NixOS manual (accessible by running ‘nixos-help’).

{ config, pkgs, ... }:

{
  imports =
    [ # Include the results of the hardware scan.
      ./hardware-configuration.nix
    ];

# Bootloader:
  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = false;
  boot.loader.efi.efiSysMountPoint = "/boot";

  boot.initrd.luks.devices."luks-911765a7-6ecb-4c99-88ef-b44c26fd3583".device = "/dev/disk/by-uuid/911765a7-6ecb-4c99-88ef-b44c26fd3583";


# Networking:
# Define your hostname. Generic hostname is still recommended.
  networking.hostName = "nixos";

# Enables wireless support via wpa_supplicant.
  networking.networkmanager.enable = true;
  networking.nameservers = [ "1.1.1.1" "8.8.8.8" ];

# Configure network proxy if necessary.
# networking.proxy.default = "http://user:password@proxy:port/";
# networking.proxy.noProxy = "127.0.0.1,localhost,internal.domain";


# 1 Set your time zone.
# 2, 3, 4 Select internationalisation properties.
  time.timeZone = "Europe/Kyiv";
  time.hardwareClockInLocalTime = true;

  i18n.defaultLocale = "uk_UA.UTF-8";
  i18n.extraLocaleSettings = { LC_ALL = "uk_UA.UTF-8"; };


# Enable the X11 windowing system.
# 1 You can disable this if you're only using the Wayland session.
# 2 Set your keyboard layout if different from "us"
  services.xserver.enable = true;
  services.xserver.xkb.options = "layout:us,ua";

# Enable touchpad support (enabled default in most desktopManager).
  services.libinput.enable = true;


# 1 Enable the KDE Plasma Desktop Environment.
# 2 Enable Plasma
  services.displayManager.sddm.enable = true;
  services.desktopManager.plasma6.enable = true;


# Configure console keymap.
  console.keyMap = "us";


# Enable CUPS to print documents.
  services.printing.enable = false;

# Sound:
# Enable PipeWire instead of PulseAudio
  services.pipewire = {
    enable = true;
    alsa.enable = true;
    pulse.enable = true;
    wireplumber.enable = true;
  };

  hardware.pulseaudio.enable = false;

  security.rtkit.enable = true;


# Define a user account. Don't forget to set a password with ‘passwd’.
  users.users.oleksandr = {
    isNormalUser = true;
    description = "oleksandr";
    extraGroups = [  "wheel" "video" "audio" "networkmanager" "libvirtd" "kvm" ];
    packages = with pkgs; [
      telegram-desktop
      discord
    ];
  };

# Limited sudo access
  security.sudo.enable = true;
  security.sudo.extraConfig = ''
    %wheel ALL=(ALL) /usr/bin/systemctl poweroff,/usr/bin/systemctl reboot,/run/current-system/sw/bin/nixos-rebuild,/run/current-system/sw/bin/home-manager
  '';


# Lock the root account
  users.users.root.hashedPassword = pkgs.lib.mkForce "";

# Core dumps disabled
  systemd.services.coredump.enable = false;


# List packages installed in system profile. To search, run:
# $ nix search wget
  environment.systemPackages = with pkgs; [

    sbctl

    kate

    pipewire
    wireplumber

# Virtualization packages
    libvirt
    pciutils
    virt-manager
    qemu
    kmod

# Another packages
    firefox
    chromium
    vim # Or emacs, neovim etc.
    wget
  ];

# Allow unfree packages
# Remove if you don't need any unfree software
# Or move to environment.systemPackages if a specific unfree package is needed
  nixpkgs.config.allowUnfree = true;


# Virtualization:
  programs.virt-manager.enable = true;

# Enable KVM via kernel modules, not this option
  users.groups.libvirtd.members = ["oleksandr"];
  virtualisation.libvirtd.enable = true;
  virtualisation.spiceUSBRedirection.enable = true;

# Microcode updates enabled
# Double-check IOMMU setting for your AMD CPU. Use appropriate IOMMU setting for AMD. Check your motherboard documentation if needed (e.g., "amd_iommu=pt").
  hardware.cpu.amd.updateMicrocode = true;

  boot.kernelModules = [ "kvm-amd" "kvm-intel" ];
  boot.kernelParams = [
      "kernel.printk=\"3 4 1 3\""
      "slab_nomerge"
      "amd_iommu=pt"
  ];

  # Some programs need SUID wrappers, can be configured further or are
  # started in user sessions.
  # programs.mtr.enable = true;
  # programs.gnupg.agent = {
  #   enable = true;
  #   enableSSHSupport = true;
  # };

  # List services that you want to enable:

  # Enable the OpenSSH daemon.
  # services.openssh.enable = true;

  # Open ports in the firewall.
  # networking.firewall.allowedTCPPorts = [ ... ];
  # networking.firewall.allowedUDPPorts = [ ... ];
  # Or disable the firewall altogether.
  # networking.firewall.enable = false;

  # This value determines the NixOS release from which the default
  # settings for stateful data, like file locations and database versions
  # on your system were taken. It‘s perfectly fine and recommended to leave
  # this value at the release version of the first install of this system.
  # Before changing this value read the documentation for this option
  # (e.g. man configuration.nix or on https://nixos.org/nixos/options.html).

  system.stateVersion = "24.11"; # Did you read the comment?

}
