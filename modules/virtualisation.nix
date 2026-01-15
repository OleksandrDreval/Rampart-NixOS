{ config, pkgs, lib, ... }:

{
  # Virtualisation configuration for KVM/QEMU
  # Security-focused settings for running virtual machines
  
  # Enable KVM virtualisation support
  virtualisation.libvirtd = {
    enable = true;
    onBoot = "ignore";        # Don't auto-start VMs on system boot
    onShutdown = "shutdown";  # Gracefully shutdown VMs on system shutdown
    
    # QEMU configuration
    qemu = {
      package = pkgs.qemu_kvm;  # Use KVM-optimized QEMU
      runAsRoot = false;        # Run QEMU as unprivileged user for security
      swtpm.enable = true;      # Enable software TPM for Windows 11 and secure boot
      ovmf = {
        enable = true;          # Enable UEFI support for VMs
        packages = [ pkgs.OVMFFull.fd ];
      };
    };
  };
  
  # Enable virt-manager GUI for VM management
  programs.virt-manager.enable = true;
  
  # Install additional packages for better VM experience
  environment.systemPackages = with pkgs; [
    virt-viewer     # Lightweight VM viewer
    spice           # SPICE protocol for VM display
    spice-gtk       # GTK client for SPICE
    spice-protocol  # SPICE protocol headers
    win-virtio      # Windows VirtIO drivers ISO
    win-spice       # Windows SPICE guest tools
  ];
  
  # L1 data cache flushing for hypervisor security
  # Protects against L1TF/Foreshadow attacks (data leaks between host and guest)
  security.virtualisation.flushL1DataCache = "cond";
  
  # "cond" = conditional flushing for predetermined code paths
  # This is a balance between security and performance
  # Alternatives:
  #   "never"  - no flushing (fastest, least secure, only if all VMs trusted)
  #   "cond"   - conditional flushing (balanced, recommended)
  #   "always" - always flush (slowest, maximum security for untrusted VMs)
  
  # Add user to libvirtd group for VM management without sudo
  # users.users.<username>.extraGroups = [ "libvirtd" ];
  # (This should be configured in users.nix instead)
  
  # Virtual machine networking
  # NAT network for VMs is configured automatically by libvirtd
  networking.firewall.checkReversePath = false;  # Allow VM network forwarding
  
  # Allowed network bridges for virtual machines
  virtualisation.libvirtd.allowedBridges = [ "virbr0" ];  # Only NAT bridge, no bridged networking
  
  # Default network configuration for virtual machines
  virtualisation.defaultNetwork = {
    enable = true;        # Enable default network
    forwardMode = "nat";  # Use NAT for internet access (secure for untrusted networks)
  };
  
  # Enable nested virtualisation (if needed for testing)
  # boot.extraModprobeConfig = ''
  #   options kvm_amd nested=1
  #   options kvm_intel nested=1
  # '';
}
