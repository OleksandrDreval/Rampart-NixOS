{ config, pkgs, lib, ... }:

{
  # Entropy / RNG related configuration centralized here

  # Kernel module for jitterentropy (software entropy source)
  boot.kernelModules = lib.mkDefault (let
    existing = config.boot.kernelModules or [];
    toAdd = [ "jitterentropy_rng" ];
  in lib.filter (p: !(lib.elem p existing)) toAdd ++ existing);

  # Userspace daemon to seed the kernel RNG from jitterentropy
  services.jitterentropy-rngd.enable = lib.mkForce true;

  # Kernel parameters related to trust in external RNG sources and early entropy
  boot.kernelParams = lib.mkDefault (let
    existing = config.boot.kernelParams or [];
    toAdd = [
      "random.trust_bootloader=off"  # Disable trust in bootloader for random number generation
      "random.trust_cpu=off"         # Disable trust in CPU for random number generation
      "extra_latent_entropy"         # Collect extra entropy early in boot (linux_hardened only)
    ];
  in lib.filter (p: !(lib.elem p existing)) toAdd ++ existing);

  # ASLR entropy defaults moved from `modules/memory.nix`:
  # These provide default mmap randomization settings and are low-priority
  # so other modules can override if necessary.
  boot.kernel.sysctl = lib.mkDefault (lib.mkMerge [ {
    "vm.mmap_rnd_bits" = 32;         # ASLR entropy for 64-bit
    "vm.mmap_rnd_compat_bits" = 16;  # ASLR entropy for 32-bit compat
  } ]);
}
