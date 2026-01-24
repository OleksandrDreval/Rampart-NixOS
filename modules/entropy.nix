{ config, pkgs, lib, ... }:

let
  # Rampart exposure for entropy-related kernel settings so finalizer can
  # aggregate and enforce authoritative defaults.

  # Kernel module for jitterentropy (software entropy source)
  rampartEntropyKernelModules = [ "jitterentropy_rng" ];

  # Kernel parameters related to trust in external RNG sources and early entropy
  rampartEntropyKernelParams = [
    "random.trust_bootloader=off"  # Disable trust in bootloader for RNG
    "random.trust_cpu=off"         # Disable trust in CPU for RNG
    "extra_latent_entropy"         # Collect extra entropy early in boot (only for linux_hardened because it requires the GCC_PLUGIN_LATENT_ENTROPY flag during compilation.)
  ];

  # ASLR entropy defaults moved from `modules/memory.nix`:
  # These provide default mmap randomization settings and are low-priority
  # so other modules can override if necessary.
  rampartEntropySysctl = {
    "vm.mmap_rnd_bits"        = 32;  # ASLR entropy for 64-bit
    "vm.mmap_rnd_compat_bits" = 16;  # ASLR entropy for 32-bit compat
  };
in

{
  # Userspace daemon to seed the kernel RNG from jitterentropy
  services.jitterentropy-rngd.enable = lib.mkForce true;

  # Export rampart attributes for finalizer aggregation
  config = {
    rampart = {
      entropyKernelModules = rampartEntropyKernelModules;
      entropyKernelParams  = rampartEntropyKernelParams;
      entropySysctl        = rampartEntropySysctl;
    };
  };
}
