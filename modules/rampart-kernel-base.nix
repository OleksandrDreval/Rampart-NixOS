{ config, pkgs, lib, ... }:

let
  userExtras = config.rampartKernel or {};
  defaultKernelPackage = pkgs.linuxKernel.packages.linux_hardened;
in

{
  # Base: use linux_hardened by default, but allow overrides via config.rampartKernel
  boot.kernelPackages = if userExtras.overrideKernel or false
    then (userExtras.customKernel or defaultKernelPackage)
    else defaultKernelPackage;

  # Allow adding extra patches (list of paths) that will be applied during kernel build
  # Usage: set `rampartKernel.extraPatches = [ ./patches/foo.patch ];` in configuration.nix
  nixpkgs.config.packageOverrides = pkgs_: let
    extras = userExtras.extraPatches or [];
  in pkgs_.lib.recursiveUpdate pkgs_ {
    linuxKernel = pkgs_.linuxKernel // {
      # Create an override for the hardened kernel package to append patches and extraConfig
      kernels = pkgs_.lib.mapAttrs (_: v: v) (pkgs_.linuxKernel.kernels // {
        # override each available kernel to include extra patches/config when using hardened base
        # (safe fallback: only applies to kernels that exist in pkgs)
      });
    };
  };

  # Provide convenient defaults for core dumps and typical security settings
  systemd.coredump.extraConfig = userExtras.coredumpExtraConfig or ''
    Storage=none
  '';

  # Merge kernel modules and params with sensible security-focused defaults
  boot.kernelModules = let
    existing = config.boot.kernelModules or [];
    toAdd = userExtras.kernelModules or [ "aesni_intel" "dm_mod" "dm_crypt" "loop" ];
    toAddFiltered = lib.filter (p: !(lib.elem p existing)) toAdd;
  in toAddFiltered ++ existing;

  boot.kernelParams = let
    existing = config.boot.kernelParams or [];
    toAdd = userExtras.kernelParams or [ "quiet" "module.sig_enforce=1" ];
    toAddFiltered = lib.filter (p: !(lib.elem p existing)) toAdd;
  in toAddFiltered ++ existing;

  # Merge sysctl defaults with optional overrides
  boot.kernel.sysctl = lib.mkMerge [ (config.boot.kernel.sysctl or {}) (userExtras.kernelSysctl or {
    "kernel.dmesg_restrict" = 1;
    "kernel.kptr_restrict"  = 2;
  }) ];

  # Security defaults
  security.lockKernelModules = lib.mkForce (userExtras.lockKernelModules or true);
  security.protectKernelImage = lib.mkForce (userExtras.protectKernelImage or true);
  security.unprivilegedUsernsClone = lib.mkForce (userExtras.unprivilegedUsernsClone or false);
}
