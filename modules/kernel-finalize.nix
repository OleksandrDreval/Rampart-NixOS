{ config, pkgs, lib, ... }:

let
  unique = list: lib.foldl' (acc: x: if lib.elem x acc then acc else acc ++ [ x ]) [] list;

  rampartAttrs = config.rampart or {};

  # Collect all rampart*KernelModules lists (only keep list-typed values)
  rampartModuleLists = lib.filter lib.isList (lib.attrValues (lib.filterAttrs (name: val: (builtins.match ".*KernelModules$" name) != null) rampartAttrs));
  allModuleLists = lib.concatMap (x: x) rampartModuleLists;

  # base + collected modules (other modules should export to `rampart.*`)
  baseModules = config.rampart.kernelBaseModules or [];
  mergedModules = unique (baseModules ++ allModuleLists);

  # Collect all rampart*KernelParams lists (only keep list-typed values)
  rampartParamLists = lib.filter lib.isList (lib.attrValues (lib.filterAttrs (name: val: (builtins.match ".*KernelParams$" name) != null) rampartAttrs));
  allParamLists = lib.concatMap (x: x) rampartParamLists;

  baseParams = config.rampart.kernelBaseParams or [];
  mergedParams = unique (baseParams ++ allParamLists);

  # Collect all rampart*Sysctl attrsets and merge them, forcing base keys
  rampartSysctlAttrs = lib.filter lib.isAttrs (lib.attrValues (lib.filterAttrs (name: val: (builtins.match ".*Sysctl$" name) != null) rampartAttrs));
  otherSysctls = lib.mkMerge rampartSysctlAttrs;

  baseSysctl = config.rampart.kernelBaseSysctl or {};
  forcedBaseSysctl = lib.mapAttrs (_: v: lib.mkForce v) baseSysctl;
  mergedSysctl = lib.mkMerge [ forcedBaseSysctl otherSysctls ];
in

{
  # Finalize and lock the computed kernel lists and sysctl map. This module
  # should be imported last so it sees additions from other modules.
  boot.kernelModules = lib.mkForce mergedModules;
  boot.kernelParams  = lib.mkForce mergedParams;
  boot.kernel.sysctl = lib.mkForce mergedSysctl;

  # Blacklisted kernel modules are defined in `modules/kernel.nix`; the finalizer does not change them.
}
