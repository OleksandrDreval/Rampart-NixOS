{ config, pkgs, lib, ... }:

let
  unique = list: lib.foldl' (acc: x: if lib.elem x acc then acc else acc ++ [ x ]) [] list;

  rampartAttrs = config.rampart or {};

  # Collect all rampart*KernelModules lists
  rampartModuleLists = lib.filter (p: p != null)
    (lib.mapAttrs (name: val: if lib.stringMatch ".*KernelModules$" name then val else null) rampartAttrs);
  allModuleLists = lib.concatMap (x: x) (lib.attrValues rampartModuleLists);

  # base + collected + existing boot.kernelModules
  baseModules = config.rampart.kernelBaseModules or [];
  otherModules = config.boot.kernelModules or [];
  mergedModules = unique (baseModules ++ allModuleLists ++ otherModules);

  # Collect all rampart*KernelParams lists
  rampartParamLists = lib.filter (p: p != null)
    (lib.mapAttrs (name: val: if lib.stringMatch ".*KernelParams$" name then val else null) rampartAttrs);
  allParamLists = lib.concatMap (x: x) (lib.attrValues rampartParamLists);

  baseParams = config.rampart.kernelBaseParams or [];
  otherParams = config.boot.kernelParams or [];
  mergedParams = unique (baseParams ++ allParamLists ++ otherParams);

  # Collect all rampart*Sysctl attrsets and merge them, forcing base keys
  rampartSysctlAttrs = lib.filter (p: p != null)
    (lib.mapAttrs (name: val: if lib.stringMatch ".*Sysctl$" name then val else null) rampartAttrs);
  otherSysctls = lib.mkMerge (lib.attrValues rampartSysctlAttrs);

  baseSysctl = config.rampart.kernelBaseSysctl or {};
  forcedBaseSysctl = lib.mapAttrs (_: v: lib.mkForce v) baseSysctl;
  mergedSysctl = lib.mkMerge [ forcedBaseSysctl otherSysctls (config.boot.kernel.sysctl or {}) ];
in

{
  # Finalize and lock the computed kernel lists and sysctl map. This module
  # should be imported last so it sees additions from other modules.
  boot.kernelModules = lib.mkForce mergedModules;
  boot.kernelParams  = lib.mkForce mergedParams;
  boot.kernel.sysctl = lib.mkForce mergedSysctl;

  # Blacklisted kernel modules are defined in `modules/kernel.nix`; the finalizer does not change them.
}
