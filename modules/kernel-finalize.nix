{ config, pkgs, lib, ... }:

let
  unique = list: lib.foldl' (acc: x: if lib.elem x acc then acc else acc ++ [ x ]) [] list;

  baseModules = config.rampart.kernelBaseModules or [];
  otherModules = config.boot.kernelModules or [];
  mergedModules = unique (baseModules ++ otherModules);

  baseParams = config.rampart.kernelBaseParams or [];
  otherParams = config.boot.kernelParams or [];
  mergedParams = unique (baseParams ++ otherParams);

  baseSysctl = config.rampart.kernelBaseSysctl or {};
  forcedBaseSysctl = lib.mapAttrs (_: v: lib.mkForce v) baseSysctl;
  mergedSysctl = lib.mkMerge [ forcedBaseSysctl (config.boot.kernel.sysctl or { }) ];
in

{
  # Finalize and lock the computed kernel lists and sysctl map. This module
  # should be imported last so it sees additions from other modules.
  boot.kernelModules = lib.mkForce mergedModules;
  boot.kernelParams  = lib.mkForce mergedParams;
  boot.kernel.sysctl = lib.mkForce mergedSysctl;

  # Blacklist is authoritative in `modules/kernel.nix`; finalizer does not modify it.
}
