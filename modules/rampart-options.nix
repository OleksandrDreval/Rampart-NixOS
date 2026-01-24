{ lib, ... }:

{
  options.rampart = lib.mkOption {
    type = lib.types.attrs;
    default = {};
    description = "Rampart aggregation namespace for kernel-related module additions";
  };
}
