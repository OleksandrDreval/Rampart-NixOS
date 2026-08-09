# Public variables for Flake outputs
# These values are needed by flake.nix outputs function BEFORE the module system is available
# They cannot use SOPS secrets since outputs runs before system evaluation
#
# Only minimal values needed for flake configuration:
# - system: Architecture for nixpkgs
# - hostName: Machine name for nixosConfigurations.${hostName}
# - stateVersion: NixOS release version
#
# All other configuration values are in secrets/secrets.yaml (encrypted with SOPS)

{
  # System architecture
  system = "x86_64-linux";

  # Machine hostname (must match secrets.yaml system.hostName)
  hostName = "RampartNix";

  # NixOS release version
  # This value determines the NixOS release from which the default settings
  # for stateful data were taken. Don't change unless you know what you're doing.
  stateVersion = "26.05";
}
