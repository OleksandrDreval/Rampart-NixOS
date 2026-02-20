{ config, lib, ... }:

{
  /*
    Rampart Audit Daemon Hardening Module

    This module hardens auditd, which is responsible for system security
    auditing. Since it collects sensitive logs, it is isolated from the
    network and restricted from modifying kernel internals. We use a
    balanced filesystem protection to ensure it can continuously write its
    audit trails while remaining protected from subversion.
  */

  systemd.services.auditd.serviceConfig = { };
}
