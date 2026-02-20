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

  systemd.services.auditd.serviceConfig = {
    # Privilege & Capability Restrictions
    NoNewPrivileges = true;   # Disallow gaining new privileges
    RestrictSUIDSGID = true;  # Disable SUID/SGID bits
    RestrictRealtime = true;  # Prevent abuse of real-time scheduling
    # Block specific capabilities while keeping those needed for auditing
    CapabilityBoundingSet = [
      "~CAP_CHOWN"
      "~CAP_FSETID"
      "~CAP_SETFCAP"
    ];
  };
}
