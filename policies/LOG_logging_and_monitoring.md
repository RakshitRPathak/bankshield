---
doc_id: LOG
title: Logging and Monitoring Standard
regulator: internal
version: "1.4"
clearance: internal
---

# Logging and Monitoring Standard (LOG)

## LOG-1 Log generation and retention

### LOG-1.1 Audit logging
Admin Activity and Data Access audit logs must be enabled on every cloud project. Disabling audit logs is itself a critical security event.

### LOG-1.2 Central collection
All audit logs are exported to the central security log bucket in shared-services within five minutes of generation.

### LOG-1.3 Retention
Security-relevant logs are retained for a minimum of 365 days online and seven years in archival storage, in locked buckets that prevent early deletion.

## LOG-2 Monitoring

### LOG-2.1 Identity monitoring
Logins, privilege changes and key creation events are monitored continuously, with alerts routed to the security operations centre within one minute.

### LOG-2.2 Data access monitoring
Access to restricted data is baselined per identity. Volumes or patterns outside the baseline (for example, more than fifty object reads per minute by one identity) raise an alert.

### LOG-2.3 Alert handling
Critical alerts are acknowledged within 15 minutes and triaged within one hour. Every alert records who handled it and what was decided.

## LOG-3 Integrity

### LOG-3.1 Tamper evidence
Audit records of security tooling, including the queries made to security assistants and the actions taken, are stored in an append-only, hash-chained store that can be verified on demand.

### LOG-3.2 Clock
All logging sources synchronise to the bank's authoritative time source.
