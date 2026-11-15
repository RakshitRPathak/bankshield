---
doc_id: IR
title: Cloud Incident Response SOP
regulator: internal
version: "2.1"
clearance: restricted
---

# Cloud Incident Response SOP (IR)

## IR-1 Classification

### IR-1.1 Severity levels
Severity 1: confirmed compromise of restricted data or a Tier-1 system. Severity 2: suspected compromise or a critical control failure. Severity 3: policy violation without evidence of compromise.

### IR-1.2 Regulatory clock
The regulatory reporting clock starts at the moment an incident is classified as Severity 1 or 2, not at the moment it is fully understood.

## IR-2 Containment playbooks

### IR-2.1 Leaked service account credential
On confirmed or suspected leak of a service account key: disable the key immediately, create a replacement key only if the workload cannot use Workload Identity, revoke active sessions, and review every action taken with the key since its last known-good use.

### IR-2.2 Public exposure of restricted storage
On discovery of a public bucket or dataset holding restricted data: remove the public binding, enable uniform access, snapshot the access logs for the exposure window, and open a data-exposure assessment.

### IR-2.3 Unauthorised privilege grant
On an unapproved privileged grant: remove the binding, suspend the granting identity pending interview, and diff all resource changes made under the elevated role.

### IR-2.4 Compromised human account
On impossible travel or credential-stuffing indicators: revoke sessions, force password and MFA re-enrolment, and review actions in the suspect window.

## IR-3 Approvals

### IR-3.1 Human approval
Containment actions that affect production availability or revoke human access require approval from a senior analyst or above before execution. Automated tooling may recommend but not execute such actions.

### IR-3.2 Pre-approved actions
The following actions are pre-approved for automated execution when the triggering evidence is unambiguous: disabling a service account key used from an unapproved country; removing an allUsers or allAuthenticatedUsers binding from a restricted resource.

### IR-3.3 Record
Every action, whether automated or approved, is written to the tamper-evident audit store with the evidence that justified it.

## IR-4 Communication

### IR-4.1 Internal escalation
Severity 1 incidents are escalated to the CISO within 30 minutes of classification.

### IR-4.2 Post-incident review
A post-incident review is completed within ten business days and must identify the control that failed and the control that detected the incident.
