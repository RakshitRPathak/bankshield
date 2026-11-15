---
doc_id: DRS
title: Data Residency and Sovereignty SOP
regulator: internal
version: "3.0"
clearance: internal
---

# Data Residency and Sovereignty SOP (DRS)

## DRS-1 Location of data

### DRS-1.1 Approved regions
Restricted data must be stored and processed only in cloud regions located in India. The approved regions are asia-south1 (Mumbai) and asia-south2 (Delhi).

### DRS-1.2 Replicas and backups
Replicas, backups, snapshots and disaster-recovery copies of restricted data are subject to the same residency rule as the primary copy. A replica outside India is a residency breach even if the primary is compliant.

### DRS-1.3 Secret replication
Secrets protecting restricted systems must use user-managed replication pinned to approved regions. Automatic (global) replication is not permitted for restricted secrets.

### DRS-1.4 Processing location
Managed services that process restricted data (analytics, machine learning, search) must be configured to run in approved regions. Multi-region or global endpoints require a CISO exception.

## DRS-2 Movement of data

### DRS-2.1 Perimeter enforcement
Residency is enforced technically through VPC Service Controls perimeters and organisation policy constraints on resource locations, not only through procedure.

### DRS-2.2 Cross-border access
Access to restricted data from outside India, whether by a person or a service identity, is prohibited without a registered exception. Such access is treated as a security incident until explained.

### DRS-2.3 Export control
Restricted data may not be exported to a bucket, dataset or system of a lower classification. Bulk reads or exports of restricted data outside normal batch patterns must raise an alert.

## DRS-3 Evidence

### DRS-3.1 Residency evidence
The security function must be able to produce, on request, a list of every resource holding restricted data with its region, derived from the live asset inventory rather than from documentation.

### DRS-3.2 Exception register
Every residency exception must record the resource, the business reason, the approver, the compensating control and an expiry date not exceeding 12 months.
