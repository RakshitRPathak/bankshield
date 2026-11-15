---
doc_id: CSP
title: Cloud Security Policy
regulator: internal
version: "2.3"
clearance: internal
---

# Cloud Security Policy (CSP)

## CSP-1 Scope and ownership

### CSP-1.1 Scope
This policy applies to every workload, dataset and identity hosted on the bank's approved public cloud platforms, including production, pre-production and sandbox environments.

### CSP-1.2 Ownership
Each cloud project must have a named business owner and a named technical owner recorded in the asset inventory. Ownerless projects must be disabled within 30 days of discovery.

## CSP-2 Classification

### CSP-2.1 Sensitivity tiers
Data and workloads are classified as public, internal or restricted. Customer financial data, card data, authentication secrets and ledger data are always restricted.

### CSP-2.2 Tier inheritance
A project that hosts any restricted dataset is treated as a restricted project for the purposes of perimeter, encryption and logging controls.

## CSP-3 Storage access

### CSP-3.1 No public storage
No storage bucket, BigQuery dataset or object store may be readable by allUsers or allAuthenticatedUsers. Public sharing of bank data requires a CISO exception recorded in the exception register.

### CSP-3.2 Uniform access control
Buckets must enforce uniform bucket-level access so that permissions are managed only through IAM and never through per-object ACLs.

### CSP-3.3 Least-privilege bindings
Storage IAM bindings must be granted to groups or service accounts, never to individual user accounts, except for break-glass access.

### CSP-3.4 Versioning for restricted data
Buckets holding restricted data must enable object versioning and a retention policy appropriate to the record class.

## CSP-4 Encryption

### CSP-4.1 Customer-managed keys
Restricted data at rest (buckets, disks, databases, datasets) must be encrypted with customer-managed encryption keys (CMEK) held in the bank's own key ring.

### CSP-4.2 Key rotation
CMEK keys must rotate automatically at least every 90 days. Keys protecting card data must rotate every 30 days.

### CSP-4.3 Encryption in transit
All database connections and service-to-service calls must require TLS 1.2 or higher. Database instances must reject unencrypted connections.

## CSP-5 Network and perimeter

### CSP-5.1 No public database endpoints
Managed database instances must not have public IP addresses. Access is via private IP, Private Service Connect or an approved proxy.

### CSP-5.2 Private workloads
Production compute must not have external IP addresses except for approved bastion hosts and load balancers.

### CSP-5.3 Service perimeter
Every restricted project must sit inside a VPC Service Controls perimeter that restricts data-plane API calls to approved networks and identities.

## CSP-6 Compute hardening

### CSP-6.1 Administrative ports
Firewall rules must not allow SSH (22) or RDP (3389) from 0.0.0.0/0. Administrative access goes through Identity-Aware Proxy or a bastion inside the perimeter.

### CSP-6.2 Kubernetes baseline
GKE clusters must use private nodes, Workload Identity and network policy, and must not enable legacy attribute-based access control.

### CSP-6.3 Instance baseline
Compute instances must enable OS Login and Shielded VM features (secure boot, vTPM, integrity monitoring).

## CSP-7 Resilience

### CSP-7.1 Recovery objectives
Tier-1 systems (core ledger, payments) must meet an RPO of 15 minutes and an RTO of 2 hours, demonstrated by an annual recovery test.

### CSP-7.2 Backups
Managed databases must have automated backups enabled with point-in-time recovery, retained for at least 35 days and stored in an approved region.
