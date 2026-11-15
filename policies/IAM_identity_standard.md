---
doc_id: IAM
title: Identity and Access Management Standard
regulator: internal
version: "1.8"
clearance: internal
---

# Identity and Access Management Standard (IAM)

## IAM-1 Authentication

### IAM-1.1 Multi-factor authentication
Every account holding an administrative role on any cloud project must have phishing-resistant multi-factor authentication enforced. Accounts without MFA must be suspended, not merely flagged.

### IAM-1.2 Session anomalies
Authentication from two geographically distant locations within a window shorter than plausible travel time is treated as a compromised session. The session must be revoked and the user re-verified.

### IAM-1.3 Geographic restriction
Console and API access for human users is permitted only from India unless an approved travel exception is registered in advance.

## IAM-2 Authorisation

### IAM-2.1 No primitive roles
The primitive roles owner and editor must not be bound to any service account or user on production projects. Use predefined or custom roles scoped to the task.

### IAM-2.2 Separation of duties
No single identity may both deploy code and approve its deployment, or both grant access and audit access.

### IAM-2.3 No default service accounts
Compute workloads must run under a dedicated, minimally scoped service account. The Compute Engine default service account must not be used.

## IAM-3 Credentials

### IAM-3.1 Service account key usage
User-managed service account keys are prohibited unless the workload runs outside the cloud platform. Workloads inside the platform must use Workload Identity or attached service accounts.

### IAM-3.2 Key age
Where a user-managed key is approved, it must be rotated at least every 90 days and the previous key disabled within 24 hours of rotation.

### IAM-3.3 Secret rotation
Application secrets stored in the secret manager must have a rotation schedule. A secret with no schedule, or whose last rotation exceeds its schedule, is a control failure.

## IAM-4 Change control

### IAM-4.1 Privileged grants
Any grant of a privileged role must reference an approved change ticket and occur inside the approved change window, except through the break-glass procedure.

### IAM-4.2 Break-glass
Break-glass access is time-boxed to four hours, generates a critical alert on use, and is reviewed by the security operations lead on the next business day.

### IAM-4.3 Access reviews
Project owners must certify all privileged bindings quarterly. Uncertified bindings are removed automatically.
