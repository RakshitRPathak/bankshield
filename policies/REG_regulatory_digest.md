---
doc_id: REG-DIG
title: Regulatory Requirements Digest (bank's own summary of external obligations)
regulator: external-digest
version: "2026-Q3"
clearance: internal
---

# Regulatory Requirements Digest (REG-DIG)

This digest is the bank's own plain-language summary of obligations that external frameworks place on cloud workloads. It is not the regulatory text; the compliance team maintains the mapping to the source documents. Each item names the family of requirement and the internal control that satisfies it.

## REG-DIG-1 Data localisation
Payment system data for Indian customers must be stored only in India. Processing abroad, where permitted at all, must be followed by deletion of the foreign copy within the mandated window. Satisfied by DRS-1.1, DRS-1.2.

## REG-DIG-2 Strong authentication for privileged access
Privileged and administrative access to systems handling customer financial data must use multi-factor authentication. Satisfied by IAM-1.1.

## REG-DIG-3 Least privilege and access governance
Access rights must follow least privilege, be reviewed periodically, and privileged changes must be controlled and logged. Satisfied by IAM-2.1, IAM-4.1, IAM-4.3.

## REG-DIG-4 Network segmentation and exposure
Systems holding cardholder or customer data must not be directly reachable from untrusted networks, and administrative interfaces must not be internet-exposed. Satisfied by CSP-3.1, CSP-5.1, CSP-6.1.

## REG-DIG-5 Encryption of sensitive data
Sensitive customer and card data must be encrypted at rest with managed keys and in transit with current protocols. Satisfied by CSP-4.1, CSP-4.3.

## REG-DIG-6 Logging, retention and monitoring
Audit trails for access to sensitive systems must be generated, protected from tampering, retained for the mandated period and reviewed. Satisfied by LOG-1.1, LOG-1.3, LOG-3.1.

## REG-DIG-7 Incident reporting
Cyber incidents affecting the bank must be reported to the regulator within a short mandated window (six hours for the Indian cyber incident reporting regime), with a defined internal classification clock. Satisfied by IR-1.2, IR-4.1.

## REG-DIG-8 Outsourcing and cloud governance
Use of cloud service providers is an outsourcing arrangement; the bank remains accountable for security, must retain audit rights, and must be able to exit. Satisfied by CSP-1.2 and the vendor-management policy.
