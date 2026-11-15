# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem. Use GitHub's private reporting:
**Security → Report a vulnerability** on this repository. Include what you found, how to
reproduce it, and the commit you tested. You should get a reply within a week.

## Scope

BankShield is a prototype that runs against a **simulated** estate. In scope: anything that
lets a caller read policy text above their clearance, see another project's findings or
incidents, act without the required permission or approval, run code through a rule
expression, or alter the audit trail without detection. `docs/THREAT_MODEL.md` lists the
threats considered and the test covering each.

## Running it safely

- The default `X-User` header identity is a demo convenience, **not authentication**. Do not
  expose the server beyond localhost in that mode. Set `BANKSHIELD_AUTH=token` and a strong
  `BANKSHIELD_SECRET` for anything shared.
- Set `BANKSHIELD_AUDIT_KEY` and keep it, and the audit checkpoint file, somewhere the
  database writer cannot reach.
- Never commit `.env`, databases or Terraform state; `.gitignore` already excludes them.

## Supply chain

GitHub Actions are pinned to commit hashes, the workflow token is read-only, dependencies are
audited on every push (`pip-audit`), CodeQL scans Python and JavaScript, and Dependabot
proposes updates weekly.
