# Security policy

## Supported version

Security fixes currently target the latest code on `main` while the first archival release is pending.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting feature for this repository. Do not open a public issue containing exploit details, credentials, or private evidence.

## Security boundary

This reference implementation is local-first and assumes a trusted local operator. It redacts sensitive receipt keys, avoids embedding credentials, and never requires repository secrets for tests. It is not a hardened multi-user service or a substitute for operating-system access controls. Treat the selected workspace as potentially sensitive because it can contain preserved evidence and approval records.
