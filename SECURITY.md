# Security Policy

## Scope

This policy applies to the ProfitPilot application, its source code, APIs, infrastructure configuration and associated documentation maintained in this repository.

## Reporting a vulnerability

Please do not disclose suspected vulnerabilities in public issues, pull requests, discussions or social media.

1. Check the repository's **Security** tab for **Report a vulnerability** and use GitHub's private vulnerability reporting flow if it is enabled.
2. If private reporting is not available, contact the repository owner through a verified, non-public channel before sharing technical details. Do not send credentials, customer records or other personal information in an initial report.
3. Include the affected component, impact, reproduction steps and any safe proof-of-concept needed to validate the issue. Redact secrets and personal data.

The project does not currently publish a guaranteed response-time SLA, bug-bounty programme or security certification. Those must not be implied in customer or buyer materials.

## Handling reports

Reports should be triaged privately, assigned an owner and severity, reproduced in a controlled environment, and tracked through remediation and verification. Do not test against production systems or access another person's data without explicit authorisation.

A fix should include a regression test where practical. Public disclosure should be coordinated after a fix is available and affected users can be informed safely.

## Supported versions

Until a production release and support policy are established, the maintained development branch is:

- `security/comprehensive-hardening`

This is a development target, not a statement that the branch is production-supported.

## Security claims

Security controls are only to be described as implemented when supported by code, configuration and repeatable test evidence. Passing CI does not constitute independent penetration testing, certification or proof that a deployed production environment is secure.
