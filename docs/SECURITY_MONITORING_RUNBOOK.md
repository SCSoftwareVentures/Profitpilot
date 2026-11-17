# Privacy-minimised security monitoring (pre-production)

The API emits structured security_window and security_threshold JSON to stderr. Counts use a fixed 60-second process-local window and a strict event allowlist. No IP, identity, token, path parameters, body, free-text, secret, provider subject or tenant ID is emitted by this telemetry. No public metrics route is exposed. The signal is not an audit trail or proof of specific-user activity. Thresholds are triage defaults, not statistically validated anomaly detection. Rate-limit and denial counts may represent ordinary user behaviour or a malicious probe. Low-volume attacks can evade thresholds; distributed deployments require externally aggregated signals.

| Category | Default threshold per minute, per process | Response |
|---|---:|---|
| authentication_denied | 20 | Investigate provider and edge abuse evidence |
| authorization_denied | 10 | Check access review, scope and tenant isolation |
| rate_limited | 10 | Review abuse limits and distributed traffic |
| malformed_or_oversized_request | 20 | Inspect edge aggregate and abuse metrics |
| request_aborted | 20 | Investigate timeout, traffic or health issues |
| service_error | 5 | Review app and database health |
| dependency_unavailable | 3 | Investigate database/identity provider availability |
| account_revocation | 5 | Check potential account compromise response |
| permission_changed | 5 | Review authorised permission audit records |
| sensitive_privacy_access | 10 | Review authorised purpose-bound privacy audit evidence |
| security_audit_access | 10 | Review administrative audit access |

## Operational release conditions
Configure restricted, encrypted log aggregation and alert routing with named technical and privacy owners, severity/on-call escalation, explicit access logging and approved retention. Configure independent health and missing-log detection: a failing sink cannot guarantee successful alert delivery. Monitor collector drops, time synchronisation, abnormal database and key events, and provider login/recovery/device signals. Keep the API's structured event output separate from any provider or reverse-proxy logs that might contain identifying data. Test log access boundaries, generated alerts, loss of telemetry and incident escalation on a non-production deployment. No collector, alert destination, real operational metrics, 24/7 alerts or monitoring infrastructure are configured.
