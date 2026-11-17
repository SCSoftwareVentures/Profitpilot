# ProfitPilot — Security Architecture Diagram

**Status:** Current prototype boundary as represented by the repository on 17 November 2026. Dashed nodes are required or future production components that are not established as configured services.

```mermaid
flowchart TB
  subgraph Client["Client boundary"]
    Browser["Browser / user interface"]
    Demo["Static demo with synthetic data"]
    Browser --- Demo
  end

  subgraph Service["Application boundary — prototype"]
    API["Express API"]
    JWT["JWT / JWKS verification"]
    Membership["Tenant membership + permission middleware"]
    StepUp["Step-up claim validation"]
    Context["Signed, transaction-scoped tenant context"]
    Engine["Deterministic validation / calculation engine"]
    API --> JWT --> Membership
    Membership --> StepUp
    Membership --> Context
    API --> Engine
  end

  subgraph Data["PostgreSQL trust boundary"]
    Runtime["Restricted runtime role — NO SUPERUSER / NO BYPASSRLS"]
    RLS["Forced tenant row-level security"]
    Subject["Privacy request subject-level policies"]
    Audit["Append-only per-tenant audit hash chain"]
    Sessions["Private session registry functions"]
    DB[("Tenant and business data")]
    Runtime --> RLS --> DB
    RLS --> Subject
    DB --> Audit
    API --> Sessions
  end

  Browser -->|"Bearer access token"| API
  Context --> Runtime

  subgraph NotEstablished["Not yet established for production"]
    IdP["Configured production IdP with MFA / passkeys"]
    KMS["Managed key custody, rotation and recovery"]
    Storage["Private object storage + malware scanning"]
    Ops["Monitoring, alerting, backups and restore drills"]
    Privacy["Export / correction / restriction / deletion executors"]
    Pentest["Independent penetration test + privacy assessment"]
  end

  IdP -.-> JWT
  KMS -.-> Context
  Storage -.-> API
  Ops -.-> Service
  Privacy -.-> DB
  Pentest -.-> Service
```

## Trust boundaries and interpretation

1. Client-supplied tenant IDs are selectors, not proof of access. The API resolves membership from the verified identity.
2. The API creates a signed tenant context for a transaction. PostgreSQL validates it and applies RLS under a restricted runtime role.
3. Privacy request RLS adds a subject-level boundary inside a tenant: members see their own requests; designated managers may review tenant requests.
4. Audit events are chained and append-only for runtime operations, but the chain is not independently anchored outside the database.
5. Dashed production components are gaps, not implied capabilities. In particular, the prototype does not yet execute data-subject exports or deletions and has no configured production identity provider or storage pipeline.
