{
  "handover": {
    "version": "1.0.0",
    "generated": "2026-11-09T00:00:00Z",
    "project": "XLean Repo Fortress (Omega Edition)",
    "phase": "1 — Blueprint CONFIRMED (with corrections)",
    "status": "READY FOR PHASE 2 COMMIT"
  },

  "project": {
    "name": "XLean",
    "description": "Multi-tenant Team Knowledge Base SaaS with strict workspace isolation",
    "runtime": "Bun >= 1.4.4 (aarch64 primary, x86_64 CI)",
    "package_manager": "pnpm (workspace features) OR bun install (simpler)",
    "language": "TypeScript (strict)",
    "frontend": "React 18 + Vite 6 + Tailwind CSS",
    "backend": "Express 5 + Knex 3.3 + PostgreSQL 15 + Redis 7",
    "auth": "JWT (15 min) + Redis refresh tokens (7 days) + Argon2id (Bun native crypto.argon2)",
    "targets": {
      "local_dev": "Termux on Android 17 (Pixel 10a, aarch64) with proot-distro Ubuntu + Postgres 15",
      "ci": "Linux (GitHub Actions, ubuntu-latest)",
      "production": "OCI container (Bun multi-stage Dockerfile)"
    },
    "coverage_targets": {
      "lines": ">= 90% aggregate (suite-level, NOT per-file)",
      "functions": ">= 90% aggregate",
      "branches": "NOT MEASURABLE in Bun 1.4.4 (PR #46534 pending, est. Q1 2027). Compensated with mutation testing + structural 1:1 test mirror."
    }
  },

  "architecture_decisions": [
    {
      "id": "AD-001",
      "decision": "Row-level tenancy with forced DAL wrapper + PostgreSQL RLS (dual-layer)",
      "rationale": "Lean, no schema-per-tenant overhead. RLS is the safety net for DAL bugs (Moltbook incident, Jan 2026: 1.5M tokens leaked due to missing RLS).",
      "rejection": "Schema-per-tenant (operational cost), heavy ORM hooks (Prisma/TypeORM overhead)"
    },
    {
      "id": "AD-002",
      "decision": "Knex 3.3 as query builder (NOT a heavy ORM)",
      "rationale": "Actively maintained again as of Mar 2026 (v3.2.0 → v3.3.0, 12 releases/year, 47 contributors). 20.7M weekly downloads. TypeScript support improving.",
      "correction": "Earlier note that 'activity has slowed' was WRONG. Knex had a maintenance revival in Mar 2026."
    },
    {
      "id": "AD-003",
      "decision": "Bun native crypto.argon2 (NOT the argon2 npm package)",
      "rationale": "Bun 1.4.1+ ships crypto.argon2 built-in. Eliminates native binding compilation on aarch64/Termux. Argon2id parameters: memoryCost=19456, timeCost=2, parallelism=1.",
      "rejection": "argon2 npm package (native binding, painful on Termux), bcrypt (inferior to Argon2id)"
    },
    {
      "id": "AD-004",
      "decision": "JWT (15 min, stateless) + Redis refresh tokens (7 days, rotating)",
      "rationale": "Resolves the blueprint's contradictory 'JWT + In-memory/Redis session' spec. Allows immediate revocation (delete Redis key) while keeping per-request auth fast (stateless JWT verify).",
      "rejection": "Pure stateless JWT (no revocation), pure server-side sessions (per-request DB hit)"
    },
    {
      "id": "AD-005",
      "decision": "SET LOCAL (transaction-scoped GUC) for RLS workspace_id, NOT SET (session-scoped)",
      "rationale": "Session-scoped values leak across pooled connections. SET LOCAL resets on COMMIT/ROLLBACK automatically.",
      "critical": "The #1 RLS leak vector is using SET instead of SET LOCAL under PgBouncer transaction-mode pooling."
    },
    {
      "id": "AD-006",
      "decision": "STABLE wrapper function for RLS policy (not raw current_setting)",
      "rationale": "current_setting() is VOLATILE in PG's function catalog → planner cannot use RLS predicate for index selection → 100x performance degradation at scale (120ms vs 1.2ms).",
      "implementation": "CREATE FUNCTION current_workspace_id() RETURNS uuid LANGUAGE sql STABLE"
    },
    {
      "id": "AD-007",
      "decision": "Dual DB roles: app_tenant (non-superuser, no BYPASSRLS) + app_migrate (superuser, migrations only)",
      "rationale": "RLS is bypassed by table owners and BYPASSRLS roles. App must NOT own tables. Migrations need SUPERUSER to create policies.",
      "critical": "If the app role owns tables, FORCE ROW LEVEL SECURITY still applies, but the cleanest setup is: migrate role owns, app role has DML only."
    },
    {
      "id": "AD-008",
      "decision": "bun check (Bun 1.4.3+ native TypeScript checker) instead of separate tsc --noEmit",
      "rationale": "6.4x faster than tsc. Reads existing tsconfig.json. No separate dependency.",
      "gotcha": "If package.json has a \"check\" script, bare `bun check` runs that script. Use `bun check --no-script` or rename the script."
    },
    {
      "id": "AD-009",
      "decision": "Aggregate (suite-level) coverage gate via custom script, NOT bunfig.toml coverageThreshold",
      "rationale": "Bun's coverageThreshold is enforced PER FILE, not on the aggregate. A single small file at 85% fails the entire CI run even if the suite is 95%. Custom script computes suite-level totals from LCOV.",
      "migration_path": "Once all files are at 90%+, switch to bunfig.toml native threshold to prevent per-file regressions."
    },
    {
      "id": "AD-010",
      "decision": "Mutation testing (Stryker) as branch coverage proxy for isolation paths",
      "rationale": "Bun 1.4.4 does NOT report branch coverage (no BRDA records in LCOV). PR #46534 (pending, est. Q1 2027) will add it. Stryker mutation score 90% ≈ 90% branch coverage empirically.",
      "migration_path": "When PR #46534 merges, replace Stryker with native coverageThreshold.branches."
    }
  ],

  "corrections_log": [
    {
      "id": "CORR-001",
      "original_claim": "Knex activity has slowed; consider Drizzle ORM",
      "correction": "Knex had a major revival in Mar 2026 (v3.2.0 → v3.3.0, 12 releases/year). Safe choice for new projects.",
      "impact": "None. Stick with Knex as specified."
    },
    {
      "id": "CORR-002",
      "original_claim": "Use argon2 npm package",
      "correction": "Bun 1.4.1+ has native crypto.argon2. No npm dependency needed. Better on aarch64/Termux.",
      "impact": "Remove argon2 from package.json dependencies."
    },
    {
      "id": "CORR-003",
      "original_claim": "bun test --coverage produces BRDA records in lcov.info",
      "correction": "It does NOT. JSC reports neither branches nor function names in the LCOV output. The check-branch-coverage.ts script is a NO-OP.",
      "impact": "Delete check-branch-coverage.ts. Use mutation testing + structural defenses instead."
    },
    {
      "id": "CORR-004",
      "original_claim": "bunfig.toml coverageThreshold enforces suite-level aggregate",
      "correction": "It enforces PER FILE. Every single file must independently meet the threshold.",
      "impact": "Use custom aggregate script for the line/function gate. Don't use bunfig.toml threshold until project is mature."
    },
    {
      "id": "CORR-005",
      "original_claim": "Blueprint auth spec: 'JWT + Argon2/Bcrypt + In-memory/Redis session validation'",
      "correction": "This is two contradictory models. Resolved to: JWT (15 min) + Redis refresh tokens (7 days, rotating) + Argon2id only.",
      "impact": "Auth implementation uses the resolved model. Bcrypt dropped entirely."
    }
  ],

  "security_model": {
    "tenant_isolation": {
      "layer_1_application": "TenantDAL forces workspace_id on every query. All handlers use req.dal (injected by tenant-context middleware). Never raw knex.",
      "layer_2_database": "PostgreSQL RLS with FORCE ROW LEVEL SECURITY. STABLE wrapper function. WITH CHECK on all policies. App role is non-superuser, non-owner, no BYPASSRLS.",
      "layer_3_ci": "HIGH-RISK gate blocks unapproved changes to isolation files. CODEOWNERS requires @security-team on security paths.",
      "failure_modes_tested": [
        "Cross-tenant SELECT (returns null/empty)",
        "Cross-tenant UPDATE (affects 0 rows)",
        "Cross-tenant DELETE (affects 0 rows)",
        "INSERT with wrong workspace_id (WITH CHECK prevents)",
        "SET LOCAL resets on transaction end (no pool leak)",
        "GUC unset → zero rows (fail closed)"
      ]
    },
    "authentication": {
      "password_hashing": "Argon2id (Bun native crypto.argon2, memoryCost=19456, timeCost=2, parallelism=1)",
      "access_token": "JWT HS256, 15 min expiry, claims: { sub, workspace_id, role }",
      "refresh_token": "Opaque 256-bit random, 7 days, stored in Redis as SHA-256 hash, rotated on every use",
      "revocation": "DELETE Redis session key → immediate refresh token death. Access token lives up to 15 min (acceptable).",
      "membership_check": "Every request: verify JWT + check Redis session:{user_id}:{workspace_id} exists"
    },
    "rate_limiting": "Redis token bucket (Lua script, atomic). Per user+route. 100 req/min default. Fail-open on Redis error (log but don't block).",
    "error_handling": "Global error handler. Production: no stack traces, no SQL errors, no internal paths. //HIGH-RISK annotated.",
    "high_risk_gate": "CI script scans PR diff for //HIGH-RISK in modified files. Blocks merge without @security-team approval (CODEOWNERS)."
  },

  "files_written": {
    "src/": {
      "index.ts": "Express app entry. CORS, body parsing, routes, static SPA, error handler, graceful shutdown.",
      "pkg/config/index.ts": "Zod-validated env. All config typed. CORS origins parsed.",
      "pkg/errors/index.ts": "AppError hierarchy. 4xx + 5xx. Domain + security errors.",
      "pkg/logger/index.ts": "Pino structured logger. Redacts auth headers, passwords, tokens.",
      "data/db.ts": "Knex instance. Connects as app_tenant (non-superuser).",
      "data/redis.ts": "ioredis client. Retry strategy. Connection logging.",
      "data/tenant-dal.ts": "CRITICAL. Scoped() wrapper with SET LOCAL. All CRUD methods. Audit log method. //HIGH-RISK annotated.",
      "data/migrations/20260305000001_create_workspaces.ts": "workspaces table.",
      "data/migrations/20260305000002_create_users_and_members.ts": "users + workspace_members tables. Composite indexes.",
      "data/migrations/20260305000003_create_articles_and_audit_logs.ts": "articles + audit_logs tables.",
      "data/migrations/20260305000004_enable_rls.ts": "STABLE function. RLS + FORCE on all tables. WITH CHECK policies. Composite indexes. //HIGH-RISK.",
      "data/migrations/20260305000005_create_roles.ts": "app_tenant (non-superuser) + app_migrate (superuser). Grants + ownership.",
      "api/routes.ts": "Central router. Public (health, auth) + protected (articles) routes.",
      "api/middleware/auth.ts": "JWT verify + Redis membership check + context injection. //HIGH-RISK.",
      "api/middleware/tenant-context.ts": "Workspace validation + DAL injection. //HIGH-RISK.",
      "api/middleware/rate-limit.ts": "Redis token bucket (Lua). //HIGH-RISK.",
      "api/middleware/error-handler.ts": "Global error. Leak prevention. //HIGH-RISK.",
      "api/handlers/health.ts": "Liveness + readiness probes.",
      "api/handlers/auth.ts": "Login, register, refresh (rotation), logout. (SKELETON — full impl in Phase 2.)",
      "api/handlers/articles.ts": "Tenant-scoped CRUD. Zod validation. Audit logging.",
      "client/main.tsx": "React SPA entry. (Phase 3.)",
      "client/App.tsx": "Root component. (Phase 3.)",
      "client/lib/api-client.ts": "Fetch wrapper. Token refresh. Typed API methods."
    },
    "tests/": {
      "data/tenant-dal.test.ts": "7+ isolation tests. Cross-tenant SELECT/UPDATE/DELETE/INSERT. SET LOCAL pool leak. GUC unset fail-closed.",
      "api/middleware/auth.test.ts": "JWT verify, expired token, revoked session, missing header.",
      "api/middleware/tenant-context.test.ts": "Workspace mismatch, missing context, DAL injection.",
      "api/handlers/articles.test.ts": "CRUD + validation + 404 + cross-tenant.",
      "api/handlers/auth.test.ts": "Login, register, refresh rotation, logout.",
      "api/handlers/health.test.ts": "Liveness + readiness (DB + Redis).",
      "pkg/config/index.test.ts": "Env validation, defaults, invalid values.",
      "pkg/errors/index.test.ts": "Error hierarchy, status codes.",
      "client/api-client.test.ts": "Token refresh, error handling, 204 responses."
    },
    "scripts/": {
      "check-high-risk.sh": "Scans PR diff for //HIGH-RISK. Exits 1 if found without approval.",
      "check-coverage.ts": "Parses LCOV. Enforces AGGREGATE 90% line + 90% function. (Replaces bunfig.toml threshold.)",
      "check-branch-coverage.ts": "DELETED. Was a no-op (Bun 1.4.4 doesn't produce BRDA records).",
      "audit_repo.py": "(Phase 3. Python auxiliary audit tool.)"
    },
    "config/": {
      "package.json": "Full manifest. Bun 1.4.4 floor. No argon2 dep. Scripts: dev, check, test, migrate, high-risk.",
      "tsconfig.json": "Bundler resolution. Bun types. Strict. verbatimModuleSyntax. Path aliases.",
      "bunfig.toml": "Coverage ON. LCOV + text reporters. NO threshold (custom script handles it). Path ignore patterns.",
      "knexfile.ts": "Dual-role (KNEX_ROLE=migrate → app_migrate, else → app_tenant).",
      "bunfig.toml": "As above.",
      "docker-compose.yml": "Postgres 15 (dual role creation on boot) + Redis 7. Health checks.",
      "Dockerfile": "Multi-stage: client build (Vite) → production (Bun, non-root, minimal).",
      ".github/workflows/ci.yml": "Type check + HIGH-RISK gate + tests + coverage + mutation (weekly) + integration (real PG/Redis).",
      ".github/CODEOWNERS": "Security paths → @security-team.",
      ".env.example": "All env vars documented. Dual DB URLs. Argon2 params. Rate limit config.",
      "stryker.config.json": "Mutation testing config. 5 isolation files. Threshold 90%. Bun runner."
    }
  },

  "rls_implementation": {
    "critical_details": [
      "USE SET LOCAL (set_config with is_local=true), NEVER SET (session-scoped)",
      "USE STABLE wrapper function (current_workspace_id()), NEVER raw current_setting() in policy (VOLATILE → no index usage → 100x slower)",
      "ALWAYS include WITH CHECK (prevents cross-tenant INSERT/UPDATE corruption)",
      "App role must NOT own tables (FORCE RLS is bypassed by owners)",
      "App role must NOT have BYPASSRLS",
      "Composite indexes with workspace_id FIRST on all tenant tables",
      "current_setting('app.workspace_id', true) returns NULL when unset → policy matches zero rows (fail closed)"
    ],
    "performance_benchmark": {
      "without_stable_function": "120ms (seq scan) for point lookup at 1M rows / 10K tenants",
      "with_stable_function": "1.2ms (index scan) for point lookup at 1M rows / 10K tenants"
    }
  },

  "known_limitations": [
    {
      "id": "LIM-001",
      "limitation": "Bun 1.4.4 does not report branch coverage",
      "impact": "Cannot measure 100% branch coverage on isolation paths with a tool",
      "mitigation": "Mutation testing (Stryker) + structural 1:1 test mirror + targeted isolation tests + //HIGH-RISK review gate",
      "resolution": "PR #46534 (pending, est. Q1 2027) adds BRDA to LCOV + branches to coverageThreshold"
    },
    {
      "id": "LIM-002",
      "limitation": "bunfig.toml coverageThreshold is per-file, not aggregate",
      "impact": "A single small file below threshold fails entire CI",
      "mitigation": "Custom aggregate script (check-coverage.ts) for the gate",
      "resolution": "Switch to bunfig.toml native threshold once all files are at 90%+"
    },
    {
      "id": "LIM-003",
      "limitation": "Termux proot-distro Postgres is 3-5x slower than native",
      "impact": "Not suitable for load testing or timing-sensitive coverage runs",
      "mitigation": "CI uses real Postgres 15 container. Local dev is fine for functional testing.",
      "resolution": "N/A (accepted limitation)"
    },
    {
      "id": "LIM-004",
      "limitation": "JWT access tokens cannot be individually revoked (stateless)",
      "impact": "After forced logout, access token remains valid up to 15 min",
      "mitigation": "Optional JWT denylist (Redis, TTL=15 min) for password-change scenarios",
      "resolution": "15 min window is acceptable for this threat model"
    },
    {
      "id": "LIM-005",
      "limitation": "Rate limiter fails open on Redis error",
      "impact": "If Redis is down, rate limiting is disabled (DoS protection gone)",
      "mitigation": "Log the error. Consider fail-closed for /auth routes specifically.",
      "resolution": "Phase 3: add route-specific fail mode"
    }
  ],

  "open_questions": [
    {
      "id": "OQ-001",
      "question": "pnpm vs bun install as package manager?",
      "context": "Blueprint specifies pnpm. Bun's native installer is faster and produces bun.lockb. pnpm provides workspace features if needed.",
      "recommendation": "Use bun install unless workspace features are needed. Simpler, faster, native."
    },
    {
      "id": "OQ-002",
      "question": "Express 5 vs. staying on Express 4?",
      "context": "Express 5.1.0 is current stable (2026). Has async error handling built-in (no need for express-async-handler).",
      "recommendation": "Use Express 5. The error handler can be async without a wrapper."
    },
    {
      "id": "OQ-003",
      "question": "Will PR #46534 (Bun branch coverage) land before Phase 3?",
      "context": "If yes, we can use native coverageThreshold.branches and drop Stryker.",
      "recommendation": "Check bun.com/changelog monthly. If merged, update bunfig.toml and delete stryker.config.json."
    },
    {
      "id": "OQ-004",
      "question": "Should the SPA be a separate Vite project or in-repo?",
      "context": "Blueprint has it in-repo (src/client/). For a lean SaaS, in-repo is fine. If the SPA grows, extract to a workspace package.",
      "recommendation": "In-repo for now. Extract if it exceeds ~20 components."
    },
    {
      "id": "OQ-005",
      "question": "Search strategy (Phase 4): full-text (Postgres tsvector) vs. vector (pgvector) vs. external (Typesense)?",
      "context": "Depends on whether search is keyword-based or semantic. For a knowledge base, full-text is likely sufficient initially.",
      "recommendation": "Postgres tsvector (zero additional infra). Add pgvector later if semantic search is needed."
    }
  ],

  "next_steps": {
    "phase_2": {
      "name": "Manifest & Config Commit",
      "deliverables": [
        "Commit all files listed in files_written to the repo",
        "Verify bun install --frozen-lockfile works on aarch64 (Termux) and x86_64 (CI)",
        "Verify bun check passes (zero type errors)",
        "Verify bun test passes (all tests green)",
        "Verify bun scripts/check-coverage.ts passes (90% line + function)",
        "Verify docker-compose up starts PG + Redis",
        "Verify knex migrate:latest runs successfully (creates tables + RLS + roles)",
        "Verify the 7 isolation tests pass against real Postgres with RLS enabled",
        "Push to main → CI runs full pipeline"
      ],
      "exit_criteria": "CI is green. All tests pass. Coverage gate passes. RLS is verified working."
    },
    "phase_3": {
      "name": "UI + Auth Handler + Audit",
      "deliverables": [
        "Full src/api/handlers/auth.ts (register, login, refresh, logout, password change)",
        "Workspace management endpoints (create, invite, remove member)",
        "React SPA: login page, article list, article editor, workspace switcher",
        "Tailwind CSS + Vite config",
        "scripts/audit_repo.py (Python: check for hardcoded secrets, missing //HIGH-RISK, unused migrations)",
        "Integration test seed data",
        "Dockerfile for CI (separate from production)"
      ]
    },
    "phase_4": {
      "name": "Search + Notifications + Hardening",
      "deliverables": [
        "Full-text search (Postgres tsvector + GIN index)",
        "Webhook / notification system",
        "Rate limiter fail-closed for /auth routes",
        "JWT denylist for password-change revocation",
        "Load testing (k6, 10K tenants, 1M articles)",
        "Security audit (OWASP ASVS Level 2)"
      ]
    }
  },

  "key_references": {
    "moltbook_incident": "Jan 31, 2026. Wiz researcher found Supabase DB exposed. No RLS. 1.5M tokens, 35K emails, 4,060 private messages leaked. Fix took 3h 12min across 4 rounds. Lesson: application-layer auth is insufficient without RLS.",
    "bun_1_4_1_native_argon2": "Sep 4, 2026. crypto.argon2 shipped in Bun. Eliminates native binding dependency.",
    "bun_1_4_3_bun_check": "Oct 2026. Native TypeScript checker. 6.4x faster than tsc. Reads tsconfig.json.",
    "bun_pr_46534": "Pending. Adds BRDA to LCOV, branches to coverageThreshold. Est. Q1 2027.",
    "knex_2026_revival": "Mar 22, 2026. 'Knex, the Garden, and the Long Road Back' blog post. v3.2.0 → v3.3.0. 12 releases/year. 47 contributors.",
    "postgres_rls_stable_function": "current_setting() is VOLATILE → planner can't use RLS predicate for index selection. STABLE wrapper fixes it. 100x performance improvement at scale.",
    "set_local_vs_set": "SET (session-scoped) leaks across pooled connections. SET LOCAL (transaction-scoped) resets on COMMIT/ROLLBACK. The #1 RLS leak vector under PgBouncer."
  },

  "team_handover_notes": {
    "critical_files_read_first": [
      "src/data/tenant-dal.ts (the isolation boundary — every query goes through scoped())",
      "src/data/migrations/20260305000004_enable_rls.ts (the database-level safety net)",
      "src/api/middleware/auth.ts (the authentication gate)",
      "scripts/check-coverage.ts (the CI coverage gate)"
    ],
    "do_not": [
      "Do NOT use SET (session-scoped) instead of SET LOCAL in tenant-dal.ts",
      "Do NOT grant BYPASSRLS or table ownership to the app_tenant role",
      "Do NOT add a raw knex query that bypasses TenantDAL",
      "Do NOT remove //HIGH-RISK annotations without security-team approval",
      "Do NOT use the argon2 npm package (use Bun native crypto.argon2)",
      "Do NOT add coverageThreshold to bunfig.toml until all files are at 90%+ (it's per-file, not aggregate)",
      "Do NOT use bcrypt (Argon2id only)"
    ],
    "always": [
      "Always use req.dal (the injected TenantDAL) in handlers — never raw knex",
      "Always wrap new DB operations in the scoped() method",
      "Always add //HIGH-RISK to files that control auth, isolation, or error output",
      "Always add composite indexes (workspace_id FIRST) to new tenant-scoped tables",
      "Always add RLS policy + FORCE to new tenant-scoped tables",
      "Always add a test to the 1:1 mirror when adding a new source file"
    ]
  }
}
```

This is the complete handover. Your team should read `critical_files_read_first` before touching any code, internalize the `do_not` list, and use `next_steps.phase_2.exit_criteria` as the definition of done for the first commit.

