# Title: YAML Detection Rule DSL (#1282)

## 1. Architectural Scope & Impact

- `gateway/src/rule_dsl.rs` (new): the YAML condition DSL — `RuleCondition`,
  `YamlRule`, validation, matching, and summary-template rendering. Pure,
  deterministic (Laws 1-2), no I/O.
- `gateway/src/detect.rs`: `Detector` becomes YAML-driven. The 5 existing
  hardcoded rule functions (`confused_deputy_block`, `approval_required_surface`,
  `critical_deny`, `replay_attempt`, `mcp_manifest_drift`) are migrated to an
  embedded default YAML rule set (`rule_dsl::default_rules()`), evaluated the
  same way as tenant-custom rules loaded from `detection_rules`.
- `gateway/src/db.rs`: no schema change (table already exists from #934/migration
  0008). Reuses `list_detection_rules`/`upsert_detection_rule`/`delete_detection_rule`.
- `gateway/src/routes.rs`: new endpoints `GET /v1/soc/rules` (effective rules =
  defaults + tenant custom), `POST /v1/soc/rules` (create/validate a tenant
  custom rule — thin wrapper over `db::upsert_detection_rule` with YAML
  validation), `POST /v1/soc/rules/reload` (documented no-op — see Phase 3).
- `gateway/src/main.rs`: route registration only. **No `AppState` change** —
  see Phase 3 note below on why the originally-planned tenant-rule cache was
  dropped.
- `gateway/src/events.rs`: `drain` loads each tenant's enabled custom rules
  fresh from `db::list_detection_rules` per event and passes them into
  `Detector::evaluate`.
- `gateway/Cargo.toml`: add `serde_yaml = "0.9"` (pinned, no wildcard).

No database migration needed — `detection_rules` (0008) already has the right
shape (`condition` TEXT holds the YAML body, `summary_template`, `severity`,
`enabled`, tenant-scoped + indexed).

## 2. Step-by-Step Execution Phases

- **Phase 1: YAML Condition DSL** (`rule_dsl.rs`)
  - `RuleCondition` (serde, `deny_unknown_fields`): `event_type`, `decision`,
    `tool`, `action`, `context_trust: Vec<String>` (6 trust levels only),
    `mutating: bool`, `min_risk_score`, `max_risk_score`,
    `matched_policy_contains: Vec<String>`.
  - `YamlRule { rule_key, name, condition, severity, summary_template }`.
  - `validate()`: severity in {high,medium,low,info}; `context_trust` values
    restricted to the 6 deterministic trust levels; `decision` in
    {allow,deny,require_approval}; unknown YAML keys rejected via
    `deny_unknown_fields` (serde error surfaced as validation error).
  - `matches(&self, event: &AseEvent) -> bool` — AND of all specified fields.
  - `render_summary(&self, event: &AseEvent) -> String` — `{tool}`, `{action}`,
    `{decision}`, `{reason}`, `{tenant_id}`, `{agent_id}` placeholders.
  - `parse_rules(yaml: &str) -> Result<Vec<YamlRule>, String>`.
  - `default_rules() -> Vec<YamlRule>` — embedded YAML, one entry per migrated
    hardcoded rule (mcp_manifest_drift split into 3 risk-score bands).
  - Unit tests for parsing, validation (valid + invalid field/operator/value
    cases), matching, template rendering.

- **Phase 2: Detector integration** (`detect.rs`)
  - `Detector::evaluate(&self, event, tenant_rules: &[YamlRule]) -> Vec<Alert>`
    runs `default_rules()` ++ `tenant_rules`, dedups by `(rule_name,
    source_event_id)` keeping the first match (preserves old single-alert
    `critical_deny`/`mcp_manifest_drift` semantics).
  - Remove the 5 hardcoded `pub fn` rules; keep `Alert`, `signals` helper (used
    by `rule_dsl`), `CRITICAL_RISK_SCORE` constant moved into `rule_dsl`.
  - Port existing `detect.rs` unit tests to call `Detector::evaluate(&ev, &[])`
    and assert on `alert.rule`/`severity` — behavior must stay equivalent.

- **Phase 3: Tenant rule loading + endpoints** (`routes.rs`, `events.rs`)
  - Dropped the originally-planned `AppState.detection_rule_cache:
    Arc<RwLock<HashMap<String, Vec<YamlRule>>>>` — 12 separate `AppState{}`
    construction sites (3 in `main.rs`, 9 in `routes.rs` test setups) made a
    new required field too mechanically invasive for the value it added.
  - Instead, `events::drain` calls `db::list_detection_rules(&pool,
    &ev.tenant_id)` fresh on every event, filters `enabled`, converts each row
    via `rule_dsl::yaml_rule_from_condition` (skipping + logging invalid
    rows), and passes the resulting `Vec<YamlRule>` to
    `Detector::evaluate(&ev, &tenant_rules)`. This is acceptable because
    detection is async/out-of-band (Law 3) — an extra tenant-scoped SELECT per
    event is not on the `/v1/authorize` hot path.
  - `POST /v1/soc/rules/reload` is therefore a **documented no-op `200`**:
    rules are always loaded fresh, so there is nothing to invalidate. Kept for
    API compatibility with rule-management tooling.
  - `GET /v1/soc/rules` returns `default_rules() ++ enabled tenant rules`,
    each a `YamlRule` flattened with a `source: "default"|"custom"` tag.
  - `POST /v1/soc/rules` validates the YAML `condition`/`severity` via
    `rule_dsl::yaml_rule_from_condition` then delegates to
    `db::upsert_detection_rule`; invalid rules return 400 with a validation
    message (never 500).

## 3. Verification & Testing Targets

```bash
cargo test  --manifest-path gateway/Cargo.toml   # full suite, including new rule_dsl + detect + routes tests
cargo fmt   --manifest-path gateway/Cargo.toml -- --check
cargo clippy --manifest-path gateway/Cargo.toml -- -D warnings
```

## 4. Security Audit Checklist

- [ ] `detection_rules` queries remain tenant-scoped + parameterized (no change
      to existing `db.rs` functions).
- [ ] YAML parsing is `serde_yaml` deserialize-only — no arbitrary code
      execution, no `!!python`-style tags reachable from user input.
- [ ] Invalid/unknown rule fields/operators rejected with 400, never panic
      (`deny_unknown_fields`, explicit `Result` — no `.unwrap()`/`.expect()`).
- [ ] Fail-closed unaffected: `Detector`/rules are advisory SOC alerts only —
      never gate `/v1/authorize`'s `allow`/`deny`/`require_approval` (Law 1).
