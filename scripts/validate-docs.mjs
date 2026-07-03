#!/usr/bin/env node
/**
 * Docs validation for the AegisAgent documentation system.
 *
 *   node scripts/validate-docs.mjs
 *
 * Checks (no dependencies, Node >= 18):
 *   1. Required docs exist.
 *   2. Internal markdown links resolve (errors for docs owned by this system,
 *      warnings for legacy docs).
 *   3. docs/architecture-map.json is valid: node fields, edge endpoints,
 *      flow keys, related_docs exist, related_files exist in the repo.
 *   4. Every diagram listed in AegisAgent_Diagram_Index.md exists on disk and
 *      every .mmd on disk is listed in the index.
 *   5. Implementation_Status_Matrix.md contains every required capability row.
 *   6. The explorer page exists and loads the architecture map.
 *   7. Active docs/scripts do not regress to stale pre-workspace paths or
 *      blocking Docker Compose quickstart snippets.
 *
 * Exit code 0 = pass (warnings allowed), 1 = errors found.
 */
import { readFileSync, readdirSync, existsSync, statSync } from "node:fs";
import { join, dirname, resolve, relative } from "node:path";

const ROOT = resolve(dirname(new URL(import.meta.url).pathname), "..");
const DOCS = join(ROOT, "docs");
const errors = [];
const warnings = [];

function* textFiles(dir, suffixes) {
  if (!existsSync(dir)) return;
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) yield* textFiles(p, suffixes);
    else if (suffixes.some(s => e.name.endsWith(s))) yield p;
  }
}

// ── 1. Required docs ────────────────────────────────────────────────────────
const REQUIRED_DOCS = [
  // Level 0: meta
  "README.md", "Documentation_Index.md", "Documentation_Audit.md",
  "Documentation_Redesign_Plan.md",
  // Level 1: simple product understanding
  "START_HERE.md", "What_Is_AegisAgent.md", "Why_AegisAgent.md",
  "The_One_Minute_Tour.md", "How_It_Works.md", "Glossary.md", "faq.md",
  "Product_Overview.md", "The_One_Minute_Tour.md",
  // Level 2: flows
  "flows/Known_Agent_Flow.md", "flows/Unknown_Agent_Cage_Flow.md",
  "flows/Approval_Flow.md", "flows/Receipt_Flow.md",
  "flows/SOC_Incident_Flow.md", "flows/Tool_Broker_Flow.md",
  "flows/Egress_Block_Flow.md", "flows/Ban_Quarantine_Flow.md",
  "flows/MCP_Gateway_Flow.md", "flows/Prompt_To_Action_Lineage.md",
  "flows/Control_Command_Flow.md",
  // Level 3: architecture
  "Architecture_Overview.md", "Last_Mile_System_Walkthrough.md",
  "AegisAgent_Runtime_Data_Plane.md", "security-model.md",
  "AegisAgent_Threat_Model.md", "fail-closed-behavior.md",
  "database-schema.md", "event-schema.md", "action-receipt-spec.md",
  "AegisAgent_World_Class_HLD.md", "AegisAgent_World_Class_LLD.md",
  "AegisAgent_Agent_Cage.md", "AegisAgent_Control_Command_Protocol.md",
  // Level 4: components
  "components/Gateway.md", "components/SDK.md", "components/Policy_Engine.md",
  "components/Approval_Engine.md", "components/Receipt_Engine.md",
  "components/SOC_Engine.md", "components/MCP_Gateway.md",
  "components/Tool_Broker.md", "components/Node_Sensor.md",
  "components/Agent_Cage.md", "components/Egress_Proxy.md",
  "components/Console_UI.md", "components/Storage.md",
  "components/Prompt_Model_Capture.md",
  // Level 5: build, run, operate
  "Local_Development.md", "quickstart.md", "deployment-guide.md",
  "production-hardening.md", "AegisAgent_Debugging_Guide.md",
  "runbooks/index.md",
  // Level 6: maintainer
  "Repo_Knowledge_Map.md", "Implementation_Status.md",
  "AegisAgent_Diagram_Index.md",
  // onboarding personas
  "onboarding/For_New_Engineer.md", "onboarding/For_Security_Architect.md",
  "onboarding/For_SOC_Analyst.md", "onboarding/For_SDK_Developer.md",
  "onboarding/For_Frontend_Engineer.md", "onboarding/For_DevOps_Engineer.md",
  // machine-readable + explorer
  "architecture-map.json", "explorer/index.html",
];
for (const f of REQUIRED_DOCS) {
  if (!existsSync(join(DOCS, f))) errors.push(`missing required doc: docs/${f}`);
}

// Docs owned by this system → broken links here are errors, not warnings.
const OWNED = new Set(REQUIRED_DOCS.filter(f => f.endsWith(".md")));

// ── 2. Internal links ───────────────────────────────────────────────────────
function* mdFiles(dir) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) yield* mdFiles(p);
    else if (e.name.endsWith(".md")) yield p;
  }
}
const LINK_RE = /\]\(([^)\s]+)\)/g;
for (const file of mdFiles(DOCS)) {
  const relFile = relative(DOCS, file);
  const text = readFileSync(file, "utf8");
  for (const m of text.matchAll(LINK_RE)) {
    let target = m[1];
    if (/^(https?:|mailto:|#|<)/.test(target)) continue;
    target = target.split("#")[0];
    if (!target) continue;
    const resolved = resolve(dirname(file), decodeURIComponent(target));
    if (!existsSync(resolved)) {
      const msg = `broken link in docs/${relFile}: ${m[1]}`;
      (OWNED.has(relFile) ? errors : warnings).push(msg);
    }
  }
}

// ── 3. architecture-map.json ────────────────────────────────────────────────
let map;
try {
  map = JSON.parse(readFileSync(join(DOCS, "architecture-map.json"), "utf8"));
} catch (e) {
  errors.push(`architecture-map.json unparseable: ${e.message}`);
}
if (map) {
  const ids = new Set();
  const VALID_STATUS = new Set(["implemented", "partial", "planned"]);
  for (const n of map.nodes ?? []) {
    for (const field of ["id", "label", "type", "layer", "status", "description"]) {
      if (n[field] === undefined) errors.push(`architecture-map node ${n.id ?? "?"} missing field: ${field}`);
    }
    if (n.status && !VALID_STATUS.has(n.status)) errors.push(`architecture-map node ${n.id}: bad status '${n.status}'`);
    if (ids.has(n.id)) errors.push(`architecture-map duplicate node id: ${n.id}`);
    ids.add(n.id);
    for (const d of n.related_docs ?? []) {
      if (!existsSync(join(DOCS, d))) errors.push(`architecture-map node ${n.id}: related_doc missing: docs/${d}`);
    }
    for (const f of n.related_files ?? []) {
      if (!existsSync(join(ROOT, f))) warnings.push(`architecture-map node ${n.id}: related_file not found at HEAD-checkout: ${f}`);
    }
  }
  for (const e of map.edges ?? []) {
    if (!ids.has(e.from)) errors.push(`architecture-map edge from unknown node: ${e.from}`);
    if (!ids.has(e.to)) errors.push(`architecture-map edge to unknown node: ${e.to}`);
    if (e.flow && !(e.flow in (map.flows ?? {}))) errors.push(`architecture-map edge ${e.from}→${e.to}: unknown flow '${e.flow}'`);
  }
}

// ── 4. Diagrams inventory ───────────────────────────────────────────────────
const DIAG_DIR = join(DOCS, "diagrams");
const indexText = existsSync(join(DOCS, "AegisAgent_Diagram_Index.md"))
  ? readFileSync(join(DOCS, "AegisAgent_Diagram_Index.md"), "utf8") : "";
const onDisk = existsSync(DIAG_DIR) ? readdirSync(DIAG_DIR).filter(f => f.endsWith(".mmd")) : [];
for (const f of onDisk) {
  if (!indexText.includes(f)) errors.push(`diagram not listed in AegisAgent_Diagram_Index.md: ${f}`);
}
for (const m of indexText.matchAll(/diagrams\/([\w-]+\.mmd)/g)) {
  if (!onDisk.includes(m[1])) errors.push(`Diagram Index references missing file: diagrams/${m[1]}`);
}
if (onDisk.length < 15) warnings.push(`only ${onDisk.length} diagram sources found (expected >= 15)`);

// ── 5. Status matrix capabilities ───────────────────────────────────────────
const REQUIRED_CAPABILITIES = [
  "Gateway authorize", "Policy engine", "Approval lifecycle", "Approval edit lifecycle",
  "Approval consume", "Receipt chain", "Receipt verification", "Receipt signing",
  "Evidence pack", "Evidence graph", "SOC events", "Incidents", "SOC query",
  "Tenant isolation", "Auth: bearer/JWT", "MCP gateway", "Tool permissions",
  "SDK Python", "SDK TypeScript", "SDK Go", "UI: approvals", "UI: receipts",
  "UI: incidents", "UI: agent-cage", "Agent runs registry", "Runtime events",
  "Control commands", "Ban system", "Quarantine records", "Node sensor",
  "Agent cage runner", "Egress proxy", "Tool broker", "Prompt capture",
  "Model call capture", "Runtime timeline", "Deployment", "CI / testing",
];
const matrixText = existsSync(join(DOCS, "Implementation_Status.md"))
  ? readFileSync(join(DOCS, "Implementation_Status.md"), "utf8") : "";
for (const cap of REQUIRED_CAPABILITIES) {
  if (!matrixText.includes(cap)) errors.push(`Implementation_Status.md missing capability row: ${cap}`);
}
// Status vocabulary check: the status column must use only these words.
const STATUS_WORDS = ["Implemented", "Partial", "Planned", "Missing"];
const matrixRows = matrixText.split("\n").filter(l => l.startsWith("| ") && l.split("|").length > 8);
for (const row of matrixRows.slice(1)) {
  const cells = row.split("|").map(c => c.trim());
  const status = cells[2] ?? "";
  if (status && status !== "Status" && !status.startsWith("--") &&
      !STATUS_WORDS.some(w => status.startsWith(w))) {
    errors.push(`Implementation_Status.md row '${cells[1]}' has invalid status '${status}' (allowed: ${STATUS_WORDS.join("/")})`);
  }
}

// ── 6. Explorer wiring ──────────────────────────────────────────────────────
const explorer = existsSync(join(DOCS, "explorer/index.html"))
  ? readFileSync(join(DOCS, "explorer/index.html"), "utf8") : "";
if (explorer && !explorer.includes("architecture-map.json")) {
  errors.push("explorer/index.html does not load architecture-map.json");
}

// ── 7. Docs hygiene guardrails ─────────────────────────────────────────────
// These checks prevent the highest-trust docs from drifting back to the
// pre-workspace gateway layout, and prevent copy-paste setup snippets that
// block forever before the seed/demo command can run.
const HYGIENE_SCAN_FILES = [
  "README.md", "CLAUDE.md", "AGENTS.md", "CONTRIBUTING.md", "Makefile",
]
  .map(f => join(ROOT, f))
  .filter(existsSync)
  .concat([...mdFiles(DOCS)])
  .concat([...textFiles(join(ROOT, "scripts"), [".sh", ".mjs", ".py"])])
  .concat([...textFiles(join(ROOT, ".github"), [".yml", ".yaml"])]);

const HYGIENE_RULES = [
  {
    name: "stale pre-workspace gateway path",
    pattern: /gateway\/(?:src|Cargo\.toml|policies\.cedar|benches|benchmarks|scripts)\b/,
    hint: "use current src/ or lib/ paths; historical notes belong in docs/feature_history.md",
  },
  {
    name: "single-crate manifest command",
    pattern: /--manifest-path\s+src\/Cargo\.toml\b/,
    hint: "use root workspace/package commands such as `cargo check --workspace` or `cargo run -p gateway --bin gateway`",
  },
  {
    name: "blocking Docker Compose quickstart",
    pattern: /docker\s+compose(?:\s+-f\s+\S+)?\s+up\s+--build(?!\s+-d\b)/,
    hint: "use `docker compose up --build -d` before follow-on seed/demo commands",
  },
];

function isHygieneExempt(relFile, line) {
  if (relFile === "docs/feature_history.md") return true;
  if (relFile === "docs/Repo_Knowledge_Map.md") {
    return (
      line.includes("Historical note:") ||
      line.includes("Generated or local-only agent skill files")
    );
  }
  return false;
}

for (const file of HYGIENE_SCAN_FILES) {
  const relFile = relative(ROOT, file);
  const lines = readFileSync(file, "utf8").split("\n");
  lines.forEach((line, idx) => {
    if (isHygieneExempt(relFile, line)) return;
    for (const rule of HYGIENE_RULES) {
      if (rule.pattern.test(line)) {
        errors.push(
          `${rule.name} in ${relFile}:${idx + 1}: ${line.trim()} (${rule.hint})`
        );
      }
    }
  });
}

// ── report ──────────────────────────────────────────────────────────────────
for (const w of warnings) console.log(`WARN  ${w}`);
for (const e of errors) console.log(`ERROR ${e}`);
console.log(`\ndocs validation: ${errors.length} error(s), ${warnings.length} warning(s)`);
process.exit(errors.length ? 1 : 0);
