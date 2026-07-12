#!/usr/bin/env node

/**
 * Deterministic documentation quality inventory.
 *
 * Usage:
 *   node scripts/audit-doc-quality.mjs          # print report
 *   node scripts/audit-doc-quality.mjs --write  # update tracked report
 *   node scripts/audit-doc-quality.mjs --check  # fail when report is stale
 *
 * This measures structural teaching signals, not factual accuracy. Source and
 * implementation claims still require human/code review.
 */
import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const DOCS = join(ROOT, "docs");
const REPORT = join(DOCS, "Documentation_Quality_Report.md");

const REFERENCE_FILES = new Set([
  "api-reference.md", "database-schema.md", "event-schema.md",
  "action-receipt-spec.md", "sdk-parity-status.md", "Implementation_Status.md",
  "current-vs-roadmap.md", "feature_history.md", "Documentation_Audit.md",
  "Documentation_Index.md", "Documentation_Quality_Report.md",
  "Product_Requirements_Traceability.md",
]);

const LANDING_FILES = new Set([
  "index.md", "START_HERE.md", "The_One_Minute_Tour.md",
  "What_Is_AegisAgent.md", "Why_AegisAgent.md", "How_It_Works.md",
  "Product_Overview.md", "getting-started.md", "Glossary.md", "faq.md",
]);

function walk(dir) {
  const result = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === "archive") continue;
      result.push(...walk(path));
    } else if (entry.name.endsWith(".md")) {
      result.push(path);
    }
  }
  return result;
}

function profile(rel) {
  if (rel === "AegisAgent_PRD.md") return "product";
  if (LANDING_FILES.has(rel)) return "landing";
  if (rel.startsWith("components/")) return "component";
  if (rel.startsWith("flows/")) return "flow";
  if (rel.startsWith("runbooks/")) return "runbook";
  if (rel.startsWith("onboarding/")) return "onboarding";
  if (rel.startsWith("adr/")) return "decision";
  if (rel.startsWith("templates/") || rel.startsWith("contributing/")) return "authoring";
  if (REFERENCE_FILES.has(rel)) return "reference";
  return "guide";
}

const checks = {
  title: ["Title", text => /^#\s+\S/m.test(text)],
  overview: ["Overview/context", text => /^##\s+(Overview|Executive summary|Purpose|Context|Start here)\b/im.test(text) || text.split("\n").slice(1, 12).join("\n").trim().length > 120],
  why: ["Why/reason", text => /^##\s+.*(Why|Problem|Rationale|Context)/im.test(text)],
  status: ["Status/scope", text => /\b(Implemented|Partial|Planned|Missing|Status:|Current status|Target design|Roadmap)\b/i.test(text)],
  diagram: ["Diagram", text => /```mermaid|diagrams\/[\w-]+\.mmd|architecture-map\.json/i.test(text)],
  example: ["Runnable/example", text => /```(?:bash|sh|shell|rust|python|typescript|javascript|go|json|yaml|http|proto|text)|^##\s+.*Example/im.test(text)],
  security: ["Security/failure", text => /^##\s+.*(Security|Threat|Failure|Fail-closed|Safety|Risk)/im.test(text)],
  operations: ["Operations", text => /^##\s+.*(Monitoring|Logging|Alerting|Troubleshooting|Rollback|Recovery|Operations|Verification)/im.test(text)],
  references: ["References/links", text => /^##\s+(References|Related docs|Next steps)\b/im.test(text) || (text.match(/\[[^\]]+\]\([^)]+\)/g) ?? []).length >= 3],
};

const requirements = {
  product: ["title", "overview", "why", "status", "diagram", "example", "security", "operations", "references"],
  component: ["title", "overview", "why", "status", "diagram", "example", "security", "operations", "references"],
  flow: ["title", "overview", "status", "diagram", "example", "security", "references"],
  runbook: ["title", "overview", "status", "example", "security", "operations", "references"],
  onboarding: ["title", "overview", "example", "security", "operations", "references"],
  decision: ["title", "overview", "why", "status", "security", "references"],
  reference: ["title", "overview", "status", "example", "references"],
  authoring: ["title", "overview", "why", "example", "references"],
  guide: ["title", "overview", "why", "status", "diagram", "example", "security", "operations", "references"],
  landing: ["title", "overview", "why", "status", "diagram", "example", "references"],
};

const pages = walk(DOCS)
  .filter(path => path !== REPORT)
  .map(path => {
    const rel = relative(DOCS, path);
    const text = readFileSync(path, "utf8");
    const kind = profile(rel);
    const required = requirements[kind];
    const passed = required.filter(key => checks[key][1](text));
    const missing = required.filter(key => !passed.includes(key));
    return {
      rel,
      kind,
      score: Math.round((passed.length / required.length) * 100),
      missing,
      lines: text.split("\n").length,
    };
  })
  .sort((a, b) => a.rel.localeCompare(b.rel));

function grade(score) {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  return "D";
}

const byProfile = [...new Set(pages.map(page => page.kind))].sort().map(kind => {
  const group = pages.filter(page => page.kind === kind);
  return {
    kind,
    count: group.length,
    average: Math.round(group.reduce((sum, page) => sum + page.score, 0) / group.length),
    below: group.filter(page => page.score < 75).length,
  };
});

const backlog = pages
  .filter(page => page.score < 75 && page.rel !== "Documentation_Quality_Report.md")
  .sort((a, b) => a.score - b.score || a.rel.localeCompare(b.rel));

const out = [];
out.push("# Documentation Quality Report", "");
out.push("> **Generated:** `node scripts/audit-doc-quality.mjs --write`  ");
out.push("> **Scope:** active Markdown under `docs/`; `docs/archive/` excluded  ");
out.push("> **Meaning:** structural teaching coverage, not factual correctness or implementation status", "");
out.push("This inventory makes the all-documentation improvement program measurable. Each page is scored against its own profile: a runbook is not penalized for lacking a class diagram, and a generated reference is not treated like a tutorial.", "");
out.push("## Summary", "");
out.push("| Profile | Pages | Average | Below 75 |", "|---|---:|---:|---:|");
for (const row of byProfile) out.push(`| ${row.kind} | ${row.count} | ${row.average}% | ${row.below} |`);
out.push("");
out.push(`**Total:** ${pages.length} active Markdown pages · **Migration backlog:** ${backlog.length} pages below 75%.`, "");
out.push("## Scoring signals", "");
out.push("The audit looks for: title, contextual overview, why/problem framing, implementation status or scope, relevant diagrams, runnable examples, security/failure treatment, operations/recovery treatment, and references. Required signals vary by profile.", "");
out.push("A = 90–100 · B = 75–89 · C = 60–74 · D = below 60.", "");
out.push("## Priority migration backlog", "");
out.push("Pages are sorted by structural coverage, then path. Improve factual accuracy and current-vs-roadmap honesty before adding visual polish.", "");
out.push("| Page | Profile | Score | Missing signals |", "|---|---|---:|---|");
for (const page of backlog) {
  const missing = page.missing.map(key => checks[key][0]).join(", ");
  out.push(`| [${page.rel}](${page.rel}) | ${page.kind} | ${grade(page.score)} · ${page.score}% | ${missing} |`);
}
if (backlog.length === 0) out.push("| — | — | — | No pages below threshold |" );
out.push("");
out.push("## Complete inventory", "");
out.push("| Page | Profile | Lines | Grade | Score |", "|---|---|---:|:---:|---:|");
for (const page of pages) {
  out.push(`| [${page.rel}](${page.rel}) | ${page.kind} | ${page.lines} | ${grade(page.score)} | ${page.score}% |`);
}
out.push("");
out.push("## Migration rules", "");
out.push("1. Verify claims against code and `Implementation_Status.md` before rewriting.");
out.push("2. Start with high-trust entry points, security guarantees, deployment, and runbooks.");
out.push("3. Use the appropriate profile; do not add irrelevant empty sections.");
out.push("4. Add or update diagrams only when they improve understanding; explain each diagram.");
out.push("5. Run the docs validator and strict MkDocs build after each batch.", "");
out.push("## References", "");
out.push("- [Documentation Standard](contributing/documentation-standard.md)");
out.push("- [Component Page Template](templates/component-page.md)");
out.push("- [Documentation Audit](Documentation_Audit.md)");
out.push("- [Implementation Status](Implementation_Status.md)");
out.push("");

const rendered = `${out.join("\n").replace(/\n+$/, "")}\n`;
const mode = process.argv[2];
if (mode === "--write") {
  writeFileSync(REPORT, rendered);
  process.stdout.write(`updated ${relative(ROOT, REPORT)}\n`);
} else if (mode === "--check") {
  if (!existsSync(REPORT) || readFileSync(REPORT, "utf8") !== rendered) {
    process.stderr.write("docs/Documentation_Quality_Report.md is stale; run node scripts/audit-doc-quality.mjs --write\n");
    process.exitCode = 1;
  } else {
    process.stdout.write("documentation quality report is current\n");
  }
} else {
  process.stdout.write(rendered);
}
