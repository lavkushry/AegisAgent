#!/usr/bin/env python3
# AegisAgent Project Plan & PRD Scanner
# Extracts tech stacks, directory structures, and agent configurations to populate .claude settings.

import os
import json
import re

WORKSPACE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PRD_PATH = os.path.join(WORKSPACE_DIR, "docs/AegisAgent_PRD.md")
AGENTS_PATH = os.path.join(WORKSPACE_DIR, "AGENTS.md")
PLAN_PATH = os.path.join(WORKSPACE_DIR, ".claude/PRPs/plans/implementation_plan.md")
SETTINGS_PATH = os.path.join(WORKSPACE_DIR, ".claude/settings.json")

def scan_prd_and_plan():
    tech_stack = set()
    directories = set()

    # Keywords to detect tech stack
    stack_keywords = {
        "Rust": ["rust", "cargo", "tokio", "axum"],
        "Python": ["python", "pip", "pytest", "black"],
        "SQLite": ["sqlite", "sqlx"],
        "Cedar Policy": ["cedar", "cedar-policy"],
        "OpenTelemetry": ["opentelemetry", "otel", "otlp"],
        "Docker": ["docker", "dockerfile", "docker compose"],
        "Helm / Kubernetes": ["helm", "kubernetes", "k8s"]
    }

    # Files to scan for tech stack
    files_to_scan = [PRD_PATH, PLAN_PATH]
    for path in files_to_scan:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                content = f.read().lower()
                for stack, words in stack_keywords.items():
                    if any(word in content for word in words):
                        tech_stack.add(stack)

    # Detect directories from project structure block
    dir_pattern = re.compile(r"^\s*/([a-zA-Z0-9_-]+)\s*$", re.MULTILINE)
    for path in files_to_scan:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
                matches = dir_pattern.findall(content)
                for folder in matches:
                    if folder not in ["git", "github", "claude", "skills"]:
                        directories.add(f"/{folder}")

    return sorted(list(tech_stack)), sorted(list(directories))

def scan_agents():
    agents = {}
    if os.path.exists(AGENTS_PATH):
        with open(AGENTS_PATH, "r", encoding="utf-8") as f:
            content = f.read()
        
        # Split into agent blocks (## 1. PersonaName, etc.)
        agent_blocks = re.split(r"##\s+\d+\.\s+", content)[1:]
        for block in agent_blocks:
            lines = block.strip().split("\n")
            name = lines[0].split("(")[0].strip()
            
            # Find directories
            dirs = []
            dir_match = re.search(r"-\s+\*\*Primary Directories:\*\*\s*(.+)", block)
            if dir_match:
                dirs = [d.strip() for d in dir_match.group(1).split(",")]
            
            # Find key responsibilities
            resps = []
            resp_match = re.search(r"-\s+\*\*Key Responsibilities:\*\*(.+?)(?:-\s+\*\*Rules|$)", block, re.DOTALL)
            if resp_match:
                resps = [r.strip().replace("- ", "") for r in resp_match.group(1).strip().split("\n") if r.strip()]

            agents[name] = {
                "directories": dirs,
                "responsibilities": resps
            }
    return agents

def main():
    print("Scanning project plan and PRD documents...")
    tech_stack, directories = scan_prd_and_plan()
    agents = scan_agents()

    print(f"Detected Tech Stack: {', '.join(tech_stack)}")
    print(f"Detected Workspace Directories: {', '.join(directories)}")

    # Update or create .claude/settings.json
    os.makedirs(os.path.dirname(SETTINGS_PATH), exist_ok=True)
    settings = {}
    if os.path.exists(SETTINGS_PATH):
        try:
            with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
                settings = json.load(f)
        except Exception:
            pass

    # Merge configuration metadata
    settings.setdefault("MAX_THINKING_TOKENS", 4096)
    settings.setdefault("CLAUDE_CODE_SUBAGENT_MODEL", "claude-3-5-sonnet")
    settings["project_metadata"] = {
        "name": "AegisAgent",
        "tech_stack": tech_stack,
        "directories": directories,
        "agents": list(agents.keys())
    }

    with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2)
    print("Updated .claude/settings.json successfully.")

    # Generate custom .cursorrules and .clauderules
    cursorrules_path = os.path.join(WORKSPACE_DIR, ".cursorrules")
    clauderules_path = os.path.join(WORKSPACE_DIR, ".clauderules")

    rules_content = f"""# AegisAgent Workspace Rules & Context (Harness Generated)
# Do NOT modify directly. Regenerate using 'bash scripts/setup_agent_harness.sh --all'

## Project Overview
AegisAgent is an Agent Action Firewall securing tools and MCP connections using Rust, SQLite, and Cedar Policy.

## Active Tech Stack
{chr(10).join(f"- {tech}" for tech in tech_stack)}

## Workspace Directory Map
{chr(10).join(f"- {d}" for d in directories)}

## Agent Personas & Boundary Rules
"""
    for name, data in agents.items():
        rules_content += f"""
### {name}
- **Primary Scope:** {", ".join(data['directories'])}
- **Responsibilities:**
{chr(10).join(f"  - {resp}" for resp in data['responsibilities'])}
"""

    rules_content += """
## Core Coding Guardrails (CLAUDE.md)
1. **Multi-Tenant Isolation:** Every SQL operation MUST bind and filter by `tenant_id` to prevent CWE-284 data leakage.
2. **SQL Injection Prevention:** Never construct SQL queries via string formatting or concatenation. Use parameterized bindings exclusively.
3. **Local Bindings:** Listeners must bind strictly to `127.0.0.1` for security testing.
4. **OpenTelemetry:** Instrument all critical database and policy spans.
"""

    with open(cursorrules_path, "w", encoding="utf-8") as f:
        f.write(rules_content)
    with open(clauderules_path, "w", encoding="utf-8") as f:
        f.write(rules_content)

    print("Regenerated .cursorrules and .clauderules successfully.")

if __name__ == "__main__":
    main()
