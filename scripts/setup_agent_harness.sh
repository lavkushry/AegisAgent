#!/bin/bash
# AegisAgent Agent Rules Harness Setup Script (ECC-Style)
# Configures modular rules for Cursor, Claude Code, and other developer LLMs.

set -euo pipefail

# Root workspace directory mapping
WORKSPACE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLAUDE_DIR="${WORKSPACE_DIR}/.claude"
CLAUDE_RULES_DIR="${CLAUDE_DIR}/rules"
CLAUDE_PRP_DIR="${CLAUDE_DIR}/PRPs"
SKILLS_DIR="${WORKSPACE_DIR}/skills"
BRAIN_ARTIFACT_DIR="/home/ems/.gemini/antigravity-ide/brain/b28a08d6-7887-4b6e-b2fb-b5fdf99c769d"

print_usage() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -p, --profile <profile>  Install specific persona rules (architect|developer|auditor|ops)"
    echo "  -a, --all                Install all persona rules and skills"
    echo "  -c, --clean              Clean all generated rules and configurations"
    echo "  -h, --help               Show this help message"
}

clean_rules() {
    echo "Cleaning up generated rules under ${CLAUDE_DIR}..."
    if [ -d "${CLAUDE_DIR}" ]; then
        rm -rf "${CLAUDE_DIR}"
        echo "Deleted ${CLAUDE_DIR}."
    fi
    # Revert .cursorrules and .clauderules to generic reference state
    echo "Resetting root .cursorrules and .clauderules..."
    cat << 'EOF' > "${WORKSPACE_DIR}/.cursorrules"
# AegisAgent General Coding Rules
# Run 'bash scripts/setup_agent_harness.sh --profile <type>' to load a specific persona.
# For commands & style conventions, consult CLAUDE.md.
EOF
    cp "${WORKSPACE_DIR}/.cursorrules" "${WORKSPACE_DIR}/.clauderules"
    echo "Cleanup complete."
}

initialize_prp_dirs() {
    echo "Initializing .claude/PRPs folders..."
    mkdir -p "${CLAUDE_PRP_DIR}/prds"
    mkdir -p "${CLAUDE_PRP_DIR}/plans"
    mkdir -p "${CLAUDE_PRP_DIR}/tasks"
    mkdir -p "${CLAUDE_PRP_DIR}/reports"

    # Copy PRD if available
    if [ -f "${WORKSPACE_DIR}/docs/AegisAgent_PRD.md" ]; then
        cp "${WORKSPACE_DIR}/docs/AegisAgent_PRD.md" "${CLAUDE_PRP_DIR}/prds/AegisAgent_PRD.md"
        echo "Copied AegisAgent_PRD.md to .claude/PRPs/prds/"
    fi

    # Copy active brain artifacts into local PRP workspace folders
    if [ -d "${BRAIN_ARTIFACT_DIR}" ]; then
        [ -f "${BRAIN_ARTIFACT_DIR}/implementation_plan.md" ] && cp "${BRAIN_ARTIFACT_DIR}/implementation_plan.md" "${CLAUDE_PRP_DIR}/plans/implementation_plan.md"
        [ -f "${BRAIN_ARTIFACT_DIR}/task.md" ] && cp "${BRAIN_ARTIFACT_DIR}/task.md" "${CLAUDE_PRP_DIR}/tasks/task.md"
        [ -f "${BRAIN_ARTIFACT_DIR}/walkthrough.md" ] && cp "${BRAIN_ARTIFACT_DIR}/walkthrough.md" "${CLAUDE_PRP_DIR}/reports/walkthrough.md"
        echo "Successfully imported active planning artifacts to .claude/PRPs/"
    fi
}

setup_profile() {
    local profile=$1
    echo "Setting up profile: ${profile}..."
    mkdir -p "${CLAUDE_RULES_DIR}"
    initialize_prp_dirs

    case "${profile}" in
        architect)
            # Architect mostly handles high-level docs. No active skills linked.
            cat << 'EOF' > "${CLAUDE_RULES_DIR}/architect.md"
# Persona: ArchitectAgent
# Active Scope: /docs, / (root files)
# Key Tasks: Update PRD/Technical docs, verify schema changes, maintain architecture bounds.
EOF
            echo "Installed architect.md rule."
            ;;
        developer)
            # Developer needs database migrations and SDK testing skills
            cp "${SKILLS_DIR}/database_migration.md" "${CLAUDE_RULES_DIR}/database_migration.md"
            cp "${SKILLS_DIR}/sdk_testing.md" "${CLAUDE_RULES_DIR}/sdk_testing.md"
            cat << 'EOF' > "${CLAUDE_RULES_DIR}/developer.md"
# Persona: DeveloperAgent
# Active Scope: /gateway, /sdk-python, /sdk-typescript, /mcp-gateway-lite, /examples
# Key Tasks: Implement gateway Axum endpoints, configure SQLx queries, test @protect_tool decorator.
# Loaded Skills: database_migration.md, sdk_testing.md
EOF
            echo "Installed developer.md, database_migration.md, and sdk_testing.md rules."
            ;;
        auditor)
            # Auditor needs security scan and cedar policy skills
            cp "${SKILLS_DIR}/security_scan.md" "${CLAUDE_RULES_DIR}/security_scan.md"
            cp "${SKILLS_DIR}/cedar_policy_authoring.md" "${CLAUDE_RULES_DIR}/cedar_policy_authoring.md"
            cat << 'EOF' > "${CLAUDE_RULES_DIR}/auditor.md"
# Persona: SecurityAuditorAgent
# Active Scope: /gateway/src/policy.rs, /gateway/policies.cedar, /policy-templates, /skills
# Key Tasks: Verify SQL query parameterization, audit multi-tenant isolation, write Cedar policies.
# Loaded Skills: security_scan.md, cedar_policy_authoring.md
EOF
            echo "Installed auditor.md, security_scan.md, and cedar_policy_authoring.md rules."
            ;;
        ops)
            cat << 'EOF' > "${CLAUDE_RULES_DIR}/ops.md"
# Persona: OpsAgent
# Active Scope: /helm, /.github, /docker
# Key Tasks: Configure CI pipelines, Helm validation, container security scans.
EOF
            echo "Installed ops.md rule."
            ;;
        *)
            echo "Error: Unknown profile '${profile}'"
            print_usage
            exit 1
            ;;
    esac

    # Invoke python scanner to dynamically compile active rules and settings
    python3 "${WORKSPACE_DIR}/scripts/scan_project_plan.py"
    echo "Profile '${profile}' initialized successfully."
}

setup_all() {
    echo "Setting up all profiles..."
    initialize_prp_dirs
    setup_profile "architect"
    setup_profile "developer"
    setup_profile "auditor"
    setup_profile "ops"
    
    # Run the final scanning suite to ensure rules files capture all configurations
    python3 "${WORKSPACE_DIR}/scripts/scan_project_plan.py"
    echo "All profiles set up."
}

# Parse command line options
if [ $# -eq 0 ]; then
    print_usage
    exit 1
fi

while [ $# -gt 0 ]; do
    case "$1" in
        -p|--profile)
            if [ -z "${2:-}" ]; then
                echo "Error: --profile requires an argument."
                exit 1
            fi
            setup_profile "$2"
            shift 2
            ;;
        -a|--all)
            setup_all
            shift
            ;;
        -c|--clean)
            clean_rules
            shift
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            echo "Error: Unknown option '$1'"
            print_usage
            exit 1
            ;;
    esac
done
