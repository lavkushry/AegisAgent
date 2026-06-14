```markdown
# AegisAgent Development Patterns

> Auto-generated skill from repository analysis

## Overview
This skill teaches you the core development patterns, coding conventions, and workflows used in the AegisAgent Rust codebase. You'll learn how to structure files, write and organize code, follow commit message conventions, and set up or run tests as practiced in this repository.

## Coding Conventions

### File Naming
- Use **camelCase** for file names.
  - Example: `agentCore.rs`, `userSession.rs`

### Import Style
- Use **relative imports** for referencing modules within the project.
  - Example:
    ```rust
    mod utils;
    use crate::utils::parseConfig;
    ```

### Export Style
- Use **named exports** to expose specific functions, structs, or modules.
  - Example:
    ```rust
    pub fn initialize_agent() { ... }
    pub struct AgentConfig { ... }
    ```

### Commit Messages
- Follow the **Conventional Commits** format.
- Prefixes used: `fix`, `feat`
- Example:
  ```
  feat: add user authentication middleware
  fix: resolve panic on agent shutdown
  ```

## Workflows

### Creating a New Feature
**Trigger:** When adding a new capability or module.
**Command:** `/new-feature`

1. Create a new file using camelCase (e.g., `sessionManager.rs`).
2. Implement your feature using relative imports for dependencies.
3. Export public functions or structs using named exports.
4. Write or update tests in a corresponding `*.test.*` file.
5. Commit changes with a message starting with `feat:` and a concise description.

### Fixing a Bug
**Trigger:** When resolving a defect or issue.
**Command:** `/fix-bug`

1. Locate the problematic code.
2. Apply the fix, ensuring code style and conventions are followed.
3. Update or add tests in the appropriate `*.test.*` file.
4. Commit with a message starting with `fix:` and a clear summary.

### Writing and Running Tests
**Trigger:** When validating code correctness.
**Command:** `/run-tests`

1. Create or update test files using the `*.test.*` naming pattern (e.g., `agentCore.test.rs`).
2. Write tests according to Rust's test module conventions.
3. Run tests using the standard Rust test runner:
   ```
   cargo test
   ```
4. Review output and address any failures.

## Testing Patterns

- Test files follow the `*.test.*` naming convention (e.g., `module.test.rs`).
- Testing framework is not explicitly defined; use Rust's built-in test framework.
- Example test structure:
  ```rust
  #[cfg(test)]
  mod tests {
      use super::*;

      #[test]
      fn test_agent_initialization() {
          // Test logic here
      }
  }
  ```

## Commands
| Command        | Purpose                                   |
|----------------|-------------------------------------------|
| /new-feature   | Start a new feature implementation        |
| /fix-bug       | Begin work on a bug fix                   |
| /run-tests     | Run all tests in the codebase             |
```
