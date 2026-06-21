---
globs:
  - "sdk-python/**/*.py"
---

# AI Skill: Python Coding Standards (`skills/python_standards.md`)

This skill defines the coding style, typing conventions, and test mock guidelines for the Python SDK and example scripts.

---

## 1. Code Style (PEP 8)

All Python code must follow PEP 8 styling rules and use `black` for formatting.

### Guidelines:
- **Indentations:** Use 4 spaces per indentation level.
- **Naming Conventions:**
  - Functions, methods, and variables: `snake_case`.
  - Classes: `PascalCase`.
  - Constants: `UPPERCASE_SNAKE_CASE`.
- **Line Length:** Max 88 characters (Black default).

---

## 2. Type Annotations

To ensure readability and IDE type checking, all public interfaces must use explicit type annotations.

### Guidelines:
- **Function Signatures:** Include type hints for all parameters and return values.
  ```python
  from typing import Dict, Any, Optional

  def authorize_action(
      self, 
      agent_id: str, 
      tool_key: str, 
      action_key: str, 
      context: Optional[Dict[str, Any]] = None
  ) -> Dict[str, Any]:
      ...
  ```

---

## 3. Exception Handling & Security Failures

Never catch generic exceptions silently. Wrap exceptions in specialized AegisAgent errors.

### Guidelines:
- **Custom Exception Classes:** Define explicit subclasses of `Exception` for security denials and connection failures:
  ```python
  class AegisError(Exception):
      """Base exception for AegisAgent SDK"""
      pass

  class AegisAuthorizationDenied(AegisError):
      """Raised when the gateway denies tool execution"""
      pass

  class AegisConnectionError(AegisError):
      """Raised when the SDK cannot reach the security gateway"""
      pass
  ```

---

## 4. Test Mocking Guidelines

Unit tests must run in isolated environments without dependency on a live running gateway.

### Guidelines:
- **Mock Network Layers:** Use `unittest.mock.patch` to mock `requests.post` and `requests.get` calls.
- **Strict Response Assertions:** Assert that the mocked responses return valid JSON schemas, and ensure the SDK handles error status codes (e.g. 401, 500) by raising the appropriate custom exceptions.
- **No Production Secrets:** Never hardcode credentials in tests. Use environment variable placeholders if needed.
