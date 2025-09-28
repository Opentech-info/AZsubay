# Contributing to AZsubay

Thank you for your interest in contributing to AZsubay! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Code Style](#code-style)
- [Submitting Changes](#submitting-changes)
- [Reporting Issues](#reporting-issues)

## Code of Conduct

This project and everyone participating in it is governed by the [AZsubay Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Getting Started

### Prerequisites

- Python 3.9 or higher
- Git
- pip or conda package manager

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/your-username/AZsubay.git
   cd AZsubay
   ```
3. Add the original repository as upstream:
   ```bash
   git remote add upstream https://github.com/Opentech-info/AZsubay.git
   ```

## Development Setup

### Create a Virtual Environment

```bash
# Using venv
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Using conda
conda create -n azsubay python=3.9
conda activate azsubay
```

### Install Dependencies

```bash
# Install in development mode with dev dependencies
pip install -e .[dev]

# Or install test dependencies only
pip install -e .[test]
```

### Verify Installation

```bash
# Test that the package works
python -c "import azsubay; print(azsubay.__version__)"

# Run the CLI
azsubay --version
azsubay test-modules
```

## Making Changes

### Branch Strategy

1. Create a feature branch from `develop`:
   ```bash
   git checkout develop
   git pull upstream develop
   git checkout -b feature/your-feature-name
   ```

2. For bug fixes, create a branch from `main`:
   ```bash
   git checkout main
   git pull upstream main
   git checkout -b fix/your-fix-name
   ```

### Code Structure

Follow the existing package structure:

```
azsubay/
├── __init__.py         # Package-level imports and constants
├── cli.py              # Command line interface
├── pay/                # Payment functionality
│   ├── __init__.py     # Module exports
│   └── payments.py     # Payment implementations
├── kyc/                # KYC functionality
│   ├── __init__.py     # Module exports
│   └── verify.py       # KYC implementations
├── ussd/               # USSD functionality
│   ├── __init__.py     # Module exports
│   └── menu.py         # USSD implementations
└── utils/              # Utility functions
    ├── __init__.py     # Module exports
    └── crypto.py       # Cryptographic utilities
```

### Adding New Features

1. **New Module**: If adding a new module (e.g., `sms`, `analytics`):
   - Create the module directory with `__init__.py`
   - Add implementation files
   - Export main functions in `__init__.py`
   - Update the main `azsubay/__init__.py` to include the new module
   - Add tests in the `test/` directory

2. **New Function**: If adding a new function to existing module:
   - Add the function to the appropriate implementation file
   - Export it in the module's `__init__.py`
   - Add comprehensive tests
   - Update documentation

### Configuration

- Use environment variables for configuration
- Provide sensible defaults
- Validate configuration values
- Don't commit sensitive data

### Error Handling

- Use custom exception classes for each module
- Provide clear error messages
- Log errors appropriately
- Handle exceptions gracefully

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=azsubay --cov-report=html

# Run specific test file
pytest test/test_pay.py

# Run specific test
pytest test/test_pay.py::test_send_payment
```

### Writing Tests

Follow these guidelines for writing tests:

1. **Test Structure**:
   ```python
   def test_function_name():
       # Arrange - set up test data
       # Act - call the function
       # Assert - verify results
   ```

2. **Test Coverage**:
   - Test both success and error cases
   - Test edge cases and boundary conditions
   - Mock external API calls
   - Test all public functions

3. **Test Naming**:
   - Use descriptive test names
   - Follow pattern: `test_[function]_[scenario]_[expected_result]`

### Example Test

```python
def test_send_payment_success():
    """Test successful payment processing."""
    # Arrange
    phone = "+255700000000"
    amount = 5000
    reference = "INV123"
    
    # Act
    result = send_payment(phone, amount, reference)
    
    # Assert
    assert result["status"] == "SUCCESS"
    assert result["phone"] == phone
    assert result["amount"] == amount
    assert result["reference"] == reference
```

## Code Style

### Formatting

We use several tools to maintain code quality:

```bash
# Format code with Black
black azsubay test

# Sort imports with isort
isort azsubay test

# Lint with flake8
flake8 azsubay test

# Type check with mypy
mypy azsubay
```

### Style Guidelines

- **Line Length**: Maximum 88 characters (Black default)
- **Quotes**: Use double quotes for strings
- **Imports**: Group imports: standard library, third-party, local
- **Docstrings**: Use Google-style docstrings
- **Type Hints**: Use type hints for all function signatures

### Example Code Style

```python
"""
Module description.

This module provides functionality for...
"""

from typing import Dict, Any, Optional
import requests


class CustomError(Exception):
    """Custom exception for this module."""
    pass


def function_name(param1: str, param2: Optional[int] = None) -> Dict[str, Any]:
    """
    Function description.
    
    Args:
        param1: Description of param1
        param2: Optional description of param2
    
    Returns:
        Dictionary containing results
    
    Raises:
        CustomError: If something goes wrong
    
    Example:
        >>> result = function_name("test", 42)
        >>> print(result)
    """
    if not param1:
        raise CustomError("param1 is required")
    
    # Function implementation
    return {"status": "success", "data": param1}
```

## Submitting Changes

### Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/) format:

```
type(scope): description

[optional body]

[optional footer(s)]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Test changes
- `chore`: Maintenance tasks

Examples:
```
feat(pay): add support for multiple currencies

fix(kyc): handle invalid document types in verify_identity

docs: update README with installation instructions

test: add comprehensive tests for USSD module
```

### Pull Request Process

1. **Update Your Branch**:
   ```bash
   git fetch upstream
   git rebase upstream/develop  # or upstream/main for fixes
   ```

2. **Push to Your Fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

3. **Create Pull Request**:
   - Go to the GitHub repository
   - Click "New Pull Request"
   - Select your branch and target branch
   - Fill in the PR template
   - Link any related issues

4. **PR Requirements**:
   - Clear title and description
   - Tests pass
   - Code follows style guidelines
   - Documentation updated if needed
   - All CI checks pass

### Review Process

- Maintainers will review your PR
- Address review comments promptly
- Keep PRs focused and small
- Be responsive to feedback

## Reporting Issues

### Bug Reports

When reporting bugs, please include:

1. **Environment**:
   - Python version
   - Operating system
   - AZsubay version

2. **Steps to Reproduce**:
   - Minimal code example
   - Expected behavior
   - Actual behavior

3. **Error Messages**:
   - Full traceback
   - Relevant logs

### Feature Requests

For feature requests, please include:

1. **Problem Statement**: What problem are you trying to solve?
2. **Proposed Solution**: How do you envision the solution?
3. **Use Cases**: How would this feature be used?
4. **Alternatives**: What alternatives have you considered?

## Getting Help

- **Documentation**: Check the [README](README.md) and docstrings
- **Issues**: Search existing issues before creating new ones
- **Discussions**: Use GitHub Discussions for general questions
- **Email**: Contact [AZsubay@protonmail.com](mailto:AZsubay@protonmail.com) for private inquiries

## Release Process

Releases are managed by maintainers following this process:

1. Update version in `pyproject.toml` and `azsubay/__init__.py`
2. Update `CHANGELOG.md`
3. Create release tag
4. Build and publish to PyPI
5. Create GitHub release

Thank you for contributing to AZsubay! 🚀
