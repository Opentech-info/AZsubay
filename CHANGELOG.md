# Changelog

All notable changes to AZsubay will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2025-01-28

### Added
- **Initial Release**: First public version of the `azsubay` SDK.
- **Payments Module**: 
  - Basic payment processing (`send_payment`)
  - STK Push functionality (`stk_push`)
  - B2C payouts (`b2c_payout`)
  - OAuth token management
  - Webhook verification with HMAC signatures
  - Phone number and amount validation
  - Error handling and logging

- **KYC Module**:
  - Identity verification with multiple providers (SmileID, Veriff, Jumio)
  - Document submission functionality
  - Verification status checking
  - Support for multiple document types
  - Provider configuration management
  - Legacy function compatibility

- **USSD Module**:
  - Session management and lifecycle
  - Menu navigation and interaction
  - Input handling and validation
  - Payment flows through USSD
  - Session expiration and cleanup
  - Multi-language support (English, Swahili)

- **Utils Module**:
  - HMAC signature generation and verification
  - AES data encryption and decryption
  - Multiple hash algorithms support
  - Cryptographically secure token generation
  - Phone number validation
  - Currency and amount formatting
  - Cryptographic error handling

- **Package Structure**:
  - Professional big-brand package structure
  - Django-style imports: `from azsubay import pay, kyc, ussd, utils`
  - Module-specific imports: `from azsubay.pay import send_payment`
  - Direct function imports: `from azsubay.pay.payments import send_payment`
  - Comprehensive __all__ definitions
  - Package-level constants and configuration

- **Testing**:
  - Comprehensive test suite for all modules
  - Unit tests with pytest
  - Mock implementations for API calls
  - Test coverage reporting
  - Integration tests for import patterns

- **Documentation**:
  - Complete README with usage examples
  - API documentation for all functions
  - Configuration guide
  - Installation instructions
  - Contributing guidelines

- **Development Tools**:
  - CLI interface (`azsubay` command)
  - Code formatting with Black
  - Import sorting with isort
  - Type checking with mypy
  - Linting with flake8
  - CI/CD pipeline with GitHub Actions
  - Automated testing and deployment

- **Configuration**:
  - Environment variable support
  - Provider configuration management
  - Secure credential handling
  - Default fallback values
  - Configuration validation

### Security
- Secure cryptographic operations
- HMAC signature verification
- AES-256-GCM encryption
- Secure token generation
- Input validation and sanitization
- Error handling without information leakage

### Dependencies
- Python 3.9+ support
- FastAPI for modern async support
- Requests for HTTP operations
- Pydantic for data validation
- Cryptography for secure operations

### Known Limitations
- Mock API implementations (requires real endpoint configuration)
- Limited to East African phone number formats
- Maximum transaction amount limit of 500,000
- Session timeout of 5 minutes for USSD
- File size limit of 10MB for document uploads

## [0.0.1] - 2025-01-28

### Added
- Initial project setup
- Basic package structure
- Core module implementations
- Placeholder functions and classes
