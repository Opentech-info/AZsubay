"""
AZsubay KYC Module

Provides identity verification and document submission functionality including:
- Identity verification with multiple providers (SmileID, Veriff, Jumio)
- Document submission for verification
- Verification status checking
- Legacy function compatibility

Usage:
    from azsubay.kyc import verify_identity, submit_documents, check_status
    from azsubay.kyc.verify import verify_identity, kyc_verify
"""

# Import main functions for easy access
from .verify import (
    verify_identity,
    submit_documents,
    check_status,
    KYCError,
    ProviderError,
    DocumentError,
    VerificationError
)

# Import legacy functions for backward compatibility
from .verify import (
    kyc_verify,
    kyc_submit,
    kyc_status,
    verify_user,
    submit_kyc_documents
)

# Define what's available when using `from azsubay.kyc import *`
__all__ = [
    'verify_identity',
    'submit_documents',
    'check_status',
    'kyc_verify',
    'kyc_submit', 
    'kyc_status',
    'verify_user',
    'submit_kyc_documents',
    'KYCError',
    'ProviderError',
    'DocumentError',
    'VerificationError'
]

# Module-level constants
SUPPORTED_PROVIDERS = ['SmileID', 'Veriff', 'Jumio']
SUPPORTED_DOCUMENT_TYPES = ['passport', 'id_card', 'drivers_license', 'residence_permit']
DEFAULT_PROVIDER = 'SmileID'
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB max file size

# Verification status codes
VERIFICATION_STATUS = {
    'PENDING': 'PENDING',
    'APPROVED': 'APPROVED',
    'REJECTED': 'REJECTED',
    'EXPIRED': 'EXPIRED',
    'REQUIRES_REVIEW': 'REQUIRES_REVIEW'
}

def get_supported_providers():
    """Get list of supported KYC providers."""
    return SUPPORTED_PROVIDERS.copy()

def get_supported_document_types():
    """Get list of supported document types."""
    return SUPPORTED_DOCUMENT_TYPES.copy()

def get_verification_status_codes():
    """Get available verification status codes."""
    return VERIFICATION_STATUS.copy()

def get_provider_config(provider: str) -> dict:
    """Get configuration for a specific provider."""
    provider_configs = {
        'SmileID': {
            'api_url': 'https://api.smileidentity.com/v1',
            'partner_id': 'required_partner_id',
            'requires_api_key': True
        },
        'Veriff': {
            'api_url': 'https://stationapi.veriff.com/v1',
            'api_key': 'required_api_key',
            'requires_api_key': True
        },
        'Jumio': {
            'api_url': 'https://netverify.com/api/v4',
            'api_token': 'required_api_token',
            'api_secret': 'required_api_secret',
            'requires_credentials': True
        }
    }
    
    if provider not in provider_configs:
        raise ValueError(f"Unsupported provider: {provider}")
    
    return provider_configs[provider].copy()
