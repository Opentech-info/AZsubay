"""
AZsubay Utils Module

Provides utility functions for cryptographic operations, data validation, 
and formatting including:
- HMAC signature generation and verification
- AES data encryption and decryption
- Multiple hash algorithms
- Cryptographically secure token generation
- Phone number validation
- Currency and amount formatting

Usage:
    from azsubay.utils import generate_signature, verify_signature, encrypt_data, decrypt_data
    from azsubay.utils.crypto import hash_data, generate_secure_token, validate_phone_number
"""

# Import main functions for easy access
from .crypto import (
    generate_signature,
    verify_signature,
    encrypt_data,
    decrypt_data,
    hash_data,
    generate_secure_token,
    validate_phone_number,
    format_amount,
    CryptoError,
    SignatureError,
    EncryptionError,
    ValidationError
)

# Define what's available when using `from azsubay.utils import *`
__all__ = [
    'generate_signature',
    'verify_signature',
    'encrypt_data',
    'decrypt_data',
    'hash_data',
    'generate_secure_token',
    'validate_phone_number',
    'format_amount',
    'CryptoError',
    'SignatureError',
    'EncryptionError',
    'ValidationError'
]

# Module-level constants
DEFAULT_HASH_ALGORITHM = 'sha256'
DEFAULT_ENCRYPTION_ALGORITHM = 'aes-256-gcm'
SIGNATURE_ALGORITHM = 'sha256'
TOKEN_LENGTH = 32
SUPPORTED_CURRENCIES = ['KES', 'USD', 'EUR', 'GBP', 'UGX', 'TZS', 'RWF', 'BIF', 'ZMW', 'MWK']

# Cryptographic constants
PBKDF2_ITERATIONS = 100000
SALT_LENGTH = 32
IV_LENGTH = 16
TAG_LENGTH = 16

def get_supported_currencies():
    """Get list of supported currencies."""
    return SUPPORTED_CURRENCIES.copy()

def get_default_hash_algorithm():
    """Get default hash algorithm."""
    return DEFAULT_HASH_ALGORITHM

def get_supported_hash_algorithms():
    """Get list of supported hash algorithms."""
    return ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']

def get_crypto_config():
    """Get cryptographic configuration."""
    return {
        'default_hash': DEFAULT_HASH_ALGORITHM,
        'default_encryption': DEFAULT_ENCRYPTION_ALGORITHM,
        'signature_algorithm': SIGNATURE_ALGORITHM,
        'token_length': TOKEN_LENGTH,
        'pbkdf2_iterations': PBKDF2_ITERATIONS,
        'salt_length': SALT_LENGTH,
        'iv_length': IV_LENGTH,
        'tag_length': TAG_LENGTH
    }
