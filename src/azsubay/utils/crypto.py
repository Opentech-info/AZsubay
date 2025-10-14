"""
AZsubay Cryptographic Utilities Implementation

Core cryptographic functionality including:
- HMAC signature generation and verification
- AES data encryption and decryption
- Multiple hash algorithms
- Cryptographically secure token generation
- Phone number validation
- Currency and amount formatting
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
from typing import Any, Dict, Optional, Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac as crypto_hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CryptoError(Exception):
    """Base exception for cryptographic errors."""

    pass


class SignatureError(CryptoError):
    """Exception for signature-related errors."""

    pass


class EncryptionError(CryptoError):
    """Exception for encryption-related errors."""

    pass


class ValidationError(CryptoError):
    """Exception for validation-related errors."""

    pass


def _normalize_algorithm(algorithm: str) -> str:
    """Normalize hash algorithm name."""
    algorithm_lower = algorithm.lower().replace("-", "")

    algorithm_mapping = {
        "md5": "md5",
        "sha1": "sha1",
        "sha": "sha1",
        "sha224": "sha224",
        "sha256": "sha256",
        "sha384": "sha384",
        "sha512": "sha512",
    }

    return algorithm_mapping.get(algorithm_lower, algorithm_lower)


def _get_hash_function(algorithm: str):
    """Get hash function for algorithm."""
    normalized = _normalize_algorithm(algorithm)

    hash_functions = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha224": hashlib.sha224,
        "sha256": hashlib.sha256,
        "sha384": hashlib.sha384,
        "sha512": hashlib.sha512,
    }

    if normalized not in hash_functions:
        raise CryptoError(f"Unsupported hash algorithm: {algorithm}")

    return hash_functions[normalized]


def generate_signature(
    data: Union[str, bytes, Dict[str, Any]], secret_key: str, algorithm: str = "sha256"
) -> str:
    """
    Generate HMAC signature for data.

    Args:
        data: Data to sign (string, bytes, or dictionary)
        secret_key: Secret key for signing
        algorithm: Hash algorithm to use (default: 'sha256')

    Returns:
        str: Hexadecimal signature string

    Example:
        >>> data = {"transaction_id": "TX123", "amount": 1000}
        >>> signature = generate_signature(data, "your_secret_key")
        >>> print(f"Signature: {signature}")
    """
    logger.info(f"Generating {algorithm} signature")

    try:
        if not secret_key:
            raise SignatureError("Secret key is required")

        # Convert data to bytes
        if isinstance(data, dict):
            # Sort dictionary keys for consistent signature
            data_str = json.dumps(data, sort_keys=True, separators=(",", ":"))
            data_bytes = data_str.encode("utf-8")
        elif isinstance(data, str):
            data_bytes = data.encode("utf-8")
        elif isinstance(data, bytes):
            data_bytes = data
        else:
            raise SignatureError(f"Unsupported data type for signing: {type(data)}")

        # Get hash function
        hash_func = _get_hash_function(algorithm)

        # Generate HMAC signature
        signature = hmac.new(
            secret_key.encode("utf-8"), data_bytes, hash_func
        ).hexdigest()

        logger.info(f"Generated {algorithm} signature: {signature[:16]}...")
        return signature

    except SignatureError:
        raise
    except Exception as e:
        logger.error(f"Signature generation failed: {e}")
        raise SignatureError(f"Signature generation failed: {e}")


def verify_signature(
    data: Union[str, bytes, Dict[str, Any]],
    signature: str,
    secret_key: str,
    algorithm: str = "sha256",
) -> bool:
    """
    Verify HMAC signature for data.

    Args:
        data: Data to verify (string, bytes, or dictionary)
        signature: Signature to verify
        secret_key: Secret key for verification
        algorithm: Hash algorithm used (default: 'sha256')

    Returns:
        bool: True if signature is valid, False otherwise

    Example:
        >>> data = {"transaction_id": "TX123", "amount": 1000}
        >>> is_valid = verify_signature(data, signature, "your_secret_key")
        >>> print(f"Signature valid: {is_valid}")
    """
    logger.info(f"Verifying {algorithm} signature")

    try:
        if not secret_key:
            raise SignatureError("Secret key is required")

        if not signature:
            raise SignatureError("Signature string is required")

        # Generate expected signature
        expected_signature = generate_signature(data, secret_key, algorithm)

        # Compare signatures using constant-time comparison
        is_valid = hmac.compare_digest(expected_signature, signature)

        logger.info(f"Signature verification: {'Valid' if is_valid else 'Invalid'}")
        return is_valid

    except SignatureError:
        raise
    except Exception as e:
        logger.error(f"Signature verification failed: {e}")
        raise SignatureError(f"Signature verification failed: {e}")


def hash_data(
    data: Union[str, bytes], algorithm: str = "sha256", salt: Optional[str] = None
) -> str:
    """
    Generate hash of data using specified algorithm.

    Args:
        data: Data to hash (string or bytes)
        algorithm: Hash algorithm to use (default: 'sha256')
        salt: Optional salt for hashing

    Returns:
        str: Hexadecimal hash string

    Example:
        >>> hash_result = hash_data("sensitive data")
        >>> print(f"Hash: {hash_result}")
    """
    logger.info(f"Generating {algorithm} hash")

    try:
        # Convert data to bytes
        if isinstance(data, str):
            data_bytes = data.encode("utf-8")
        elif isinstance(data, bytes):
            data_bytes = data
        else:
            raise CryptoError(f"Unsupported data type for hashing: {type(data)}")

        # Add salt if provided
        if salt:
            data_bytes += salt.encode("utf-8")

        # Get hash function
        hash_func = _get_hash_function(algorithm)

        # Generate hash
        hash_result = hash_func(data_bytes).hexdigest()

        logger.info(f"Generated {algorithm} hash: {hash_result[:16]}...")
        return hash_result

    except CryptoError:
        raise
    except Exception as e:
        logger.error(f"Hash generation failed: {e}")
        raise CryptoError(f"Hash generation failed: {e}")


def encrypt_data(
    data: Union[str, bytes],
    password: Optional[Union[str, bytes]] = None,
    key: Optional[bytes] = None,
    salt_b64: Optional[str] = None,
) -> Dict[str, str]:
    """
    Encrypt data using AES-256-GCM with password-based key derivation.

    Args:
        data: Data to encrypt (string or bytes)
        password: Password for encryption (if key is not provided)
        key: 32-byte encryption key (if password is not provided)
        salt_b64: Optional base64-encoded salt (generates new if not provided)

    Returns:
        Dict containing encrypted data, IV, salt, and tag

    Example:
        >>> encrypted = encrypt_data("sensitive data", "my_password")
        >>> print(f"Encrypted: {encrypted['encrypted_data']}")
    """
    logger.info("Encrypting data with AES-256-GCM")

    try:
        if not password and not key:
            raise EncryptionError("Either password or key must be provided")

        # Convert data to bytes
        if isinstance(data, str):
            data_bytes = data.encode("utf-8")
        elif isinstance(data, bytes):
            data_bytes = data
        else:
            raise EncryptionError(f"Unsupported data type for encryption: {type(data)}")

        salt = None
        if password:
            # Convert password to bytes if it's a string
            if isinstance(password, str):
                password_bytes = password.encode("utf-8")
            elif isinstance(password, bytes):
                password_bytes = password
            else:
                raise EncryptionError(
                    f"Unsupported password type: {type(password)}. Must be str or bytes."
                )

            # Generate or use provided salt
            if salt_b64:
                salt = base64.b64decode(salt_b64)
            else:
                salt = os.urandom(32)

            # Derive key using PBKDF2
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,  # 256 bits
                salt=salt,
                iterations=100000,
                backend=default_backend(),
            )
            key = kdf.derive(password_bytes)

        # Generate random IV
        iv = os.urandom(16)

        # Encrypt using AES-256-GCM
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        encrypted_data = encryptor.update(data_bytes) + encryptor.finalize()

        # Get authentication tag
        tag = encryptor.tag

        result = {
            "encrypted_data": base64.b64encode(encrypted_data).decode("utf-8"),
            "iv": base64.b64encode(iv).decode("utf-8"),
            "salt": base64.b64encode(salt).decode("utf-8") if salt else "",
            "tag": base64.b64encode(tag).decode("utf-8"),
            "algorithm": "aes-256-gcm",
            "kdf": "pbkdf2-sha256",
        }

        logger.info("Data encrypted successfully")
        return result

    except EncryptionError:
        raise
    except Exception as e:
        logger.error(f"Data encryption failed: {e}")
        raise EncryptionError(f"Data encryption failed: {e}")


def decrypt_data(
    encrypted_data_b64: str,
    iv_b64: str,
    tag_b64: str,
    password: Optional[str] = None,
    key: Optional[bytes] = None,
    salt_b64: Optional[str] = None,
) -> bytes:
    """
    Decrypt data using AES-256-GCM with password-based key derivation.

    Args:
        encrypted_data_b64: Base64-encoded encrypted data
        iv_b64: Base64-encoded initialization vector
        tag_b64: Base64-encoded authentication tag
        password: Password for decryption (if key is not provided)
        key: 32-byte decryption key (if password is not provided)
        salt_b64: Base64-encoded salt (required if using password)

    Returns:
        bytes: Decrypted data

    Example:
        >>> decrypted = decrypt_data(encrypted["encrypted_data"], encrypted["iv"], encrypted["tag"], password="my_password", salt_b64=encrypted["salt"])
        >>> print(f"Decrypted: {decrypted.decode('utf-8')}")
    """
    logger.info("Decrypting data with AES-256-GCM")

    try:
        if not password and not key:
            raise EncryptionError("Either key or password with salt must be provided")

        # Decode base64 components
        encrypted_data = base64.b64decode(encrypted_data_b64)
        iv = base64.b64decode(iv_b64)
        tag = base64.b64decode(tag_b64)

        if password:
            # This check must happen before trying to use the password
            if not isinstance(password, (str, bytes)):
                raise EncryptionError(
                    f"Unsupported password type: {type(password)}. Must be str or bytes."
                )
            if isinstance(password, str):
                password = password.encode("utf-8")

            if not salt_b64:
                raise EncryptionError(
                    "Salt is required when decrypting with a password"
                )
            salt = base64.b64decode(salt_b64)
            # Derive key using PBKDF2
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,  # 256 bits
                salt=salt,
                iterations=100000,
                backend=default_backend(),
            )
            key = kdf.derive(password)

        # Decrypt using AES-256-GCM
        cipher = Cipher(
            algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()
        )
        decryptor = cipher.decryptor()

        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        logger.info("Data decrypted successfully")
        return decrypted_data

    except EncryptionError:
        raise
    except Exception as e:
        logger.error(f"Data decryption failed: {e}")
        raise EncryptionError(f"Data decryption failed: {e}")


def generate_secure_token(length: int = 32) -> str:
    """
    Generate a cryptographically secure random token.

    Args:
        length: Token length in bytes (default: 32)

    Returns:
        str: Hexadecimal token string

    Example:
        >>> token = generate_secure_token()
        >>> print(f"Token: {token}")
    """
    logger.info(f"Generating secure token of length {length}")

    try:
        if length <= 0:
            raise CryptoError("Token length must be positive")

        token = secrets.token_hex(length)

        logger.info(f"Generated secure token: {token[:16]}...")
        return token

    except CryptoError:
        raise
    except Exception as e:
        logger.error(f"Token generation failed: {e}")
        raise CryptoError(f"Token generation failed: {e}")


def validate_phone_number(phone: str) -> bool:
    """
    Validate phone number format for African markets.

    Args:
        phone: Phone number to validate

    Returns:
        bool: True if phone number is valid, False otherwise

    Example:
        >>> is_valid = validate_phone_number("+254712345678")
        >>> print(f"Phone valid: {is_valid}")
    """
    logger.info(f"Validating phone number: {phone}")

    try:
        if not phone or not isinstance(phone, str):
            raise ValidationError("Phone number must be a non-empty string.")

        # Remove any spaces, dashes, or parentheses
        clean_phone = re.sub(r"[\s\-\(\)]", "", phone)

        # Check if it starts with + and contains only digits after that
        if not clean_phone.startswith("+"):
            # Handle local format (e.g., 0712345678)
            if clean_phone.startswith("0"):
                # Convert to international format
                if clean_phone.startswith("07") or clean_phone.startswith("01"):
                    clean_phone = "+254" + clean_phone[1:]
                else:
                    raise ValidationError(f"Invalid local phone number format: {phone}")
            elif clean_phone.isdigit() and len(clean_phone) > 9:
                clean_phone = "+" + clean_phone
            else:
                raise ValidationError(f"Invalid phone number format: {phone}")

        # Remove the + and check if remaining is digits only
        digits_only = clean_phone[1:]
        if not digits_only.isdigit():
            raise ValidationError(
                f"Phone number contains non-digit characters after country code: {phone}"
            )

        # Check length (typical African phone numbers are 12-15 digits with country code)
        if len(digits_only) < 11 or len(digits_only) > 15:
            return False

        # Check for common African country codes
        country_code = digits_only[:3]
        african_country_codes = [
            "254",  # Kenya
            "256",  # Uganda
            "255",  # Tanzania
            "250",  # Rwanda
            "257",  # Burundi
            "260",  # Zambia
            "265",  # Malawi
            "234",  # Nigeria
            "233",  # Ghana
            "225",  # Ivory Coast
            "221",  # Senegal
            "220",  # Gambia
            "237",  # Cameroon
        ]

        if country_code not in african_country_codes:
            raise ValidationError(
                f"Unsupported country code: {country_code} in {phone}"
            )

        return True

    except ValidationError:
        raise
    except Exception as e:
        logger.error(f"Phone validation failed: {e}")
        return False


def format_amount(
    amount: Union[int, float, str], currency: str = "KES", locale: str = "en_KE"
) -> str:
    """
    Format amount with currency and locale-specific formatting.

    Args:
        amount: Amount to format (number or string)
        currency: Currency code (default: 'KES')
        locale: Locale for formatting (default: 'en_KE')

    Returns:
        str: Formatted amount string

    Example:
        >>> formatted = format_amount(1500.50, "KES")
        >>> print(f"Formatted: {formatted}")
    """
    logger.info(f"Formatting amount: {amount} {currency}")

    try:
        # Convert amount to float
        if isinstance(amount, str):
            try:
                amount_float = float(amount.replace(",", ""))
            except ValueError:
                raise ValidationError(f"Invalid amount string format: {amount}")
        elif isinstance(amount, (int, float)):
            amount_float = float(amount)
        else:
            raise ValidationError(f"Unsupported amount type: {type(amount)}")

        # Validate currency
        supported_currencies = [
            "KES",
            "USD",
            "EUR",
            "GBP",
            "UGX",
            "TZS",
            "RWF",
            "BIF",
            "ZMW",
            "MWK",
        ]
        if currency not in supported_currencies:
            raise ValidationError(f"Unsupported currency: {currency}")

        # Format based on currency
        if currency in ["KES", "UGX", "TZS", "RWF", "BIF", "ZMW", "MWK"]:
            # African currencies typically use 2 decimal places
            formatted_amount = f"{amount_float:,.2f}"
        else:
            # International currencies
            formatted_amount = f"{amount_float:,.2f}"

        # Add currency symbol or code
        currency_symbols = {
            "KES": "KES",
            "USD": "USD",
            "EUR": "EUR",
            "GBP": "GBP",
            "UGX": "UGX",
            "TZS": "TZS",
            "RWF": "RWF",
            "BIF": "BIF",
            "ZMW": "ZMW",
            "MWK": "MWK",
        }

        symbol = currency_symbols.get(currency, currency)

        # Format based on locale conventions
        if locale.startswith("en_"):
            # Kenyan format: KES 1,500.50
            result = f"{symbol} {formatted_amount}"
        elif locale.startswith("en_") and currency in ["USD", "EUR", "GBP"]:
            # English format with symbol first: $1,500.50
            result = f"{symbol}{formatted_amount}"
        else:
            # Default format: 1,500.50 KES
            result = f"{formatted_amount} {symbol}"

        logger.info(f"Formatted amount: {result}")
        return result

    except ValidationError:
        raise
    except Exception as e:
        logger.error(f"Amount formatting failed: {e}")
        raise ValidationError(f"Amount formatting failed: {e}")


# Utility functions for common operations
def generate_api_key() -> str:
    """Generate a secure API key."""
    return f"azsk_{generate_secure_token(16)}"


def generate_webhook_secret() -> str:
    """Generate a secure webhook secret."""
    return f"whsec_{generate_secure_token(24)}"


def validate_email(email: str) -> bool:
    """Validate email address format."""
    if not email or not isinstance(email, str):
        return False

    # Basic email validation regex
    email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(email_pattern, email) is not None


def sanitize_input(input_str: str, max_length: int = 1000) -> str:
    """Sanitize user input to prevent injection attacks."""
    if not input_str:
        return ""

    # Remove potentially dangerous characters
    sanitized = re.sub(r'[<>"\'`]', "", input_str)

    # Truncate to max length
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length]

    return sanitized.strip()


def generate_key_pair() -> Dict[str, str]:
    """Generate a cryptographic key pair."""
    private_key = generate_secure_token(32)
    public_key = generate_secure_token(32)
    return {"private_key": private_key, "public_key": public_key}
