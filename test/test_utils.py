"""
Tests for AZsubay Utils Module
"""

import os

import pytest
import base64
import azsubay.utils.crypto
from azsubay.utils import (
    generate_signature,
    verify_signature,
    encrypt_data,
    decrypt_data,
    EncryptionError,
    SignatureError,
    CryptoError,
    ValidationError,
)


def test_generate_signature():
    """Test HMAC signature generation."""
    data = "test data"
    secret_key = "secret_key"

    signature = generate_signature(data, secret_key)

    assert isinstance(signature, str)
    assert len(signature) == 64  # SHA256 produces 64 character hex string
    assert signature.isalnum()


def test_generate_signature_with_dict():
    """Test signature generation with dictionary data."""
    data = {"key": "value", "number": 123}
    secret_key = "secret_key"

    signature = generate_signature(data, secret_key)

    assert isinstance(signature, str)
    assert len(signature) == 64


def test_verify_signature():
    """Test signature verification."""
    data = "test data"
    secret_key = "secret_key"

    signature = generate_signature(data, secret_key)
    is_valid = verify_signature(data, signature, secret_key)

    assert is_valid is True


def test_verify_signature_invalid():
    """Test signature verification with invalid signature."""
    data = "test data"
    secret_key = "secret_key"
    wrong_signature = "wrong_signature"

    is_valid = verify_signature(data, wrong_signature, secret_key)

    assert is_valid is False


def test_different_algorithms():
    """Test signature generation with different algorithms."""
    data = "test data"
    secret_key = "secret_key"

    sha256_sig = generate_signature(data, secret_key, "sha256")
    sha512_sig = generate_signature(data, secret_key, "sha512")

    assert len(sha256_sig) == 64
    assert len(sha512_sig) == 128
    assert sha256_sig != sha512_sig


def test_generate_signature_missing_secret_key():
    """Test generate_signature with missing secret key."""
    data = "test data"
    with pytest.raises(SignatureError, match="Secret key is required"):
        generate_signature(data, "")


def test_generate_signature_unsupported_data_type():
    """Test generate_signature with unsupported data type."""
    data = 123  # Invalid type
    secret_key = "secret_key"
    with pytest.raises(
        SignatureError, match=r"Unsupported data type for signing: <class 'int'>"
    ):
        generate_signature(data, secret_key)


def test_verify_signature_missing_signature_string():
    """Test verify_signature with missing signature string."""
    data = "test data"
    secret_key = "secret_key"
    with pytest.raises(SignatureError, match=r"Signature string is required"):
        verify_signature(data, "", secret_key)


def test_get_hash_function_unsupported_algorithm():
    """Test _get_hash_function with an unsupported algorithm."""
    with pytest.raises(CryptoError, match=r"Unsupported hash algorithm: invalid_algo"):
        azsubay.utils.crypto._get_hash_function("invalid_algo")


def test_encrypt_decrypt_with_key():
    """Test encryption and decryption with provided key."""
    data = "sensitive data"
    key = b"12345678901234567890123456789012"  # Exactly 32 bytes

    encrypted = encrypt_data(data, key=key)
    decrypted = decrypt_data(
        encrypted["encrypted_data"],
        encrypted["iv"],
        encrypted["tag"],
        key=key,
        salt_b64=encrypted["salt"],
    )

    assert isinstance(encrypted, dict)
    assert "encrypted_data" in encrypted
    assert "iv" in encrypted
    assert "algorithm" in encrypted
    assert decrypted.decode("utf-8") == data


def test_encrypt_decrypt_with_password():
    """Test encryption and decryption with password."""
    data = "sensitive data"
    password = "my_password"

    encrypted = encrypt_data(data, password=password)
    decrypted = decrypt_data(
        encrypted["encrypted_data"],
        encrypted["iv"],
        encrypted["tag"],
        password=password,
        salt_b64=encrypted["salt"],
    )

    assert "salt" in encrypted
    assert decrypted.decode("utf-8") == data


def test_encrypt_data_unsupported_data_type():
    """Test encrypt_data with unsupported data type."""
    with pytest.raises(EncryptionError, match="Unsupported data type for encryption"):
        encrypt_data(123, password="password")


def test_encrypt_data_unsupported_password_type():
    """Test encrypt_data with unsupported password type."""
    with pytest.raises(EncryptionError, match="Unsupported password type"):
        encrypt_data("data", password=123)


def test_decrypt_data_unsupported_password_type():
    """Test decrypt_data with unsupported password type."""
    encrypted = encrypt_data("data", password="password")
    with pytest.raises(EncryptionError, match="Unsupported password type"):
        decrypt_data(
            encrypted["encrypted_data"],
            encrypted["iv"],
            encrypted["tag"],
            password=123,  # Invalid type
            salt_b64=encrypted["salt"],
        )


def test_encrypt_decrypt_auto_key():
    """Test encryption and decryption with auto-generated key."""
    data = "sensitive data"

    # This should fail because password/key is required
    with pytest.raises(
        EncryptionError, match="Either password or key must be provided"
    ):
        encrypt_data(data)

    with pytest.raises(
        EncryptionError, match="Either key or password with salt must be provided"
    ):
        decrypt_data("dummy_data", "dummy_iv", "dummy_tag")


def test_hash_data():
    """Test data hashing."""
    data = "test data"

    from azsubay.utils.crypto import hash_data

    hash_result = hash_data(data)

    assert isinstance(hash_result, str)
    assert len(hash_result) == 64  # SHA256 default
    assert hash_result.isalnum()


def test_hash_data_unsupported_data_type():
    """Test hash_data with unsupported data type."""
    from azsubay.utils.crypto import hash_data

    with pytest.raises(
        CryptoError, match=r"Unsupported data type for hashing: <class 'int'>"
    ):
        hash_data(123)


def test_hash_data_general_exception(monkeypatch):
    """Test hash_data for general exceptions."""

    def mock_get_hash_function(*args, **kwargs):
        raise Exception("Simulated general error")

    monkeypatch.setattr(
        "azsubay.utils.crypto._get_hash_function", mock_get_hash_function
    )
    from azsubay.utils.crypto import hash_data

    with pytest.raises(
        CryptoError, match="Hash generation failed: Simulated general error"
    ):
        hash_data("test data")


def test_hash_data_with_salt():
    """Test hash_data with a salt."""
    from azsubay.utils.crypto import hash_data

    assert hash_data("data", salt="salt") != hash_data("data")


def test_hash_data_different_algorithms():
    """Test hashing with different algorithms."""
    data = "test data"

    from azsubay.utils.crypto import hash_data

    sha256_hash = hash_data(data, "sha256")
    sha512_hash = hash_data(data, "sha512")
    md5_hash = hash_data(data, "md5")

    assert len(sha256_hash) == 64
    assert len(sha512_hash) == 128
    assert len(md5_hash) == 32
    assert sha256_hash != sha512_hash
    assert sha256_hash != md5_hash


def test_generate_secure_token():
    """Test secure token generation."""
    from azsubay.utils.crypto import generate_secure_token

    token = generate_secure_token()

    assert isinstance(token, str)
    assert len(token) == 64  # 32 bytes * 2 (hex)
    assert token.isalnum()


def test_generate_secure_token_custom_length():
    """Test secure token generation with custom length."""
    from azsubay.utils.crypto import generate_secure_token

    token = generate_secure_token(16)

    assert isinstance(token, str)
    assert len(token) == 32  # 16 bytes * 2 (hex)


def test_generate_secure_token_invalid_length():
    """Test generate_secure_token with invalid length."""
    from azsubay.utils.crypto import generate_secure_token

    with pytest.raises(CryptoError, match="Token length must be positive"):
        generate_secure_token(0)


def test_generate_secure_token_general_exception(monkeypatch):
    """Test generate_secure_token for general exceptions."""

    def mock_token_hex(*args, **kwargs):
        raise Exception("Simulated general error")

    monkeypatch.setattr("secrets.token_hex", mock_token_hex)
    from azsubay.utils.crypto import generate_secure_token

    with pytest.raises(
        CryptoError, match="Token generation failed: Simulated general error"
    ):
        generate_secure_token(10)


def test_validate_phone_number():
    """Test phone number validation."""
    from azsubay.utils.crypto import validate_phone_number

    # Valid phone numbers
    assert validate_phone_number("0712345678")
    assert validate_phone_number("+254712345678")
    assert validate_phone_number("254712345678")  # Handled by adding '+'
    assert validate_phone_number("0112345678")
    assert validate_phone_number("+256771234567")  # Uganda
    assert validate_phone_number("+255712345678")  # Tanzania
    assert validate_phone_number("+2348012345678")  # Nigeria
    assert validate_phone_number("+233241234567")  # Ghana

    # Invalid phone numbers
    with pytest.raises(
        ValidationError, match="Phone number must be a non-empty string."
    ):
        validate_phone_number("")
    with pytest.raises(
        ValidationError, match="Phone number must be a non-empty string."
    ):
        validate_phone_number(None)
    with pytest.raises(ValidationError, match="Invalid phone number format"):
        validate_phone_number("123")  # Too short, no country code
    with pytest.raises(ValidationError, match="Unsupported country code"):
        validate_phone_number("+12345678901")  # US country code
    with pytest.raises(
        ValidationError, match="Phone number contains non-digit characters"
    ):
        validate_phone_number("+254712abc456")


def test_format_amount():
    """Test amount formatting."""
    from azsubay.utils.crypto import ValidationError
    from azsubay.utils.crypto import format_amount

    # Test with different amount types
    assert format_amount(1000) == "KES 1,000.00"
    assert format_amount(1000.5) == "KES 1,000.50"
    assert format_amount("1000") == "KES 1,000.00"
    assert format_amount("1000.5") == "KES 1,000.50"

    # Test with different currencies
    assert format_amount(1000, "USD") == "USD 1,000.00"  # Changed from $ to USD
    assert format_amount(1000, "EUR") == "EUR 1,000.00"

    # Test invalid amounts
    with pytest.raises(ValidationError):
        format_amount("invalid")
    with pytest.raises(ValidationError):
        format_amount(None)  # type: ignore
    with pytest.raises(ValidationError, match="Unsupported amount type"):
        format_amount([100])  # type: ignore
    with pytest.raises(ValidationError, match="Unsupported currency"):
        format_amount(100, "XYZ")


def test_format_amount_different_locales():
    """Test amount formatting with different locales."""
    from azsubay.utils.crypto import format_amount

    assert format_amount(1000, "KES", "en_KE") == "KES 1,000.00"
    assert format_amount(1000, "USD", "en_US") == "USD 1,000.00"
    assert format_amount(1000, "EUR", "en_GB") == "EUR 1,000.00"
    assert format_amount(1000, "KES", "fr_FR") == "1,000.00 KES"  # Fallback


def test_format_amount_general_exception(monkeypatch):
    """Test format_amount for general exceptions."""
    from azsubay.utils.crypto import format_amount

    def mock_float(*args, **kwargs):
        raise Exception("Simulated general error")

    monkeypatch.setattr("builtins.float", mock_float)
    with pytest.raises(
        ValidationError, match="Amount formatting failed: Simulated general error"
    ):
        format_amount(100)


def test_generate_api_key():
    """Test generate_api_key function."""
    from azsubay.utils.crypto import generate_api_key

    key = generate_api_key()
    assert key.startswith("azsk_")
    assert len(key) == 5 + (16 * 2)  # "azsk_" is 5 chars


def test_generate_webhook_secret():
    """Test generate_webhook_secret function."""
    from azsubay.utils.crypto import generate_webhook_secret

    secret = generate_webhook_secret()
    assert secret.startswith("whsec_")
    assert len(secret) == 6 + (24 * 2)  # prefix + 24 bytes hex


def test_validate_email():
    """Test validate_email function."""
    from azsubay.utils.crypto import validate_email

    assert validate_email("test@example.com")
    assert not validate_email("invalid-email")
    assert not validate_email(None)  # type: ignore


def test_sanitize_input():
    """Test sanitize_input function."""
    from azsubay.utils.crypto import sanitize_input

    assert sanitize_input("<script>alert('xss')</script>") == "scriptalert(xss)/script"
    assert sanitize_input("normal text") == "normal text"
    assert sanitize_input("a" * 1001) == "a" * 1000


def test_generate_key_pair():
    """Test generate_key_pair function."""
    from azsubay.utils.crypto import generate_key_pair

    key_pair = generate_key_pair()
    assert "private_key" in key_pair
    assert "public_key" in key_pair
    assert len(key_pair["private_key"]) == 32 * 2
    assert len(key_pair["public_key"]) == 32 * 2


def test_import_structure():
    """Test that all expected functions can be imported."""
    from azsubay.utils.crypto import (
        generate_signature,
        verify_signature,
        generate_key_pair,
        encrypt_data,
        decrypt_data,
        hash_data,
        generate_secure_token,
        validate_phone_number,
        format_amount,
    )

    # Test that functions are callable
    assert callable(generate_signature)
    assert callable(verify_signature)
    assert callable(generate_key_pair)
    assert callable(encrypt_data)
    assert callable(decrypt_data)
    assert callable(hash_data)
    assert callable(generate_secure_token)
    assert callable(validate_phone_number)
    assert callable(format_amount)


def test_utils_init_module_functions():
    """Test functions exposed directly in azsubay.utils.__init__."""
    from azsubay.utils import (
        get_supported_currencies,
        get_default_hash_algorithm,
        get_supported_hash_algorithms,
        get_crypto_config,
    )

    currencies = get_supported_currencies()
    assert "KES" in currencies
    assert "USD" in currencies

    default_hash = get_default_hash_algorithm()
    assert default_hash == "sha256"

    supported_hashes = get_supported_hash_algorithms()
    assert "sha256" in supported_hashes
    assert "md5" in supported_hashes

    crypto_config = get_crypto_config()
    assert crypto_config["token_length"] == 32
