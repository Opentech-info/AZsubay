"""
Tests for AZsubay Utils Module
"""

import pytest
import base64
from azsubay.utils import generate_signature, verify_signature, encrypt_data, decrypt_data

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

def test_encrypt_decrypt_with_key():
    """Test encryption and decryption with provided key."""
    data = "sensitive data"
    key = b'12345678901234567890123456789012'  # Exactly 32 bytes
    
    encrypted = encrypt_data(data, key)
    decrypted = decrypt_data(
        encrypted["encrypted_data"],
        encrypted["iv"],
        key
    )
    
    assert isinstance(encrypted, dict)
    assert "encrypted_data" in encrypted
    assert "iv" in encrypted
    assert "algorithm" in encrypted
    assert decrypted.decode('utf-8') == data

def test_encrypt_decrypt_with_password():
    """Test encryption and decryption with password."""
    data = "sensitive data"
    password = "my_password"
    
    encrypted = encrypt_data(data, password=password)
    decrypted = decrypt_data(
        encrypted["encrypted_data"],
        encrypted["iv"],
        password=password,
        salt_b64=encrypted["salt"]
    )
    
    assert "salt" in encrypted
    assert decrypted.decode('utf-8') == data

def test_encrypt_decrypt_auto_key():
    """Test encryption and decryption with auto-generated key."""
    data = "sensitive data"
    
    encrypted = encrypt_data(data)  # Auto-generates key
    
    # This should fail because we don't have the key
    with pytest.raises(ValueError, match="Either key or password with salt must be provided"):
        decrypt_data(
            encrypted["encrypted_data"],
            encrypted["iv"]
        )

def test_hash_data():
    """Test data hashing."""
    data = "test data"
    
    from azsubay.utils.crypto import hash_data
    hash_result = hash_data(data)
    
    assert isinstance(hash_result, str)
    assert len(hash_result) == 64  # SHA256 default
    assert hash_result.isalnum()

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

def test_validate_phone_number():
    """Test phone number validation."""
    from azsubay.utils.crypto import validate_phone_number
    
    # Valid phone numbers
    assert validate_phone_number("0712345678") is True
    assert validate_phone_number("+254712345678") is True
    assert validate_phone_number("254712345678") is True
    assert validate_phone_number("0112345678") is True
    
    # Invalid phone numbers
    assert validate_phone_number("123") is False  # Too short
    assert validate_phone_number("12345678901234567890") is False  # Too long
    assert validate_phone_number("abc123") is False  # Contains letters
    assert validate_phone_number("") is False  # Empty

def test_format_amount():
    """Test amount formatting."""
    from azsubay.utils.crypto import format_amount
    
    # Test with different amount types
    assert format_amount(1000) == "KES 1,000.00"
    assert format_amount(1000.5) == "KES 1,000.50"
    assert format_amount("1000") == "KES 1,000.00"
    assert format_amount("1000.5") == "KES 1,000.50"
    
    # Test with different currencies
    assert format_amount(1000, "USD") == "USD 1,000.00"
    assert format_amount(1000, "EUR") == "EUR 1,000.00"
    
    # Test invalid amounts
    assert format_amount("invalid") == "KES 0.00"
    assert format_amount(None) == "KES 0.00"

def test_import_structure():
    """Test that all expected functions can be imported."""
    from azsubay.utils.crypto import (
        generate_signature, verify_signature, generate_key_pair,
        encrypt_data, decrypt_data, hash_data, generate_secure_token,
        validate_phone_number, format_amount
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
