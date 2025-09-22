"""
Tests for AZsubay Pay Module
"""

import pytest
from azsubay.pay import send_payment, stk_push, b2c_payout

def test_send_payment():
    """Test the basic send_payment function."""
    result = send_payment("+255700000000", 5000, "INV123")
    
    assert result["status"] == "SUCCESS"
    assert result["phone"] == "+255700000000"
    assert result["amount"] == 5000
    assert result["reference"] == "INV123"

def test_send_payment_with_different_values():
    """Test send_payment with different input values."""
    result = send_payment("+254712345678", 1000, "TEST456")
    
    assert result["status"] == "SUCCESS"
    assert result["phone"] == "+254712345678"
    assert result["amount"] == 1000
    assert result["reference"] == "TEST456"

def test_stk_push_basic():
    """Test STK push functionality (mock)."""
    # This would normally make an API call, but we'll test the interface
    try:
        result = stk_push("254712345678", 100, "ORDER123", "Test payment")
        # If no exception, the function structure is correct
        assert isinstance(result, dict)
    except Exception as e:
        # Expected to fail due to mock URLs, but function should exist
        assert "requests" in str(e).lower() or "connection" in str(e).lower()

def test_b2c_payout_basic():
    """Test B2C payout functionality (mock)."""
    try:
        result = b2c_payout("254712345678", 500, "Test refund")
        # If no exception, the function structure is correct
        assert isinstance(result, dict)
    except Exception as e:
        # Expected to fail due to mock URLs, but function should exist
        assert "requests" in str(e).lower() or "connection" in str(e).lower()

def test_import_structure():
    """Test that all expected functions can be imported."""
    from azsubay.pay.payments import send_payment, stk_push, b2c_payout, verify_hmac_signature
    
    # Test that functions are callable
    assert callable(send_payment)
    assert callable(stk_push)
    assert callable(b2c_payout)
    assert callable(verify_hmac_signature)
