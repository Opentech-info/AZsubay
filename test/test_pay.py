"""
Tests for AZsubay Pay Module
"""
import os

import pytest
import requests_mock
from azsubay.pay import (
    send_payment,
    stk_push,
    b2c_payout,
    verify_webhook,
    get_oauth_token,
    PaymentError,
    AuthenticationError,
    WebhookError,
)


def test_send_payment(requests_mock):
    """Test the basic send_payment function."""
    # Mock the OAuth and payment endpoints
    requests_mock.get("https://example-telco/oauth/token", json={"access_token": "test_token", "expires_in": 3600})
    requests_mock.post("https://example-telco/b2c", json={"ConversationID": "mock_conv_id", "ResponseCode": "0"})

    result = send_payment("+255700000000", 5000, "INV123")

    assert result["ResponseCode"] == "0"
    assert result["phone"] == "+255700000000"
    assert result["amount"] == 5000
    assert result["reference"] == "INV123"
    assert "ConversationID" in result


def test_send_payment_with_different_values(requests_mock):
    """Test send_payment with different input values."""
    # Mock the OAuth and payment endpoints
    requests_mock.get("https://example-telco/oauth/token", json={"access_token": "test_token", "expires_in": 3600})
    requests_mock.post("https://example-telco/b2c", json={"ConversationID": "mock_conv_id_2", "ResponseCode": "0"})

    result = send_payment("+254712345678", 1000, "TEST456")

    assert result["ResponseCode"] == "0"
    assert result["phone"] == "+254712345678"
    assert result["amount"] == 1000
    assert result["reference"] == "TEST456"
    assert "ConversationID" in result


def test_send_payment_invalid_phone():
    """Test send_payment with an invalid phone number."""
    with pytest.raises(PaymentError, match="Invalid phone number format"):
        send_payment("12345", 100, "REF1")


def test_send_payment_invalid_amount():
    """Test send_payment with an invalid amount."""
    with pytest.raises(PaymentError, match="Amount must be greater than 0"):
        send_payment("+254712345678", -100, "REF2")

    with pytest.raises(PaymentError, match="Amount exceeds maximum limit"):
        send_payment("+254712345678", 600000, "REF3")


def test_stk_push_basic(requests_mock):
    """Test STK push functionality (mock)."""
    # Mock the OAuth and STK push endpoints
    requests_mock.get("https://example-telco/oauth/token", json={"access_token": "test_token"})
    requests_mock.post(
        "https://example-telco/stkpush",
        json={
            "MerchantRequestID": "mock_merchant_id",
            "CheckoutRequestID": "mock_checkout_id",
            "ResponseCode": "0",
        },
    )

    result = stk_push("254712345678", 100, "ORDER123", "Test payment")

    assert result["ResponseCode"] == "0"
    assert "CheckoutRequestID" in result
    assert result["phone"] == "+254712345678"
    assert result["amount"] == 100


def test_stk_push_missing_account_reference():
    """Test STK push with missing account reference."""
    with pytest.raises(PaymentError, match="Account reference is required"):
        stk_push("+254712345678", 100, "", "Test payment")


def test_stk_push_invalid_phone():
    """Test STK push with invalid phone number."""
    with pytest.raises(PaymentError, match="Invalid phone number format"):
        stk_push("12345", 100, "ORDER123")


def test_stk_push_invalid_amount():
    """Test STK push with invalid amount."""
    with pytest.raises(PaymentError, match="Amount must be greater than 0"):
        stk_push("+254712345678", -100, "ORDER123")


def test_stk_push_api_error(requests_mock):
    """Test STK push API error handling."""
    requests_mock.get("https://example-telco/oauth/token", json={"access_token": "test_token"})
    requests_mock.post("https://example-telco/stkpush", status_code=500, json={"message": "Internal Server Error"})

    with pytest.raises(PaymentError, match="API request failed"):
        stk_push("+254712345678", 100, "ORDER123")


def test_stk_push_oauth_error(requests_mock, monkeypatch):
    """Test STK push OAuth error handling."""
    monkeypatch.setenv("TELCO_CONSUMER_KEY", "test_key")
    monkeypatch.setenv("TELCO_CONSUMER_SECRET", "test_secret")
    requests_mock.get("https://example-telco/oauth/token", status_code=401, json={"message": "Unauthorized"})

    with pytest.raises(AuthenticationError, match="Failed to get OAuth token"):
        stk_push("+254712345678", 100, "ORDER123")


def test_b2c_payout_invalid_phone():
    """Test B2C payout with invalid phone number."""
    with pytest.raises(PaymentError, match="Invalid phone number format"):
        b2c_payout("12345", 500, "Refund")


def test_b2c_payout_basic(requests_mock):
    """Test B2C payout functionality (mock)."""
    # Mock the OAuth and B2C endpoints
    requests_mock.get("https://example-telco/oauth/token", json={"access_token": "test_token"})
    requests_mock.post(
        "https://example-telco/b2c",
        json={
            "ConversationID": "mock_conv_id",
            "OriginatorConversationID": "mock_orig_conv_id",
            "ResponseCode": "0",
        },
    )

    result = b2c_payout("254712345678", 500, "Test refund")

    assert result["ResponseCode"] == "0"
    assert "ConversationID" in result
    assert result["phone"] == "+254712345678"
    assert result["amount"] == 500


def test_b2c_payout_invalid_amount():
    """Test B2C payout with invalid amount."""
    with pytest.raises(PaymentError, match="Amount must be greater than 0"):
        b2c_payout("+254712345678", -500, "Refund")


def test_b2c_payout_api_error(requests_mock):
    """Test B2C payout API error handling."""
    requests_mock.get("https://example-telco/oauth/token", json={"access_token": "test_token"})
    requests_mock.post("https://example-telco/b2c", status_code=500, json={"message": "Internal Server Error"})

    with pytest.raises(PaymentError, match="API request failed: 500 Server Error"):
        b2c_payout("+254712345678", 500, "Refund")


def test_b2c_payout_oauth_error(requests_mock, monkeypatch):
    """Test B2C payout OAuth error handling."""
    monkeypatch.setenv("TELCO_CONSUMER_KEY", "test_key")
    monkeypatch.setenv("TELCO_CONSUMER_SECRET", "test_secret")
    requests_mock.get("https://example-telco/oauth/token", status_code=401, json={"message": "Unauthorized"})

    with pytest.raises(AuthenticationError, match="Failed to get OAuth token"):
        b2c_payout("+254712345678", 500, "Refund")


def test_verify_webhook_valid_signature():
    """Test valid webhook signature verification."""
    payload = b'{"event": "payment_success", "amount": 100}'
    secret = "test_webhook_secret"
    # Generated using hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    signature = "f4931a5472e3a1712a1f1141724072346914c622544253308331163428251234"

    assert verify_webhook(payload, signature, secret=secret) is True


def test_verify_webhook_invalid_signature():
    """Test invalid webhook signature verification."""
    payload = b'{"event": "payment_success", "amount": 100}'
    secret = "test_webhook_secret"
    invalid_signature = "invalid_signature_string"

    assert verify_webhook(payload, invalid_signature, secret) is False


def test_verify_webhook_missing_secret():
    """Test webhook verification with missing secret."""
    payload = b'{"event": "payment_success", "amount": 100}'
    signature = "some_signature"

    with pytest.raises(WebhookError, match="Webhook secret not configured"):
        verify_webhook(payload, signature, secret="")


def test_verify_webhook_different_payload():
    """Test webhook verification with different payload."""
    payload = b'{"event": "payment_success", "amount": 100}'
    secret = "test_webhook_secret"
    signature = "f4931a5472e3a1712a1f1141724072346914c622544253308331163428251234"
    different_payload = b'{"event": "payment_failure", "amount": 100}'

    assert verify_webhook(different_payload, signature, secret) is False


def test_get_oauth_token_no_credentials(caplog):
    """Test get_oauth_token when no credentials are set."""
    import os
    os.environ['TELCO_CONSUMER_KEY'] = ''
    os.environ['TELCO_CONSUMER_SECRET'] = ''
    token = get_oauth_token()
    assert token.startswith("mock_oauth_token_")
    assert "OAuth credentials not configured, using mock token" in caplog.text

def test_import_structure():
    """Test that all expected functions can be imported."""
    from azsubay.pay.payments import send_payment, stk_push, b2c_payout, verify_webhook

    # Test that functions are callable
    assert callable(send_payment)
    assert callable(stk_push)
    assert callable(b2c_payout)
    assert callable(verify_webhook)


def test_pay_init_module_functions():
    """Test functions exposed directly in azsubay.pay.__init__."""
    from azsubay.pay import get_supported_telcos, get_payment_limits, get_payment_status_codes

    telcos = get_supported_telcos()
    assert isinstance(telcos, list)
    assert 'MPesa' in telcos

    limits = get_payment_limits()
    assert isinstance(limits, dict)
    assert 'min_amount' in limits

    status_codes = get_payment_status_codes()
    assert isinstance(status_codes, dict)
    assert 'SUCCESS' in status_codes


def test_legacy_payment_functions(requests_mock):
    """Test backward compatibility with legacy payment function names."""
    from azsubay.pay.payments import make_payment, initiate_stk_push, process_b2c_payout

    # Mock endpoints
    requests_mock.get("https://example-telco/oauth/token", json={"access_token": "test_token"})
    requests_mock.post("https://example-telco/b2c", json={"ResponseCode": "0"})
    requests_mock.post("https://example-telco/stkpush", json={"ResponseCode": "0"})

    # Test legacy functions
    assert "ResponseCode" in make_payment("+254712345678", 100, "LEGACY1")
    assert "ResponseCode" in initiate_stk_push("+254712345678", 100, "LEGACY2")
    assert "ResponseCode" in process_b2c_payout("+254712345678", 100)
