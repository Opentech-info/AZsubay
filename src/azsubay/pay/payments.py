"""
AZsubay Payments Implementation

Core payment functionality for mobile money operations including:
- Basic payment processing (send_payment)
- STK Push for customer-initiated payments  
- B2C payouts for business-to-customer transfers
- OAuth token management
- Webhook verification with HMAC signatures
"""

import os
import json
import time
import hmac
import hashlib
import base64
import logging
from typing import Dict, Any, Optional, Union
from datetime import datetime, timedelta
import requests
from azsubay.utils.crypto import generate_signature as generate_hmac_signature

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PaymentError(Exception):
    """Base exception for payment-related errors."""
    pass


class WebhookError(Exception):
    """Exception for webhook-related errors."""
    pass


class AuthenticationError(Exception):
    """Exception for authentication-related errors."""
    pass


def get_config() -> Dict[str, str]:
    """Get payment configuration from environment variables."""
    return {
        'consumer_key': os.getenv('TELCO_CONSUMER_KEY', ''),
        'consumer_secret': os.getenv('TELCO_CONSUMER_SECRET', ''),
        'oauth_url': os.getenv('TELCO_OAUTH_URL', 'https://example-telco/oauth/token'),
        'stk_push_url': os.getenv('TELCO_STK_PUSH_URL', 'https://example-telco/stkpush'),
        'b2c_url': os.getenv('TELCO_B2C_URL', 'https://example-telco/b2c'),
        'webhook_secret': os.getenv('WEBHOOK_SHARED_SECRET', ''),
        'timeout': int(os.getenv('REQUEST_TIMEOUT', '30'))
    }


def _validate_phone_number(phone: str) -> str:
    """Validate and format phone number."""
    if not phone:
        raise PaymentError("Phone number is required")
    
    # Remove any spaces or special characters
    clean_phone = ''.join(c for c in phone if c.isdigit() or c == '+')
    
    # Ensure it starts with country code
    if clean_phone.startswith('0'):
        clean_phone = '+254' + clean_phone[1:]
    elif clean_phone.startswith('7') or clean_phone.startswith('1'):
        clean_phone = '+254' + clean_phone
    elif not clean_phone.startswith('+'):
        clean_phone = '+' + clean_phone
    
    # Basic validation for East African numbers
    african_country_codes = ['+254', '+255', '+256', '+250']  # Kenya, Tanzania, Uganda, Rwanda
    country_code = clean_phone[:4]
    
    if len(clean_phone) != 13 or country_code not in african_country_codes:
        raise PaymentError(f"Invalid phone number format: {phone}")
    
    return clean_phone


def _validate_amount(amount: Union[int, float, str]) -> float:
    """Validate and convert amount to float."""
    try:
        amount_float = float(amount)
    except (ValueError, TypeError):
        raise PaymentError(f"Invalid amount: {amount}")
    
    if amount_float <= 0:
        raise PaymentError("Amount must be greater than 0")
    
    if amount_float > 500000:  # Max amount limit
        raise PaymentError("Amount exceeds maximum limit of 500,000")
    
    return amount_float


def _get_oauth_token() -> str:
    """Get OAuth access token from telco API."""
    config = get_config()
    
    if not config['consumer_key'] or not config['consumer_secret']:
        logger.warning("OAuth credentials not configured, using mock token (for development/testing)")
        return "mock_oauth_token_" + str(int(time.time()))
    
    try:
        # Combine consumer key and secret
        credentials = f"{config['consumer_key']}:{config['consumer_secret']}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()
        
        headers = {
            'Authorization': f'Basic {encoded_credentials}',
            'Content-Type': 'application/json'
        }
        
        # This makes a real API call to the OAuth endpoint
        response = requests.get(config['oauth_url'], headers=headers, timeout=config['timeout'])
        response.raise_for_status()  # Raises HTTPError for bad status codes (4xx or 5xx)
        
        token_data = response.json()
        
        logger.info("Successfully retrieved OAuth token")
        return token_data['access_token']
        
    except requests.RequestException as e:
        logger.error(f"OAuth token request failed: {e}")
        raise AuthenticationError(f"Failed to get OAuth token: {e}")



def _make_api_request(url: str, data: Dict[str, Any], headers: Dict[str, str], timeout: int) -> Dict[str, Any]:
    """Make HTTP request to telco API."""
    try:
        response = requests.post(url, json=data, headers=headers, timeout=timeout)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"API request failed: {e}")
        raise PaymentError(f"API request failed: {e}")


def send_payment(phone: str, amount: Union[int, float, str], reference: str, description: str = "") -> Dict[str, Any]:
    """
    Send a basic mobile money payment.
    
    This is the core payment function specified in the requirements.
    
    Args:
        phone: Recipient phone number (e.g., "+255700000000")
        amount: Amount to send
        reference: Transaction reference (e.g., "INV123")
        description: Optional payment description
    
    Returns:
        Dict containing payment status and details
    
    Example:
        >>> resp = send_payment("+255700000000", 5000, "INV123")
        >>> print(resp)
        {'status': 'SUCCESS', 'phone': '+255700000000', 'amount': 5000, 'reference': 'INV123'}
    """
    logger.info(f"Processing payment: {phone} - {amount} - {reference}")
    
    try:
        # Validate inputs
        clean_phone = _validate_phone_number(phone)
        clean_amount = _validate_amount(amount)
        
        if not reference:
            raise PaymentError("Transaction reference is required")
        
        # Get OAuth token
        token = _get_oauth_token()
        
        # Prepare payment data
        payment_data = {
            'phone': clean_phone,
            'amount': clean_amount,
            'reference': reference,
            'description': description or f"Payment for {reference}",
            'timestamp': datetime.now().isoformat()
        }
        
        config = get_config()
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        # This makes a real API call to the payment endpoint
        # Note: The URL for send_payment is not defined, assuming 'b2c_url' for now.
        result = _make_api_request(config['b2c_url'], payment_data, headers, config['timeout'])
        
        logger.info(f"Payment successful: {result.get('ConversationID', 'N/A')}")
        
        # Enrich the result with original request data for better context
        result.update({
            'phone': clean_phone,
            'amount': clean_amount,
            'reference': reference
        })
        return result
        
    except (PaymentError, AuthenticationError):
        raise
    except Exception as e:
        logger.error(f"Payment failed: {e}")
        raise PaymentError(f"Payment processing failed: {e}")


def stk_push(msisdn: str, amount: Union[int, float, str], account_reference: str, transaction_desc: str = "") -> Dict[str, Any]:
    """
    Initiate STK Push for customer payment confirmation.
    
    Args:
        msisdn: Customer phone number
        amount: Amount to charge
        account_reference: Account reference for the transaction
        transaction_desc: Description of the transaction
    
    Returns:
        Dict containing STK push response
    
    Example:
        >>> result = stk_push("254712345678", 100, "ORDER123", "Payment for goods")
        >>> print(result)
    """
    logger.info(f"Initiating STK Push: {msisdn} - {amount}")
    
    try:
        # Validate inputs
        clean_phone = _validate_phone_number(msisdn)
        clean_amount = _validate_amount(amount)
        
        if not account_reference:
            raise PaymentError("Account reference is required")
        
        # Get OAuth token
        token = _get_oauth_token()
        
        # Prepare STK push data
        stk_data = {
            'BusinessShortCode': '174379',  # Default shortcode
            'Password': 'mock_password',  # In real implementation, this would be generated
            'Timestamp': datetime.now().strftime('%Y%m%d%H%M%S'),
            'TransactionType': 'CustomerPayBillOnline',
            'Amount': int(clean_amount),
            'PartyA': clean_phone,
            'PartyB': '174379',
            'PhoneNumber': clean_phone,
            'CallBackURL': 'https://your-domain.com/webhook',
            'AccountReference': account_reference,
            'TransactionDesc': transaction_desc or f"Payment for {account_reference}"
        }
        
        config = get_config()
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        # This makes a real API call to the STK Push endpoint
        result = _make_api_request(config['stk_push_url'], stk_data, headers, config['timeout'])
        
        logger.info(f"STK Push initiated: {result.get('CheckoutRequestID', 'N/A')}")
        
        # Enrich the result with original request data
        result.update({
            'phone': clean_phone,
            'amount': clean_amount,
            'account_reference': account_reference
        })
        return result
        
    except (PaymentError, AuthenticationError):
        raise
    except Exception as e:
        logger.error(f"STK Push failed: {e}")
        raise PaymentError(f"STK Push failed: {e}")


def b2c_payout(msisdn: str, amount: Union[int, float, str], remarks: str = "", occasion: str = "") -> Dict[str, Any]:
    """
    Initiate B2C (Business-to-Customer) payout.
    
    Args:
        msisdn: Recipient phone number
        amount: Amount to send
        remarks: Remarks for the transaction
        occasion: Occasion for the transaction
    
    Returns:
        Dict containing B2C payout response
    
    Example:
        >>> result = b2c_payout("254712345678", 50, "Refund")
        >>> print(result)
    """
    logger.info(f"Initiating B2C payout: {msisdn} - {amount}")
    
    try:
        # Validate inputs
        clean_phone = _validate_phone_number(msisdn)
        clean_amount = _validate_amount(amount)
        
        # Get OAuth token
        token = _get_oauth_token()
        
        # Prepare B2C data
        b2c_data = {
            'InitiatorName': 'testapi',
            'SecurityCredential': 'mock_security_credential',
            'CommandID': 'SalaryPayment',
            'Amount': int(clean_amount),
            'PartyA': '600000',  # Business shortcode
            'PartyB': clean_phone,
            'Remarks': remarks or 'B2C payment',
            'QueueTimeOutURL': 'https://your-domain.com/b2c-timeout',
            'ResultURL': 'https://your-domain.com/b2c-result',
            'Occasion': occasion or 'Payment'
        }
        
        config = get_config()
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        # This makes a real API call to the B2C endpoint
        result = _make_api_request(config['b2c_url'], b2c_data, headers, config['timeout'])
        
        logger.info(f"B2C payout initiated: {result.get('ConversationID', 'N/A')}")
        
        # Enrich the result with original request data
        result.update({
            'phone': clean_phone,
            'amount': clean_amount,
            'remarks': remarks
        })
        return result
        
    except (PaymentError, AuthenticationError):
        raise
    except Exception as e:
        logger.error(f"B2C payout failed: {e}")
        raise PaymentError(f"B2C payout failed: {e}")


def verify_webhook(payload: Union[str, bytes], signature: str, secret: Optional[str] = None) -> bool:
    """
    Verify webhook signature using HMAC.
    
    Args:
        payload: Webhook payload (string or bytes)
        signature: Signature from webhook header
        secret: Optional secret key (uses environment variable if not provided)
    
    Returns:
        bool: True if signature is valid, False otherwise
    
    Example:
        >>> is_valid = verify_webhook(payload, signature, "your_secret_key")
        >>> print(f"Signature valid: {is_valid}")
    """
    try:
        # Get secret from parameter or environment
        webhook_secret = secret or os.getenv('WEBHOOK_SHARED_SECRET', '')
        if not webhook_secret:
            raise WebhookError("Webhook secret not configured")
        
        # Convert payload to bytes if it's a string, assuming UTF-8
        if isinstance(payload, str):
            payload = payload.encode('utf-8')
        
        # Use the centralized signature generation for consistency.
        expected_signature = generate_hmac_signature(payload, webhook_secret, 'sha256')
        return hmac.compare_digest(expected_signature, signature) # Ensure constant-time comparison
        
    except Exception as e:
        logger.error(f"Webhook verification failed: {e}")
        raise WebhookError(f"Webhook verification failed: {e}")


def get_oauth_token() -> str:
    """
    Get OAuth access token for API authentication.
    
    Returns:
        str: OAuth access token
    
    Example:
        >>> token = get_oauth_token()
        >>> print(f"Token: {token}")
    """
    return _get_oauth_token()


# Legacy function names for backward compatibility
def make_payment(phone: str, amount: Union[int, float, str], reference: str) -> Dict[str, Any]:
    """Legacy function name for send_payment."""
    return send_payment(phone, amount, reference)


def initiate_stk_push(msisdn: str, amount: Union[int, float, str], account_reference: str) -> Dict[str, Any]:
    """Legacy function name for stk_push."""
    return stk_push(msisdn, amount, account_reference)


def process_b2c_payout(msisdn: str, amount: Union[int, float, str]) -> Dict[str, Any]:
    """Legacy function name for b2c_payout."""
    return b2c_payout(msisdn, amount)


def verify_hmac_signature(payload: Union[str, bytes], signature: str, secret: Optional[str] = None) -> bool:
    """Legacy function name for verify_webhook."""
    return verify_webhook(payload, signature, secret)
