"""
AZsubay Payments Module

Provides mobile money payment functionality including:
- STK Push for customer-initiated payments
- B2C payouts for business-to-customer transfers
- Basic payment processing
- Webhook verification and OAuth token management

Usage:
    from azsubay.pay import send_payment, stk_push, b2c_payout
    from azsubay.pay.payments import send_payment, verify_webhook
"""

# Import main functions for easy access
from .payments import (
    send_payment,
    stk_push, 
    b2c_payout,
    verify_webhook,
    get_oauth_token,
    PaymentError,
    WebhookError,
    AuthenticationError
)

# Define what's available when using `from azsubay.pay import *`
__all__ = [
    'send_payment',
    'stk_push',
    'b2c_payout', 
    'verify_webhook',
    'get_oauth_token',
    'PaymentError',
    'WebhookError',
    'AuthenticationError'
]

# Module-level constants
SUPPORTED_TELCOS = ['MPesa', 'AirtelMoney', 'TigoPesa', 'MTNMobileMoney']
DEFAULT_CURRENCY = 'KES'
MINIMUM_AMOUNT = 10  # Minimum amount in default currency
MAXIMUM_AMOUNT = 500000  # Maximum amount in default currency

# Payment status codes
PAYMENT_STATUS = {
    'PENDING': 'PENDING',
    'SUCCESS': 'SUCCESS', 
    'FAILED': 'FAILED',
    'TIMEOUT': 'TIMEOUT',
    'CANCELLED': 'CANCELLED'
}

def get_supported_telcos():
    """Get list of supported telecom operators."""
    return SUPPORTED_TELCOS.copy()

def get_payment_limits():
    """Get payment limits information."""
    return {
        'min_amount': MINIMUM_AMOUNT,
        'max_amount': MAXIMUM_AMOUNT,
        'currency': DEFAULT_CURRENCY
    }

def get_payment_status_codes():
    """Get available payment status codes."""
    return PAYMENT_STATUS.copy()
