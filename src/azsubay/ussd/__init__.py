"""
AZsubay USSD Module

Provides USSD (Unstructured Supplementary Service Data) functionality including:
- Session management and lifecycle
- Menu navigation and interaction
- Input handling and validation
- Payment flows through USSD
- Session expiration and cleanup

Usage:
    from azsubay.ussd import start_session, navigate_menu, end_session
    from azsubay.ussd.menu import start_session, navigate_menu, get_session_data
"""

# Import main functions for easy access
from .menu import (
    start_session,
    navigate_menu,
    end_session,
    get_session_data,
    USSDError,
    SessionError,
    MenuError,
    InputError,
)

# Define what's available when using `from azsubay.ussd import *`
__all__ = [
    "start_session",
    "navigate_menu",
    "end_session",
    "get_session_data",
    "USSDError",
    "SessionError",
    "MenuError",
    "InputError",
]

# Module-level constants
DEFAULT_SESSION_TIMEOUT = 300  # 5 minutes in seconds
MAX_SESSIONS = 1000
MAX_INPUT_LENGTH = 50
SUPPORTED_LANGUAGES = ["en", "sw"]  # English, Swahili

# Session status codes
SESSION_STATUS = {
    "ACTIVE": "ACTIVE",
    "EXPIRED": "EXPIRED",
    "CLOSED": "CLOSED",
    "ERROR": "ERROR",
}

# Menu navigation constants
MAIN_MENU = "main"
PAYMENT_MENU = "payment"
ACCOUNT_MENU = "account"
AIRTIME_MENU = "airtime"
BILL_MENU = "bill"


def get_supported_languages():
    """Get list of supported languages."""
    return SUPPORTED_LANGUAGES.copy()


def get_session_timeout():
    """Get default session timeout."""
    return DEFAULT_SESSION_TIMEOUT


def get_max_sessions():
    """Get maximum number of concurrent sessions."""
    return MAX_SESSIONS


def get_session_status_codes():
    """Get available session status codes."""
    return SESSION_STATUS.copy()


def get_menu_structure():
    """Get the complete menu structure."""
    return {
        "main": {
            "title": "Welcome to AZsubay",
            "options": [
                {"key": "1", "text": "Send Money", "menu": "payment"},
                {"key": "2", "text": "Check Balance", "menu": "balance"},
                {"key": "3", "text": "Buy Airtime", "menu": "airtime"},
                {"key": "4", "text": "Pay Bill", "menu": "bill"},
                {"key": "5", "text": "My Account", "menu": "account"},
            ],
        },
        "payment": {
            "title": "Send Money",
            "options": [
                {"key": "1", "text": "To Phone", "action": "phone_payment"},
                {"key": "2", "text": "To Bank", "action": "bank_payment"},
                {"key": "3", "text": "To AZsubay User", "action": "user_payment"},
                {"key": "0", "text": "Back", "menu": "main"},
            ],
        },
        "airtime": {
            "title": "Buy Airtime",
            "options": [
                {"key": "1", "text": "For My Number", "action": "self_airtime"},
                {"key": "2", "text": "For Other Number", "action": "other_airtime"},
                {"key": "0", "text": "Back", "menu": "main"},
            ],
        },
        "bill": {
            "title": "Pay Bill",
            "options": [
                {"key": "1", "text": "Electricity", "action": "electricity_bill"},
                {"key": "2", "text": "Water", "action": "water_bill"},
                {"key": "3", "text": "TV Subscription", "action": "tv_bill"},
                {"key": "0", "text": "Back", "menu": "main"},
            ],
        },
        "account": {
            "title": "My Account",
            "options": [
                {"key": "1", "text": "Check Balance", "action": "check_balance"},
                {"key": "2", "text": "Mini Statement", "action": "mini_statement"},
                {"key": "3", "text": "Change PIN", "action": "change_pin"},
                {"key": "4", "text": "Help", "action": "help"},
                {"key": "0", "text": "Back", "menu": "main"},
            ],
        },
    }
