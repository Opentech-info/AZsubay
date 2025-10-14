"""
AZsubay: Unified SDK for payments, KYC, and USSD integrations

A comprehensive Python library that follows the big brand package structure
with modular design for mobile money payments, KYC verification, and USSD services.

Author: AZsubay
Email: AZsubay@protonmail.com
Version: 0.1.0
"""

__version__ = "0.1.0"
__author__ = "AZsubay"
__email__ = "AZsubay@protonmail.com"
__description__ = "Unified SDK for payments, KYC, and USSD integrations"

# Make all modules available for Django-style imports
from . import kyc, pay, ussd, utils

# Define what's available when using `from azsubay import *`
__all__ = ["pay", "kyc", "ussd", "utils"]

# Package-level constants
SUPPORTED_PROVIDERS = {
    "kyc": ["SmileID", "Veriff", "Jumio"],
    "payments": ["MPesa", "AirtelMoney", "TigoPesa", "MTNMobileMoney"],
    "ussd": ["MPesaUSSD", "AirtelUSSD", "GenericUSSD"],
}

# Package-level configuration
DEFAULT_TIMEOUT = 30
MAX_RETRY_ATTEMPTS = 3


def get_version():
    """Get the current package version."""
    return __version__


def get_supported_services():
    """Get list of supported services."""
    return list(__all__)


def get_info():
    """Get package information."""
    return {
        "name": "azsubay",
        "version": __version__,
        "author": __author__,
        "email": __email__,
        "description": __description__,
        "supported_services": get_supported_services(),
        "supported_providers": SUPPORTED_PROVIDERS,
    }
