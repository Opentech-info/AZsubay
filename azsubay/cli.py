#!/usr/bin/env python3
"""
AZsubay Command Line Interface

Provides CLI commands for common AZsubay operations including:
- Package information and version display
- Configuration validation
- Testing connectivity
- Utility functions
"""

import argparse
import sys
import json
from typing import Dict, Any, Optional

try:
    import azsubay
except ImportError:
    print("Error: AZsubay package not found. Please install it first.")
    sys.exit(1)


def show_version(args) -> None:
    """Show package version information."""
    print(f"AZsubay v{azsubay.__version__}")
    print(f"Author: {azsubay.__author__}")
    print(f"Email: {azsubay.__email__}")
    print(f"Description: {azsubay.__description__}")


def show_info(args) -> None:
    """Show detailed package information."""
    info = azsubay.get_info()
    print("AZsubay Package Information")
    print("=" * 40)
    for key, value in info.items():
        if isinstance(value, dict):
            print(f"{key.replace('_', ' ').title()}:")
            for sub_key, sub_value in value.items():
                print(f"  {sub_key}: {sub_value}")
        else:
            print(f"{key.replace('_', ' ').title()}: {value}")


def validate_config(args) -> None:
    """Validate configuration for each module."""
    import os
    from azsubay.pay import _get_config as get_pay_config
    from azsubay.utils import generate_signature
    
    print("Validating AZsubay Configuration")
    print("=" * 40)
    
    # Check payment configuration
    print("\n💳 Payment Configuration:")
    pay_config = get_pay_config()
    required_pay_keys = ['consumer_key', 'consumer_secret', 'webhook_secret']
    
    for key in required_pay_keys:
        value = pay_config.get(key, '')
        if value:
            print(f"  ✅ {key}: [SET]")
        else:
            print(f"  ❌ {key}: [MISSING]")
    
    # Check environment variables
    print("\n🔧 Environment Variables:")
    env_vars = [
        'TELCO_CONSUMER_KEY',
        'TELCO_CONSUMER_SECRET', 
        'WEBHOOK_SHARED_SECRET',
        'TELCO_OAUTH_URL',
        'TELCO_STK_PUSH_URL',
        'TELCO_B2C_URL'
    ]
    
    for var in env_vars:
        value = os.getenv(var, '')
        if value:
            print(f"  ✅ {var}: [SET]")
        else:
            print(f"  ⚠️  {var}: [NOT SET - using defaults]")
    
    # Test crypto functions
    print("\n🔐 Cryptographic Functions:")
    try:
        test_data = {"test": "data"}
        signature = generate_signature(test_data, "test_key")
        print(f"  ✅ Signature generation: [WORKING]")
    except Exception as e:
        print(f"  ❌ Signature generation: [ERROR - {e}]")
    
    print("\nConfiguration validation complete!")


def test_modules(args) -> None:
    """Test basic functionality of all modules."""
    print("Testing AZsubay Modules")
    print("=" * 40)
    
    # Test imports
    print("\n📦 Testing Imports:")
    try:
        from azsubay import pay, kyc, ussd, utils
        print("  ✅ Main modules imported successfully")
    except ImportError as e:
        print(f"  ❌ Import failed: {e}")
        return
    
    # Test payment module
    print("\n💳 Testing Payment Module:")
    try:
        from azsubay.pay import send_payment
        result = send_payment("+255700000000", 100, "TEST")
        print(f"  ✅ send_payment: [WORKING] - {result['status']}")
    except Exception as e:
        print(f"  ❌ send_payment: [ERROR - {e}]")
    
    # Test KYC module
    print("\n🆔 Testing KYC Module:")
    try:
        from azsubay.kyc import verify_identity
        result = verify_identity("SmileID", "TEST_USER", "passport")
        print(f"  ✅ verify_identity: [WORKING] - {result['status']}")
    except Exception as e:
        print(f"  ❌ verify_identity: [ERROR - {e}]")
    
    # Test USSD module
    print("\n📱 Testing USSD Module:")
    try:
        from azsubay.ussd import start_session
        result = start_session("+254712345678")
        print(f"  ✅ start_session: [WORKING] - Session {result['session_id'][:8]}...")
    except Exception as e:
        print(f"  ❌ start_session: [ERROR - {e}]")
    
    # Test utils module
    print("\n🔐 Testing Utils Module:")
    try:
        from azsubay.utils import generate_signature, validate_phone_number
        signature = generate_signature({"test": "data"}, "test_key")
        is_valid = validate_phone_number("+254712345678")
        print(f"  ✅ generate_signature: [WORKING]")
        print(f"  ✅ validate_phone_number: [WORKING] - {is_valid}")
    except Exception as e:
        print(f"  ❌ Utils functions: [ERROR - {e}]")
    
    print("\nModule testing complete!")


def show_usage(args) -> None:
    """Show usage examples."""
    print("AZsubay Usage Examples")
    print("=" * 40)
    
    print("\n💳 Payment Examples:")
    print("  from azsubay.pay import send_payment, stk_push")
    print("  result = send_payment('+255700000000', 5000, 'INV123')")
    print("  result = stk_push('254712345678', 100, 'ORDER123')")
    
    print("\n🆔 KYC Examples:")
    print("  from azsubay.kyc import verify_identity, submit_documents")
    print("  result = verify_identity('SmileID', 'USER123', 'passport')")
    print("  result = submit_documents('Veriff', 'USER123', 'id_card', data)")
    
    print("\n📱 USSD Examples:")
    print("  from azsubay.ussd import start_session, navigate_menu")
    print("  session = start_session('+254712345678')")
    print("  response = navigate_menu(session['session_id'], '1')")
    
    print("\n🔐 Utils Examples:")
    print("  from azsubay.utils import generate_signature, encrypt_data")
    print("  signature = generate_signature(data, secret_key)")
    print("  encrypted = encrypt_data('sensitive data', password)")
    
    print("\n📦 Import Styles:")
    print("  from azsubay import pay, kyc, ussd, utils")
    print("  from azsubay.pay import send_payment")
    print("  from azsubay.pay.payments import send_payment")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="AZsubay - Unified SDK for payments, KYC, and USSD integrations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  azsubay --version
  azsubay info
  azsubay validate-config
  azsubay test-modules
  azsubay usage
        """
    )
    
    parser.add_argument("--version", "-v", action="store_true", help="Show version information")
    parser.add_argument("command", nargs="?", choices=["info", "validate-config", "test-modules", "usage"], 
                       help="Command to execute")
    
    args = parser.parse_args()
    
    if args.version:
        show_version(args)
    elif args.command == "info":
        show_info(args)
    elif args.command == "validate-config":
        validate_config(args)
    elif args.command == "test-modules":
        test_modules(args)
    elif args.command == "usage":
        show_usage(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
