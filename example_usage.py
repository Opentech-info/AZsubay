#!/usr/bin/env python3
"""
AZsubay - Complete Usage Example

This script demonstrates the full functionality of the azsubay package
following the professional big brand package structure.
"""


def main():
    """Demonstrate all azsubay package features."""

    print("🚀 AZsubay - Unified SDK Demo")
    print("=" * 50)

    # 1. Payment Module Examples
    print("\n💳 PAYMENT MODULE")
    print("-" * 20)

    from azsubay.pay import send_payment, stk_push, b2c_payout

    # Basic payment (from the spec example)
    print("1. Basic Payment:")
    resp = send_payment("+255700000000", 5000, "INV123")
    print(f"   Result: {resp}")

    print("\n2. STK Push:")
    try:
        result = stk_push("254712345678", 100, "ORDER123", "Test payment")
        print(f"   Result: {result}")
    except Exception as e:
        print(f"   Expected API error (demo): {type(e).__name__}")

    print("\n3. B2C Payout:")
    try:
        result = b2c_payout("254712345678", 500, "Test refund")
        print(f"   Result: {result}")
    except Exception as e:
        print(f"   Expected API error (demo): {type(e).__name__}")

    # 2. KYC Module Examples
    print("\n🆔 KYC MODULE")
    print("-" * 20)

    from azsubay.kyc import verify_identity, submit_documents, check_status

    print("1. Identity Verification:")
    result = verify_identity("SmileID", "USER123", "passport")
    print(f"   Result: {result}")

    print("\n2. Submit Documents:")
    # Use valid base64 data for demo
    import base64

    document_data = {
        "front_image": base64.b64encode(b"mock_front_image_data").decode("utf-8"),
        "back_image": base64.b64encode(b"mock_back_image_data").decode("utf-8"),
        "selfie": base64.b64encode(b"mock_selfie_image_data").decode("utf-8"),
    }
    result = submit_documents("Veriff", "USER123", "id_card", document_data)
    print(f"   Result: {result}")

    print("\n3. Check Status:")
    result = check_status("SmileID", "sub_USER123_1642435200")
    print(f"   Result: {result}")

    # 3. USSD Module Examples
    print("\n📱 USSD MODULE")
    print("-" * 20)

    from azsubay.ussd import start_session, navigate_menu, end_session

    print("1. Start Session:")
    session = start_session("+254712345678")
    print(f"   Session ID: {session['session_id']}")
    print(f"   Response: {session['response']}")

    print("\n2. Navigate Menu:")
    response = navigate_menu(session["session_id"], "1")
    print(f"   Navigated to 'Send Money': {response['response']}")

    # Continue with a simple payment flow
    print("\n3. Complete Payment Flow:")
    responses = []
    responses.append(
        navigate_menu(session["session_id"], "0722000000")
    )  # Enter phone number
    responses.append(navigate_menu(session["session_id"], "1500"))  # Enter amount
    responses.append(navigate_menu(session["session_id"], "1"))  # Confirm

    for i, resp in enumerate(responses, 1):
        print(f"   Flow Step {i}: {resp['response'].splitlines()[0]}")

    print("\n4. End Session:")
    result = end_session(session["session_id"])
    print(f"   Session ended: {result['response']}")

    # 4. Utils Module Examples
    print("\n🔐 UTILS MODULE")
    print("-" * 20)

    from azsubay.utils import (
        generate_signature,
        verify_signature,
        encrypt_data,
        decrypt_data,
    )
    from azsubay.utils.crypto import (
        hash_data,
        generate_secure_token,
        validate_phone_number,
        format_amount,
    )

    print("1. Signature Generation & Verification:")
    data = {"transaction_id": "TX123", "amount": 1500, "phone": "+254712345678"}
    secret_key = "your_secret_key"

    signature = generate_signature(data, secret_key)
    is_valid = verify_signature(data, signature, secret_key)
    print(f"   Data: {data}")
    print(f"   Signature: {signature[:32]}...")
    print(f"   Valid: {is_valid}")

    print("\n2. Data Encryption & Decryption:")
    sensitive_data = "This is sensitive information"
    password = "my_secure_password"

    encrypted = encrypt_data(sensitive_data, password=password)
    decrypted = decrypt_data(
        encrypted["encrypted_data"],
        encrypted["iv"],
        password=password,
        salt_b64=encrypted["salt"],
        tag_b64=encrypted["tag"],
    )
    print(f"   Original: {sensitive_data}")
    print(f"   Encrypted: {encrypted['encrypted_data'][:32]}...")
    print(f"   Decrypted: {decrypted.decode('utf-8')}")

    print("\n3. Data Hashing:")
    hash_result = hash_data(sensitive_data)
    print(f"   Data: {sensitive_data}")
    print(f"   SHA256 Hash: {hash_result}")

    print("\n4. Secure Token Generation:")
    token = generate_secure_token()
    print(f"   Token: {token}")
    print(f"   Length: {len(token)} characters")

    print("\n5. Phone Number Validation:")
    test_numbers = [
        "0712345678",
        "+254712345678",
        "254712345678",
        "123",  # Too short
        "abc123",  # Invalid characters
    ]

    for number in test_numbers:
        is_valid = validate_phone_number(number)
        print(f"   {number}: {'✅ Valid' if is_valid else '❌ Invalid'}")

    print("\n6. Amount Formatting:")
    test_amounts = [1000, 1500.5, "2000"]
    for amount in test_amounts:
        formatted = format_amount(amount, "KES")
        print(f"   {amount} → {formatted}")

    # Test error handling
    try:
        format_amount("invalid", "KES")
    except Exception as e:
        print(f"   invalid → Error: {type(e).__name__}")

    # 5. Import Style Examples
    print("\n📦 IMPORT STYLES")
    print("-" * 20)

    print("1. Django-style imports:")
    try:
        from azsubay import pay, kyc, ussd, utils

        print("   ✅ Successfully imported modules: pay, kyc, ussd, utils")
    except ImportError as e:
        print(f"   ❌ Import failed: {e}")

    print("\n2. Module-specific imports:")
    try:
        from azsubay.pay import send_payment
        from azsubay.kyc import verify_identity
        from azsubay.ussd import start_session
        from azsubay.utils import generate_signature

        print("   ✅ Successfully imported specific functions")
    except ImportError as e:
        print(f"   ❌ Import failed: {e}")

    print("\n3. Direct function imports:")
    try:
        from azsubay.pay.payments import send_payment
        from azsubay.kyc.verify import verify_identity
        from azsubay.ussd.menu import start_session
        from azsubay.utils.crypto import generate_signature

        print("   ✅ Successfully imported from submodules")
    except ImportError as e:
        print(f"   ❌ Import failed: {e}")

    # 6. Package Information
    print("\n📋 PACKAGE INFO")
    print("-" * 20)

    import azsubay

    print(f"   Package Name: azsubay")
    print(f"   Version: {azsubay.__version__}")
    print(f"   Author: {azsubay.__author__}")
    print(f"   Email: {azsubay.__email__}")
    print(f"   Available Modules: {azsubay.__all__}")

    print("\n" + "=" * 50)
    print("✅ AZsubay demo completed successfully!")
    print("🚀 Ready for production use with real API endpoints!")
    print("📚 Check README.md for configuration details")


if __name__ == "__main__":
    main()
