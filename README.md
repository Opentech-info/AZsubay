# AZsubay

**AZsubay: The Unified SDK for African FinTech.**

A comprehensive Python library that follows the big brand package structure with modular design for mobile money payments, KYC verification, and USSD services.

## Features

*   **Modular Architecture**: A single, scalable package with distinct modules for `pay`, `kyc`, and `ussd`.
*   **Comprehensive Payments**: Full support for mobile money operations, including STK Push, B2C payouts, and secure webhook handling.
*   **Multi-Provider KYC**: Abstracted identity verification with built-in support for providers like SmileID, Veriff, and Jumio.
*   **Stateful USSD Engine**: A complete framework for building and managing complex, Redis-backed USSD menu flows.
*   **Robust Security**: Includes essential cryptographic utilities for signature generation, data encryption, and webhook validation.
*   **Simple Installation**: Get access to the entire suite of tools with a single `pip install azsubay`.

## Installation

```bash
pip install azsubay
```

## Quick Start

### Mobile Money Payments

```python
from azsubay.pay import send_payment

# Simple B2C payment
resp = send_payment("+255700000000", 5000, "INV123")
print(resp)

# Advanced STK Push
from azsubay.pay import stk_push, b2c_payout

result = stk_push(
    msisdn="254712345678",
    amount=100,
    account_reference="ORDER123",
    transaction_desc="Payment for goods"
)
print(result)

# B2C Payout
result = b2c_payout(
    msisdn="254712345678",
    amount=50,
    remarks="Refund"
)
print(result)
```

### KYC Verification

```python
from azsubay.kyc import verify_identity, submit_documents, check_status

# Verify identity
result = verify_identity(
    provider="SmileID",
    user_id="USER123",
    document_type="passport"
)
print(result)

# Submit documents
document_data = {
    "front_image": "base64_encoded_image_data",
    "selfie": "base64_encoded_selfie"
}
result = submit_documents(
    provider="Veriff",
    user_id="USER123",
    document_type="id_card",
    document_data=document_data
)
print(result)

# Check status
result = check_status(
    provider="SmileID",
    submission_id="SUB123"
)
print(result)
```

### USSD Services

```python
from azsubay.ussd import start_session, navigate_menu, end_session

# Start USSD session
session = start_session("+254712345678")
print(session["response"])
# Output: Welcome to AZsubay:
# 1. Send Money
# 2. Check Balance
# 3. Buy Airtime
# 4. Pay Bill
# 5. My Account

# Navigate menu
response = navigate_menu(session["session_id"], "1")
print(response["response"])
# Output: Send Money:
# 1. To Phone
# 2. To Bank
# 3. To AZsubay User
# 0. Back
```

### Security Utilities

```python
from azsubay.utils import generate_signature, verify_signature, encrypt_data, decrypt_data

# Generate and verify signatures
data = {"transaction_id": "TX123", "amount": 1000}
signature = generate_signature(data, "your_secret_key")
is_valid = verify_signature(data, signature, "your_secret_key")
print(f"Signature valid: {is_valid}")

# Encrypt/decrypt sensitive data
encrypted = encrypt_data("sensitive data", password="my_password")
decrypted = decrypt_data(
    encrypted["encrypted_data"],
    encrypted["iv"],
    password="my_password",
    salt_b64=encrypted["salt"]
)
print(f"Decrypted: {decrypted.decode('utf-8')}")
```


## Usage Patterns

This structure follows professional patterns used by major SDKs:

### Django-style imports
```python
from azsubay import pay, kyc, ussd, utils
```

### Module-specific imports
```python
from azsubay.pay import send_payment, stk_push
from azsubay.kyc import verify_identity, submit_documents
from azsubay.ussd import start_session, navigate_menu
from azsubay.utils import generate_signature, encrypt_data
```

### Direct function imports
```python
from azsubay.pay.payments import send_payment
from azsubay.kyc.verify import verify_identity
from azsubay.ussd.menu import start_session
from azsubay.utils.crypto import generate_signature
```

## Configuration

### B2C Security Credential Generation

For B2C (Business-to-Customer) payouts, telcos require the initiator's password to be RSA-encrypted with a public key they provide. This library includes a utility to generate this credential.

**This is a one-time setup step.** You should generate the credential and store it securely as an environment variable.

1.  Obtain the public key certificate file (e.g., `cert.cer`) from your payment provider.
2.  Create a Python script to generate the credential:

```python
# create_credential.py
from azsubay.pay import create_b2c_credential

initiator_password = "YourPlainTextPassword"
public_key_path = "/path/to/your/cert.cer"

security_credential = create_b2c_credential(initiator_password, public_key_path)
print(security_credential)
```

3.  Run the script (`python create_credential.py`) and copy the output.
4.  Set the output as the `TELCO_B2C_SECURITY_CREDENTIAL` environment variable.

### Environment Variables

```bash
# --- General Payment Configuration ---
TELCO_CONSUMER_KEY=your_consumer_key
TELCO_CONSUMER_SECRET=your_consumer_secret
TELCO_OAUTH_URL=https://example-telco/oauth/token
REQUEST_TIMEOUT=30

# Security Configuration
WEBHOOK_SHARED_SECRET=your_webhook_secret
WHITELISTED_IPS=127.0.0.1,192.168.1.1

# USSD Session Configuration (Redis)
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0

# --- STK Push Configuration ---
TELCO_STK_PUSH_URL=https://example-telco/stkpush
TELCO_STK_SHORTCODE=your_business_shortcode
TELCO_STK_PASSKEY=your_stk_passkey
TELCO_CALLBACK_URL=https://your-domain.com/stk-callback

# --- B2C Payout Configuration ---
TELCO_B2C_URL=https://example-telco/b2c
TELCO_B2C_SHORTCODE=your_b2c_shortcode
TELCO_B2C_INITIATOR_NAME=your_initiator_name
TELCO_B2C_SECURITY_CREDENTIAL=your_generated_encrypted_credential # See generation steps above
TELCO_B2C_PUBLIC_KEY_CERT_PATH=/path/to/your/cert.cer # Only needed for generating the credential
TELCO_B2C_RESULT_URL=https://your-domain.com/b2c-result
TELCO_B2C_TIMEOUT_URL=https://your-domain.com/b2c-timeout
```

## Requirements

- Python 3.9+
- fastapi>=0.70
- requests>=2.25
- pydantic>=1.10
- cryptography>=3.4

## Testing

Run the test suite:

```bash
pip install pytest
pytest tests/
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Professional Benefits

- **One Brand, One Install**: Developers only run `pip install azsubay`
- **Scalable**: Add new modules (sms, analytics, wallet) without publishing new PyPI packages
- **Clean Ecosystem**: Avoids clutter like azsubay-pay, azsubay-kyc, etc.
- **Professional**: Matches what Stripe, AWS, Google Cloud SDK do

## Support

For support, please open an issue on the [GitHub repository](https://github.com/azsubay/azsubay/issues).

---

**AZsubay** - Professional mobile money & KYC integration for Africa 
