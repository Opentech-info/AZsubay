"""
Tests for AZsubay KYC Module
"""
import os
import base64

import pytest
from azsubay.kyc import (
    verify_identity,
    submit_documents,
    check_status,
    ProviderError,
    VerificationError,
    DocumentError,
)

def test_verify_identity():
    """Test the basic verify_identity function."""
    result = verify_identity("SmileID", "USER123", "passport")
    
    assert result["status"] == "PENDING"
    assert result["provider"] == "SmileID"
    assert result["user_id"] == "USER123"
    assert "submission_id" in result
    assert result["submission_id"].startswith("sub_")

def test_verify_identity_with_document_type():
    """Test verify_identity with different document types."""
    result = verify_identity("Veriff", "USER456", "passport")
    
    assert result["status"] == "PENDING"
    assert result["provider"] == "Veriff"
    assert result["user_id"] == "USER456"
    assert result["document_type"] == "passport"

def test_submit_documents():
    """Test document submission functionality."""
    import base64
    document_data = {
        "front_image": base64.b64encode(b"mock_front_image_data").decode('utf-8'),
        "back_image": base64.b64encode(b"mock_back_image_data").decode('utf-8'),
        "selfie": base64.b64encode(b"mock_selfie_image_data").decode('utf-8')
    }
    
    result = submit_documents("Jumio", "USER789", "id_card", document_data)
    
    assert result["status"] == "PENDING"
    assert result["provider"] == "Jumio"
    assert result["user_id"] == "USER789"
    assert result["document_type"] == "id_card"
    assert "submission_id" in result
    assert "estimated_processing_time" in result

def test_check_status():
    """Test status checking functionality."""
    result = check_status("SmileID", "sub_USER123_1642435200")
    
    # Status can be PENDING, APPROVED, REJECTED, or REQUIRES_REVIEW
    assert result["status"] in ["PENDING", "APPROVED", "REJECTED", "REQUIRES_REVIEW"]
    assert result["provider"] == "SmileID"
    assert result["submission_id"] == "sub_USER123_1642435200"
    assert "timestamp" in result

def test_different_providers():
    """Test functionality with different KYC providers."""
    providers = ["SmileID", "Veriff", "Jumio"]
    
    for provider in providers:
        result = verify_identity(provider, f"TEST_{provider}", "passport")
        assert result["provider"] == provider
        assert result["status"] == "PENDING"

def test_legacy_functions():
    """Test backward compatibility with legacy function names."""
    from azsubay.kyc.verify import kyc_verify, kyc_submit, kyc_status
    
    # Test legacy verify function
    result = kyc_verify("SmileID", "LEGACY_USER", "id_card")
    assert result["status"] == "PENDING"
    assert result["provider"] == "SmileID"
    
    # Test legacy submit function
    import base64
    doc_data = {
        "front_image": base64.b64encode(b"mock_front_image_data").decode('utf-8'),
        "selfie": base64.b64encode(b"mock_selfie_image_data").decode('utf-8')
    }
    result = kyc_submit("Veriff", "LEGACY_USER", "id_card", doc_data)
    assert result["status"] == "PENDING"
    
    # Test legacy check status function
    result = kyc_status("Jumio", "LEGACY_SUBMISSION")
    assert result["status"] in ["PENDING", "APPROVED", "REJECTED", "REQUIRES_REVIEW"]

def test_import_structure():
    """Test that all expected functions can be imported."""
    from azsubay.kyc.verify import verify_identity, submit_documents, check_status
    
    # Test that functions are callable
    assert callable(verify_identity)
    assert callable(submit_documents)
    assert callable(check_status)


def test_verify_identity_invalid_provider():
    """Test verify_identity with an unsupported provider."""
    with pytest.raises(ProviderError, match="Unsupported KYC provider: InvalidProvider"):
        verify_identity("InvalidProvider", "USER123", "passport")


def test_verify_identity_empty_user_id():
    """Test verify_identity with an empty user ID."""
    with pytest.raises(VerificationError, match="User ID cannot be empty"):
        verify_identity("SmileID", "", "passport")


def test_verify_identity_empty_document_type():
    """Test verify_identity with an empty document type."""
    with pytest.raises(DocumentError, match="Document type cannot be empty"):
        verify_identity("SmileID", "USER123", "")


def test_verify_identity_invalid_document_type():
    """Test verify_identity with an invalid document type."""
    with pytest.raises(DocumentError, match="Invalid document type: invalid_doc"):
        verify_identity("SmileID", "USER123", "invalid_doc")


def test_submit_documents_invalid_provider():
    """Test submit_documents with an unsupported provider."""
    document_data = {"front_image": base64.b64encode(b"data").decode()}
    with pytest.raises(ProviderError, match="Unsupported KYC provider: InvalidProvider"):
        submit_documents("InvalidProvider", "USER123", "id_card", document_data)


def test_submit_documents_empty_document_data():
    """Test submit_documents with empty document data."""
    with pytest.raises(DocumentError, match="Required field 'front_image' is missing or empty."):
        submit_documents("SmileID", "USER123", "id_card", {})


def test_submit_documents_invalid_base64():
    """Test submit_documents with invalid base64 data."""
    document_data = {"front_image": "not-base64-data"}
    with pytest.raises(DocumentError, match="Field 'front_image' contains invalid base64 data."):
        submit_documents("SmileID", "USER123", "id_card", document_data)


def test_check_status_invalid_provider():
    """Test check_status with an unsupported provider."""
    with pytest.raises(ProviderError, match="Unsupported KYC provider: InvalidProvider"):
        check_status("InvalidProvider", "sub_123")


def test_check_status_empty_submission_id():
    """Test check_status with an empty submission ID."""
    with pytest.raises(VerificationError, match="Submission ID cannot be empty."):
        check_status("SmileID", "")


def test_kyc_provider_config_missing_keys(monkeypatch):
    """Test _get_provider_config when required environment variables are missing."""
    from azsubay.kyc.verify import _get_provider_config

    # Temporarily unset environment variables
    monkeypatch.delenv("SMILEID_API_URL", raising=False)
    monkeypatch.delenv("SMILEID_PARTNER_ID", raising=False)
    monkeypatch.delenv("SMILEID_API_KEY", raising=False)

    config = _get_provider_config("SmileID")
    assert config['api_url'] == 'https://api.smileidentity.com/v1'
    assert config['partner_id'] == ''
    assert config['api_key'] == ''


def test_kyc_make_provider_request_api_error(requests_mock):
    """Test _make_provider_request error handling."""
    from azsubay.kyc.verify import _make_provider_request, ProviderError

    # Mock a 500 error from the provider API
    requests_mock.post("https://api.smileidentity.com/v1/verify", status_code=500, json={"error": "server error"})

    # Temporarily set environment variables for SmileID
    os.environ['SMILEID_API_URL'] = 'https://api.smileidentity.com/v1'
    os.environ['SMILEID_PARTNER_ID'] = 'test_partner'
    os.environ['SMILEID_API_KEY'] = 'test_key'

    with pytest.raises(ProviderError, match="Provider SmileID API request failed"):
        _make_provider_request("SmileID", "verify", {}, {})

    # Clean up environment variables
    del os.environ['SMILEID_API_URL']
    del os.environ['SMILEID_PARTNER_ID']
    del os.environ['SMILEID_API_KEY']


def test_verify_identity_general_exception(monkeypatch):
    """Test verify_identity for general exceptions."""
    def mock_validate_provider(*args, **kwargs):
        raise Exception("Simulated general error")

    monkeypatch.setattr("azsubay.kyc.verify._validate_provider", mock_validate_provider)
    with pytest.raises(VerificationError, match="Identity verification failed: Simulated general error"):
        verify_identity("SmileID", "USER123", "passport")


def test_kyc_init_module_functions():
    """Test functions exposed directly in azsubay.kyc.__init__."""
    from azsubay.kyc import get_supported_providers, get_supported_document_types, get_verification_status_codes, get_provider_config

    providers = get_supported_providers()
    assert isinstance(providers, list)
    assert 'SmileID' in providers

    doc_types = get_supported_document_types()
    assert isinstance(doc_types, list)
    assert 'passport' in doc_types

    status_codes = get_verification_status_codes()
    assert isinstance(status_codes, dict)
    assert 'APPROVED' in status_codes

    smile_config = get_provider_config('SmileID')
    assert 'api_url' in smile_config

    with pytest.raises(ValueError, match="Unsupported provider: InvalidProvider"):
        get_provider_config('InvalidProvider')
