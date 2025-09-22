"""
Tests for AZsubay KYC Module
"""

import pytest
from azsubay.kyc import verify_identity, submit_documents, check_status

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
