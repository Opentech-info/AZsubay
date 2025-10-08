"""
Tests for AZsubay package __init__.py
"""

import azsubay

def test_get_version():
    """Test get_version function."""
    version = azsubay.get_version()
    assert isinstance(version, str)
    assert version == azsubay.__version__

def test_get_supported_services():
    """Test get_supported_services function."""
    services = azsubay.get_supported_services()
    assert isinstance(services, list)
    assert 'pay' in services
    assert 'kyc' in services
    assert 'ussd' in services
    assert 'utils' in services

def test_get_info():
    """Test get_info function."""
    info = azsubay.get_info()
    assert isinstance(info, dict)
    assert info['name'] == 'azsubay'
    assert info['version'] == azsubay.__version__
    assert 'supported_providers' in info