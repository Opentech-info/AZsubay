"""
Tests for AZsubay USSD Module
"""

import pytest
import time
from azsubay.ussd import start_session, navigate_menu, end_session

def test_start_session():
    """Test starting a new USSD session."""
    result = start_session("+254712345678")
    
    assert "session_id" in result
    assert "response" in result
    assert "status" in result
    assert result["status"] == "ACTIVE"
    assert "Welcome to AZsubay:" in result["response"]
    assert "Send Money" in result["response"]

def test_navigate_main_menu():
    """Test navigation from main menu."""
    # Start a session
    session_start = start_session("+254712345678")
    session_id = session_start["session_id"]
    
    # Navigate to send money
    result = navigate_menu(session_id, "1")
    
    assert result["status"] == "ACTIVE"
    assert "Send Money:" in result["response"]
    assert "To Phone" in result["response"]

def test_navigate_back_to_main():
    """Test navigation back to main menu."""
    # Start a session and navigate to send money
    session_start = start_session("+254712345678")
    session_id = session_start["session_id"]
    
    navigate_menu(session_id, "1")  # Go to send money
    
    # Go back to main
    result = navigate_menu(session_id, "0")
    
    assert result["status"] == "ACTIVE"
    assert "Welcome to AZsubay:" in result["response"]

def test_phone_input_menu():
    """Test phone number input menu."""
    session_start = start_session("+254712345678")
    session_id = session_start["session_id"]
    
    # Navigate to phone input
    navigate_menu(session_id, "1")  # Send Money
    navigate_menu(session_id, "1")  # To Phone
    
    # Test phone number input
    result = navigate_menu(session_id, "0712345678")
    
    # The result should be continue since it goes to amount input
    assert result["status"] == "ACTIVE"
    assert "Enter amount:" in result["response"]

def test_amount_input_and_confirmation():
    """Test amount input and payment confirmation."""
    session_start = start_session("+254712345678")
    session_id = session_start["session_id"]
    
    # Navigate through payment flow
    navigate_menu(session_id, "1")  # Send Money
    navigate_menu(session_id, "1")  # To Phone
    navigate_menu(session_id, "0712345678")  # Phone number
    navigate_menu(session_id, "1000")  # Amount
    
    # Should be at confirmation screen
    result = navigate_menu(session_id, "1")  # Confirm
    
    assert result["status"] == "CLOSED"
    assert "Payment Successful!" in result["response"]

def test_invalid_option():
    """Test handling of invalid menu options."""
    session_start = start_session("+254712345678")
    session_id = session_start["session_id"]
    
    # Try invalid option
    try:
        result = navigate_menu(session_id, "99")
        assert False, "Should have raised InputError"
    except Exception as e:
        # Should raise an error for invalid option
        assert "Invalid option" in str(e)
