"""
Tests for AZsubay USSD Module
"""

import os
import time
from unittest.mock import MagicMock, patch

import pytest
import redis

import azsubay
from azsubay.ussd import (
    InputError,
    MenuError,
    SessionError,
    USSDError,
    end_session,
    navigate_menu,
    start_session,
)


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
    res1 = navigate_menu(session_id, "1")  # Send Money
    res2 = navigate_menu(session_id, "1")  # To Phone

    # Test phone number input
    result = navigate_menu(session_id, "+254712345678")

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
    navigate_menu(session_id, "+254712345678")  # Phone number
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


def test_navigate_to_balance_and_help():
    """Test navigating to the check balance and help menus."""
    session_start = start_session("+254712345678")
    session_id = session_start["session_id"]

    # Navigate to check balance
    result = navigate_menu(session_id, "2")
    assert "Your balance is:" in result["response"]
    assert result["status"] == "ACTIVE"

    # Navigate back to main from balance
    result = navigate_menu(session_id, "0")
    assert "Welcome to AZsubay:" in result["response"]

    # Navigate to help
    result = navigate_menu(session_id, "5")  # My Account
    result = navigate_menu(session_id, "4")  # Help
    assert "AZsubay USSD Help:" in result["response"]
    assert result["status"] == "ACTIVE"

    # Navigate back to main from help
    result = navigate_menu(session_id, "0")
    assert "Welcome to AZsubay:" in result["response"]


def test_start_session_no_redis_store(monkeypatch):
    """Test start_session when RedisSessionStore is not initialized."""
    monkeypatch.setattr("azsubay.ussd.menu.session_store", None)
    with pytest.raises(SessionError, match="RedisSessionStore is not initialized"):
        start_session("+254712345678")


def test_start_session_invalid_phone():
    """Test start_session with an invalid phone number."""
    with pytest.raises(InputError, match="Invalid phone number format"):
        start_session("123")


def test_start_session_general_exception(monkeypatch):
    """Test start_session for general exceptions."""

    def mock_validate_phone_number(*args, **kwargs):
        raise Exception("Simulated general error")

    monkeypatch.setattr(
        "azsubay.ussd.menu._validate_phone_number", mock_validate_phone_number
    )
    with pytest.raises(
        USSDError, match="Failed to start USSD session: Simulated general error"
    ):
        start_session("+254712345678")


def test_navigate_menu_no_redis_store(monkeypatch):
    """Test navigate_menu when RedisSessionStore is not initialized."""
    monkeypatch.setattr("azsubay.ussd.menu.session_store", None)
    with pytest.raises(SessionError, match="RedisSessionStore is not initialized"):
        navigate_menu("some_id", "1")


def test_navigate_menu_session_not_found():
    """Test navigate_menu with a non-existent session."""
    # Mock session_store.get to return None
    with patch("azsubay.ussd.menu.session_store.get", return_value=None):
        with pytest.raises(SessionError, match="Session not found"):
            navigate_menu("non_existent_id", "1")


def test_navigate_menu_session_not_active():
    """Test navigate_menu with an inactive session."""
    session_start = start_session("+254712345678")
    session_id = session_start["session_id"]
    end_session(session_id)  # End the session

    with pytest.raises(SessionError, match="Session is CLOSED"):
        navigate_menu(session_id, "1")


def test_navigate_menu_empty_input():
    """Test navigate_menu with empty user input."""
    session_start = start_session("+254712345678")
    session_id = session_start["session_id"]
    with pytest.raises(InputError, match="Input cannot be empty"):
        navigate_menu(session_id, "")


def test_navigate_menu_input_too_long():
    """Test navigate_menu with user input that is too long."""
    session_start = start_session("+254712345678")
    session_id = session_start["session_id"]
    with pytest.raises(InputError, match="Input too long"):
        navigate_menu(session_id, "a" * 51)


def test_navigate_menu_invalid_amount_input():
    """Test navigate_menu with invalid amount input."""
    session_start = start_session("+254712345678")
    session_id = session_start["session_id"]

    # Navigate to amount input
    navigate_menu(session_id, "1")  # Send Money
    navigate_menu(session_id, "1")  # To Phone
    navigate_menu(session_id, "+254787654321")  # Phone

    with pytest.raises(InputError, match="Invalid amount format"):
        navigate_menu(session_id, "not-a-number")


def test_navigate_menu_unknown_menu_state(monkeypatch):
    """Test navigate_menu with an unknown current_menu state."""
    session_start = start_session("+254712345678")
    session_id = session_start["session_id"]

    # Manually set current_menu to an unknown state
    session = azsubay.ussd.menu.session_store.get(session_id)
    session["current_menu"] = "unknown_menu_state"
    azsubay.ussd.menu.session_store.set(session_id, session, timeout=300)

    with pytest.raises(MenuError, match="Unknown menu state: unknown_menu_state"):
        navigate_menu(session_id, "1")


def test_navigate_menu_general_exception(monkeypatch):
    """Test navigate_menu for general exceptions."""

    def mock_validate_input(*args, **kwargs):
        raise Exception("Simulated general error")

    session_start = start_session("+254712345678")
    session_id = session_start["session_id"]
    monkeypatch.setattr("azsubay.ussd.menu._validate_input", mock_validate_input)
    with pytest.raises(
        USSDError, match="Menu navigation failed: Simulated general error"
    ):
        navigate_menu(session_id, "1")


def test_end_session_no_redis_store(monkeypatch):
    """Test end_session when RedisSessionStore is not initialized."""
    monkeypatch.setattr("azsubay.ussd.menu.session_store", None)
    with pytest.raises(SessionError, match="RedisSessionStore is not initialized"):
        end_session("some_id")


def test_end_session_not_found():
    """Test end_session with a non-existent session."""
    with patch("azsubay.ussd.menu.session_store.get", return_value=None):
        with pytest.raises(SessionError, match="Session not found"):
            end_session("non_existent_id")


def test_end_session_general_exception(monkeypatch):
    """Test end_session for general exceptions."""

    def mock_get_session_data(*args, **kwargs):
        raise Exception("Simulated general error")

    monkeypatch.setattr("azsubay.ussd.menu.session_store.get", mock_get_session_data)
    with pytest.raises(
        USSDError, match="Failed to end USSD session: Simulated general error"
    ):
        end_session("some_id")


def test_get_session_data_no_redis_store(monkeypatch):
    """Test get_session_data when RedisSessionStore is not initialized."""
    monkeypatch.setattr("azsubay.ussd.menu.session_store", None)
    with pytest.raises(SessionError, match="RedisSessionStore is not initialized"):
        azsubay.ussd.menu.get_session_data("some_id")


def test_get_session_data_not_found():
    """Test get_session_data with a non-existent session."""
    with patch("azsubay.ussd.menu.session_store.get", return_value=None):
        with pytest.raises(SessionError, match="Session not found"):
            azsubay.ussd.menu.get_session_data("non_existent_id")


def test_get_active_sessions_count_no_redis_store(monkeypatch):
    """Test get_active_sessions_count when RedisSessionStore is not initialized."""
    monkeypatch.setattr("azsubay.ussd.menu.session_store", None)
    assert azsubay.ussd.menu.get_active_sessions_count() == 0


def test_redis_session_store_connection_error(monkeypatch):
    """Test RedisSessionStore initialization with connection error."""
    mock_redis_client = MagicMock()
    mock_redis_client.ping.side_effect = redis.exceptions.ConnectionError(
        "Mock connection error"
    )
    monkeypatch.setattr("redis.Redis", MagicMock(return_value=mock_redis_client))

    # Ensure session_store is None after this
    monkeypatch.setattr("azsubay.ussd.menu.session_store", None)

    with pytest.raises(SessionError, match="Could not connect to Redis"):
        azsubay.ussd.menu.RedisSessionStore()


def test_ussd_menu_unhandled_action():
    """Test _handle_action with an unhandled action."""
    session_start = start_session("+254712345678")
    session_id = session_start["session_id"]

    # Manually set an unhandled action in context
    session = azsubay.ussd.menu.session_store.get(session_id)
    session["context"]["action"] = "unhandled_action"
    azsubay.ussd.menu.session_store.set(session_id, session, timeout=300)

    result = azsubay.ussd.menu._handle_action("unhandled_action", session_id)
    assert "Action not available" in result["response"]


def test_ussd_menu_confirm_airtime_cancel():
    """Test canceling airtime purchase."""
    session_start = start_session("+254712345678")
    session_id = session_start["session_id"]

    navigate_menu(session_id, "3")  # Buy Airtime
    navigate_menu(session_id, "1")  # For My Number
    navigate_menu(session_id, "50")  # Amount

    result = navigate_menu(session_id, "0")  # Cancel
    assert "Welcome to AZsubay:" in result["response"]
    assert result["status"] == "ACTIVE"


def test_ussd_init_module_functions():
    """Test functions exposed directly in azsubay.ussd.__init__."""
    from azsubay.ussd import (
        get_max_sessions,
        get_menu_structure,
        get_session_status_codes,
        get_session_timeout,
        get_supported_languages,
    )

    languages = get_supported_languages()
    assert "en" in languages

    timeout = get_session_timeout()
    assert timeout == 300

    max_sessions = get_max_sessions()
    assert max_sessions == 1000

    status_codes = get_session_status_codes()
    assert "ACTIVE" in status_codes

    menu = get_menu_structure()
    assert "main" in menu
