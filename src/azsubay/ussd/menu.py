"""
AZsubay USSD Menu Implementation

Core USSD functionality for menu navigation and session management including:
- Session management and lifecycle
- Menu navigation and interaction
- Input handling and validation
- Payment flows through USSD
- Session expiration and cleanup
"""

import json
import logging
import os
import secrets
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union

try:
    import redis
except ImportError:
    redis = None


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class USSDError(Exception):
    """Base exception for USSD-related errors."""

    pass


class SessionError(USSDError):
    """Exception for session-related errors."""

    pass


class MenuError(USSDError):
    """Exception for menu-related errors."""

    pass


class InputError(USSDError):
    """Exception for input-related errors."""

    pass


class RedisSessionStore:
    """
    A production-ready session store using Redis.

    This store handles creating, retrieving, updating, and deleting USSD sessions
    in a Redis database, making it scalable and persistent.
    """

    def __init__(self):
        if redis is None:
            raise ImportError(
                "The 'redis' package is required to use RedisSessionStore. Please install it with 'pip install redis'."
            )

        self.redis_host = os.getenv("REDIS_HOST", "localhost")
        self.redis_port = int(os.getenv("REDIS_PORT", "6379"))
        self.redis_db = int(os.getenv("REDIS_DB", "0"))
        self.prefix = "azsubay:ussd:session:"

        try:
            self.client = redis.Redis(
                host=self.redis_host,
                port=self.redis_port,
                db=self.redis_db,
                decode_responses=False,
            )
            self.client.ping()
            logger.info(
                f"Successfully connected to Redis at {self.redis_host}:{self.redis_port}"
            )
        except redis.exceptions.ConnectionError as e:
            logger.error(
                f"Could not connect to Redis: {e}. USSD module will not function correctly."
            )
            raise SessionError(f"Could not connect to Redis: {e}") from e

    def get(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a session from Redis."""
        session_data = self.client.get(f"{self.prefix}{session_id}")
        if session_data:
            return json.loads(session_data)
        return None

    def set(self, session_id: str, session_data: Dict[str, Any], timeout: int):
        """Save a session to Redis with a timeout (TTL)."""
        self.client.set(
            f"{self.prefix}{session_id}", json.dumps(session_data), ex=timeout
        )

    def delete(self, session_id: str):
        """Delete a session from Redis."""
        self.client.delete(f"{self.prefix}{session_id}")

    def exists(self, session_id: str) -> bool:
        """Check if a session exists in Redis."""
        return self.client.exists(f"{self.prefix}{session_id}") > 0

    def count_active(self) -> int:
        """Count the number of active sessions."""
        # This can be slow on large databases, use with caution in production.
        return len(list(self.client.scan_iter(f"{self.prefix}*")))


# Instantiate the session store.
# This will raise an error on startup if Redis is not available.
try:
    session_store = RedisSessionStore()
except (ImportError, SessionError) as e:
    logger.warning(
        f"USSD Redis session store not available: {e}. Using a mock store for demonstration purposes."
    )
    session_store = None  # Fallback for environments without Redis


def _generate_session_id() -> str:
    """Generate a unique session ID."""
    return f"ussd_{secrets.token_hex(8)}_{int(time.time())}"


def _validate_phone_number(phone: str) -> str:
    """Validate and format phone number for USSD."""
    if not phone:
        raise InputError("Phone number is required")

    # Remove any spaces or special characters except +
    clean_phone = "".join(c for c in phone if c.isdigit() or c == "+")

    # Ensure it starts with country code
    if clean_phone.startswith("0"):
        clean_phone = "+254" + clean_phone[1:]
    elif clean_phone.startswith("7") or clean_phone.startswith("1"):
        clean_phone = "+254" + clean_phone
    elif not clean_phone.startswith("+"):
        clean_phone = "+" + clean_phone

    # Basic validation for Kenyan numbers
    if len(clean_phone) != 13 or not clean_phone.startswith("+254"):
        raise InputError(f"Invalid phone number format: {phone}")

    return clean_phone


def _validate_input(input_str: str, max_length: int = 50) -> str:
    """Validate user input."""
    if not input_str or not input_str.strip():
        raise InputError("Input cannot be empty")

    clean_input = input_str.strip()

    if len(clean_input) > max_length:
        raise InputError(f"Input too long (max {max_length} characters)")

    return clean_input


def _get_menu_structure() -> Dict[str, Dict[str, Any]]:
    """Get the complete menu structure."""
    return {
        "main": {
            "title": "Welcome to AZsubay",
            "options": [
                {"key": "1", "text": "Send Money", "menu": "payment"},
                {"key": "2", "text": "Check Balance", "action": "check_balance"},
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


def _format_menu_response(menu_data: Dict[str, Any], session_id: str) -> str:
    """Format menu data as USSD response."""
    response = f"{menu_data['title']}:\n"

    for option in menu_data["options"]:
        response += f"{option['key']}. {option['text']}\n"

    return response.strip()


def _handle_action(
    action: str, session_id: str, input_data: str = ""
) -> Dict[str, Any]:
    """Handle menu actions and return response."""
    session = session_store.get(session_id)
    if not session:
        raise SessionError("Session not found")

    # Handle different actions
    if action == "phone_payment":
        if "phone" not in session.get("context", {}):
            # Ask for phone number
            session["context"]["action"] = "phone_payment"
            session["current_menu"] = "input_phone"
            session_store.set(session_id, session, timeout=300)  # Save state change
            return {
                "response": "Enter phone number:",
                "session_id": session_id,
                "status": "ACTIVE",
            }
        else:
            # Process payment
            phone = session["context"]["phone"]
            amount = session["context"].get("amount", "0")
            return _process_payment(session_id, phone, amount)

    elif action == "self_airtime":
        if "amount" not in session.get("context", {}):
            session["context"]["action"] = "self_airtime"
            session["current_menu"] = "input_amount"
            session_store.set(session_id, session, timeout=300)  # Save state change
            return {
                "response": "Enter amount:",
                "session_id": session_id,
                "status": "ACTIVE",
            }
        else:
            amount = session["context"]["amount"]
            phone = session["phone_number"]
            return _process_airtime_purchase(session_id, phone, amount)

    elif action == "check_balance":
        balance = "KES 15,750.50"  # Mock balance
        session["current_menu"] = "action_result"  # Set state to allow going back
        session_store.set(session_id, session, timeout=300)  # Save the state change
        return {
            "response": f"Your balance is: {balance}\n\n0. Main Menu",
            "session_id": session_id,
            "status": "ACTIVE",
        }

    elif action == "help":
        help_text = (
            "AZsubay USSD Help:\n"
            "• Use numbers to select options\n"
            "• Enter 0 to go back\n"
            "• Sessions timeout after 5 minutes\n"
            "• For support call: 0800222111"
        )
        session["current_menu"] = "action_result"  # Set state to allow going back
        session_store.set(session_id, session, timeout=300)  # Save the state change
        return {
            "response": f"{help_text}\n\n0. Main Menu",
            "session_id": session_id,
            "status": "ACTIVE",
        }

    # Default response for unhandled actions
    return {
        "response": "Action not available. Please try again.\n\n0. Main Menu",
        "session_id": session_id,
        "status": "ACTIVE",
    }


def _process_payment(session_id: str, phone: str, amount: str) -> Dict[str, Any]:
    """Process a payment transaction."""
    try:
        # Validate amount
        amount_float = float(amount)
        if amount_float <= 0:
            raise InputError("Amount must be greater than 0")

        # Mock payment processing
        transaction_id = f"TXN_{secrets.token_hex(4)}"

        response_text = (
            f"Payment Processing:\n"
            f"To: {phone}\n"
            f"Amount: KES {amount_float:,.2f}\n"
            f"Ref: {transaction_id}\n\n"
            f"1. Confirm\n"
            f"0. Cancel"
        )

        session = session_store.get(session_id)
        session["context"]["pending_transaction"] = {
            "transaction_id": transaction_id,
            "phone": phone,
            "amount": amount_float,
        }
        session["current_menu"] = "confirm_payment"

        session_store.set(session_id, session, timeout=300)  # Reset timer
        return {"response": response_text, "session_id": session_id, "status": "ACTIVE"}

    except ValueError:
        raise InputError("Invalid amount format")
    except Exception as e:
        logger.error(f"Payment processing failed: {e}")
        raise USSDError(f"Payment processing failed: {e}")


def _process_airtime_purchase(
    session_id: str, phone: str, amount: str
) -> Dict[str, Any]:
    """Process airtime purchase."""
    try:
        # Validate amount
        amount_float = float(amount)
        if amount_float <= 0:
            raise InputError("Amount must be greater than 0")

        # Mock airtime processing
        transaction_id = f"AIR_{secrets.token_hex(4)}"

        response_text = (
            f"Airtime Purchase:\n"
            f"Phone: {phone}\n"
            f"Amount: KES {amount_float:,.2f}\n"
            f"Ref: {transaction_id}\n\n"
            f"1. Confirm\n"
            f"0. Cancel"
        )

        session = session_store.get(session_id)
        session["context"]["pending_transaction"] = {
            "transaction_id": transaction_id,
            "phone": phone,
            "amount": amount_float,
            "type": "airtime",
        }
        session["current_menu"] = "confirm_airtime"

        session_store.set(session_id, session, timeout=300)  # Reset timer

        return {"response": response_text, "session_id": session_id, "status": "ACTIVE"}

    except ValueError:
        raise InputError("Invalid amount format")
    except Exception as e:
        logger.error(f"Airtime processing failed: {e}")
        raise USSDError(f"Airtime processing failed: {e}")


def start_session(
    phone_number: str, language: str = "en", timeout: int = 300
) -> Dict[str, Any]:
    """
    Start a new USSD session.

    Args:
        phone_number: User's phone number
        language: Language preference (default: 'en')
        timeout: Session timeout in seconds (default: 300)

    Returns:
        Dict containing session information and main menu

    Example:
        >>> session = start_session("+254712345678")
        >>> print(session["response"])
        Welcome to AZsubay:
        1. Send Money
        2. Check Balance
        3. Buy Airtime
        4. Pay Bill
        5. My Account
    """
    logger.info(f"Starting USSD session for: {phone_number}")

    if not session_store:
        raise SessionError(
            "RedisSessionStore is not initialized. Cannot start session."
        )

    try:
        # Validate phone number
        clean_phone = _validate_phone_number(phone_number)

        # Generate session ID
        session_id = _generate_session_id()

        # Create session
        session = {
            "session_id": session_id,
            "phone_number": clean_phone,
            "language": language,
            "current_menu": "main",
            "status": "ACTIVE",
            "start_time": datetime.now().isoformat(),
            "context": {},
            "history": [],
        }

        # Store session in Redis with timeout
        session_store.set(session_id, session, timeout)

        # Get main menu
        menu_structure = _get_menu_structure()
        main_menu = menu_structure["main"]
        menu_response = _format_menu_response(main_menu, session_id)

        result = {
            "session_id": session_id,
            "response": menu_response,
            "status": "ACTIVE",
            "phone_number": clean_phone,
            "language": language,
        }

        logger.info(f"USSD session started: {session_id}")
        return result

    except (InputError, SessionError):
        raise
    except Exception as e:
        logger.error(f"Failed to start USSD session: {e}")
        raise USSDError(f"Failed to start USSD session: {e}")


def navigate_menu(session_id: str, user_input: str) -> Dict[str, Any]:
    """
    Navigate through USSD menu based on user input.

    Args:
        session_id: Active session ID
        user_input: User's menu selection or input

    Returns:
        Dict containing menu response and session status

    Example:
        >>> response = navigate_menu(session["session_id"], "1")
        >>> print(response["response"])
        Send Money:
        1. To Phone
        2. To Bank
        3. To AZsubay User
        0. Back
    """
    logger.info(f"Processing USSD input: {session_id} - {user_input}")

    try:
        if not session_store:
            raise SessionError(
                "RedisSessionStore is not initialized. Cannot navigate menu."
            )

        # Validate session
        session = session_store.get(session_id)
        if not session:
            raise SessionError("Session not found")

        # Check session status
        if session["status"] != "ACTIVE":
            raise SessionError(f"Session is {session['status']}")

        # Validate input
        clean_input = _validate_input(user_input)

        # Add to history
        session["history"].append(
            {
                "input": clean_input,
                "timestamp": datetime.now().isoformat(),
                "menu": session["current_menu"],
            }
        )

        # Reset session timer by re-setting the key in Redis
        session_store.set(session_id, session, timeout=300)

        # Handle input based on current menu/state
        current_menu = session["current_menu"]

        # Global handler for "Back" from action results
        if current_menu == "action_result" and clean_input == "0":
            session["current_menu"] = "main"
            menu_structure = _get_menu_structure()
            main_menu = menu_structure["main"]
            session_store.set(session_id, session, timeout=300)
            menu_response = _format_menu_response(main_menu, session_id)

            return {
                "response": menu_response,
                "session_id": session_id,
                "status": "ACTIVE",
            }

        # Handle special input states
        if current_menu == "input_phone":
            # Handle phone number input
            phone = _validate_phone_number(clean_input)
            session["context"]["phone"] = phone
            session["current_menu"] = "input_amount"
            session_store.set(session_id, session, timeout=300)
            return {
                "response": "Enter amount:",
                "session_id": session_id,
                "status": "ACTIVE",
            }

        elif current_menu == "input_amount":
            # Handle amount input
            try:
                amount = float(clean_input)
                if amount <= 0:
                    raise InputError("Amount must be greater than 0")

                session["context"]["amount"] = str(amount)

                # Go back to complete the action
                action = session["context"].get("action", "")
                if action:
                    session_store.set(session_id, session, timeout=300)
                    return _handle_action(action, session_id)
                else:
                    raise MenuError("No action context found")

            except ValueError:
                raise InputError("Invalid amount format")

        elif current_menu == "confirm_payment":
            if clean_input == "1":
                # Confirm payment
                pending = session["context"]["pending_transaction"]
                # Mock successful payment
                response_text = (
                    f"Payment Successful!\n"
                    f"Ref: {pending['transaction_id']}\n"
                    f"Amount: KES {pending['amount']:,.2f}\n\n"
                    f"Thank you for using AZsubay!"
                )

                # End session after successful payment
                end_session(session_id)

                return {
                    "response": response_text,
                    "session_id": session_id,
                    "status": "CLOSED",
                }
            else:
                # Cancel payment
                session["current_menu"] = "main"
                menu_structure = _get_menu_structure()
                main_menu = menu_structure["main"]
                session_store.set(session_id, session, timeout=300)
                menu_response = _format_menu_response(main_menu, session_id)

                return {
                    "response": menu_response,
                    "session_id": session_id,
                    "status": "ACTIVE",
                }

        elif current_menu == "confirm_airtime":
            if clean_input == "1":
                # Confirm airtime
                pending = session["context"]["pending_transaction"]
                response_text = (
                    f"Airtime Purchase Successful!\n"
                    f"To: {pending['phone']}\n"
                    f"Amount: KES {pending['amount']:,.2f}\n\n"
                    f"Thank you for using AZsubay!"
                )
                end_session(session_id)
                return {
                    "response": response_text,
                    "session_id": session_id,
                    "status": "CLOSED",
                }
            else:
                # Cancel airtime
                session["current_menu"] = "main"
                menu_structure = _get_menu_structure()
                main_menu = menu_structure["main"]
                session_store.set(session_id, session, timeout=300)
                menu_response = _format_menu_response(main_menu, session_id)
                return {
                    "response": menu_response,
                    "session_id": session_id,
                    "status": "ACTIVE",
                }

        # Handle regular menu navigation
        menu_structure = _get_menu_structure()

        if current_menu in menu_structure:
            menu_data = menu_structure[current_menu]

            # Find matching option
            for option in menu_data["options"]:
                if option["key"] == clean_input:
                    if "menu" in option:
                        # Navigate to submenu
                        session["current_menu"] = option["menu"]
                        submenu = menu_structure[option["menu"]]
                        session_store.set(session_id, session, timeout=300)
                        menu_response = _format_menu_response(submenu, session_id)

                        return {
                            "response": menu_response,
                            "session_id": session_id,
                            "status": "ACTIVE",
                        }
                    elif "action" in option:
                        # Handle action
                        session_store.set(session_id, session, timeout=300)
                        return _handle_action(option["action"], session_id)

            # No matching option found
            raise InputError("Invalid option")

        else:
            raise MenuError(f"Unknown menu state: {current_menu}")

    except (SessionError, InputError, MenuError):
        raise
    except Exception as e:
        logger.error(f"Menu navigation failed: {e}")
        raise USSDError(f"Menu navigation failed: {e}")


def end_session(session_id: str) -> Dict[str, Any]:
    """
    End a USSD session and clean up resources.

    Args:
        session_id: Session ID to end

    Returns:
        Dict containing session end confirmation

    Example:
        >>> result = end_session(session["session_id"])
        >>> print(result["response"])
        Session ended. Thank you for using AZsubay!
    """
    logger.info(f"Ending USSD session: {session_id}")

    try:
        if not session_store:
            raise SessionError(
                "RedisSessionStore is not initialized. Cannot end session."
            )

        # Validate session
        session = session_store.get(session_id)
        if not session:
            raise SessionError("Session not found")

        # Update session status and set a short TTL instead of immediate deletion.
        # This allows subsequent calls to correctly identify the session as CLOSED
        # before it is removed from Redis.
        session["status"] = "CLOSED"
        session["end_time"] = datetime.now().isoformat()
        session_store.set(
            session_id, session, timeout=60
        )  # Keep closed session for 1 minute

        # Calculate duration for the final response
        start_time = datetime.fromisoformat(session["start_time"])
        duration = (datetime.now() - start_time).total_seconds()

        result: Dict[str, Any] = {
            "session_id": session_id,
            "response": "Session ended. Thank you for using AZsubay!",
            "status": "CLOSED",
        }

        logger.info(f"USSD session ended: {session_id}")
        return result

    except SessionError:
        raise
    except Exception as e:
        logger.error(f"Failed to end USSD session: {e}")
        raise USSDError(f"Failed to end USSD session: {e}")


def get_session_data(session_id: str) -> Dict[str, Any]:
    """
    Get session data for debugging or monitoring.

    Args:
        session_id: Session ID to retrieve

    Returns:
        Dict containing complete session data

    Example:
        >>> data = get_session_data(session["session_id"])
        >>> print(f"Session status: {data['status']}")
    """
    if not session_store:
        raise SessionError(
            "RedisSessionStore is not initialized. Cannot get session data."
        )

    session = session_store.get(session_id)
    if not session:
        raise SessionError("Session not found")

    # Calculate duration if session has ended
    if session["status"] in ["CLOSED", "EXPIRED"] and session.get("end_time"):
        start_time = datetime.fromisoformat(session["start_time"])
        end_time = datetime.fromisoformat(session["end_time"])
        duration = (end_time - start_time).total_seconds()
        session["duration"] = f"{duration:.2f} seconds"

    return session


def cleanup_expired_sessions():
    """No-op. Redis handles automatic expiration of sessions via TTL."""
    logger.info(
        "Cleanup is handled automatically by Redis TTL. No manual cleanup needed."
    )


def get_active_sessions_count() -> int:
    """Get count of active sessions."""
    if not session_store:
        return 0
    return session_store.count_active()
