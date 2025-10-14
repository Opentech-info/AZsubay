"""
Tests for AZsubay Command Line Interface
"""

import argparse
import pytest
from unittest.mock import patch
import os
from azsubay import cli


@pytest.fixture
def mock_args():
    """Fixture to mock command line arguments."""

    def _mock_args(command=None, version=False):
        with patch("argparse.ArgumentParser.parse_args") as mock_parse_args:
            mock_parse_args.return_value = argparse.Namespace(
                command=command, version=version
            )
            yield

    import argparse

    return _mock_args


def test_cli_version(capsys):
    """Test the --version flag."""
    with patch.object(cli.sys, "argv", ["azsubay", "--version"]):
        with pytest.raises(SystemExit) as e:
            cli.main()
        assert e.value.code == 0

    captured = capsys.readouterr()
    assert "AZsubay v" in captured.out


def test_cli_info(capsys):
    """Test the 'info' command."""
    with patch.object(cli.sys, "argv", ["azsubay", "info"]):
        cli.main()

    captured = capsys.readouterr()
    assert "AZsubay Package Information" in captured.out
    assert "Version:" in captured.out
    assert "Supported Providers:" in captured.out


def test_cli_validate_config(capsys, monkeypatch):
    """Test the 'validate-config' command."""
    # Set some env vars for the test
    monkeypatch.setenv("TELCO_CONSUMER_KEY", "test_key")
    monkeypatch.setenv("REDIS_HOST", "test_redis")

    # Patch Redis to avoid a real connection
    with patch("azsubay.ussd.menu.redis") as mock_redis:
        # Ensure the redis object is not None so RedisSessionStore initializes
        mock_redis.Redis.return_value.ping.return_value = True

        with patch.object(cli.sys, "argv", ["azsubay", "validate-config"]):
            cli.main()  # This will now use the mocked RedisSessionStore

    captured = capsys.readouterr()
    assert "Validating AZsubay Configuration" in captured.out
    assert "TELCO_CONSUMER_KEY: [SET]" in captured.out
    assert "consumer_secret: [MISSING]" in captured.out
    assert "Redis Connection: [OK]" in captured.out
    assert "Signature generation: [WORKING]" in captured.out


def test_cli_test_modules(capsys, requests_mock):
    """Test the 'test-modules' command."""
    # Mock the API calls made by the test-modules command
    requests_mock.get(
        "https://example-telco/oauth/token", json={"access_token": "test_token"}
    )
    requests_mock.post(
        "https://example-telco/b2c",
        json={
            "ConversationID": "mock_conv_id",
            "ResponseCode": "0",
            "status": "SUCCESS",
        },
    )

    with patch("azsubay.ussd.menu.session_store"):  # Mock ussd session store
        with patch.object(cli.sys, "argv", ["azsubay", "test-modules"]):
            cli.main()

    captured = capsys.readouterr()
    assert "Testing AZsubay Modules" in captured.out
    assert "Main modules imported successfully" in captured.out
    assert "send_payment: [WORKING]" in captured.out
    assert "verify_identity: [WORKING]" in captured.out
    assert "start_session: [WORKING]" in captured.out
    assert "generate_signature: [WORKING]" in captured.out


def test_cli_usage(capsys):
    """Test the 'usage' command."""
    with patch.object(cli.sys, "argv", ["azsubay", "usage"]):
        cli.main()

    captured = capsys.readouterr()
    assert "AZsubay Usage Examples" in captured.out
    assert "💳 Payment Examples:" in captured.out
    assert "from azsubay.pay import send_payment" in captured.out


def test_cli_no_command(capsys):
    """Test the CLI with no command, which should show help."""
    with patch.object(cli.sys, "argv", ["azsubay"]):
        cli.main()

    captured = capsys.readouterr()
    assert "usage: azsubay" in captured.out
    assert "Examples:" in captured.out
