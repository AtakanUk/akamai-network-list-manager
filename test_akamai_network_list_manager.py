import argparse
from unittest.mock import MagicMock

import pytest

from akamai_network_list_manager import AkamaiClient, AkamaiSettings, normalize_items, run

SETTINGS = AkamaiSettings(
    "https://akab-example.luna.akamaiapis.net", "ct", "cs", "at", network_list_id="1234_BLOCKLIST"
)


def ok(body=b"{}"):
    response = MagicMock()
    response.ok = True
    response.status_code = 200
    response.content = body
    response.json.return_value = {"activationId": 99} if body else {}
    return response


def make_client():
    session = MagicMock()
    session.headers = {}
    session.request.return_value = ok()
    return AkamaiClient(SETTINGS, session=session), session


def test_normalize_items_validates_and_dedupes():
    assert normalize_items(["192.0.2.9", " 192.0.2.9 ", "198.51.100.7/24", "2001:db8::1", ""]) == [
        "192.0.2.9",
        "198.51.100.0/24",
        "2001:db8::1",
    ]
    with pytest.raises(ValueError):
        normalize_items(["not-an-ip"])


def test_block_then_activate():
    client, session = make_client()
    args = argparse.Namespace(
        command="block",
        list_id=None,
        items="192.0.2.9,192.0.2.9",
        activate="PRODUCTION",
        comment="",
        notify="soc@example.com",
    )
    result = run(args, client, SETTINGS)

    append, activate = session.request.call_args_list
    assert append.args[0] == "POST" and append.args[1].endswith(
        "/network-lists/1234_BLOCKLIST/append"
    )
    assert append.kwargs["json"] == {"list": ["192.0.2.9"]}
    assert activate.args[1].endswith("/environments/PRODUCTION/activate")
    assert activate.kwargs["json"]["notificationRecipients"] == ["soc@example.com"]
    assert result["activation"]["activationId"] == 99


def test_unblock_deletes_each_element_and_handles_empty_responses():
    client, session = make_client()
    session.request.return_value = ok(b"")
    result = client.unblock("1234_BLOCKLIST", ["192.0.2.9", "198.51.100.0/24"])
    assert [call.kwargs["params"]["element"] for call in session.request.call_args_list] == [
        "192.0.2.9",
        "198.51.100.0/24",
    ]
    assert result["removed"][0]["response"] == {}


def test_account_switch_key_is_added():
    settings = AkamaiSettings(**{**SETTINGS.__dict__, "account_switch_key": "1-ABC"})
    session = MagicMock()
    session.headers = {}
    session.request.return_value = ok()
    AkamaiClient(settings, session=session).list_all()
    assert session.request.call_args.kwargs["params"]["accountSwitchKey"] == "1-ABC"


def test_invalid_environment():
    client, _ = make_client()
    with pytest.raises(ValueError):
        client.activate("1234_BLOCKLIST", "DEV")
