"""Manage Akamai Network Lists (IP block lists used by Akamai WAF / App & API Protector).

Typical SOC use: block an attacking IP or range at the edge from a SOAR playbook,
push the change to STAGING or PRODUCTION, and remove it again when the case is closed.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin

import requests

log = logging.getLogger("akamai_network_list")
BASE = "/network-list/v2/network-lists"
ENVIRONMENTS = ("STAGING", "PRODUCTION")


@dataclass
class AkamaiSettings:
    host: str
    client_token: str
    client_secret: str
    access_token: str
    account_switch_key: str | None = None
    network_list_id: str | None = None
    environment: str = "STAGING"

    @classmethod
    def from_env(cls) -> AkamaiSettings:
        values = {
            name: os.getenv(name, "").strip()
            for name in (
                "AKAMAI_HOST",
                "AKAMAI_CLIENT_TOKEN",
                "AKAMAI_CLIENT_SECRET",
                "AKAMAI_ACCESS_TOKEN",
            )
        }
        missing = [name for name, value in values.items() if not value]
        if missing:
            raise SystemExit(f"Missing required configuration: {', '.join(missing)}")
        host = values["AKAMAI_HOST"]
        return cls(
            host=host if host.startswith("https://") else f"https://{host}",
            client_token=values["AKAMAI_CLIENT_TOKEN"],
            client_secret=values["AKAMAI_CLIENT_SECRET"],
            access_token=values["AKAMAI_ACCESS_TOKEN"],
            account_switch_key=os.getenv("AKAMAI_ACCOUNT_SWITCH_KEY", "").strip() or None,
            network_list_id=os.getenv("AKAMAI_NETWORK_LIST_ID", "").strip() or None,
            environment=os.getenv("AKAMAI_ENVIRONMENT", "STAGING").strip().upper(),
        )


def normalize_items(items: Iterable[str]) -> list[str]:
    """Validate IPs/CIDRs, normalise them (``192.0.2.9/24`` -> ``192.0.2.0/24``) and drop duplicates."""
    result: list[str] = []
    for raw in items:
        item = raw.strip()
        if not item:
            continue
        try:
            value = (
                str(ipaddress.ip_network(item, strict=False))
                if "/" in item
                else str(ipaddress.ip_address(item))
            )
        except ValueError as exc:
            raise ValueError(f"Not an IP address or CIDR: {item!r}") from exc
        if value not in result:
            result.append(value)
    return result


class AkamaiClient:
    def __init__(self, settings: AkamaiSettings, session: requests.Session | None = None) -> None:
        self.settings = settings
        self.session = session or requests.Session()
        if session is None:
            from akamai.edgegrid import EdgeGridAuth

            self.session.auth = EdgeGridAuth(
                client_token=settings.client_token,
                client_secret=settings.client_secret,
                access_token=settings.access_token,
            )
        self.session.headers.update(
            {"Accept": "application/json", "Content-Type": "application/json"}
        )

    def request(
        self, method: str, path: str, *, params: dict[str, Any] | None = None, body: Any = None
    ) -> dict[str, Any]:
        params = dict(params or {})
        if self.settings.account_switch_key:
            params["accountSwitchKey"] = self.settings.account_switch_key
        url = urljoin(self.settings.host.rstrip("/") + "/", path.lstrip("/"))
        log.info(
            "%s %s params=%s body=%s",
            method,
            path,
            params,
            json.dumps(body) if body is not None else "-",
        )
        response = self.session.request(method, url, params=params, json=body, timeout=30)
        log.info("-> HTTP %s", response.status_code)
        if not response.ok:
            log.error(
                "%s %s failed: HTTP %s %s", method, path, response.status_code, response.text[:2000]
            )
            response.raise_for_status()
        return response.json() if response.content else {}

    def block(self, list_id: str, items: Iterable[str]) -> dict[str, Any]:
        return self.request(
            "POST", f"{BASE}/{list_id}/append", body={"list": normalize_items(items)}
        )

    def unblock(self, list_id: str, items: Iterable[str]) -> dict[str, Any]:
        removed = [
            {
                "item": item,
                "response": self.request(
                    "DELETE", f"{BASE}/{list_id}/elements", params={"element": item}
                ),
            }
            for item in normalize_items(items)
        ]
        return {"removed": removed}

    def activate(
        self, list_id: str, environment: str, comment: str = "", recipients: list[str] | None = None
    ) -> dict[str, Any]:
        environment = environment.upper()
        if environment not in ENVIRONMENTS:
            raise ValueError(f"environment must be one of {ENVIRONMENTS}")
        result = self.request(
            "POST",
            f"{BASE}/{list_id}/environments/{environment}/activate",
            body={"comments": comment, "notificationRecipients": recipients or []},
        )
        log.info(
            "Activation on %s submitted, activationId=%s",
            environment,
            result.get("activationId", "-"),
        )
        return result

    def activation_status(self, list_id: str, environment: str) -> dict[str, Any]:
        return self.request("GET", f"{BASE}/{list_id}/environments/{environment.upper()}/status")

    def get_list(self, list_id: str) -> dict[str, Any]:
        return self.request(
            "GET", f"{BASE}/{list_id}", params={"extended": "true", "includeElements": "true"}
        )

    def list_all(self, list_type: str = "IP") -> dict[str, Any]:
        return self.request(
            "GET",
            BASE,
            params={"extended": "true", "includeElements": "false", "listType": list_type},
        )

    def client_lists(self) -> dict[str, Any]:
        return self.request("GET", "/client-list/v1/lists")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Akamai Network Lists manager")
    parser.add_argument(
        "--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"]
    )
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("list-all", help="all IP network lists of the account")
    commands.add_parser("client-lists", help="all client lists of the account")
    get = commands.add_parser("get", help="one network list with its elements")
    get.add_argument("--list-id")

    for name, help_text in (
        ("block", "add IPs/CIDRs to a list"),
        ("unblock", "remove IPs/CIDRs from a list"),
    ):
        change = commands.add_parser(name, help=help_text)
        change.add_argument("--list-id")
        change.add_argument("--items", required=True, help="comma-separated IPs or CIDRs")
        change.add_argument(
            "--activate",
            metavar="ENV",
            nargs="?",
            const="default",
            help="activate afterwards (STAGING/PRODUCTION)",
        )
        change.add_argument("--comment", default="")
        change.add_argument(
            "--notify", default="", help="comma-separated activation notification recipients"
        )

    activate = commands.add_parser("activate", help="push the list to STAGING or PRODUCTION")
    activate.add_argument("--list-id")
    activate.add_argument("--environment")
    activate.add_argument("--comment", default="")
    activate.add_argument("--notify", default="")

    status = commands.add_parser("status", help="activation status of a list")
    status.add_argument("--list-id")
    status.add_argument("--environment")
    return parser


def _list_id(value: str | None, settings: AkamaiSettings) -> str:
    if not (value or settings.network_list_id):
        raise SystemExit("A network list ID is required (--list-id or AKAMAI_NETWORK_LIST_ID)")
    return value or settings.network_list_id  # type: ignore[return-value]


def run(args: argparse.Namespace, client: AkamaiClient, settings: AkamaiSettings) -> dict[str, Any]:
    recipients = [item.strip() for item in getattr(args, "notify", "").split(",") if item.strip()]
    if args.command == "list-all":
        return client.list_all()
    if args.command == "client-lists":
        return client.client_lists()
    list_id = _list_id(args.list_id, settings)
    if args.command == "get":
        return client.get_list(list_id)
    if args.command == "status":
        return client.activation_status(list_id, args.environment or settings.environment)
    if args.command == "activate":
        return client.activate(
            list_id, args.environment or settings.environment, args.comment, recipients
        )

    items = args.items.split(",")
    result = (
        client.block(list_id, items) if args.command == "block" else client.unblock(list_id, items)
    )
    if args.activate:
        environment = settings.environment if args.activate == "default" else args.activate
        comment = args.comment or f"SOAR {args.command}: {', '.join(normalize_items(items))}"
        result["activation"] = client.activate(list_id, environment, comment, recipients)
    return result


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level), format="%(asctime)s %(levelname)s %(message)s"
    )
    settings = AkamaiSettings.from_env()
    try:
        result = run(args, AkamaiClient(settings), settings)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
