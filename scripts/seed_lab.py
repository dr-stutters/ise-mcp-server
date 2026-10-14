"""Seed the ISE lab with the objects and RADIUS history the live tests expect. Idempotent.

    uv run python scripts/seed_lab.py            # reads ISE_* from .env

Creates or updates (all prefixed mcp-test-):
  - NAD  mcp-test-radius-client covering this host's source subnet (so it can send RADIUS)
  - identity group mcp-test-group, internal user mcp-test-user (in that group)
  - endpoint group mcp-test-endpoints, endpoint 02:00:5E:00:00:01 (static group assignment)
Then sends RADIUS traffic from this host so MnT has data:
  - PAP success for mcp-test-user from 02:00:5E:00:00:01, plus Accounting-Start (an active session)
  - PAP wrong password for mcp-test-user from 02:00:5E:00:00:02  (failure 22040 / 24408)
  - PAP unknown user mcp-test-nobody from 02:00:5E:00:00:03     (failure 22056)

The RADIUS shared secret and the user's password are random per run (set on ISE each time), so no
secret lives in the repo. Nothing here prints a secret.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import socket
import struct
import sys
import time
from typing import Any
from urllib.parse import urlsplit

import httpx

NAD = "mcp-test-radius-client"
GROUP = "mcp-test-group"
USER = "mcp-test-user"
EP_GROUP = "mcp-test-endpoints"
MAC_OK, MAC_BADPW, MAC_UNKNOWN = "02:00:5E:00:00:01", "02:00:5E:00:00:02", "02:00:5E:00:00:03"
SESSION_IP = "10.250.0.11"


def load_env(path: str = ".env") -> None:
    if not os.path.exists(path):
        return
    with open(path) as fh:
        lines = fh.read().splitlines()
    for line in lines:
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


class Ers:
    def __init__(self) -> None:
        url = os.environ["ISE_URL"].rstrip("/")
        port = int(os.environ.get("ISE_ERS_PORT", "443"))
        parts = urlsplit(url)
        self.host = parts.hostname or ""
        base = url if port == 443 else f"{parts.scheme}://{self.host}:{port}"
        verify = os.environ.get("ISE_VERIFY_SSL", "true").lower() not in ("false", "0", "no")
        self.http = httpx.Client(
            base_url=base,
            auth=(os.environ["ISE_USERNAME"], os.environ["ISE_PASSWORD"]),
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            verify=verify,
            timeout=30,
        )

    def find(self, resource: str, name: str) -> str | None:
        field = "mac" if resource == "endpoint" else "name"
        r = self.http.get(f"/ers/config/{resource}", params={"filter": f"{field}.EQ.{name}"})
        r.raise_for_status()
        for item in r.json()["SearchResult"].get("resources", []):
            if item.get("name") == name:
                return str(item["id"])
        return None

    def upsert(self, resource: str, wrapper: str, body: dict[str, Any], name: str | None = None) -> str:
        name = name or body["name"]
        existing = self.find(resource, name)
        if existing:
            r = self.http.put(f"/ers/config/{resource}/{existing}", json={wrapper: {"id": existing, **body}})
            check(r, f"update {resource} {name}")
            print(f"updated {resource} {name}")
            return existing
        r = self.http.post(f"/ers/config/{resource}", json={wrapper: body})
        check(r, f"create {resource} {name}")
        print(f"created {resource} {name}")
        return r.headers["Location"].rstrip("/").rsplit("/", 1)[-1]


def check(r: httpx.Response, what: str) -> None:
    if r.is_error:
        sys.exit(f"{what} failed: HTTP {r.status_code} {r.text[:300]}")


# --- minimal RADIUS client (RFC 2865/2866), no dependencies -----------------------------------


def _attr(t: int, v: bytes) -> bytes:
    return struct.pack("!BB", t, len(v) + 2) + v


def _vsa_cisco(text: str) -> bytes:
    sub = _attr(1, text.encode())  # cisco-av-pair
    return _attr(26, struct.pack("!I", 9) + sub)


def _pap(secret: bytes, authenticator: bytes, password: str) -> bytes:
    pw = password.encode()
    pw += b"\0" * (-len(pw) % 16)
    out, last = b"", authenticator
    for i in range(0, len(pw), 16):
        block = bytes(a ^ b for a, b in zip(pw[i : i + 16], hashlib.md5(secret + last).digest(), strict=True))
        out += block
        last = block
    return out


def _common(user: str, mac: str, src_ip: str, session: str) -> bytes:
    return (
        _attr(1, user.encode())
        + _attr(31, mac.encode())
        + _attr(30, b"00-00-5E-00-53-00")
        + _attr(4, socket.inet_aton(src_ip))
        + _attr(5, struct.pack("!I", 10101))
        + _attr(61, struct.pack("!I", 15))  # Ethernet
        + _attr(87, b"GigabitEthernet1/0/1")
        + _vsa_cisco(f"audit-session-id={session}")
    )


def access_request(
    host: str, secret: bytes, user: str, password: str, mac: str, src_ip: str, session: str
) -> int:
    authenticator = os.urandom(16)
    attrs = _common(user, mac, src_ip, session) + _attr(2, _pap(secret, authenticator, password))
    attrs += _attr(6, struct.pack("!I", 2))  # Service-Type: Framed
    attrs += _attr(80, b"\0" * 16)
    ident = secrets.randbelow(256)
    pkt = struct.pack("!BBH", 1, ident, 20 + len(attrs)) + authenticator + attrs
    mac_auth = hmac.new(secret, pkt, hashlib.md5).digest()
    pkt = pkt[:-16] + mac_auth
    return _send(host, 1812, pkt)


def accounting_start(host: str, secret: bytes, user: str, mac: str, src_ip: str, session: str) -> int:
    attrs = (
        _common(user, mac, src_ip, session)
        + _attr(40, struct.pack("!I", 1))  # Acct-Status-Type Start
        + _attr(44, session.encode())  # Acct-Session-Id
        + _attr(8, socket.inet_aton(SESSION_IP))  # Framed-IP-Address
    )
    ident = secrets.randbelow(256)
    length = 20 + len(attrs)
    header = struct.pack("!BBH", 4, ident, length)
    authenticator = hashlib.md5(header + b"\0" * 16 + attrs + secret).digest()
    return _send(host, 1813, header + authenticator + attrs)


def _send(host: str, port: int, pkt: bytes) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(10)
        s.sendto(pkt, (host, port))
        try:
            data, _ = s.recvfrom(4096)
        except TimeoutError:
            return -1
        return data[0]


def source_ip(host: str) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect((host, 1812))
        return str(s.getsockname()[0])


def main() -> None:
    load_env()
    ers = Ers()
    src = source_ip(ers.host)
    radius_secret = "mcp-" + secrets.token_urlsafe(18)
    user_password = "Mcp-" + secrets.token_urlsafe(12) + "1a"

    ers.upsert(
        "networkdevice",
        "NetworkDevice",
        {
            "name": NAD,
            "description": "mcp-test: RADIUS client used by ise-mcp-server live tests",
            "authenticationSettings": {
                "networkProtocol": "RADIUS",
                "radiusSharedSecret": radius_secret,
                "enableKeyWrap": False,
                "keyInputFormat": "ASCII",
            },
            "coaPort": 1700,
            "NetworkDeviceIPList": [{"ipaddress": src, "mask": 32}],
            "NetworkDeviceGroupList": ["Location#All Locations", "Device Type#All Device Types"],
        },
    )
    group_id = ers.upsert("identitygroup", "IdentityGroup", {"name": GROUP, "description": "mcp-test group"})
    ers.upsert(
        "internaluser",
        "InternalUser",
        {
            "name": USER,
            "description": "mcp-test user",
            "enabled": True,
            "password": user_password,
            "changePassword": False,
            "identityGroups": group_id,
            "passwordIDStore": "Internal Users",
        },
    )
    ep_group_id = ers.upsert(
        "endpointgroup", "EndPointGroup", {"name": EP_GROUP, "description": "mcp-test endpoints"}
    )
    ers.upsert(
        "endpoint",
        "ERSEndPoint",
        {
            "name": MAC_OK,
            "mac": MAC_OK,
            "description": "mcp-test endpoint",
            "groupId": ep_group_id,
            "staticGroupAssignment": True,
        },
        name=MAC_OK,
    )
    time.sleep(3)  # let the NAD/user changes reach the runtime

    secret = radius_secret.encode()
    session = "0A000001000000" + secrets.token_hex(5).upper()
    codes = {2: "Accept", 3: "Reject", -1: "timeout"}
    r = access_request(ers.host, secret, USER, user_password, MAC_OK, src, session)
    print(f"RADIUS {USER} good password -> {codes.get(r, r)}")
    r = accounting_start(ers.host, secret, USER, MAC_OK, src, session)
    print(f"RADIUS accounting start -> {'ok' if r == 5 else r}")
    r = access_request(ers.host, secret, USER, "wrong-password", MAC_BADPW, src, session + "B")
    print(f"RADIUS {USER} wrong password -> {codes.get(r, r)}")
    r = access_request(ers.host, secret, "mcp-test-nobody", "x", MAC_UNKNOWN, src, session + "C")
    print(f"RADIUS unknown user -> {codes.get(r, r)}")
    print(f"done (RADIUS source {src}); MnT may take ~10s to show the new records")


if __name__ == "__main__":
    main()
