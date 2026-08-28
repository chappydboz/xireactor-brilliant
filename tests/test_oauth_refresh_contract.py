"""Regression tests for Claude Code's OAuth refresh-token contract.

These tests are intentionally database-free. They verify the configuration
Claude discovers and the provider result generated after a successful PKCE
code exchange without ever writing real OAuth credentials.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from types import SimpleNamespace


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MCP_DIR = PROJECT_ROOT / "mcp"
if str(MCP_DIR) not in sys.path:
    sys.path.insert(0, str(MCP_DIR))

from mcp.server.auth.middleware.client_auth import ClientAuthenticator  # noqa: E402
from mcp.shared.auth import OAuthClientInformationFull  # noqa: E402
from remote_server import (  # noqa: E402
    BrilliantOAuthProvider,
    _public_client_authorization_metadata,
    create_app,
    mcp,
)


class _MemoryStore:
    """Minimal async OAuth store for provider-contract tests."""

    def __init__(self) -> None:
        self.deleted_codes: list[str] = []
        self.access_tokens = []
        self.refresh_tokens = []

    async def delete_auth_code(self, code: str) -> None:
        self.deleted_codes.append(code)

    async def save_access_token(self, token, *, user_id=None) -> None:
        self.access_tokens.append((token, user_id))

    async def save_refresh_token(self, token) -> None:
        self.refresh_tokens.append(token)


def test_offline_access_is_a_discoverable_supported_scope() -> None:
    """Claude must see offline_access before it will request a refresh token."""
    options = mcp.settings.auth.client_registration_options
    assert "brilliant" in options.valid_scopes
    assert "offline_access" in options.valid_scopes
    assert options.default_scopes == ["brilliant"]


def test_public_client_method_is_advertised_in_authorization_metadata() -> None:
    """RFC 8414 metadata must identify `none` for public PKCE clients."""
    response = _public_client_authorization_metadata(SimpleNamespace())
    metadata = json.loads(response.body)

    assert response.headers["cache-control"] == "no-store"
    assert metadata["token_endpoint_auth_methods_supported"] == [
        "none",
        "client_secret_post",
        "client_secret_basic",
    ]


def test_application_serves_the_corrected_public_client_metadata() -> None:
    """The live app route, not only the helper, advertises `none`."""
    from starlette.testclient import TestClient

    response = TestClient(create_app()).get(
        "/.well-known/oauth-authorization-server"
    )
    metadata = response.json()

    assert response.status_code == 200
    assert "none" in metadata["token_endpoint_auth_methods_supported"]
    assert "offline_access" in metadata["scopes_supported"]


class _PublicClientProvider:
    """Minimal provider returning a public PKCE client with no secret."""

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        if client_id != "test-public-pkce-client":
            return None
        return OAuthClientInformationFull(
            client_id=client_id,
            client_secret=None,
            redirect_uris=["http://127.0.0.1:15273/oauth/callback"],
            token_endpoint_auth_method="none",
        )


def test_public_pkce_client_authenticates_with_client_id_and_no_secret() -> None:
    """The token authenticator accepts the public method advertised in metadata."""
    from starlette.requests import Request

    body = b"client_id=test-public-pkce-client&grant_type=refresh_token"
    sent = False

    async def receive():
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "scheme": "https",
            "path": "/token",
            "query_string": b"",
            "headers": [
                (b"content-type", b"application/x-www-form-urlencoded"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
            "client": ("127.0.0.1", 50000),
            "server": ("testserver", 443),
        },
        receive,
    )

    client = asyncio.run(
        ClientAuthenticator(_PublicClientProvider()).authenticate_request(request)
    )

    assert client.client_id == "test-public-pkce-client"
    assert client.token_endpoint_auth_method == "none"


def test_authorization_code_exchange_returns_a_refresh_token() -> None:
    """A Claude Code grant requesting offline access receives a refresh token."""
    store = _MemoryStore()
    provider = BrilliantOAuthProvider(store)
    client = SimpleNamespace(client_id="test-claude-code-client")
    code = SimpleNamespace(
        code="test-authorization-code",
        scopes=["brilliant", "offline_access"],
        user_id="test-user",
    )

    issued = asyncio.run(provider.exchange_authorization_code(client, code))

    assert issued.access_token
    assert issued.refresh_token
    assert issued.scope == "brilliant offline_access"
    assert store.deleted_codes == ["test-authorization-code"]
    assert len(store.access_tokens) == 1
    assert store.access_tokens[0][1] == "test-user"
    assert len(store.refresh_tokens) == 1
    assert store.refresh_tokens[0].scopes == ["brilliant", "offline_access"]
