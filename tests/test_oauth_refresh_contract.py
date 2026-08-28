"""Regression tests for Claude Code's OAuth refresh-token contract.

These tests are intentionally database-free. They verify the configuration
Claude discovers and the provider result generated after a successful PKCE
code exchange without ever writing real OAuth credentials.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MCP_DIR = PROJECT_ROOT / "mcp"
if str(MCP_DIR) not in sys.path:
    sys.path.insert(0, str(MCP_DIR))

from remote_server import BrilliantOAuthProvider, mcp  # noqa: E402


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
