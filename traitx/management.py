"""Management client — policies and lists.

These are the **portal** APIs (SPEC.md section 2). They authenticate with a
bearer JWT obtained by a human operator logging in, not with the private key, and
they are application-scoped. Unlike :meth:`TraitXClient.evaluate`, they raise on
failure: an admin script should fail loudly, not silently no-op.

Typical uses: assert at boot that the policies you rely on are enabled, and push
a confirmed-fraud device or IP onto a blocklist after a chargeback.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional, Sequence
from urllib.parse import quote

from .config import Config
from .errors import ApiError, ConfigurationError, ValidationError
from .http import RequestSpec, Transport
from .types import to_iso


class ManagementClient:
    def __init__(self, config: Config, transport: Transport) -> None:
        self._config = config
        self._transport = transport
        self._token: Optional[str] = None

    def with_token(self, jwt: str) -> "ManagementClient":
        """Supply the portal JWT.

        Obtain it however your operations tooling prefers — ``POST
        /api/v1/user/login`` plus OTP verification returns one. The SDK does not
        perform the login flow because it involves a second factor.
        """
        cleaned = (jwt or "").strip()
        if not cleaned:
            raise ConfigurationError("a non-empty JWT is required")
        self._token = cleaned[7:] if cleaned.startswith("Bearer ") else cleaned
        return self

    # -- policies -----------------------------------------------------------

    def list_policies(self, application_id: Optional[str] = None) -> List[Dict[str, Any]]:
        body = self._call(
            "GET", "/api/v1/policies", query={"application_id": self._app_id(application_id)}
        )
        return body.get("policies") or []

    def get_policy(self, policy_id: str) -> Dict[str, Any]:
        return self._call("GET", f"/api/v1/policies/{quote(policy_id, safe='')}")

    def enable_policy(self, policy_id: str) -> None:
        self._call("PATCH", f"/api/v1/policies/{quote(policy_id, safe='')}/enable")

    def disable_policy(self, policy_id: str) -> None:
        self._call("PATCH", f"/api/v1/policies/{quote(policy_id, safe='')}/disable")

    def enable_shadow_mode(self, policy_id: str) -> None:
        """Put a policy into shadow mode: it evaluates and logs but does not enforce."""
        self._call("PATCH", f"/api/v1/policies/{quote(policy_id, safe='')}/pass-through/enable")

    def disable_shadow_mode(self, policy_id: str) -> None:
        """Promote a policy out of shadow mode so its action is enforced."""
        self._call("PATCH", f"/api/v1/policies/{quote(policy_id, safe='')}/pass-through/disable")

    def audit_policies(self, application_id: Optional[str] = None) -> Dict[str, Any]:
        """Report which policies are live, shadowed or disabled.

        Run it at boot and log the result rather than assuming the control plane
        matches your code.
        """
        policies = self.list_policies(application_id)
        return {
            "total": len(policies),
            "disabled": [p.get("name") for p in policies if not p.get("enabled")],
            "shadow": [
                p.get("name") for p in policies if p.get("enabled") and p.get("pass_through")
            ],
            "live": [
                p.get("name") for p in policies if p.get("enabled") and not p.get("pass_through")
            ],
        }

    # -- lists --------------------------------------------------------------

    def list_lists(self, application_id: Optional[str] = None) -> List[Dict[str, Any]]:
        body = self._call(
            "GET", "/api/v1/lists", query={"application_id": self._app_id(application_id)}
        )
        return body.get("lists") or []

    def get_list_entries(
        self, list_id: str, limit: int = 100, offset: int = 0
    ) -> List[Dict[str, Any]]:
        body = self._call(
            "GET",
            f"/api/v1/lists/{quote(list_id, safe='')}/entries",
            query={"limit": str(limit), "offset": str(offset)},
        )
        return body.get("entries") or []

    def add_list_entry(
        self,
        list_id: str,
        value: str,
        comment: Optional[str] = None,
        expires_at: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """Add one value — a device id, IP, email domain, BIN — to a list."""
        if not str(value or "").strip():
            raise ValidationError("value is required")
        payload: Dict[str, Any] = {"value": value}
        if comment:
            payload["comment"] = comment
        if expires_at is not None:
            payload["expires_at"] = to_iso(expires_at)
        return self._call(
            "POST", f"/api/v1/lists/{quote(list_id, safe='')}/entries", body=payload
        )

    def add_list_entries(self, list_id: str, entries: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
        """Bulk add. The API accepts at most 1000 entries per call."""
        if not entries:
            raise ValidationError("at least one entry is required")
        if len(entries) > 1000:
            raise ValidationError(
                f"the API accepts at most 1000 entries per call, got {len(entries)}"
            )
        prepared = []
        for entry in entries:
            item: Dict[str, Any] = {"value": entry["value"]}
            if entry.get("comment"):
                item["comment"] = entry["comment"]
            if entry.get("expires_at") is not None:
                item["expires_at"] = to_iso(entry["expires_at"])
            prepared.append(item)
        return self._call(
            "POST",
            f"/api/v1/lists/{quote(list_id, safe='')}/entries/bulk",
            body={"entries": prepared},
        )

    def archive_list_entry(self, list_id: str, entry_id: str) -> None:
        self._call(
            "PATCH",
            f"/api/v1/lists/{quote(list_id, safe='')}/entries/{quote(entry_id, safe='')}/archive",
        )

    def delete_list_entry(self, list_id: str, entry_id: str) -> None:
        self._call(
            "DELETE",
            f"/api/v1/lists/{quote(list_id, safe='')}/entries/{quote(entry_id, safe='')}",
        )

    # -- internals ----------------------------------------------------------

    def _app_id(self, override: Optional[str]) -> Optional[str]:
        return override or self._config.application_id

    def _call(
        self,
        method: str,
        path: str,
        query: Optional[Mapping[str, Optional[str]]] = None,
        body: Optional[Any] = None,
    ) -> Dict[str, Any]:
        if not self._token:
            raise ConfigurationError(
                "management calls need a portal JWT: client.management.with_token(jwt). "
                "The private API key does not authorise the policy and list endpoints."
            )

        outcome = self._transport.send(
            RequestSpec(
                method=method,
                path=path,
                query=query,
                body=body,
                omit_api_key=True,
                headers={"Authorization": f"Bearer {self._token}"},
            )
        )

        if outcome.transport_error:
            raise ApiError(outcome.transport_error, outcome.status_code, outcome.body)
        if outcome.status_code >= 400:
            detail = "no detail"
            if isinstance(outcome.body, dict):
                detail = outcome.body.get("error") or outcome.body.get("message") or detail
            raise ApiError(
                f"{method} {path} failed: HTTP {outcome.status_code} — {detail}",
                outcome.status_code,
                outcome.body,
            )
        return outcome.body or {}


__all__ = ["ManagementClient"]
