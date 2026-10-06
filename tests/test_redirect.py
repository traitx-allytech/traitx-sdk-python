"""Redirect policy (SDK-01): the transport must never follow a redirect.

urllib's default redirect handler replays the request — with ``X-API-Key`` and
``Authorization`` — against whatever the ``Location`` header names. These
tests run two loopback HTTP servers and assert the redirect target is never
reached, for cross-host, port-change and management-JWT cases, plus a
same-origin redirect (also refused: no retry loop, no credential replay) and
the HTTPS→HTTP downgrade rule on the pure origin check.
"""

from __future__ import annotations

import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from traitx import Action, ApiError, EventUser, TraitXClient  # noqa: E402
from traitx.http import is_same_origin  # noqa: E402

API_KEY = "trx_pvk_test_key_abcd"


class _Server:
    """Loopback server that records every request's headers."""

    def __init__(self, redirect_to: Optional[str] = None, status: int = 302) -> None:
        self.hits: List[Dict[str, str]] = []
        self.paths: List[str] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def _handle(self) -> None:
                outer.hits.append({k.lower(): v for k, v in self.headers.items()})
                outer.paths.append(self.path)
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    self.rfile.read(length)
                if outer.redirect_to is not None:
                    self.send_response(outer.status)
                    if outer.redirect_to:
                        self.send_header("Location", outer.redirect_to)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                body = json.dumps({"score": 1, "signals": [], "matched_policies": []}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = do_POST = _handle  # type: ignore[assignment]

            def log_message(self, *args: object) -> None:  # silence
                pass

        self.redirect_to = redirect_to
        self.status = status
        self.httpd = HTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


class RedirectTest(unittest.TestCase):
    def setUp(self) -> None:
        self.target = _Server()
        self.addCleanup(self.target.close)

    def _origin(self, location: Optional[str], status: int = 302) -> _Server:
        origin = _Server(redirect_to=location, status=status)
        self.addCleanup(origin.close)
        return origin

    def _client(self, origin: _Server, **options: object) -> TraitXClient:
        return TraitXClient(base_url=origin.base_url, api_key=API_KEY, max_retries=2, **options)

    def test_cross_host_302_is_not_followed(self) -> None:
        # Different hostname (localhost vs 127.0.0.1) and different port.
        target_port = self.target.httpd.server_address[1]
        origin = self._origin(f"http://localhost:{target_port}/api/v1/risk")
        decision = self._client(origin, failure_mode=Action.DENY).evaluate_login(
            "req_1", user=EventUser(id="u1")
        )

        self.assertEqual(self.target.hits, [], "redirect target must never see the request")
        self.assertEqual(len(origin.hits), 1, "a redirect must not be retried")
        self.assertEqual(origin.hits[0]["x-api-key"], API_KEY)
        self.assertTrue(decision.degraded)
        self.assertEqual(decision.action, Action.DENY)
        self.assertIn("cross-origin", decision.error or "")

    def test_port_change_is_not_followed(self) -> None:
        origin = self._origin(f"{self.target.base_url}/api/v1/risk", status=307)
        decision = self._client(origin).evaluate_login("req_1", user=EventUser(id="u1"))

        self.assertEqual(self.target.hits, [])
        self.assertEqual(len(origin.hits), 1)
        self.assertTrue(decision.degraded)
        self.assertIn("cross-origin", decision.error or "")

    def test_same_origin_redirect_is_refused_without_retry(self) -> None:
        origin = self._origin("/api/v1/risk/", status=308)
        decision = self._client(origin).evaluate_login("req_1", user=EventUser(id="u1"))

        self.assertEqual(len(origin.hits), 1, "same-origin redirect must not be followed or retried")
        self.assertEqual(origin.paths, ["/api/v1/risk"])
        self.assertTrue(decision.degraded)
        self.assertIn("same-origin", decision.error or "")

    def test_redirect_without_location_is_refused(self) -> None:
        origin = self._origin("", status=302)
        decision = self._client(origin).evaluate_login("req_1", user=EventUser(id="u1"))

        self.assertEqual(len(origin.hits), 1)
        self.assertTrue(decision.degraded)
        self.assertIn("without a usable Location", decision.error or "")

    def test_management_jwt_is_not_forwarded_cross_host(self) -> None:
        target_port = self.target.httpd.server_address[1]
        origin = self._origin(f"http://localhost:{target_port}/api/v1/policies")
        client = self._client(origin, application_id="app-1")

        with self.assertRaises(ApiError) as raised:
            client.management.with_token("eyJ.jwt.token").list_policies()

        self.assertIn("cross-origin", str(raised.exception))
        self.assertEqual(self.target.hits, [])
        self.assertEqual(len(origin.hits), 1)
        self.assertEqual(origin.hits[0]["authorization"], "Bearer eyJ.jwt.token")

    def test_non_redirect_responses_still_work(self) -> None:
        origin = self._origin(None)
        decision = self._client(origin).evaluate_login("req_1", user=EventUser(id="u1"))
        self.assertFalse(decision.degraded)
        self.assertEqual(origin.hits[0]["x-api-key"], API_KEY)


class SameOriginTest(unittest.TestCase):
    def test_scheme_host_and_port_must_match(self) -> None:
        self.assertTrue(is_same_origin("https://a.example/x", "https://a.example/y"))
        self.assertTrue(is_same_origin("https://a.example/x", "/y"))
        self.assertTrue(is_same_origin("https://a.example:443/x", "https://a.example/y"))
        self.assertFalse(is_same_origin("https://a.example/x", "https://b.example/x"))
        self.assertFalse(is_same_origin("https://a.example/x", "https://a.example:8443/x"))

    def test_https_to_http_downgrade_is_a_different_origin(self) -> None:
        self.assertFalse(is_same_origin("https://a.example/x", "http://a.example/x"))

    def test_garbage_is_never_same_origin(self) -> None:
        self.assertFalse(is_same_origin("not a url", "https://a.example/x"))
        self.assertFalse(is_same_origin("https://a.example/x", "https://a.example:notaport/x"))


if __name__ == "__main__":
    unittest.main()
