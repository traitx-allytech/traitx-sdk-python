"""Runs sdk/conformance/vectors.json against the Python decision engine.

    cd sdk/python && python -m unittest discover -s tests -v

Every language SDK ships the equivalent of this file. If a vector fails here but
passes elsewhere, the bindings have drifted.
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from traitx import Action, HttpOutcome, build_config, resolve_decision  # noqa: E402

def _locate_vectors() -> Path:
    """Find the shared fixture whether this lives in the monorepo or its own repo."""
    here = Path(__file__).resolve()
    for parent in (here.parent, *here.parents):
        candidate = parent / "conformance" / "vectors.json"
        if candidate.is_file():
            return candidate
    raise FileNotFoundError("could not find conformance/vectors.json")


VECTORS = json.loads(_locate_vectors().read_text())


def config_for(overrides: dict):
    defaults = VECTORS["defaults"]["config"]
    thresholds = {**defaults["thresholds"], **(overrides.get("thresholds") or {})}
    return build_config(
        base_url="https://example.test",
        api_key="trx_pvk_conformance_key_0000",
        failure_mode=Action(overrides.get("failureMode", defaults["failureMode"])),
        client_error_mode=Action(overrides.get("clientErrorMode", defaults["clientErrorMode"])),
        challenge_threshold=thresholds["challenge"],
        deny_threshold=thresholds["deny"],
        deny_on_signals=overrides.get("denyOnSignals", defaults["denyOnSignals"]),
        challenge_on_signals=overrides.get(
            "challengeOnSignals", defaults["challengeOnSignals"]
        ),
        enforce_shadow_decisions=overrides.get(
            "enforceShadowDecisions", defaults["enforceShadowDecisions"]
        ),
    )


def outcome_for(http: dict) -> HttpOutcome:
    if http.get("transportError"):
        return HttpOutcome(status_code=0, latency_ms=3, transport_error=http["transportError"])
    if "rawBody" in http:
        # A body that is not decodable JSON reaches the engine as body=None.
        return HttpOutcome(status_code=http["status"], latency_ms=3, body=None)
    status = http["status"]
    retryable = status >= 500 or status in (408, 429)
    return HttpOutcome(
        status_code=status,
        latency_ms=3,
        body=http.get("body"),
        transport_error=f"risk api returned HTTP {status}" if retryable else None,
    )


class ConformanceTest(unittest.TestCase):
    maxDiff = None


def _make_test(vector: dict):
    def test(self: ConformanceTest) -> None:
        config = config_for(vector.get("config") or {})
        decision = resolve_decision(outcome_for(vector["http"]), config, "req_conformance")
        want = vector["expect"]

        self.assertEqual(decision.action.value, want["action"], "action")

        if "observedAction" in want:
            observed = decision.observed_action.value if decision.observed_action else None
            self.assertEqual(observed, want["observedAction"], "observed_action")
        if "enforced" in want:
            self.assertEqual(decision.enforced, want["enforced"], "enforced")
        if "reason" in want:
            self.assertEqual(decision.reason.value, want["reason"], "reason")
        if "score" in want:
            self.assertEqual(decision.score, want["score"], "score")
        if "riskLevel" in want:
            self.assertEqual(decision.risk_level.value, want["riskLevel"], "risk_level")
        if "degraded" in want:
            self.assertEqual(decision.degraded, want["degraded"], "degraded")
        if "statusCode" in want:
            self.assertEqual(decision.status_code, want["statusCode"], "status_code")
        if "matchedCount" in want:
            self.assertEqual(len(decision.matched_policies), want["matchedCount"], "matched")
        if "firstMatchedId" in want:
            self.assertEqual(decision.matched_policies[0].id, want["firstMatchedId"])
        if "firstMatchedName" in want:
            self.assertEqual(decision.matched_policies[0].name, want["firstMatchedName"])
        if "hasError" in want:
            self.assertEqual(bool(decision.error), want["hasError"], "error present")
        if "hasDeviceContext" in want:
            self.assertEqual(
                decision.has_device_context(), want["hasDeviceContext"], "has_device_context"
            )

        # Invariants that hold for every vector.
        self.assertIn(decision.action, list(Action))
        self.assertEqual(decision.is_allowed(), decision.action == Action.ALLOW)
        self.assertFalse(decision.is_allowed() and decision.is_denied())

    return test


for index, _vector in enumerate(VECTORS["vectors"]):
    slug = "".join(ch if ch.isalnum() else "_" for ch in _vector["name"])[:80]
    setattr(ConformanceTest, f"test_{index:02d}_{slug}", _make_test(_vector))


class ReasonCoverageTest(unittest.TestCase):
    def test_every_reason_is_exercised(self) -> None:
        seen = {v["expect"].get("reason") for v in VECTORS["vectors"]}
        for reason in (
            "policy_match",
            "shadow",
            "score_threshold",
            "signal_override",
            "no_match",
            "degraded",
            "client_error",
        ):
            self.assertIn(reason, seen, f'no vector exercises reason "{reason}"')


if __name__ == "__main__":
    unittest.main()
