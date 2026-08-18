"""Integration self-check.

::

    TRAITX_BASE_URL=https://traitx.allytech.sa \\
    TRAITX_PRIVATE_KEY=trx_pvk_... \\
    TRAITX_APPLICATION_ID=ccf2d2a0-... \\
    python -m traitx.doctor [collector-request-id]

Pass a real ``requestId`` from your browser collector to also verify that the key
is accepted, that IP enrichment is attached and that the policy chain returns an
action. Without one, only connectivity and configuration are checked.
See SPEC.md section 13.
"""

from __future__ import annotations

import os
import sys
from typing import Optional

from .client import TraitXClient


def main(argv: Optional[list] = None) -> int:
    argv = list(sys.argv if argv is None else argv)
    base_url = os.environ.get("TRAITX_BASE_URL")
    api_key = os.environ.get("TRAITX_PRIVATE_KEY")

    if not base_url or not api_key:
        print("set TRAITX_BASE_URL and TRAITX_PRIVATE_KEY", file=sys.stderr)
        return 2

    client = TraitXClient(
        base_url=base_url,
        api_key=api_key,
        application_id=os.environ.get("TRAITX_APPLICATION_ID"),
        timeout_ms=int(os.environ.get("TRAITX_TIMEOUT_MS", "5000")),
    )

    probe = argv[1] if len(argv) > 1 else None
    report = client.doctor(probe)

    for finding in report["findings"]:
        status = "ok  " if finding["ok"] else "FAIL"
        print(f"{status}  {finding['check']:<32} {finding['detail']}")

    print()
    print("All checks passed." if report["ok"] else "Some checks failed — see above.")
    return 0 if report["ok"] else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv))
