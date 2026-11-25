#!/usr/bin/env python3
"""Developer CLI to view recent anonymous diagnostic reports in Cloud Firestore (wgplus-qa)."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import urllib.error
import urllib.request

FIRESTORE_URL = (
    "https://firestore.googleapis.com/v1/projects/wgplus-qa/"
    "databases/(default)/documents/wgplus_diagnostics"
)


def resolve_gcloud_token() -> str:
    gcloud = shutil.which("gcloud")
    if not gcloud:
        raise RuntimeError("gcloud CLI not found on PATH. Authenticate via gcloud auth application-default login.")
    out = subprocess.check_output([gcloud, "auth", "print-access-token"], text=True, timeout=15)
    tok = out.strip()
    if not tok:
        raise RuntimeError("Empty access token from gcloud auth print-access-token")
    return tok


def str_val(fields: dict, key: str, default: str = "") -> str:
    v = fields.get(key) or {}
    return v.get("stringValue", v.get("integerValue", default))


def main() -> int:
    parser = argparse.ArgumentParser(description="Fetch WireGuard Plus automatic diagnostic reports.")
    parser.add_argument("--limit", type=int, default=20, help="Maximum reports to fetch")
    parser.add_argument("--trigger", default="", help="Filter by triggerCode (e.g. VERIFY_ROUTE_FAILED)")
    args = parser.parse_args()

    try:
        token = resolve_gcloud_token()
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    url = f"{FIRESTORE_URL}?pageSize={max(1, min(100, args.limit))}"
    req = urllib.request.Request(
        url,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        print(f"[ERROR] HTTP {exc.code}: {exc.read().decode('utf-8', 'replace')}", file=sys.stderr)
        return 1

    docs = payload.get("documents", [])
    shown = 0
    for doc in docs:
        fields = doc.get("fields", {})
        trig = str_val(fields, "triggerCode")
        if args.trigger and trig != args.trigger:
            continue
        shown += 1
        print("=" * 72)
        print(
            f"[{str_val(fields, 'createdAt')}] {trig} | "
            f"{str_val(fields, 'deviceModel')} Android {str_val(fields, 'androidRelease')} "
            f"(SDK {str_val(fields, 'sdkInt')}) | {str_val(fields, 'hostPackage')} "
            f"{str_val(fields, 'hostVersion')} | mod v{str_val(fields, 'moduleVersion')} | "
            f"tier={str_val(fields, 'continuityTier')}"
        )
        print(str_val(fields, "reportMarkdown"))
    print(f"\nDisplayed {shown} diagnostic report(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
