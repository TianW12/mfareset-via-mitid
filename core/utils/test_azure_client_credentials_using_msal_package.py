#!/usr/bin/env python3
import json
import os
import sys

import msal
from dotenv import load_dotenv


def require_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise ValueError(f"Missing or empty required environment variable: {name}")
    return value


def main() -> int:
    load_dotenv()

    try:
        tenant_id = require_env("AZURE_TENANT_ID")
        client_id = require_env("AZURE_APP_REGISTRATION_CLIENT_ID")
        client_secret = require_env("AZURE_APP_REGISTRATION_CLIENT_SECRET")
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    authority = f"https://login.microsoftonline.com/{tenant_id}"
    scopes = ["https://graph.microsoft.com/.default"]

    app = msal.ConfidentialClientApplication(
        client_id=client_id,
        client_credential=client_secret,
        authority=authority,
    )

    result = app.acquire_token_for_client(scopes=scopes)

    print(json.dumps(result, indent=2))

    if "access_token" in result:
        print("\nSUCCESS: access token received")
        return 0

    print("\nFAILED: no access token returned", file=sys.stderr)
    print(f"error: {result.get('error')}", file=sys.stderr)
    print(f"error_description: {result.get('error_description')}", file=sys.stderr)
    print(f"correlation_id: {result.get('correlation_id')}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())