#!/usr/bin/env python3
import json
import os
import sys

import requests
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

    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/token"

 

    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "client_credentials",
    }

    try:
        response = requests.post(token_url, data=data, timeout=30)
    except requests.RequestException as exc:
        print(f"HTTP request failed: {exc}", file=sys.stderr)
        return 1

    print(f"HTTP {response.status_code}")

    try:
        body = response.json()
    except ValueError:
        print("Non-JSON response:")
        print(response.text)
        return 1

    print(json.dumps(body, indent=2))

    if response.ok and "access_token" in body:
        print("\nSUCCESS: access token received")
        return 0

    print("\nFAILED: no access token returned", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())