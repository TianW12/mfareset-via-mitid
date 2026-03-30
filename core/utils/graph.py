import os
from typing import Any

import msal
import requests


def require_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"Missing or empty environment variable: {name}")
    return value


TENANT_ID = require_env("AZURE_TENANT_ID")
CLIENT_ID = require_env("AZURE_APP_REGISTRATION_CLIENT_ID")
CLIENT_SECRET = require_env("AZURE_APP_REGISTRATION_CLIENT_SECRET")

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPES = ["https://graph.microsoft.com/.default"]

# In-memory app token cache is handled by MSAL automatically.
_msal_app = msal.ConfidentialClientApplication(
    client_id=CLIENT_ID,
    client_credential=CLIENT_SECRET,
    authority=AUTHORITY,
)


def get_app_access_token() -> str:
    result = _msal_app.acquire_token_for_client(scopes=SCOPES)
    if "access_token" not in result:
        raise RuntimeError(
            f"Failed to acquire Graph token: "
            f"{result.get('error')} - {result.get('error_description')}"
        )
    return result["access_token"]


def graph_get(url: str) -> dict[str, Any]:
    token = get_app_access_token()
    response = requests.get(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        },
        timeout=30,
    )
    response.raise_for_status()
    return response.json()


def list_user_authentication_methods(user_principal_name: str) -> list[dict[str, Any]]:
    url = (
        "https://graph.microsoft.com/v1.0/"
        f"users/{user_principal_name}/authentication/methods"
    )
    data = graph_get(url)
    return data.get("value", [])