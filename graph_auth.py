import os
from msal import ConfidentialClientApplication
import requests
from graph_auth import get_graph_token

# Load from env
TENANT_ID     = os.getenv("AZURE_TENANT_ID")
CLIENT_ID     = os.getenv("AZURE_CLIENT_ID")
CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET")

# Authority URL for MSAL
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"

# Scopes for client-credentials: the “.default” scope bundle for Graph
SCOPE = ["https://graph.microsoft.com/.default"]

_msal_app = ConfidentialClientApplication(
    CLIENT_ID,
    authority=AUTHORITY,
    client_credential=CLIENT_SECRET
)

def get_graph_token() -> str:
    """Acquire an app-only token for Microsoft Graph."""
    result = _msal_app.acquire_token_for_client(scopes=SCOPE)
    if "access_token" not in result:
        raise RuntimeError(f"Could not acquire token: {result.get('error_description')}")
    return result["access_token"]

GRAPH_BASE = "https://graph.microsoft.com/v1.0"

def get_user_by_email(email: str) -> dict:
    """Look up a user by email (userPrincipalName)."""
    token = get_graph_token()
    url   = f"{GRAPH_BASE}/users/{email}"
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(url, headers=headers)
    resp.raise_for_status()
    return resp.json()

def list_all_users() -> dict:
    """Retrieve all users in the tenant."""
    token = get_graph_token()
    url   = f"{GRAPH_BASE}/users"
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(url, headers=headers)
    resp.raise_for_status()
    return resp.json()
