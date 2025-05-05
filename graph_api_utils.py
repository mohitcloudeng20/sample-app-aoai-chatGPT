import os
from datetime import datetime, timedelta
from msal import ConfidentialClientApplication
import httpx

GRAPH_API_BASE = "https://graph.microsoft.com"

def get_graph_client_token():
    app = ConfidentialClientApplication(
        client_id=os.getenv("AZURE_CLIENT_ID"),
        client_credential=os.getenv("AZURE_CLIENT_SECRET"),
        authority=f"https://login.microsoftonline.com/{os.getenv('AZURE_TENANT_ID')}"
    )
    token_response = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
    if "access_token" not in token_response:
        raise Exception(f"Failed to get access token: {token_response.get('error_description')}")
    return token_response["access_token"]

async def fetch_user_graph_data(user_principal_name):
    token = get_graph_client_token()
    headers = {"Authorization": f"Bearer {token}"}

    async with httpx.AsyncClient() as client:
        # Use beta endpoint for passwordProfile
        profile_resp = await client.get(f"{GRAPH_API_BASE}/beta/users/{user_principal_name}", headers=headers)
        groups_resp = await client.get(f"{GRAPH_API_BASE}/v1.0/users/{user_principal_name}/memberOf", headers=headers)

        if profile_resp.status_code != 200 or groups_resp.status_code != 200:
            raise Exception(f"Graph API error: {profile_resp.text} / {groups_resp.text}")

        profile = profile_resp.json()
        groups = groups_resp.json().get("value", [])

        last_password_change = profile.get("passwordProfile", {}).get("lastPasswordChangeDateTime")
        expiry_estimate = None

        if last_password_change:
            expiry_days = int(os.getenv("PASSWORD_EXPIRY_DAYS", 90))
            last_change_dt = datetime.fromisoformat(last_password_change.rstrip("Z"))
            expiry_estimate = (last_change_dt + timedelta(days=expiry_days)).strftime("%Y-%m-%d")

        return {
            "displayName": profile.get("displayName"),
            "email": profile.get("userPrincipalName"),
            "lastPasswordChange": last_password_change,
            "passwordExpiryEstimate": expiry_estimate,
            "groups": [g.get("displayName", "Unnamed Group") for g in groups if "displayName" in g]
        }
