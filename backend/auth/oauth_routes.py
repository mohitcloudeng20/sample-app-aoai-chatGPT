from quart import Blueprint, redirect, request, session, url_for, jsonify
import os, uuid
from msal import ConfidentialClientApplication

bp_auth = Blueprint("auth", __name__)

TENANT_ID = os.environ["AZURE_TENANT_ID"]
CLIENT_ID = os.environ["AZURE_CLIENT_ID"]
CLIENT_SECRET = os.environ["AZURE_CLIENT_SECRET"]
REDIRECT_PATH = "/auth/callback"
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPES = ["User.Read"]

authenticated_users = {}  # TEMPORARY: Replace with Redis/Cosmos later

@bp_auth.route("/auth/login")
async def login():
    session["state"] = str(uuid.uuid4())
    client = ConfidentialClientApplication(CLIENT_ID, authority=AUTHORITY, client_credential=CLIENT_SECRET)
    auth_url = client.get_authorization_request_url(
        SCOPES,
        state=session["state"],
        redirect_uri=url_for("auth.auth_callback", _external=True)
    )
    return redirect(auth_url)

@bp_auth.route(REDIRECT_PATH)
async def auth_callback():
    if request.args.get("state") != session.get("state"):
        return jsonify({"error": "State mismatch"}), 401

    code = request.args.get("code")
    client = ConfidentialClientApplication(CLIENT_ID, authority=AUTHORITY, client_credential=CLIENT_SECRET)
    token_response = client.acquire_token_by_authorization_code(
        code, scopes=SCOPES,
        redirect_uri=url_for("auth.auth_callback", _external=True)
    )

    if "access_token" in token_response:
        user = token_response["id_token_claims"]
        upn = user.get("preferred_username")
        authenticated_users[upn] = token_response["access_token"]
        return f"✅ You're signed in as {upn}. You can go back to Google Chat now."

    return jsonify({"error": "Login failed"}), 401
