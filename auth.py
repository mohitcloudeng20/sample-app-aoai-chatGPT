import os
from flask import Blueprint, redirect, request, session, url_for
from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
from google.auth.transport import requests as grequests

auth_bp = Blueprint('auth', __name__)

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")

# Replace with your real values!
REDIRECT_URI = "https://it-bot.azurewebsites.net/oauth2callback"

@auth_bp.route("/login")
def login():
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        },
        scopes=["openid", "email", "profile"],
        redirect_uri=REDIRECT_URI
    )
    auth_url, _ = flow.authorization_url(prompt="consent")
    return redirect(auth_url)

@auth_bp.route("/oauth2callback")
def oauth2callback():
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        },
        scopes=["openid", "email", "profile"],
        redirect_uri=REDIRECT_URI
    )

    flow.fetch_token(authorization_response=request.url)

    if not flow.credentials:
        return "Login failed", 401

    idinfo = id_token.verify_oauth2_token(
        flow.credentials.id_token,
        grequests.Request(),
        GOOGLE_CLIENT_ID
    )

    session['email'] = idinfo['email']
    session['name'] = idinfo.get('name', '')
    return redirect(url_for('home'))  # Redirect wherever you want
