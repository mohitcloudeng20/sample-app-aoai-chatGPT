from flask import request, abort
from google.auth import jwt
from google.auth.transport import requests as grequests

def verify_google_chat_request():
    """Verifies that the incoming request is from Google Chat."""
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        abort(401, "Missing Authorization Header")

    parts = auth_header.split()
    if parts[0].lower() != 'bearer' or len(parts) != 2:
        abort(401, "Invalid Authorization Header")

    token = parts[1]
    request_adapter = grequests.Request()

    try:
        info = jwt.decode(token, request_adapter, audience="YOUR_GOOGLE_CHAT_BOT_URL")
        return info  # You could use fields like info['sub'] later if needed
    except Exception as e:
        print(f"Token verification failed: {e}")
        abort(401, "Unauthorized")
