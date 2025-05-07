from jose import jwt
import aiohttp

TENANT_ID = "d2e7c801-ebde-478a-8094-73a9bce9a69c"  # Replace with your real tenant ID
CLIENT_ID = "e32115d3-fda1-424d-b36a-935cb75f09af"  # Replace with your app registration client ID
JWK_URL = f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys"
ALGORITHM = "RS256"

def get_user_roles_from_token(headers: dict):
    """
    Extract roles from the ID token passed via EasyAuth header.
    """
    id_token = headers.get("X-Ms-Token-Aad-Id-Token")
    if not id_token:
        logging.warning("Missing X-Ms-Token-Aad-Id-Token header")
        return []

    try:
        # Parse the token without verifying the signature (since it's already trusted in EasyAuth context)
        claims = jwt.get_unverified_claims(id_token)
        return claims.get("roles", [])
    except Exception as e:
        logging.exception("Failed to extract roles from ID token")
        return []

def get_authenticated_user_details(request_headers):
    user_object = {}

    ## check the headers for the Principal-Id (the guid of the signed in user)
    if "X-Ms-Client-Principal-Id" not in request_headers.keys():
        ## if it's not, assume we're in development mode and return a default user
        from . import sample_user
        raw_user_object = sample_user.sample_user
    else:
        ## if it is, get the user details from the EasyAuth headers
        raw_user_object = {k:v for k,v in request_headers.items()}

    user_object['user_principal_id'] = raw_user_object.get('X-Ms-Client-Principal-Id')
    user_object['user_name'] = raw_user_object.get('X-Ms-Client-Principal-Name')
    user_object['auth_provider'] = raw_user_object.get('X-Ms-Client-Principal-Idp')
    user_object['auth_token'] = raw_user_object.get('X-Ms-Token-Aad-Id-Token')
    user_object['client_principal_b64'] = raw_user_object.get('X-Ms-Client-Principal')
    user_object['aad_id_token'] = raw_user_object.get('X-Ms-Token-Aad-Id-Token')

    return user_object

from functools import wraps
from quart import request, jsonify

def require_login(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        headers = request.headers
        user_email = headers.get("X-User-Email")
        if not user_email or user_email not in authenticated_users:
            return jsonify({"error": "Unauthorized"}), 401
        return await func(*args, **kwargs)
    return wrapper
