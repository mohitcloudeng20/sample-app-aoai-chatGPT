from jose import jwt
import aiohttp

TENANT_ID = "d2e7c801-ebde-478a-8094-73a9bce9a69c"  # Replace with your real tenant ID
CLIENT_ID = "e32115d3-fda1-424d-b36a-935cb75f09af"  # Replace with your app registration client ID
JWK_URL = f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys"
ALGORITHM = "RS256"

async def get_user_roles_from_token(auth_header: str):
    if not auth_header or not auth_header.startswith("Bearer "):
        return []

    token = auth_header.split("Bearer ")[-1]

    async with aiohttp.ClientSession() as session:
        async with session.get(JWK_URL) as resp:
            jwks = await resp.json()
            unverified_header = jwt.get_unverified_header(token)
            key = next((k for k in jwks["keys"] if k["kid"] == unverified_header["kid"]), None)
            if not key:
                return []

            public_key = jwt.construct_rsa_public_key(key)
            payload = jwt.decode(
                token,
                public_key,
                algorithms=[ALGORITHM],
                audience=CLIENT_ID,
                issuer=f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"
            )
            return payload.get("roles", [])

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
