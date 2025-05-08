from jose import jwt
import aiohttp
import os
import logging

# Get these from environment variables instead of hardcoding
TENANT_ID = os.environ.get("AZURE_TENANT_ID", "d2e7c801-ebde-478a-8094-73a9bce9a69c")
CLIENT_ID = os.environ.get("AZURE_CLIENT_ID", "e32115d3-fda1-424d-b36a-935cb75f09af")
JWK_URL = f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys"
ALGORITHM = "RS256"

async def get_user_roles_from_token(auth_header: str):
    """Extract roles from the Azure AD token"""
    if not auth_header or not auth_header.startswith("Bearer "):
        logging.warning("Missing or invalid authorization header")
        return []

    token = auth_header.split("Bearer ")[-1]

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(JWK_URL) as resp:
                jwks = await resp.json()
                unverified_header = jwt.get_unverified_header(token)
                key = next((k for k in jwks["keys"] if k["kid"] == unverified_header["kid"]), None)
                if not key:
                    logging.warning("No matching key found in JWKS")
                    return []

                public_key = jwt.construct_rsa_public_key(key)
                payload = jwt.decode(
                    token,
                    public_key,
                    algorithms=[ALGORITHM],
                    audience=CLIENT_ID,
                    issuer=f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"
                )
                
                # Extract roles - Azure AD app roles will be in the "roles" claim
                roles = payload.get("roles", [])
                logging.info(f"User roles extracted from token: {roles}")
                return roles
    except Exception as e:
        logging.exception("Error extracting roles from token")
        return []

def get_authenticated_user_details(request_headers):
    """Get user details from EasyAuth headers"""
    user_object = {}

    # Check if we're running in Azure with EasyAuth
    if "X-Ms-Client-Principal-Id" not in request_headers.keys():
        # Development mode - you can customize this for testing
        from . import sample_user
        raw_user_object = sample_user.sample_user
        # For testing, you might want to simulate different roles
        # sample_user.sample_user could have predefined roles for development
    else:
        # Production mode with EasyAuth
        raw_user_object = {k:v for k,v in request_headers.items()}

    user_object['user_principal_id'] = raw_user_object.get('X-Ms-Client-Principal-Id')
    user_object['user_name'] = raw_user_object.get('X-Ms-Client-Principal-Name')
    user_object['auth_provider'] = raw_user_object.get('X-Ms-Client-Principal-Idp')
    user_object['auth_token'] = raw_user_object.get('X-Ms-Token-Aad-Id-Token')
    user_object['client_principal_b64'] = raw_user_object.get('X-Ms-Client-Principal')
    user_object['aad_id_token'] = raw_user_object.get('X-Ms-Token-Aad-Id-Token')

    return user_object

# Define role-based decorators
from functools import wraps
from quart import request, jsonify

def require_role(role_name):
    """Decorator to require a specific role"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                auth_header = request.headers.get("Authorization")
                roles = await get_user_roles_from_token(auth_header)
                
                if not roles or role_name not in roles:
                    logging.warning(f"Access denied: required role '{role_name}' not found. User roles: {roles}")
                    return jsonify({"error": "Unauthorized - Required role not assigned"}), 403
                
                return await func(*args, **kwargs)
            except Exception as e:
                logging.exception("Error in role authorization")
                return jsonify({"error": "Authorization error"}), 401
        return wrapper
    return decorator

# Decorator for Admin role
def require_admin(func):
    return require_role("Admin")(func)

# Decorator for User role
def require_user(func):
    return require_role("User")(func)
