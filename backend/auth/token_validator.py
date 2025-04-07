import jwt
import requests
from jwt.algorithms import RSAAlgorithm

# Caching keys for faster reuse
_jwks = None

def get_openid_config(tenant_id):
    url = f"https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration"
    return requests.get(url).json()

def get_jwks(tenant_id):
    global _jwks
    if _jwks is None:
        openid_config = get_openid_config(tenant_id)
        jwks_uri = openid_config["jwks_uri"]
        _jwks = requests.get(jwks_uri).json()
    return _jwks

def validate_jwt(token: str, tenant_id: str, client_id: str):
    jwks = get_jwks(tenant_id)
    unverified_header = jwt.get_unverified_header(token)
    key = None

    for k in jwks["keys"]:
        if k["kid"] == unverified_header["kid"]:
            key = RSAAlgorithm.from_jwk(k)
            break

    if not key:
        raise ValueError("Unable to find appropriate key")

    payload = jwt.decode(
        token,
        key=key,
        algorithms=["RS256"],
        audience=client_id,
        issuer=f"https://login.microsoftonline.com/{tenant_id}/v2.0"
    )
    return payload
