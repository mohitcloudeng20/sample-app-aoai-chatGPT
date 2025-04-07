import jwt
import requests
from jwt.algorithms import RSAAlgorithm

_jwks = None

def get_openid_config(tenant_id):
    return requests.get(f"https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration").json()

def get_jwks(tenant_id):
    global _jwks
    if _jwks is None:
        jwks_uri = get_openid_config(tenant_id)["jwks_uri"]
        _jwks = requests.get(jwks_uri).json()
    return _jwks

def validate_jwt(token, tenant_id, client_id):
    jwks = get_jwks(tenant_id)
    header = jwt.get_unverified_header(token)
    key = next((RSAAlgorithm.from_jwk(k) for k in jwks["keys"] if k["kid"] == header["kid"]), None)
    if not key:
        raise Exception("Unable to find matching key")

    return jwt.decode(
        token,
        key=key,
        algorithms=["RS256"],
        audience=client_id,
        issuer=f"https://login.microsoftonline.com/{tenant_id}/v2.0"
    )
