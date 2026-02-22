import time
from typing import Any

import httpx
import jwt
from jwt import PyJWK
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import settings

_bearer = HTTPBearer()

_jwks: dict[str, Any] = {}
_jwks_fetched_at: float = 0
_oidc_issuer: str | None = None
_JWKS_TTL = 3600


async def _fetch_jwks() -> dict[str, Any]:
    """Fetch and cache the OIDC provider's JSON Web Key Set."""
    global _jwks, _jwks_fetched_at, _oidc_issuer

    if _jwks and (time.time() - _jwks_fetched_at) < _JWKS_TTL:
        return _jwks

    discovery_url = f"{settings.OIDC_ISSUER.rstrip('/')}/.well-known/openid-configuration"
    async with httpx.AsyncClient() as client:
        resp = await client.get(discovery_url, timeout=10)
        resp.raise_for_status()
        config = resp.json()
        _oidc_issuer = config["issuer"]

        jwks_resp = await client.get(config["jwks_uri"], timeout=10)
        jwks_resp.raise_for_status()
        _jwks = jwks_resp.json()
        _jwks_fetched_at = time.time()

    return _jwks


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
) -> dict[str, Any]:
    """Validate the Bearer token against the OIDC provider's JWKS."""
    token = credentials.credentials

    try:
        jwks = await _fetch_jwks()
        header = jwt.get_unverified_header(token)

        key_data = next(
            (k for k in jwks.get("keys", []) if k["kid"] == header.get("kid")),
            None,
        )
        if not key_data:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Signing key not found")

        signing_key = PyJWK.from_dict(key_data)

        decode_kwargs: dict[str, Any] = {
            "algorithms": ["RS256", "ES256"],
            "issuer": _oidc_issuer,
        }
        if settings.OIDC_CLIENT_ID:
            decode_kwargs["audience"] = settings.OIDC_CLIENT_ID
            decode_kwargs["options"] = {"verify_aud": True}
        else:
            decode_kwargs["options"] = {"verify_aud": False}

        return jwt.decode(token, signing_key.key, **decode_kwargs)

    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token expired")
    except jwt.PyJWTError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, f"Invalid token: {exc}")
    except httpx.HTTPError:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Identity provider unreachable",
        )
