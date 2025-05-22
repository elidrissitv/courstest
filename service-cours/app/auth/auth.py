import jwt
import httpx
from fastapi import Request, HTTPException
from fastapi.security import HTTPBearer
from fastapi.security.http import HTTPAuthorizationCredentials
from fastapi import Depends
from log import logger

class JWTBearer(HTTPBearer):
    async def verify_token(self, request: Request = Depends(get_token)):
        """Vérifie le token JWT et retourne les informations de l'utilisateur."""
        try:
            token = request.headers.get('Authorization')
            if not token or not token.startswith('Bearer '):
                raise HTTPException(
                    status_code=401,
                    detail="Token manquant ou invalide"
 