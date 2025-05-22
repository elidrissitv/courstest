from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import requests
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

security = HTTPBearer()
AUTH_SERVICE_URL = "http://auth-service:8000"

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    """
    Vérifie le token JWT avec le service d'authentification
    """
    try:
        token = credentials.credentials
        logger.debug(f"Vérification du token avec le service d'authentification")
        
        # Appel au service d'authentification pour valider le token
        response = requests.get(
            f"{AUTH_SERVICE_URL}/api/auth/validate",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        if response.status_code != 200:
            logger.error(f"Token invalide: {response.status_code}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token invalide ou expiré",
                headers={"WWW-Authenticate": "Bearer"},
            )
            
        user_data = response.json()
        if not user_data.get("valid", False):
            logger.error(f"Token invalide: {user_data.get('message')}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=user_data.get("message", "Token invalide"),
                headers={"WWW-Authenticate": "Bearer"},
            )
            
        logger.debug(f"Token validé pour l'utilisateur: {user_data.get('user', {}).get('sub')}")
        return user_data.get("user", {})
        
    except requests.RequestException as e:
        logger.error(f"Erreur lors de la validation du token: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service d'authentification indisponible"
        )
    except Exception as e:
        logger.error(f"Erreur inattendue lors de l'authentification: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erreur lors de la validation du token"
        ) 