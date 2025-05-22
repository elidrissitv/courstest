from functools import wraps
from fastapi import HTTPException, Depends
from typing import List, Union, Callable
from app.auth.auth import verify_token
import logging

logger = logging.getLogger(__name__)

def require_roles(roles: list):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                token = kwargs.get('token')
                if not token:
                    logger.error("Token non trouvé dans les arguments")
                    raise HTTPException(
                        status_code=401,
                        detail="Token d'authentification manquant"
                    )

                user_roles = token.get('realm_access', {}).get('roles', [])
                logger.info(f"Rôles de l'utilisateur: {user_roles}")
                logger.info(f"Rôles requis: {roles}")
                
                if not any(role in user_roles for role in roles):
                    logger.warning(f"Accès refusé: l'utilisateur n'a pas les rôles requis")
                    raise HTTPException(
                        status_code=403,
                        detail="Vous n'avez pas les permissions nécessaires pour effectuer cette action"
                    )
                return await func(*args, **kwargs)
            except HTTPException as he:
                raise he
            except Exception as e:
                logger.error(f"Erreur lors de la vérification des rôles: {str(e)}")
                raise HTTPException(
                    status_code=500,
                    detail="Erreur lors de la vérification des permissions"
                )
        return wrapper
    return decorator

def is_admin(token: dict = Depends(verify_token)) -> bool:
    """Vérifie si l'utilisateur est un administrateur"""
    return 'admin' in token.get('realm_access', {}).get('roles', [])

def is_enseignant(token: dict = Depends(verify_token)) -> bool:
    """Vérifie si l'utilisateur est un enseignant"""
    return 'enseignant' in token.get('realm_access', {}).get('roles', [])

def is_etudiant(token: dict = Depends(verify_token)) -> bool:
    """Vérifie si l'utilisateur est un étudiant"""
    return 'etudiant' in token.get('realm_access', {}).get('roles', []) 