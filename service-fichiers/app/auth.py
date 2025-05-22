from fastapi import HTTPException, Security, Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, OAuth2PasswordBearer
from jose import jwt, JWTError
import httpx
import logging
from jose import jwk as jose_jwk
import os
from typing import Dict

# Configuration des logs
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

security = HTTPBearer()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
jwks_cache = {}

# Configuration de l'authentification
KEYCLOAK_URL = os.getenv('KEYCLOAK_URL', 'http://keycloak:8080')
REALM = os.getenv('KEYCLOAK_REALM', 'ent_realm')
KEYCLOAK_CLIENT_ID = os.getenv('KEYCLOAK_CLIENT_ID', 'ent_client')
KEYCLOAK_JWKS_URL = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/certs"
KEYCLOAK_ISSUER = f"{KEYCLOAK_URL}/realms/{REALM}"
KEYCLOAK_AUDIENCE = 'account'

# Configuration des issuers valides
VALID_ISSUERS = [
    'http://keycloak:8080/realms/ent_realm',
    'http://localhost:8081/realms/ent_realm',
    'http://localhost:8080/realms/ent_realm'
]

async def get_jwks():
    """Récupère les clés JWKS depuis Keycloak"""
    try:
        if not jwks_cache:
            logger.info(f"Récupération des clés JWKS depuis {KEYCLOAK_JWKS_URL}")
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(KEYCLOAK_JWKS_URL)
                if response.status_code != 200:
                    logger.error(f"Erreur lors de la récupération des clés JWKS: {response.status_code}")
                    raise HTTPException(status_code=500, detail="Impossible de récupérer les clés JWKS")
                jwks_cache.update(response.json())
                logger.info(f"Clés JWKS mises en cache: {jwks_cache}")
        return jwks_cache
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des clés JWKS: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erreur lors de la récupération des clés JWKS: {str(e)}")

async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict:
    """Vérifie le token JWT et retourne les informations de l'utilisateur."""
    try:
        token = credentials.credentials
        logger.info("Token reçu, tentative de décodage...")
        
        # Récupérer les clés JWKS depuis Keycloak
        jwks = await get_jwks()
        logger.info(f"JWKS récupérés: {jwks}")
        
        # Décoder le header du token pour obtenir le kid
        unverified_header = jwt.get_unverified_header(token)
        logger.info(f"Header non vérifié: {unverified_header}")
        
        # Trouver la clé correspondante
        rsa_key = {}
        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"]
                }
                logger.info(f"Clé trouvée pour kid {key['kid']}")
                break
        
        if not rsa_key:
            logger.error("Clé publique non trouvée")
            raise HTTPException(
                status_code=401,
                detail="Clé publique non trouvée"
            )
        
        # Essayer avec chaque issuer valide
        last_error = None
        for issuer in VALID_ISSUERS:
            try:
                logger.info(f"Tentative de décodage avec issuer={issuer} et audience=account")
                payload = jwt.decode(
                    token,
                    rsa_key,
                    algorithms=["RS256"],
                    audience="account",
                    issuer=issuer
                )
                logger.info(f"Token validé avec succès pour l'utilisateur {payload.get('sub')}")
                logger.info(f"Audience du token: {payload.get('aud')}")
                
                # Extraire les informations utilisateur
                user_info = {
                    "id": payload.get("sub"),
                    "username": payload.get("preferred_username"),
                    "email": payload.get("email"),
                    "roles": payload.get("realm_access", {}).get("roles", [])
                }
                logger.info(f"Informations utilisateur extraites du token: {user_info}")
                
                return user_info
                
            except JWTError as e:
                logger.error(f"Échec avec issuer {issuer}: {str(e)}")
                last_error = e
                continue
        
        # Si aucun issuer n'a fonctionné
        logger.error(f"Tous les issuers ont échoué. Dernière erreur: {str(last_error)}")
        raise HTTPException(
            status_code=401,
            detail=f"Erreur d'authentification: Token invalide"
        )
            
    except Exception as e:
        logger.error(f"Erreur inattendue lors de la vérification du token: {str(e)}")
        raise HTTPException(
            status_code=401,
            detail=f"Erreur d'authentification: {str(e)}"
        ) 