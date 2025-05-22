from fastapi import HTTPException, Security, Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import jwt, JWTError
import httpx
import logging
from jose import jwk as jose_jwk
import os

# Configuration des logs
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

security = HTTPBearer()
jwks_cache = {}

# Configuration de l'authentification
KEYCLOAK_URL = os.getenv('KEYCLOAK_URL', 'http://keycloak:8080')
REALM = os.getenv('KEYCLOAK_REALM', 'ent_realm')
KEYCLOAK_CLIENT_ID = os.getenv('KEYCLOAK_CLIENT_ID', 'ent_client')
KEYCLOAK_JWKS_URL = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/certs"
KEYCLOAK_ISSUER = f"{KEYCLOAK_URL}/realms/{REALM}"
KEYCLOAK_AUDIENCE = 'account'

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

async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Vérifie le token JWT"""
    try:
        token = credentials.credentials
        logger.info("Token reçu, tentative de décodage...")
        
        # Récupération des clés publiques de Keycloak
        jwks = await get_jwks()
        logger.info(f"JWKS récupérés: {jwks}")
        
        # Récupération de la clé publique
        unverified_header = jwt.get_unverified_header(token)
        logger.info(f"Header non vérifié: {unverified_header}")
        
        key_id = unverified_header.get("kid")
        if not key_id:
            logger.error("Token invalide: pas de kid")
            raise HTTPException(status_code=401, detail="Token invalide: pas de kid")
            
        key = None
        for jwk_dict in jwks.get("keys", []):
            if jwk_dict.get("kid") == key_id:
                key = jose_jwk.construct(jwk_dict)
                logger.info(f"Clé trouvée pour kid {key_id}")
                break
                
        if not key:
            logger.error("Clé publique non trouvée")
            raise HTTPException(status_code=401, detail="Clé publique non trouvée")
        
        # Liste des issuers valides
        valid_issuers = [
            KEYCLOAK_ISSUER,
            f"http://localhost:8081/realms/{REALM}",
            f"http://localhost:8080/realms/{REALM}"
        ]
        logger.info(f"Issuers valides: {valid_issuers}")
        
        # Validation du token
        try:
            logger.info(f"Tentative de décodage avec audience={KEYCLOAK_AUDIENCE}")
            payload = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                audience=KEYCLOAK_AUDIENCE,
                options={
                    "verify_aud": True,
                    "verify_iss": False  # On désactive la vérification de l'issuer car on le vérifie manuellement
                }
            )
            
            # Vérification manuelle de l'issuer
            token_issuer = payload.get('iss')
            if token_issuer not in valid_issuers:
                logger.error(f"Invalid issuer: {token_issuer}. Valid issuers are: {valid_issuers}")
                raise HTTPException(status_code=401, detail=f"Invalid issuer: {token_issuer}")
            
            logger.info(f"Token validé avec succès pour l'utilisateur {payload.get('sub')}")
            logger.info(f"Audience du token: {payload.get('aud')}")
            return payload
            
        except JWTError as e:
            logger.error(f"Erreur lors du décodage du token: {str(e)}")
            raise HTTPException(status_code=401, detail=f"Token invalide: {str(e)}")
            
    except Exception as e:
        logger.error(f"Erreur inattendue lors de la vérification du token: {str(e)}")
        raise HTTPException(
            status_code=401,
            detail=f"Erreur d'authentification: {str(e)}"
        )

async def get_current_user(token: dict = Depends(verify_token)):
    """Récupère les informations de l'utilisateur courant à partir du token"""
    try:
        # Extraire les informations de base du token
        user_info = {
            'id': token.get('sub'),
            'username': token.get('preferred_username'),
            'email': token.get('email'),
            'roles': token.get('realm_access', {}).get('roles', [])
        }
        
        logger.info(f"Informations utilisateur extraites du token: {user_info}")
        return user_info
        
    except Exception as e:
        logger.error(f"Erreur lors de l'extraction des informations utilisateur: {str(e)}")
        raise HTTPException(
            status_code=401,
            detail=f"Erreur lors de l'extraction des informations utilisateur: {str(e)}"
        ) 