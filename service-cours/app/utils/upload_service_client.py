import httpx
import logging
from fastapi import HTTPException
from io import BytesIO
import os
import asyncio
from typing import Optional
import json

logger = logging.getLogger(__name__)

class UploadServiceClient:
    def __init__(self):
        self.service_url = os.getenv("FILES_SERVICE_URL", "http://service-fichiers:8003")
        # Timeouts plus courts pour la vérification de disponibilité
        self.check_timeout = httpx.Timeout(5.0)
        # Timeouts plus longs pour l'upload
        self.upload_timeout = httpx.Timeout(
            connect=30.0,    # 30 secondes pour la connexion
            read=120.0,      # 2 minutes pour la lecture
            write=120.0,     # 2 minutes pour l'écriture
            pool=30.0        # 30 secondes pour le pool
        )
        self.max_retries = 3
        self.retry_delay = 1.0  # secondes

    async def _make_request_with_retry(self, client: httpx.AsyncClient, method: str, url: str, **kwargs) -> httpx.Response:
        """Effectue une requête avec retry en cas d'échec."""
        last_error = None
        for attempt in range(self.max_retries):
            try:
                logger.info(f"Tentative {attempt + 1}/{self.max_retries} pour {method} {url}")
                response = await client.request(method, url, **kwargs)
                
                # Log de la réponse pour le debug
                logger.debug(f"Réponse reçue - Status: {response.status_code}")
                logger.debug(f"Headers: {response.headers}")
                try:
                    logger.debug(f"Body: {response.text}")
                except:
                    logger.debug("Body: [contenu binaire]")
                
                response.raise_for_status()
                return response
            except httpx.TimeoutException as e:
                last_error = e
                logger.warning(f"Timeout sur la tentative {attempt + 1}: {str(e)}")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.retry_delay * (attempt + 1))
            except httpx.HTTPStatusError as e:
                last_error = e
                logger.error(f"Erreur HTTP {e.response.status_code} sur la tentative {attempt + 1}")
                try:
                    error_detail = e.response.json()
                    logger.error(f"Détails de l'erreur: {error_detail}")
                except:
                    logger.error(f"Réponse brute: {e.response.text}")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.retry_delay * (attempt + 1))
            except Exception as e:
                last_error = e
                logger.error(f"Erreur inattendue sur la tentative {attempt + 1}: {str(e)}")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.retry_delay * (attempt + 1))
        
        if isinstance(last_error, httpx.HTTPStatusError):
            try:
                error_detail = last_error.response.json()
                raise HTTPException(
                    status_code=last_error.response.status_code,
                    detail=error_detail.get('detail', str(last_error))
                )
            except:
                raise HTTPException(
                    status_code=last_error.response.status_code,
                    detail=str(last_error)
                )
        raise HTTPException(
            status_code=500,
            detail=f"Erreur lors de la communication avec le service: {str(last_error)}"
        )

    async def upload_file(self, file_content: bytes, filename: str, content_type: str, auth_header: str) -> dict:
        """
        Upload un fichier vers le service-fichiers avec retry.
        
        Args:
            file_content: Contenu du fichier en bytes
            filename: Nom du fichier
            content_type: Type MIME du fichier
            auth_header: Header d'authentification
            
        Returns:
            dict: Réponse du service contenant l'URL du fichier
        """
        try:
            logger.info(f"Début de l'upload du fichier {filename} vers {self.service_url}")
            logger.info(f"Type MIME: {content_type}")
            logger.info(f"Taille du fichier: {len(file_content)} octets")
            
            # Vérifier la taille du fichier
            file_size = len(file_content)
            if file_size == 0:
                logger.error("Le fichier est vide")
                raise HTTPException(
                    status_code=400,
                    detail="Le fichier est vide"
                )
            
            # Vérifier la connectivité avec le service-fichiers
            logger.info("Vérification de la disponibilité du service-fichiers...")
            await self._check_service_availability(auth_header)
            logger.info("Service-fichiers disponible")
            
            # Préparer les données du fichier
            files = {
                'file': (
                    filename,
                    BytesIO(file_content),
                    content_type
                )
            }
            
            logger.info(f"Envoi de la requête vers {self.service_url}/api/fichiers/upload")
            logger.info(f"Headers: Authorization={auth_header[:20]}..., Accept=application/json")
            
            # Envoyer le fichier avec retry
            async with httpx.AsyncClient(timeout=self.upload_timeout) as client:
                response = await self._make_request_with_retry(
                    client,
                    "POST",
                    f"{self.service_url}/api/fichiers/upload",
                    files=files,
                    headers={
                        "Authorization": auth_header,
                        "Accept": "application/json"
                    }
                )
                
                logger.info(f"Réponse reçue - Status: {response.status_code}")
                logger.info(f"Headers de réponse: {response.headers}")
                
                try:
                    result = response.json()
                    logger.info(f"Fichier uploadé avec succès: {result}")
                    return result
                except json.JSONDecodeError as e:
                    logger.error(f"Erreur de décodage JSON de la réponse: {str(e)}")
                    logger.error(f"Réponse brute: {response.text}")
                    raise HTTPException(
                        status_code=500,
                        detail="Réponse invalide du service de fichiers"
                    )
                
        except httpx.TimeoutException as e:
            logger.error(f"Timeout lors de l'upload vers {self.service_url}: {str(e)}")
            raise HTTPException(
                status_code=503,
                detail="Le service de fichiers ne répond pas dans le délai imparti"
            )
        except httpx.RequestError as e:
            logger.error(f"Erreur de connexion au service-fichiers {self.service_url}: {str(e)}")
            raise HTTPException(
                status_code=503,
                detail="Service de fichiers indisponible"
            )
        except HTTPException as he:
            raise he
        except Exception as e:
            logger.error(f"Erreur inattendue lors de l'upload: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail=f"Erreur lors de l'upload du fichier: {str(e)}"
            )

    async def _check_service_availability(self, auth_header: str):
        """Vérifie la disponibilité du service-fichiers."""
        try:
            logger.info(f"Vérification de la disponibilité du service-fichiers {self.service_url}")
            async with httpx.AsyncClient(timeout=self.check_timeout) as client:
                response = await self._make_request_with_retry(
                    client,
                    "GET",
                    f"{self.service_url}/api/fichiers/files",
                    headers={
                        "Authorization": auth_header,
                        "Accept": "application/json"
                    }
                )
                logger.info("Service-fichiers disponible")
        except httpx.TimeoutException as e:
            logger.error(f"Timeout lors de la vérification du service-fichiers: {str(e)}")
            raise HTTPException(
                status_code=503,
                detail="Le service de fichiers ne répond pas"
            )
        except httpx.RequestError as e:
            logger.error(f"Erreur de connexion au service-fichiers: {str(e)}")
            raise HTTPException(
                status_code=503,
                detail="Service de fichiers indisponible"
            )
        except httpx.HTTPStatusError as e:
            logger.error(f"Erreur HTTP du service-fichiers: {str(e)}")
            if e.response.status_code == 404:
                raise HTTPException(
                    status_code=503,
                    detail="Service de fichiers indisponible ou mal configuré"
                )
            raise HTTPException(
                status_code=e.response.status_code,
                detail=f"Erreur du service de fichiers: {str(e)}"
            ) 