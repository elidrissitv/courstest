from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Depends, Request, Body
from uuid import UUID, uuid4
from datetime import datetime
from app.cassandra_conn import session
from app.auth import verify_token, get_current_user
from app.decorators import require_roles, is_admin
from app.models import Cours, CoursCreate, CoursBase
from app.utils.upload_service_client import UploadServiceClient
import httpx
import json
from typing import Optional, List, Dict, Tuple
import logging
import urllib.parse
from io import BytesIO
import aiohttp
import os
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import select
from werkzeug.utils import secure_filename

# Configuration via variables d'environnement
KEYCLOAK_TOKEN_URL = os.getenv("KEYCLOAK_TOKEN_URL", "http://keycloak:8080/realms/ent_realm/protocol/openid-connect/token")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "ent_client")
KEYCLOAK_CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET", "your-client-secret")

FILE_SERVICE_BASE_URL = os.getenv("FILE_SERVICE_BASE_URL", "http://localhost:8003")
FILE_UPLOAD_URL = f"{FILE_SERVICE_BASE_URL}/api/fichiers/upload"
FILE_DELETE_URL = f"{FILE_SERVICE_BASE_URL}/api/fichiers/delete"
FILE_DOWNLOAD_URL_PREFIX = f"{FILE_SERVICE_BASE_URL}/api/fichiers/download"

ALLOWED_CORS_ORIGIN = os.getenv("ALLOWED_CORS_ORIGIN", "http://localhost:3001")

# Configuration des logs
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

router = APIRouter()
upload_client = UploadServiceClient()

class CoursCreateRequest(BaseModel):
    titre: str
    description: str
    fichier_base64: Optional[str] = None
    nom_fichier: Optional[str] = None
    type_fichier: Optional[str] = None

async def verify_token_with_raw(request: Request, token: Dict = Depends(verify_token)) -> Tuple[Dict, str]:
    """Obtient le token décodé et le token brut pour l'authentification service-à-service."""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        raise HTTPException(status_code=401, detail="Non authentifié")
    raw_token = auth_header.split(' ')[1]
    return token, raw_token

@router.get("/", response_model=List[CoursBase])
@require_roles(['admin', 'enseignant', 'etudiant'])
async def get_cours(token: Dict = Depends(verify_token)):
    """Récupère la liste des cours. Accessible à tous les rôles."""
    logger.info(f"Récupération des cours pour l'utilisateur: {token.get('preferred_username')}")
    try:
        rows = session.execute("SELECT id, titre, description, date_ajout, fichier_url, id_enseignant FROM ent_keyspace.cours")
        cours_list = []
        for row in rows:
            cours_list.append(CoursBase(
                id=row.id,
                titre=row.titre,
                description=row.description,
                date_ajout=row.date_ajout.isoformat() if row.date_ajout else None,
                fichier_url=row.fichier_url,
                id_enseignant=row.id_enseignant
            ))
        return cours_list
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des cours: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Erreur lors de la récupération des cours")

@router.post("/")
async def create_cours(
    request: Request,
    titre: str = Form(...),
    description: str = Form(...),
    id_enseignant: UUID = Form(...),
    fichier: Optional[UploadFile] = File(None),
    auth_data: Tuple[Dict, str] = Depends(verify_token_with_raw)
):
    try:
        current_user, raw_token = auth_data
        logger.info("=== Début de la création d'un cours ===")
        logger.info(f"Titre: {titre}")
        logger.info(f"Description: {description}")
        logger.info(f"ID Enseignant: {id_enseignant}")
        logger.info(f"Fichier fourni: {fichier.filename if fichier else 'Aucun'}")
        
        # Validation des données
        if not titre or len(titre.strip()) == 0:
            raise HTTPException(
                status_code=400,
                detail="Le titre du cours est requis"
            )
        
        if not description or len(description.strip()) == 0:
            raise HTTPException(
                status_code=400,
                detail="La description du cours est requise"
            )
        
        # Vérification de l'existence de l'enseignant
        try:
            logger.info(f"Vérification de l'existence de l'enseignant avec keycloak_id {current_user.get('sub')} dans la base de données")
            enseignant = session.execute(
                "SELECT id FROM ent_keyspace.utilisateurs WHERE keycloak_id = %s",
                (current_user.get('sub'),)
            ).one()
            
            if not enseignant:
                logger.info(f"Enseignant non trouvé avec keycloak_id {current_user.get('sub')}, création automatique...")
                # Créer l'utilisateur automatiquement
                session.execute(
                    """
                    INSERT INTO ent_keyspace.utilisateurs (id, keycloak_id, nom, prenom, email, role, statut, date_creation)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        id_enseignant,
                        current_user.get('sub'),
                        current_user.get('name', ''),
                        current_user.get('given_name', ''),
                        current_user.get('email', ''),
                        'enseignant',
                        'active',
                        datetime.utcnow()
                    )
                )
                logger.info(f"Utilisateur créé avec succès: {id_enseignant}")
            else:
                # Utiliser l'ID existant de l'utilisateur
                id_enseignant = enseignant.id
                logger.info(f"Enseignant trouvé avec l'ID {id_enseignant}")
        except Exception as e:
            logger.error(f"Erreur lors de la vérification/création de l'enseignant: {str(e)}")
            if "Connection refused" in str(e):
                raise HTTPException(
                    status_code=503,
                    detail="Service de base de données temporairement indisponible"
                )
            elif "NoHostAvailable" in str(e):
                raise HTTPException(
                    status_code=503,
                    detail="Impossible de se connecter à la base de données"
                )
            else:
                raise HTTPException(
                    status_code=500,
                    detail=f"Erreur lors de la vérification/création de l'enseignant: {str(e)}"
                )
        
        # Générer un nouvel ID de cours
        cours_id = uuid4()
        date_ajout = datetime.utcnow()
        
        # Si un fichier est fourni, l'uploader
        if fichier:
            try:
                # Vérification du type de fichier
                content_type = fichier.content_type
                if not content_type:
                    raise HTTPException(
                        status_code=400,
                        detail="Le type de fichier n'a pas été détecté"
                    )
                
                # Upload du fichier vers le service-fichiers
                if fichier:
                    logger.info(f"Fichier fourni: {fichier.filename}")
                    try:
                        # Préparation des données pour l'upload
                        files = {"file": (fichier.filename, fichier.file, fichier.content_type)}
                        data = {"cours_id": str(cours_id)}
                        
                        # Appel au service-fichiers pour l'upload
                        response = httpx.post(
                            f"{FILE_SERVICE_BASE_URL}/api/fichiers/upload",
                            files=files,
                            data=data,
                            headers={"Authorization": f"Bearer {raw_token}"}
                        )
                        response.raise_for_status()
                        
                        # Récupération du chemin MinIO de la réponse
                        upload_response = response.json()
                        minio_path = upload_response.get("object_name")
                        
                        if not minio_path:
                            raise HTTPException(
                                status_code=500,
                                detail="Le chemin MinIO n'a pas été retourné par le service-fichiers"
                            )
                        
                        logger.info(f"Fichier uploadé avec succès, chemin MinIO: {minio_path}")
                        
                        # Création du cours avec le chemin MinIO
                        session.execute(
                            """
                            INSERT INTO ent_keyspace.cours (id, titre, description, id_enseignant, date_ajout, fichier_url)
                            VALUES (%s, %s, %s, %s, %s, %s)
                            """,
                            (cours_id, titre, description, id_enseignant, date_ajout, minio_path)
                        )
                        logger.info(f"Cours créé avec succès avec le chemin MinIO: {minio_path}")
                        
                        return {
                            "message": "Cours créé avec succès",
                            "cours": {
                                "id": str(cours_id),
                                "titre": titre,
                                "description": description,
                                "id_enseignant": str(id_enseignant),
                                "date_ajout": date_ajout.isoformat(),
                                "fichier_url": minio_path
                            }
                        }
                    except Exception as e:
                        logger.error(f"Erreur lors de l'upload du fichier: {str(e)}")
                        raise HTTPException(
                            status_code=500,
                            detail=f"Erreur lors de l'upload du fichier: {str(e)}"
                        )
            except HTTPException as he:
                raise he
            except Exception as e:
                logger.error(f"Erreur lors de l'upload du fichier: {str(e)}")
                raise HTTPException(
                    status_code=500,
                    detail=f"Erreur lors de l'upload du fichier: {str(e)}"
                )
        else:
            # Si aucun fichier n'est fourni, créer le cours sans fichier
            try:
                session.execute(
                    """
                    INSERT INTO ent_keyspace.cours (id, titre, description, id_enseignant, date_ajout, fichier_url)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (cours_id, titre, description, id_enseignant, date_ajout, None)
                )
                logger.info(f"Cours créé avec succès sans fichier: {cours_id}")
                
                return {
                    "message": "Cours créé avec succès",
                    "cours": {
                        "id": str(cours_id),
                        "titre": titre,
                        "description": description,
                        "id_enseignant": str(id_enseignant),
                        "date_ajout": date_ajout.isoformat(),
                        "fichier_url": None
                    }
                }
            except Exception as e:
                logger.error(f"Erreur lors de la création du cours sans fichier: {str(e)}")
                raise HTTPException(
                    status_code=500,
                    detail=f"Erreur lors de la création du cours: {str(e)}"
                )
        
    except HTTPException as he:
        logger.error(f"Erreur HTTP: {str(he)}")
        raise he
    except Exception as e:
        logger.error(f"Erreur inattendue: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Erreur inattendue lors de la création du cours: {str(e)}"
        )

@router.put("/{cours_id}", response_model=CoursBase)
@require_roles(['admin', 'enseignant'])
async def update_cours(
    cours_id: UUID,
    titre: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    fichier: Optional[UploadFile] = File(None),
    auth_data: Tuple[Dict, str] = Depends(verify_token_with_raw)
):
    """Met à jour un cours. Accessible aux administrateurs ou à l'enseignant propriétaire."""
    current_user, raw_token = auth_data
    logger.info(f"Mise à jour du cours {cours_id} par l'utilisateur: {current_user.get('preferred_username')}")

    try:
        row = session.execute(
            "SELECT id, titre, description, date_ajout, fichier_url, id_enseignant FROM ent_keyspace.cours WHERE id = %s",
            (cours_id,)
        ).one()

        if not row:
            raise HTTPException(status_code=404, detail="Cours non trouvé")

        is_user_admin = 'admin' in current_user.get('realm_access', {}).get('roles', [])
        is_owner = str(row.id_enseignant) == current_user.get('sub')

        if not (is_user_admin or is_owner):
            logger.warning(f"Accès refusé pour la mise à jour du cours {cours_id}: utilisateur {current_user.get('preferred_username')} n'est ni admin ni propriétaire")
            raise HTTPException(
                status_code=403,
                detail="Accès refusé: vous n'êtes pas autorisé à modifier ce cours"
            )

        updates = {}
        values = []

        if titre is not None:
            updates['titre'] = titre
            values.append(titre)
        if description is not None:
            updates['description'] = description
            values.append(description)

        if fichier:
            logger.info(f"Nouveau fichier fourni pour le cours {cours_id}: {fichier.filename}")
            try:
                files = {'file': (fichier.filename, fichier.file, fichier.content_type)}
                data = {"cours_id": str(cours_id)}
                async with httpx.AsyncClient() as client:
                    response = await client.post(
                        f"{FILE_SERVICE_BASE_URL}/api/fichiers/upload",
                        files=files,
                        data=data,
                        headers={"Authorization": f"Bearer {raw_token}"}
                    )
                    if response.status_code != 200:
                        logger.error(f"Erreur lors de l'upload du fichier: {response.text}")
                        raise HTTPException(
                            status_code=response.status_code,
                            detail=f"Erreur lors de l'upload du fichier: {response.text}"
                        )
                    
                    # Récupération du chemin MinIO de la réponse
                    upload_response = response.json()
                    minio_path = upload_response.get("object_name")
                    
                    if not minio_path:
                        raise HTTPException(
                            status_code=500,
                            detail="Le chemin MinIO n'a pas été retourné par le service-fichiers"
                        )
                    
                    updates['fichier_url'] = minio_path
                    values.append(minio_path)
                    logger.info(f"Fichier uploadé avec succès, chemin MinIO: {minio_path}")

                    # Si un ancien fichier existe, le supprimer
                    if row.fichier_url:
                        try:
                            async with httpx.AsyncClient() as client:
                                await client.delete(
                                    f"{FILE_DELETE_URL}/{row.fichier_url}",
                                    headers={"Authorization": f"Bearer {raw_token}"}
                                )
                            logger.info(f"Ancien fichier {row.fichier_url} supprimé avec succès")
                        except Exception as e:
                            logger.error(f"Erreur lors de la suppression de l'ancien fichier {row.fichier_url}: {str(e)}")
                            # On continue même si la suppression échoue
            except Exception as e:
                logger.error(f"Erreur lors de l'upload du fichier: {str(e)}")
                raise HTTPException(
                    status_code=500,
                    detail=f"Erreur lors de l'upload du fichier: {str(e)}"
                )

        if updates:
            set_clause = ", ".join(f"{k} = %s" for k in updates.keys())
            values.append(cours_id)

            logger.info(f"Mise à jour du cours {cours_id} dans Cassandra: SET {set_clause}")

            session.execute(
                f"""
                UPDATE ent_keyspace.cours
                SET {set_clause}
                WHERE id = %s
                """,
                values
            )
            logger.info(f"Cours {cours_id} mis à jour dans Cassandra")
        else:
            logger.info(f"Aucune mise à jour de données pour le cours {cours_id}")

        updated_row = session.execute(
            "SELECT id, titre, description, date_ajout, fichier_url, id_enseignant FROM ent_keyspace.cours WHERE id = %s",
            (cours_id,)
        ).one()

        if not updated_row:
            raise HTTPException(status_code=500, detail="Erreur interne: Impossible de récupérer le cours après mise à jour")

        return CoursBase(
            id=updated_row.id,
            titre=updated_row.titre,
            description=updated_row.description,
            date_ajout=updated_row.date_ajout.isoformat() if updated_row.date_ajout else None,
            fichier_url=updated_row.fichier_url,
            id_enseignant=updated_row.id_enseignant
        )

    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"Erreur lors de la mise à jour du cours {cours_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erreur lors de la mise à jour du cours: {str(e)}")

@router.delete("/{cours_id}", response_model=dict)
async def delete_cours(
    cours_id: str,
    auth_data: Tuple[Dict, str] = Depends(verify_token_with_raw)
):
    current_user, raw_token = auth_data
    user_roles = current_user.get('realm_access', {}).get('roles', [])
    user_id = current_user.get('sub')
    
    logger.info(f"Tentative de suppression du cours {cours_id} par l'utilisateur {current_user.get('preferred_username')}")
    logger.info(f"Rôles de l'utilisateur: {user_roles}")
    logger.info(f"ID de l'utilisateur: {user_id}")
    
    try:
        # Récupérer le cours
        row = session.execute(
            "SELECT id, titre, description, date_ajout, fichier_url, id_enseignant FROM ent_keyspace.cours WHERE id = %s",
            (cours_id,)
        ).one()

        if not row:
            logger.warning(f"Cours {cours_id} non trouvé")
            raise HTTPException(status_code=404, detail="Cours non trouvé")
        
        # Vérifier les permissions
        is_admin = 'admin' in user_roles
        is_owner = str(row.id_enseignant) == str(user_id)
        
        logger.info(f"Vérification des permissions - Admin: {is_admin}, Propriétaire: {is_owner}")
        logger.info(f"ID enseignant du cours: {row.id_enseignant}")
        
        if not (is_admin or is_owner):
            logger.warning(f"Accès refusé: l'utilisateur {current_user.get('preferred_username')} n'a pas les permissions nécessaires")
            raise HTTPException(
                status_code=403,
                detail="Vous n'avez pas les permissions nécessaires pour supprimer ce cours"
            )
        
        # Supprimer les fichiers associés
        if row.fichier_url:
            try:
                # Utiliser directement le chemin MinIO complet
                minio_path = row.fichier_url
                logger.info(f"Tentative de suppression du fichier avec le chemin MinIO: {minio_path}")
                
                async with httpx.AsyncClient() as client:
                    response = await client.delete(
                        f"{FILE_DELETE_URL}/{minio_path}",
                        headers={
                            "Authorization": f"Bearer {raw_token}",
                            "Content-Type": "application/json",
                            "Accept": "application/json",
                            "X-User-ID": user_id,
                            "X-User-Roles": ",".join(user_roles)
                        },
                        timeout=30.0
                    )
                    
                    if response.status_code == 404:
                        logger.warning(f"Fichier {minio_path} non trouvé dans le service de fichiers")
                    elif response.status_code == 401:
                        logger.error(f"Erreur d'authentification lors de la suppression du fichier {minio_path}")
                        raise HTTPException(
                            status_code=401,
                            detail="Erreur d'authentification lors de la suppression du fichier"
                        )
                    elif response.status_code != 200:
                        logger.error(f"Erreur lors de la suppression du fichier {minio_path}: {response.text}")
                        raise HTTPException(
                            status_code=response.status_code,
                            detail=f"Erreur lors de la suppression du fichier: {response.text}"
                        )
            except httpx.TimeoutException:
                logger.error(f"Timeout lors de la suppression du fichier {minio_path}")
                raise HTTPException(
                    status_code=504,
                    detail="Le service de fichiers a mis trop de temps à répondre"
                )
            except Exception as e:
                logger.error(f"Erreur lors de la suppression du fichier {minio_path}: {str(e)}")
                raise HTTPException(
                    status_code=500,
                    detail=f"Erreur lors de la suppression du fichier: {str(e)}"
                )
        
        # Supprimer le cours
        try:
            session.execute("DELETE FROM ent_keyspace.cours WHERE id = %s", (cours_id,))
            logger.info(f"Cours {cours_id} supprimé avec succès")
            return {"message": "Cours supprimé avec succès"}
        except Exception as e:
            logger.error(f"Erreur lors de la suppression du cours {cours_id}: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail=f"Erreur lors de la suppression du cours: {str(e)}"
            )
        
    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"Erreur inattendue lors de la suppression du cours {cours_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Erreur inattendue lors de la suppression du cours: {str(e)}"
        )

@router.options("/download-proxy")
async def options_download_proxy():
    """Gestion des requêtes OPTIONS pour le proxy de téléchargement."""
    logger.info("Requête OPTIONS reçue pour /download-proxy")
    return {
        "headers": {
            "Access-Control-Allow-Origin": ALLOWED_CORS_ORIGIN,
            "Access-Control-Allow-Methods": "GET, OPTIONS",
            "Access-Control-Allow-Headers": "Authorization, Content-Type, Accept",
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Expose-Headers": "Content-Disposition, Content-Type, Content-Length",
            "Access-Control-Max-Age": "3600"
        }
    }

@router.get("/download-proxy")
@require_auth(["admin", "enseignant", "etudiant"])
async def download_proxy(
    file_id: str,
    current_user: dict = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """
    Proxy de téléchargement qui vérifie les permissions avant de rediriger vers le service-fichiers.
    """
    logger.info(f"Tentative de téléchargement via proxy pour le fichier ID: {file_id} par l'utilisateur {current_user['username']}")

    # Récupérer le cours pour obtenir le chemin du fichier
    query = select(Cours).where(Cours.id == file_id)
    result = await session.execute(query)
    row = result.scalar_one_or_none()

    if not row:
        raise HTTPException(status_code=404, detail="Cours non trouvé")

    if not row.fichier_url:
        raise HTTPException(status_code=404, detail="Aucun fichier associé à ce cours")

    logger.info(f"Chemin MinIO stocké dans la base de données: {row.fichier_url}")

    # Construire l'URL de téléchargement en utilisant le chemin complet stocké dans fichier_url
    download_url = f"{FILE_SERVICE_BASE_URL}/api/fichiers/download/{row.fichier_url}"
    logger.info(f"URL de téléchargement complète: {download_url}")

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                download_url,
                headers={"Authorization": request.headers.get("Authorization", "")},
                timeout=30.0,
            )
            logger.info(f"Réponse du service-fichiers pour téléchargement reçue: Status={response.status_code}")

            if response.status_code == 404:
                logger.error(f"Fichier non trouvé dans le service-fichiers: {row.fichier_url}")
                raise HTTPException(status_code=404, detail="Fichier non trouvé dans le service de stockage")

            response.raise_for_status()
            logger.info(f"Téléchargement réussi pour le fichier: {row.fichier_url}")

            # Extraire le nom du fichier du chemin
            filename = row.fichier_url.split('/')[-1]
            logger.info(f"Nom du fichier extrait: {filename}")

            return StreamingResponse(
                response.iter_bytes(),
                media_type=response.headers.get("content-type", "application/octet-stream"),
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}"',
                    "Content-Type": response.headers.get("content-type", "application/octet-stream"),
                },
            )

    except httpx.HTTPStatusError as e:
        logger.error(f"Erreur HTTP du service-fichiers lors du téléchargement de {file_id}: {e.response.status_code} - {e.response.text}")
        raise HTTPException(status_code=e.response.status_code, detail=str(e))
    except httpx.RequestError as e:
        logger.error(f"Erreur de connexion au service-fichiers: {str(e)}")
        raise HTTPException(status_code=500, detail="Erreur de connexion au service de fichiers")
    except Exception as e:
        logger.error(f"Erreur inattendue lors du téléchargement: {str(e)}")
        raise HTTPException(status_code=500, detail="Erreur lors du téléchargement du fichier")
