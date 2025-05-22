from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Request, Response, Depends
from minio import Minio
import os
from app.minio_conn import minio_client, bucket_name, ensure_bucket_exists
from fastapi.responses import StreamingResponse
from io import BytesIO
import logging
from datetime import datetime
import uuid
import magic
import tempfile
from typing import List, Optional, Dict, Tuple
import mimetypes
from app.auth.auth import get_current_user, verify_token_with_raw
from minio.error import S3Error
from cassandra.cluster import Cluster
from cassandra.auth import PlainTextAuthProvider
from werkzeug.utils import secure_filename

# Configuration des logs
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

router = APIRouter()

# Configuration
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 Mo
ALLOWED_EXTENSIONS = {".pdf", ".jpg", ".png", ".docx", ".doc"}
ALLOWED_MIME_TYPES = {
    "application/pdf": ".pdf",
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/msword": ".doc"
}

# Configuration Cassandra
CASSANDRA_HOSTS = os.getenv("CASSANDRA_HOSTS", "cassandra").split(",")
CASSANDRA_PORT = int(os.getenv("CASSANDRA_PORT", "9042"))
CASSANDRA_USER = os.getenv("CASSANDRA_USER", "cassandra")
CASSANDRA_PASSWORD = os.getenv("CASSANDRA_PASSWORD", "cassandra")

# Variables globales pour Cassandra
session = None
cluster = None

def init_cassandra():
    """Initialise la connexion à Cassandra et crée la table si nécessaire."""
    global session, cluster
    
    logger.info(f"Configuration Cassandra - Hosts: {CASSANDRA_HOSTS}, Port: {CASSANDRA_PORT}, User: {CASSANDRA_USER}")
    
    try:
        logger.info("Tentative de connexion à Cassandra...")
        auth_provider = PlainTextAuthProvider(username=CASSANDRA_USER, password=CASSANDRA_PASSWORD)
        cluster = Cluster(CASSANDRA_HOSTS, port=CASSANDRA_PORT, auth_provider=auth_provider)
        session = cluster.connect()
        logger.info("Connexion à Cassandra établie avec succès")
        
        # Vérification de l'existence de la table
        logger.info("Vérification de l'existence de la table fichiers_mapping...")
        result = session.execute("""
            SELECT table_name 
            FROM system_schema.tables 
            WHERE keyspace_name = 'ent_keyspace' 
            AND table_name = 'fichiers_mapping'
        """)
        
        if not result.one():
            logger.info("Table fichiers_mapping n'existe pas, création en cours...")
            session.execute("""
                CREATE TABLE IF NOT EXISTS ent_keyspace.fichiers_mapping (
                    id uuid PRIMARY KEY,
                    minio_path text,
                    original_filename text,
                    content_type text,
                    size bigint,
                    upload_date timestamp,
                    uploaded_by text,
                    cours_id uuid
                )
            """)
            logger.info("Table fichiers_mapping créée avec succès")
        else:
            logger.info("Table fichiers_mapping existe déjà")
            
        # Vérification du contenu de la table
        count = session.execute("SELECT COUNT(*) FROM ent_keyspace.fichiers_mapping").one()[0]
        logger.info(f"Nombre d'enregistrements dans fichiers_mapping: {count}")
        
    except Exception as e:
        logger.error(f"Erreur lors de l'initialisation de Cassandra: {str(e)}", exc_info=True)
        raise

def migrate_existing_files():
    """Migre les fichiers existants de la table cours vers fichiers_mapping."""
    try:
        logger.info("Début de la migration des fichiers existants...")
        
        # Récupérer tous les cours avec des fichiers
        rows = session.execute("""
            SELECT id, fichier_url 
            FROM ent_keyspace.cours 
            WHERE fichier_url IS NOT NULL
        """)
        
        for row in rows:
            if not row.fichier_url:
                continue
                
            try:
                # Extraire le file_id et le chemin du fichier de l'URL
                url_parts = row.fichier_url.split('/')
                if len(url_parts) < 2:
                    continue
                    
                file_id = url_parts[-2]  # L'avant-dernier élément est le file_id
                minio_path = url_parts[-1]  # Le dernier élément est le nom du fichier
                
                # Vérifier si le fichier existe déjà dans fichiers_mapping
                existing = session.execute(
                    "SELECT id FROM ent_keyspace.fichiers_mapping WHERE id = %s",
                    (uuid.UUID(file_id),)
                ).one()
                
                if existing:
                    logger.info(f"Fichier {file_id} existe déjà dans fichiers_mapping")
                    continue
                
                # Récupérer les métadonnées du fichier depuis MinIO
                try:
                    stat = minio_client.stat_object(bucket_name, minio_path)
                    
                    # Insérer dans fichiers_mapping
                    session.execute("""
                        INSERT INTO ent_keyspace.fichiers_mapping (
                            id, minio_path, original_filename, content_type, size,
                            upload_date, uploaded_by, cours_id
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """, (
                        uuid.UUID(file_id),
                        minio_path,
                        minio_path,
                        stat.content_type,
                        stat.size,
                        datetime.utcnow(),
                        row.id_enseignant,
                        row.id
                    ))
                    
                    logger.info(f"Fichier {file_id} migré avec succès")
                    
                except Exception as e:
                    logger.error(f"Erreur lors de la migration du fichier {file_id}: {str(e)}")
                    continue
                    
            except Exception as e:
                logger.error(f"Erreur lors du traitement du cours {row.id}: {str(e)}")
                continue
                
        logger.info("Migration des fichiers terminée")
        
    except Exception as e:
        logger.error(f"Erreur lors de la migration des fichiers: {str(e)}", exc_info=True)

# Initialisation de Cassandra au démarrage
init_cassandra()
migrate_existing_files()

def get_file_mapping(file_id: str) -> Dict:
    """Récupère les informations de mapping d'un fichier par son ID."""
    try:
        row = session.execute(
            "SELECT * FROM ent_keyspace.fichiers_mapping WHERE id = %s",
            (uuid.UUID(file_id),)
        ).one()
        
        if not row:
            raise HTTPException(status_code=404, detail="Fichier non trouvé")
            
        return {
            "id": str(row.id),
            "minio_path": row.minio_path,
            "original_filename": row.original_filename,
            "content_type": row.content_type,
            "size": row.size,
            "upload_date": row.upload_date,
            "uploaded_by": row.uploaded_by,
            "cours_id": str(row.cours_id) if row.cours_id else None
        }
    except Exception as e:
        logger.error(f"Erreur lors de la récupération du mapping du fichier {file_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Erreur lors de la récupération des informations du fichier: {str(e)}"
        )

@router.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    cours_id: Optional[UUID] = None,
    auth_data: Tuple[Dict, str] = Depends(verify_token_with_raw)
):
    """Upload un fichier et stocke ses métadonnées."""
    current_user, raw_token = auth_data
    logger.info(f"Tentative d'upload de fichier: {file.filename} par l'utilisateur {current_user.get('preferred_username')}")

    # Vérification de la connexion Cassandra
    if not session:
        logger.error("Session Cassandra non initialisée")
        raise HTTPException(
            status_code=500,
            detail="Erreur de connexion à la base de données"
        )

    try:
        # Vérification de la connexion Cassandra
        try:
            logger.info("Test de la connexion Cassandra...")
            session.execute("SELECT now() FROM system.local")
            logger.info("Connexion Cassandra OK")
        except Exception as e:
            logger.error(f"Erreur de connexion Cassandra: {str(e)}", exc_info=True)
            raise HTTPException(
                status_code=500,
                detail="Erreur de connexion à la base de données"
            )

        # Vérification du type de fichier
        content_type = file.content_type
        if not content_type:
            raise HTTPException(
                status_code=400,
                detail="Le type de fichier n'a pas été détecté"
            )

        # Vérification de la taille du fichier
        file_size = 0
        file_content = await file.read()
        file_size = len(file_content)
        
        if file_size > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=413,
                detail=f"Le fichier est trop volumineux. Taille maximale: {MAX_FILE_SIZE/1024/1024}MB"
            )

        # Vérification du type MIME
        detected_mime = magic.from_buffer(file_content, mime=True)
        if detected_mime not in ALLOWED_MIME_TYPES:
            raise HTTPException(
                status_code=415,
                detail=f"Type de fichier non autorisé. Types acceptés: {', '.join(ALLOWED_MIME_TYPES)}"
            )

        # Génération d'un ID unique pour le fichier
        file_id = uuid.uuid4()
        
        # Nettoyage du nom de fichier
        original_filename = file.filename
        safe_filename = secure_filename(original_filename)
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        
        # Construction du chemin MinIO avec le format demandé
        if cours_id:
            minio_path = f"{cours_id}/{safe_filename}_{timestamp}{os.path.splitext(original_filename)[1]}"
        else:
            minio_path = f"{safe_filename}_{timestamp}{os.path.splitext(original_filename)[1]}"
        logger.info(f"Chemin MinIO généré: {minio_path}")

        # Upload vers MinIO
        try:
            minio_client.put_object(
                bucket_name=bucket_name,
                object_name=minio_path,
                data=BytesIO(file_content),
                length=file_size,
                content_type=detected_mime
            )
            logger.info(f"Fichier uploadé avec succès dans MinIO: {minio_path}")
        except Exception as e:
            logger.error(f"Erreur lors de l'upload vers MinIO: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail=f"Erreur lors de l'upload du fichier: {str(e)}"
            )

        # Stockage des métadonnées dans Cassandra
        try:
            # Préparation des valeurs pour l'insertion
            values = (
                file_id,
                minio_path,
                original_filename,
                detected_mime,
                file_size,
                datetime.utcnow(),
                current_user.get('sub'),
                cours_id
            )
            
            logger.info(f"Tentative d'insertion dans fichiers_mapping avec file_id={file_id}, minio_path={minio_path}")
            logger.info(f"Valeurs complètes: {values}")
            
            # Insertion dans la table fichiers_mapping
            session.execute(
                """
                INSERT INTO ent_keyspace.fichiers_mapping (
                    id, minio_path, original_filename, content_type, size,
                    upload_date, uploaded_by, cours_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                values
            )
            logger.info("Insertion Cassandra terminée")
            
            # Vérification que l'insertion a réussi
            inserted_row = session.execute(
                "SELECT * FROM ent_keyspace.fichiers_mapping WHERE id = %s",
                (file_id,)
            ).one()
            
            if not inserted_row:
                logger.error("L'insertion dans fichiers_mapping a échoué - Aucune ligne trouvée après insertion")
                raise Exception("L'insertion dans fichiers_mapping a échoué")
                
            logger.info(f"Métadonnées du fichier stockées avec succès dans Cassandra: {file_id}")
            logger.info(f"Ligne insérée: {inserted_row}")
            
        except Exception as e:
            logger.error(f"Erreur lors du stockage des métadonnées: {str(e)}", exc_info=True)
            # Si l'insertion dans Cassandra échoue, supprimer le fichier de MinIO
            try:
                minio_client.remove_object(bucket_name, minio_path)
                logger.info(f"Fichier supprimé de MinIO après échec de l'insertion dans Cassandra: {minio_path}")
            except Exception as delete_error:
                logger.error(f"Erreur lors de la suppression du fichier après échec de stockage des métadonnées: {str(delete_error)}")
            raise HTTPException(
                status_code=500,
                detail=f"Erreur lors du stockage des métadonnées du fichier: {str(e)}"
            )

        return {
            "message": "Fichier uploadé avec succès",
            "file_id": str(file_id),
            "original_filename": original_filename,
            "size": file_size,
            "content_type": detected_mime,
            "object_name": minio_path
        }

    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"Erreur inattendue lors de l'upload: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Erreur inattendue lors de l'upload: {str(e)}"
        )

@router.get("/files")
async def list_files(cours_id: str = None):
    try:
        # Si un cours_id est fourni, on filtre les objets avec ce préfixe
        prefix = f"{cours_id}/" if cours_id else ""
        objects = minio_client.list_objects(bucket_name, prefix=prefix, recursive=True)
        
        files = []
        for obj in objects:
            try:
                stat = minio_client.stat_object(bucket_name, obj.object_name)
                files.append({
                    "name": os.path.basename(obj.object_name),  # Nom du fichier uniquement pour l'affichage
                    "minio_path": obj.object_name,  # Chemin complet MinIO pour les opérations
                    "size": stat.size,
                    "content_type": stat.content_type,
                    "last_modified": stat.last_modified,
                    "download_url": f"/api/fichiers/download/{obj.object_name}"  # Utilisation du chemin complet
                })
            except Exception as e:
                logger.error(f"Erreur lors de la récupération des métadonnées pour {obj.object_name}: {str(e)}")
                continue
                
        return files
    except Exception as e:
        logger.error(f"Erreur lors de la liste des fichiers: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/download/{file_id}")
async def download_file(
    file_id: str,
    auth_data: Tuple[Dict, str] = Depends(verify_token_with_raw)
):
    """Télécharge un fichier en utilisant le chemin MinIO."""
    current_user, raw_token = auth_data
    logger.info(f"Tentative de téléchargement du fichier {file_id} par l'utilisateur {current_user.get('preferred_username')}")

    try:
        # Utiliser directement le chemin MinIO
        minio_path = file_id
        logger.info(f"Chemin MinIO utilisé: {minio_path}")

        # Vérifier les permissions
        user_roles = current_user.get('realm_access', {}).get('roles', [])
        is_admin = 'admin' in user_roles
        
        if not is_admin:
            # Vérifier si l'utilisateur est l'enseignant du cours
            try:
                # Extraire l'UUID du cours du chemin MinIO
                cours_id = minio_path.split('/')[0]
                cours_row = session.execute(
                    "SELECT id_enseignant FROM ent_keyspace.cours WHERE id = %s",
                    (uuid.UUID(cours_id),)
                ).one()
                
                if cours_row:
                    is_owner = str(cours_row.id_enseignant) == current_user.get('sub')
                    if not is_owner:
                        logger.warning(f"Accès refusé pour le téléchargement du fichier {file_id}")
                        raise HTTPException(
                            status_code=403,
                            detail="Vous n'avez pas les permissions nécessaires pour télécharger ce fichier"
                        )
            except Exception as e:
                logger.error(f"Erreur lors de la vérification des permissions: {str(e)}")
                # En cas d'erreur, on continue car le fichier pourrait être public

        # Récupérer les métadonnées depuis MinIO
        try:
            logger.info(f"Tentative de récupération des métadonnées depuis MinIO: {minio_path}")
            stat = minio_client.stat_object(bucket_name, minio_path)
            content_type = stat.content_type
            file_size = stat.size
            original_filename = os.path.basename(minio_path)
            logger.info(f"Métadonnées récupérées - Type: {content_type}, Taille: {file_size}")
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des métadonnées depuis MinIO: {str(e)}")
            raise HTTPException(status_code=404, detail="Fichier non trouvé")

        # Récupérer le fichier depuis MinIO
        try:
            logger.info(f"Tentative de récupération du fichier depuis MinIO: {minio_path}")
            response = minio_client.get_object(
                bucket_name=bucket_name,
                object_name=minio_path
            )
            
            logger.info(f"Fichier récupéré avec succès depuis MinIO: {minio_path}")

            return StreamingResponse(
                content=response.stream(32*1024),
                media_type=content_type,
                headers={
                    "Content-Disposition": f'attachment; filename="{original_filename}"',
                    "Content-Length": str(file_size)
                }
            )

        except Exception as e:
            logger.error(f"Erreur lors de la récupération du fichier depuis MinIO: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail=f"Erreur lors de la récupération du fichier: {str(e)}"
            )

    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"Erreur inattendue lors du téléchargement: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Erreur inattendue lors du téléchargement: {str(e)}"
        )

@router.delete("/delete/{file_id}")
async def delete_file(
    file_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Supprime un fichier du stockage en utilisant le chemin MinIO complet"""
    try:
        logger.info(f"Tentative de suppression du fichier {file_id} par l'utilisateur {current_user.get('preferred_username')}")
        
        # Utiliser directement le chemin MinIO pour la suppression
        minio_path = file_id
        logger.info(f"Chemin MinIO utilisé pour la suppression: {minio_path}")
        
        # Vérification des rôles
        user_roles = current_user.get('realm_access', {}).get('roles', [])
        logger.info(f"Rôles de l'utilisateur: {user_roles}")
        
        try:
            # Vérifier les permissions
            is_admin = 'admin' in user_roles
            
            # Si l'utilisateur n'est pas admin, vérifier s'il est l'enseignant du cours
            if not is_admin:
                # Extraire l'UUID du cours du chemin MinIO
                cours_id = minio_path.split('/')[0]
                cours_row = session.execute(
                    "SELECT id_enseignant FROM ent_keyspace.cours WHERE id = %s",
                    (uuid.UUID(cours_id),)
                ).one()
                
                if cours_row:
                    is_owner = str(cours_row.id_enseignant) == current_user.get('sub')
                    if not is_owner:
                        logger.warning(f"Accès refusé pour la suppression du fichier {file_id}")
                        raise HTTPException(
                            status_code=403,
                            detail="Vous n'avez pas les permissions nécessaires pour supprimer ce fichier"
                        )
            
            # Supprimer le fichier de MinIO
            minio_client.remove_object(bucket_name, minio_path)
            logger.info(f"Fichier supprimé de MinIO: {minio_path}")
            
            # Supprimer le mapping de Cassandra
            session.execute(
                "DELETE FROM ent_keyspace.fichiers_mapping WHERE minio_path = %s",
                (minio_path,)
            )
            logger.info(f"Mapping supprimé pour le fichier: {minio_path}")
            
            # Mettre à jour la table cours si nécessaire
            try:
                session.execute(
                    "UPDATE ent_keyspace.cours SET fichier_url = NULL WHERE fichier_url = %s",
                    (minio_path,)
                )
                logger.info(f"Table cours mise à jour pour le fichier: {minio_path}")
            except Exception as e:
                logger.warning(f"Erreur lors de la mise à jour de la table cours: {str(e)}")
                # On continue car ce n'est pas critique
            
            return {"message": "Fichier supprimé avec succès"}
            
        except S3Error as e:
            if e.code == 'NoSuchKey':
                logger.warning(f"Fichier non trouvé dans MinIO: {minio_path}")
                raise HTTPException(status_code=404, detail="Fichier non trouvé dans le stockage")
            logger.error(f"Erreur lors de la suppression du fichier: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail=f"Erreur lors de la suppression du fichier: {str(e)}"
            )
            
    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"Erreur inattendue lors de la suppression du fichier: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Erreur inattendue lors de la suppression: {str(e)}"
        )
