from minio import Minio
import os
from minio.error import S3Error
import logging

logger = logging.getLogger(__name__)

# Configuration MinIO
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "minio:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "minioadmin")

logger.info(f"Configuration MinIO - Endpoint: {MINIO_ENDPOINT}")
logger.info(f"Configuration MinIO - Access Key: {MINIO_ACCESS_KEY}")
logger.info(f"Configuration MinIO - Secret Key: {'*' * len(MINIO_SECRET_KEY) if MINIO_SECRET_KEY else 'None'}")

# Initialisation du client MinIO
minio_client = Minio(
    MINIO_ENDPOINT,
    access_key=MINIO_ACCESS_KEY,
    secret_key=MINIO_SECRET_KEY,
    secure=False
)

bucket_name = "fichiers-cours"

def ensure_bucket_exists(bucket_name: str):
    """Vérifie si le bucket existe, sinon le crée."""
    try:
        logger.info(f"Vérification de l'existence du bucket: {bucket_name}")
        if not minio_client.bucket_exists(bucket_name):
            logger.info(f"Création du bucket: {bucket_name}")
            minio_client.make_bucket(bucket_name)
            logger.info(f"Bucket {bucket_name} créé avec succès")
        else:
            logger.info(f"Bucket {bucket_name} existe déjà")
    except S3Error as e:
        logger.error(f"Erreur lors de la vérification/création du bucket {bucket_name}: {str(e)}")
        raise
