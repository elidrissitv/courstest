from cassandra.cluster import Cluster
import time
import logging

MAX_RETRIES = 10
RETRY_DELAY = 5

# Nom du service dans Docker Compose
cluster = Cluster(["cassandra"])  # Nom du service Cassandra dans docker-compose
session = None

logger = logging.getLogger(__name__)

for attempt in range(MAX_RETRIES):
    try:
        session = cluster.connect()
        session.set_keyspace('ent_keyspace')  # Définir le keyspace après connexion
        print("✅ Connexion à Cassandra réussie.")
        break
    except Exception as e:
        print(f"❌ Cassandra non disponible (tentative {attempt + 1}) : {e}")
        time.sleep(RETRY_DELAY)

if session is None:
    raise Exception("Impossible de se connecter à Cassandra.")
