from cassandra.cluster import Cluster
import os
import logging

# Configuration des logs
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Connexion à Cassandra
cassandra_hosts = os.getenv('CASSANDRA_HOSTS', '["cassandra"]').replace('"', '').strip('[]').split(',')
cassandra_port = int(os.getenv('CASSANDRA_PORT', '9042'))
cassandra_keyspace = os.getenv('CASSANDRA_KEYSPACE', 'ent_keyspace')

logger.info(f"Connexion à Cassandra sur {cassandra_hosts}:{cassandra_port}")
logger.info(f"Utilisation du keyspace: {cassandra_keyspace}")

try:
    cluster = Cluster(cassandra_hosts, port=cassandra_port)
    session = cluster.connect(cassandra_keyspace)
    logger.info("Connexion à Cassandra établie avec succès")
except Exception as e:
    logger.error(f"Erreur lors de la connexion à Cassandra: {str(e)}")
    raise
