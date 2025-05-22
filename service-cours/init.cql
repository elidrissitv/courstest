-- Attendre que Cassandra soit prêt
SELECT now() FROM system.local;

-- Création du keyspace
CREATE KEYSPACE IF NOT EXISTS ent_keyspace
WITH replication = {
    'class': 'SimpleStrategy',
    'replication_factor': 1
};

-- Utilisation du keyspace
USE ent_keyspace;

-- Table des utilisateurs
CREATE TABLE IF NOT EXISTS utilisateurs (
    id UUID PRIMARY KEY,
    keycloak_id TEXT,
    nom TEXT,
    prenom TEXT,
    email TEXT,
    role TEXT,
    statut TEXT,
    date_creation TIMESTAMP
);

-- Table des cours
CREATE TABLE IF NOT EXISTS cours (
    id UUID PRIMARY KEY,
    titre TEXT,
    description TEXT,
    id_enseignant UUID,
    fichier_url TEXT,
    date_ajout TIMESTAMP
);

-- Table des consultations de cours
CREATE TABLE IF NOT EXISTS consultation_cours (
    id_cours UUID,
    id_etudiant UUID,
    date_consultation TIMESTAMP,
    PRIMARY KEY ((id_cours), id_etudiant, date_consultation)
);

-- Table des interactions avec le chatbot IA
CREATE TABLE IF NOT EXISTS interactions_chatbot (
    id UUID PRIMARY KEY,
    id_utilisateur UUID,
    question TEXT,
    reponse TEXT,
    date_interaction TIMESTAMP
);

-- Table des notifications
CREATE TABLE IF NOT EXISTS notifications (
    id UUID PRIMARY KEY,
    id_utilisateur UUID,
    message TEXT,
    type TEXT,
    lu BOOLEAN,
    date_envoi TIMESTAMP
);

-- Index pour les recherches courantes
CREATE INDEX IF NOT EXISTS idx_utilisateurs_email ON utilisateurs (email);
CREATE INDEX IF NOT EXISTS idx_utilisateurs_keycloak ON utilisateurs (keycloak_id);
CREATE INDEX IF NOT EXISTS idx_cours_enseignant ON cours (id_enseignant);
CREATE INDEX IF NOT EXISTS idx_notifications_utilisateur ON notifications (id_utilisateur);
CREATE INDEX IF NOT EXISTS idx_notifications_non_lues ON notifications (lu); 