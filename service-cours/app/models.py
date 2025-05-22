from pydantic import BaseModel
from uuid import UUID
from datetime import datetime
from typing import Optional

class CoursBase(BaseModel):
    id: UUID
    titre: str
    description: str
    date_ajout: Optional[str] = None
    fichier_url: Optional[str] = None
    id_enseignant: UUID

class CoursCreate(CoursBase):
    fichier_base64: Optional[str] = None
    nom_fichier: Optional[str] = None
    type_fichier: Optional[str] = None

class Cours(CoursBase):
    id: UUID
    date_ajout: datetime
    fichier_url: Optional[str] = None
    id_enseignant: UUID
