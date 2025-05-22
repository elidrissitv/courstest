from pydantic import BaseModel
from uuid import UUID

class Cours(BaseModel):
    id: UUID
    nom_cours: str
    description: str
    user_id: UUID

class CoursCreate(BaseModel):
    nom_cours: str
    description: str
    user_id: UUID
