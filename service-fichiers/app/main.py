from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routes import fichiers

app = FastAPI()

# Configuration CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # À ajuster selon vos besoins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration pour les requêtes multipart
app.include_router(
    fichiers.router,
    prefix="/api/fichiers",
    tags=["fichiers"]
)
