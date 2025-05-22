from fastapi import FastAPI, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from app.routes import cours
from app.auth import verify_token
import uvicorn
import logging
import os

# Configuration des logs
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Service Cours",
    description="API pour la gestion des cours",
    version="1.0.0"
)

# Configuration CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3001", "http://localhost:3000", "http://frontend:80", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"]
)

@app.middleware("http")
async def log_requests(request: Request, call_next):
    logger.info(f"Requête entrante: {request.method} {request.url}")
    response = await call_next(request)
    logger.info(f"Réponse: {response.status_code}")
    return response

# Inclure le router sans dépendance d'authentification globale
app.include_router(
    cours.router,
    prefix="/api/cours"
)

@app.get("/")
async def root():
    return {"message": "Service Cours API"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8002)
