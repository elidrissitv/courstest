#!/bin/bash

# Démarrer l'application
exec uvicorn app.main:app --host 0.0.0.0 --port 8002 